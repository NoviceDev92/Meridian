#pragma once

#include "dissector.hpp"
#include "pcap_writer.hpp"
#include "udp_socket.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace netproto {

// ============================================================================
// Live Tap Capture Session (Backend for CLI Sniffer & Phase 5 3-Pane UI)
// ============================================================================
class CaptureSession {
public:
    using PacketCallback = std::function<void(const DissectedPacket&)>;

    explicit CaptureSession(uint16_t tap_port = TAP_SNIFFER_PORT,
                            std::string bind_ip = "127.0.0.1")
        : tap_port_(tap_port), bind_ip_(std::move(bind_ip)) {}

    ~CaptureSession() { stop(); }

    void start(PacketCallback on_packet = nullptr) {
        if (running_.load()) return;
        on_packet_ = std::move(on_packet);
        sock_ = UdpSocket();
        sock_.bind(tap_port_, bind_ip_);
        sock_.set_timeout_ms(100);
        bound_port_ = sock_.local_port();
        running_.store(true);

        worker_ = std::thread([this]() { listen_loop(); });
    }

    void stop() {
        running_.store(false);
        if (worker_.joinable()) {
            worker_.join();
        }
        sock_.close();
    }

    uint16_t bound_port() const { return bound_port_; }
    bool is_running() const { return running_.load(); }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        packets_.clear();
        first_ts_us_ = 0;
    }

    size_t count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return packets_.size();
    }

    std::vector<DissectedPacket> snapshot(const std::string& filter = "") const {
        std::lock_guard<std::mutex> lk(mu_);
        if (filter.empty()) return packets_;

        std::vector<DissectedPacket> filtered;
        for (const auto& p : packets_) {
            if (PacketDissector::matches_filter(p, filter)) {
                filtered.push_back(p);
            }
        }
        return filtered;
    }

    bool export_pcap(const std::string& path) const {
        std::lock_guard<std::mutex> lk(mu_);
        return PcapStorage::save_pcap(path, packets_);
    }

    bool import_pcap(const std::string& path) {
        std::vector<DissectedPacket> loaded;
        if (!PcapStorage::load_pcap(path, loaded)) return false;
        std::lock_guard<std::mutex> lk(mu_);
        packets_ = std::move(loaded);
        first_ts_us_ = packets_.empty() ? 0 : packets_.front().timestamp_us;
        return true;
    }

private:
    void listen_loop() {
        while (running_.load()) {
            std::vector<uint8_t> buf;
            std::string src_ip;
            uint16_t src_port = 0;
            int n = sock_.recv_from(buf, src_ip, src_port);
            if (n <= 0) continue;

            try {
                TapEnvelope env = TapEnvelope::deserialize_tap(buf.data(), buf.size());
                auto wire = env.to_wire_frame();

                DissectedPacket pkt;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (packets_.empty()) {
                        first_ts_us_ = env.timestamp_us;
                    }
                    double rel = static_cast<double>(env.timestamp_us - first_ts_us_) / 1000000.0;
                    uint32_t no = static_cast<uint32_t>(packets_.size() + 1);
                    pkt = PacketDissector::dissect_wire_frame(
                        no, env.timestamp_us, rel, wire, static_cast<AppProtoHint>(env.proto_hint));
                    packets_.push_back(pkt);
                }

                if (on_packet_) {
                    on_packet_(pkt);
                }
            } catch (const std::exception&) {}
        }
    }

    uint16_t tap_port_;
    std::string bind_ip_;
    uint16_t bound_port_ = 0;
    UdpSocket sock_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    PacketCallback on_packet_;

    mutable std::mutex mu_;
    std::vector<DissectedPacket> packets_;
    uint64_t first_ts_us_ = 0;
};

} // namespace netproto

