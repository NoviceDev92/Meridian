#pragma once

#include "analysis.hpp"
#include "dissector.hpp"
#include "pcap_writer.hpp"
#include "udp_socket.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace netproto {

// ============================================================================
// Live Tap Capture Session (Backend for CLI Sniffer & Phase 5 3-Pane UI)
//
// Pipeline for every tap datagram:
//   UDP :9999 -> TapEnvelope::deserialize_tap -> EndpointResolver (fix
//   loopback addresses) -> to_wire_frame (Eth+IPv4+UDP, real checksums) ->
//   PacketDissector -> TransactionTracker (request/response pairing) ->
//   packet store -> callback (GUI posts WM_APP_NEW_PACKET)
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

    // Bumped whenever earlier frames were renumbered (out-of-order arrival);
    // a UI that only appends new rows must then do a full refresh.
    uint64_t reorder_generation() const { return reorder_generation_.load(); }
    bool is_running() const { return running_.load(); }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        packets_.clear();
        records_.clear();
        first_ts_us_ = 0;
        tracker_.reset();
        resolver_.reset();
    }

    size_t count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return packets_.size();
    }

    std::vector<DissectedPacket> snapshot(const std::string& filter = "") const {
        return snapshot(DisplayFilter::compile(filter));
    }

    // Filter compiled once, then evaluated per packet.
    std::vector<DissectedPacket> snapshot(const DisplayFilter& filter) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (filter.empty()) return packets_;

        std::vector<DissectedPacket> filtered;
        for (const auto& p : packets_) {
            if (filter.matches(p)) {
                filtered.push_back(p);
            }
        }
        return filtered;
    }

    CaptureStatistics statistics() const {
        std::lock_guard<std::mutex> lk(mu_);
        return CaptureStatistics::compute(packets_);
    }

    bool export_pcap(const std::string& path) const {
        std::lock_guard<std::mutex> lk(mu_);
        return PcapStorage::save_pcap(path, packets_);
    }

    bool import_pcap(const std::string& path, std::string* error = nullptr) {
        std::vector<PcapStorage::RawRecord> recs;
        std::string err;
        if (!PcapStorage::read_records(path, recs, err)) {
            if (error) *error = err;
            return false;
        }
        std::vector<DissectedPacket> loaded;
        loaded.reserve(recs.size());
        uint64_t first = recs.empty() ? 0 : recs.front().ts_us;
        uint32_t idx = 1;
        for (const auto& r : recs) {
            double rel = (static_cast<double>(r.ts_us) - static_cast<double>(first)) / 1e6;
            loaded.push_back(PacketDissector::dissect_wire_frame(idx++, r.ts_us, rel, r.frame));
        }
        std::lock_guard<std::mutex> lk(mu_);
        packets_ = std::move(loaded);
        first_ts_us_ = first;
        tracker_.process_all(packets_);
        resolver_.reset();
        records_.clear();
        for (const auto& r : recs) {
            TapRecord tr;
            tr.ts_us = r.ts_us;
            tr.frame = r.frame;
            records_.push_back(std::move(tr));
        }
        return true;
    }

private:
    // A tap record kept so frames can be re-dissected when re-ordered.
    struct TapRecord {
        uint64_t ts_us = 0;
        AppProtoHint hint = AppProtoHint::UNKNOWN;
        bool from_tap = false;      // true: frame is rebuilt from `env`
        TapEnvelope env;            // original (unresolved) tap envelope
        std::vector<uint8_t> frame; // wire frame (pcap import: as read)
    };

    // Re-dissects every stored frame (numbers, relative times and request/
    // response links all depend on order). Caller holds mu_.
    void rebuild_locked() {
        packets_.clear();
        packets_.reserve(records_.size());
        first_ts_us_ = records_.empty() ? 0 : records_.front().ts_us;
        resolver_.reset();
        uint32_t no = 1;
        for (auto& r : records_) {
            if (r.from_tap) {
                // Re-learn port owners in timestamp order, then re-synthesize
                TapEnvelope e = r.env;
                resolver_.resolve(e);
                r.frame = e.to_wire_frame();
            }
            double rel = (static_cast<double>(r.ts_us) - static_cast<double>(first_ts_us_)) / 1e6;
            packets_.push_back(PacketDissector::dissect_wire_frame(no++, r.ts_us, rel, r.frame, r.hint));
        }
        tracker_.process_all(packets_);
    }

    void listen_loop() {
        while (running_.load()) {
            std::vector<uint8_t> buf;
            std::string src_ip;
            uint16_t src_port = 0;
            int n = sock_.recv_from(buf, src_ip, src_port);
            if (n <= 0) continue;

            try {
                TapEnvelope env = TapEnvelope::deserialize_tap(buf.data(), buf.size());

                DissectedPacket pkt;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    TapRecord rec;
                    rec.ts_us    = env.timestamp_us;
                    rec.hint     = static_cast<AppProtoHint>(env.proto_hint);
                    rec.from_tap = true;
                    rec.env      = env;

                    if (!records_.empty() && rec.ts_us < records_.back().ts_us) {
                        // Out-of-order arrival: datagrams from different
                        // processes/threads race on the loopback tap. Keep the
                        // capture sorted by the sender's timestamp, like a
                        // real NIC would see them, then renumber everything.
                        auto pos = std::upper_bound(records_.begin(), records_.end(), rec.ts_us,
                            [](uint64_t ts, const TapRecord& r) { return ts < r.ts_us; });
                        size_t at = static_cast<size_t>(pos - records_.begin());
                        records_.insert(pos, std::move(rec));
                        rebuild_locked();
                        reorder_generation_.fetch_add(1);
                        pkt = packets_[at];
                    } else {
                        resolver_.resolve(env);
                        rec.frame = env.to_wire_frame();
                        if (records_.empty()) first_ts_us_ = rec.ts_us;
                        double rel = (static_cast<double>(rec.ts_us) -
                                      static_cast<double>(first_ts_us_)) / 1e6;
                        uint32_t no = static_cast<uint32_t>(packets_.size() + 1);
                        packets_.push_back(PacketDissector::dissect_wire_frame(
                            no, rec.ts_us, rel, rec.frame, rec.hint));
                        records_.push_back(std::move(rec));
                        tracker_.process(packets_, packets_.size() - 1);
                        pkt = packets_.back();
                    }
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
    std::vector<TapRecord> records_;
    TransactionTracker tracker_;
    EndpointResolver resolver_;
    std::atomic<uint64_t> reorder_generation_{0};
};

} // namespace netproto
