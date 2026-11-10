#pragma once

#include "protocol_headers.hpp"
#include "udp_socket.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace netproto {

// ============================================================================
// Client-Acquired Network Configuration (Output of BOOTP -> Input to DNS)
// ============================================================================
struct BootpNetworkConfig {
    bool valid           = false;
    uint32_t client_ip   = 0;
    uint32_t server_ip   = 0;
    uint32_t relay_ip    = 0;
    uint32_t subnet_mask = 0;
    uint32_t router_ip   = 0;
    uint32_t dns_ip      = 0;
    uint32_t lease_secs  = 0;
    std::string hostname;
    std::string domain_name;
    std::string server_name;

    std::string summary() const {
        std::ostringstream oss;
        oss << "IP=" << ipv4_to_string(client_ip)
            << " | Mask=" << ipv4_to_string(subnet_mask)
            << " | GW=" << ipv4_to_string(router_ip)
            << " | DNS=" << ipv4_to_string(dns_ip)
            << " | Domain=" << (domain_name.empty() ? "-" : domain_name)
            << " | Lease=" << lease_secs << "s";
        if (relay_ip != 0) {
            oss << " | Relay=" << ipv4_to_string(relay_ip);
        }
        return oss.str();
    }
};

// ============================================================================
// BOOTP Server Lease & Pool Configuration
// ============================================================================
struct SubnetPool {
    uint32_t network_ip  = 0; // e.g. 192.168.10.0
    uint32_t subnet_mask = 0; // e.g. 255.255.255.0
    uint32_t router_ip   = 0; // e.g. 192.168.10.1
    uint32_t pool_start  = 0; // e.g. 192.168.10.100
    uint32_t pool_end    = 0; // e.g. 192.168.10.200
};

struct BootpLease {
    std::string mac_str;
    uint32_t ip          = 0;
    uint32_t subnet_mask = 0;
    uint32_t router_ip   = 0;
    std::string hostname;
    bool is_static       = false;
    std::chrono::steady_clock::time_point expires_at;
};

struct BootpServerConfig {
    uint16_t listen_port     = BOOTP_SERVER_PORT;
    std::string bind_ip      = "0.0.0.0";
    std::string server_ip    = "192.168.10.1";
    std::string server_name  = "bootp-srv.lab.local";
    std::string dns_ip       = "192.168.10.2";
    std::string domain_name  = "lab.local";
    uint32_t lease_secs      = 3600;
    uint32_t drop_rate_pct   = 0; // 0..100 for simulating packet loss
    bool enable_tap          = true;
    bool tap_on_receive      = false; // Avoid duplicate tap entries when paired with BootpClient
    uint16_t tap_port        = TAP_SNIFFER_PORT;

    SubnetPool default_pool{
        ipv4_from_string("192.168.10.0"),
        ipv4_from_string("255.255.255.0"),
        ipv4_from_string("192.168.10.1"),
        ipv4_from_string("192.168.10.100"),
        ipv4_from_string("192.168.10.200")
    };

    // Additional relay-reached subnets (keyed by giaddr network match)
    std::vector<SubnetPool> relay_pools{
        {
            ipv4_from_string("10.0.2.0"),
            ipv4_from_string("255.255.255.0"),
            ipv4_from_string("10.0.2.1"),
            ipv4_from_string("10.0.2.100"),
            ipv4_from_string("10.0.2.150")
        }
    };
};

// ============================================================================
// BOOTP Server Implementation
// ============================================================================
class BootpServer {
public:
    explicit BootpServer(BootpServerConfig cfg = {})
        : cfg_(std::move(cfg)),
          tap_(cfg_.tap_port),
          rng_(std::random_device{}()) {
        sock_.bind(cfg_.listen_port, cfg_.bind_ip);
        sock_.set_timeout_ms(100);
        sock_.enable_broadcast(true);
    }

    uint16_t bound_port() const { return sock_.local_port(); }

    void add_static_reservation(const std::string& mac_str,
                                const std::string& ip_str,
                                const std::string& hostname = "") {
        std::lock_guard<std::mutex> lk(mu_);
        BootpLease lease;
        lease.mac_str     = normalize_mac(mac_str);
        lease.ip          = ipv4_from_string(ip_str);
        lease.subnet_mask = cfg_.default_pool.subnet_mask;
        lease.router_ip   = cfg_.default_pool.router_ip;
        lease.hostname    = hostname;
        lease.is_static   = true;
        lease.expires_at  = std::chrono::steady_clock::time_point::max();
        leases_[lease.mac_str] = lease;
        allocated_ips_[lease.ip] = lease.mac_str;
    }

    std::vector<BootpLease> get_leases() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<BootpLease> out;
        out.reserve(leases_.size());
        for (const auto& kv : leases_) out.push_back(kv.second);
        return out;
    }

    void run(bool verbose = true) {
        running_.store(true);
        if (verbose) {
            std::cout << "[BOOTP SERVER] Listening on " << cfg_.bind_ip << ":" << bound_port()
                      << " (DNS Opt 6=" << cfg_.dns_ip
                      << ", DropRate=" << cfg_.drop_rate_pct << "%)\n";
        }
        while (running_.load()) {
            std::vector<uint8_t> rx_buf;
            std::string peer_ip;
            uint16_t peer_port = 0;
            int n = sock_.recv_from(rx_buf, peer_ip, peer_port);
            if (n <= 0) continue;

            try {
                handle_datagram(rx_buf, peer_ip, peer_port, verbose);
            } catch (const std::exception& ex) {
                if (verbose) {
                    std::cerr << "[BOOTP SERVER] Malformed packet from " << peer_ip
                              << ":" << peer_port << " (" << ex.what() << ")\n";
                }
            }
        }
    }

    void stop() { running_.store(false); }

private:
    static std::string normalize_mac(const std::string& mac) {
        return mac_to_string(mac_from_string(mac));
    }

    bool should_simulate_drop() {
        if (cfg_.drop_rate_pct == 0) return false;
        std::uniform_int_distribution<uint32_t> dist(1, 100);
        return dist(rng_) <= cfg_.drop_rate_pct;
    }

    const SubnetPool& select_pool(uint32_t giaddr) const {
        if (giaddr != 0) {
            for (const auto& p : cfg_.relay_pools) {
                if ((giaddr & p.subnet_mask) == p.network_ip) {
                    return p;
                }
            }
        }
        return cfg_.default_pool;
    }

    bool allocate_lease(const std::string& mac_str,
                        uint32_t giaddr,
                        BootpLease& out_lease) {
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();

        // Purge expired dynamic leases
        for (auto it = leases_.begin(); it != leases_.end();) {
            if (!it->second.is_static && it->second.expires_at <= now) {
                allocated_ips_.erase(it->second.ip);
                it = leases_.erase(it);
            } else {
                ++it;
            }
        }

        const SubnetPool& pool = select_pool(giaddr);

        // Existing active lease (static or valid dynamic)
        auto existing = leases_.find(mac_str);
        if (existing != leases_.end()) {
            // If static or matches target subnet, reuse idempotently
            if (existing->second.is_static ||
                (existing->second.ip & pool.subnet_mask) == pool.network_ip) {
                if (!existing->second.is_static) {
                    existing->second.expires_at = now + std::chrono::seconds(cfg_.lease_secs);
                }
                out_lease = existing->second;
                return true;
            }
        }

        // Allocate next free IP in selected pool
        for (uint32_t candidate = pool.pool_start; candidate <= pool.pool_end; ++candidate) {
            if (allocated_ips_.find(candidate) == allocated_ips_.end()) {
                BootpLease lease;
                lease.mac_str     = mac_str;
                lease.ip          = candidate;
                lease.subnet_mask = pool.subnet_mask;
                lease.router_ip   = pool.router_ip;
                lease.hostname    = "node-" + std::to_string(candidate & 0xFF);
                lease.is_static   = false;
                lease.expires_at  = now + std::chrono::seconds(cfg_.lease_secs);

                leases_[mac_str]         = lease;
                allocated_ips_[candidate] = mac_str;
                out_lease = lease;
                return true;
            }
        }
        return false; // Pool exhausted
    }

    void handle_datagram(const std::vector<uint8_t>& rx_buf,
                         const std::string& peer_ip,
                         uint16_t peer_port,
                         bool verbose) {
        BootpPacket req = BootpPacket::deserialize(rx_buf.data(), rx_buf.size());
        if (req.op != static_cast<uint8_t>(BootpOp::REQUEST)) {
            return;
        }

        auto mac = req.get_mac();
        std::string mac_str = mac_to_string(mac);

        if (cfg_.enable_tap && cfg_.tap_on_receive) {
            std::string tap_src = (req.giaddr != 0) ? ipv4_to_string(req.giaddr) : "0.0.0.0";
            tap_.emit(tap_src, peer_port, cfg_.server_ip, bound_port(),
                      AppProtoHint::BOOTP, rx_buf, mac);
        }

        if (should_simulate_drop()) {
            if (verbose) {
                std::cout << "[BOOTP SERVER] [DROP SIM] Dropped BOOTREQUEST from "
                          << mac_str << " (xid=0x" << std::hex << req.xid << std::dec << ")\n";
            }
            return;
        }

        BootpLease lease;
        if (!allocate_lease(mac_str, req.giaddr, lease)) {
            if (verbose) {
                std::cerr << "[BOOTP SERVER] Pool exhausted! Cannot serve " << mac_str << "\n";
            }
            return;
        }

        BootpPacket rep;
        rep.op     = static_cast<uint8_t>(BootpOp::REPLY);
        rep.htype  = req.htype;
        rep.hlen   = req.hlen;
        rep.hops   = req.hops;
        rep.xid    = req.xid;
        rep.secs   = req.secs;
        rep.flags  = req.flags;
        rep.ciaddr = req.ciaddr;
        rep.yiaddr = lease.ip;
        rep.siaddr = ipv4_from_string(cfg_.server_ip);
        rep.giaddr = req.giaddr;
        rep.chaddr = req.chaddr;
        rep.sname  = cfg_.server_name;

        rep.add_ip_option(BootpOptionTag::SUBNET_MASK, lease.subnet_mask);
        rep.add_ip_option(BootpOptionTag::ROUTER, lease.router_ip);
        rep.add_ip_option(BootpOptionTag::DNS_SERVER, ipv4_from_string(cfg_.dns_ip));
        if (!lease.hostname.empty()) {
            rep.add_string_option(BootpOptionTag::HOSTNAME, lease.hostname);
        }
        rep.add_string_option(BootpOptionTag::DOMAIN_NAME, cfg_.domain_name);
        rep.add_u32_option(BootpOptionTag::LEASE_TIME, cfg_.lease_secs);

        auto rep_bytes = rep.serialize();
        sock_.send_to(rep_bytes, peer_ip, peer_port);

        if (cfg_.enable_tap) {
            std::string tap_dst = (req.giaddr != 0)
                                      ? ipv4_to_string(req.giaddr)
                                      : ipv4_to_string(lease.ip);
            tap_.emit(cfg_.server_ip, bound_port(), tap_dst, peer_port,
                      AppProtoHint::BOOTP, rep_bytes,
                      {0x02, 0x00, 0x00, 0xAA, 0xBB, 0x01}, mac);
        }

        if (verbose) {
            std::cout << "[BOOTP SERVER] BOOTREQUEST (" << mac_str << ", xid=0x"
                      << std::hex << req.xid << std::dec
                      << (req.giaddr ? ", via relay " + ipv4_to_string(req.giaddr) : "")
                      << ") -> Assigned " << ipv4_to_string(lease.ip)
                      << (lease.is_static ? " [STATIC]" : " [DYNAMIC]")
                      << " | DNS=" << cfg_.dns_ip << "\n";
        }
    }

    BootpServerConfig cfg_;
    UdpSocket sock_;
    TapMirror tap_;
    std::atomic<bool> running_{false};

    mutable std::mutex mu_;
    std::map<std::string, BootpLease> leases_;
    std::map<uint32_t, std::string> allocated_ips_;
    std::mt19937 rng_;
};

// ============================================================================
// BOOTP Relay Agent (Cross-Subnet Forwarding via giaddr & hops)
// ============================================================================
struct BootpRelayConfig {
    uint16_t listen_port    = BOOTP_RELAY_PORT;
    std::string bind_ip     = "127.0.0.1";
    std::string relay_ip    = "10.0.2.1";      // giaddr stamped onto forwarded requests
    std::string server_ip   = "127.0.0.1";     // Upstream BOOTP server socket IP
    uint16_t server_port    = BOOTP_SERVER_PORT;
    uint8_t max_hops        = 4;
    bool enable_tap         = true;
    uint16_t tap_port       = TAP_SNIFFER_PORT;
};

class BootpRelay {
public:
    explicit BootpRelay(BootpRelayConfig cfg = {})
        : cfg_(std::move(cfg)), tap_(cfg_.tap_port) {
        client_facing_.bind(cfg_.listen_port, cfg_.bind_ip);
        client_facing_.set_timeout_ms(100);
        server_facing_.bind(0, cfg_.bind_ip);
        server_facing_.set_timeout_ms(100);
    }

    uint16_t bound_port() const { return client_facing_.local_port(); }

    void run(bool verbose = true) {
        running_.store(true);
        if (verbose) {
            std::cout << "[BOOTP RELAY] Listening on " << cfg_.bind_ip << ":" << bound_port()
                      << " (giaddr=" << cfg_.relay_ip
                      << " -> Server " << cfg_.server_ip << ":" << cfg_.server_port << ")\n";
        }
        while (running_.load()) {
            poll_client_side(verbose);
            poll_server_side(verbose);
        }
    }

    void stop() { running_.store(false); }

private:
    struct PendingClient {
        std::string ip;
        uint16_t port = 0;
    };

    void poll_client_side(bool verbose) {
        std::vector<uint8_t> buf;
        std::string src_ip;
        uint16_t src_port = 0;
        if (client_facing_.recv_from(buf, src_ip, src_port) <= 0) return;

        try {
            BootpPacket pkt = BootpPacket::deserialize(buf.data(), buf.size());
            if (pkt.op != static_cast<uint8_t>(BootpOp::REQUEST)) return;
            if (pkt.hops >= cfg_.max_hops) {
                if (verbose) {
                    std::cout << "[BOOTP RELAY] Dropping packet: hops="
                              << static_cast<int>(pkt.hops) << " >= max_hops\n";
                }
                return;
            }
            pkt.hops += 1;
            if (pkt.giaddr == 0) {
                pkt.giaddr = ipv4_from_string(cfg_.relay_ip);
            }
            {
                std::lock_guard<std::mutex> lk(mu_);
                pending_[pkt.xid] = {src_ip, src_port};
            }
            auto fwd = pkt.serialize();
            server_facing_.send_to(fwd, cfg_.server_ip, cfg_.server_port);

            if (cfg_.enable_tap) {
                tap_.emit(cfg_.relay_ip, server_facing_.local_port(),
                          cfg_.server_ip, cfg_.server_port,
                          AppProtoHint::BOOTP, fwd,
                          {0x02, 0x00, 0x00, 0xCC, 0xDD, 0x01},
                          {0x02, 0x00, 0x00, 0xAA, 0xBB, 0x01});
            }
            if (verbose) {
                std::cout << "[BOOTP RELAY] Forwarded BOOTREQUEST (xid=0x"
                          << std::hex << pkt.xid << std::dec
                          << ", hops=" << static_cast<int>(pkt.hops)
                          << ", giaddr=" << ipv4_to_string(pkt.giaddr) << ")\n";
            }
        } catch (const std::exception&) {}
    }

    void poll_server_side(bool verbose) {
        std::vector<uint8_t> buf;
        std::string src_ip;
        uint16_t src_port = 0;
        if (server_facing_.recv_from(buf, src_ip, src_port) <= 0) return;

        try {
            BootpPacket pkt = BootpPacket::deserialize(buf.data(), buf.size());
            if (pkt.op != static_cast<uint8_t>(BootpOp::REPLY)) return;

            PendingClient target;
            {
                std::lock_guard<std::mutex> lk(mu_);
                auto it = pending_.find(pkt.xid);
                if (it == pending_.end()) return;
                target = it->second;
                pending_.erase(it);
            }

            client_facing_.send_to(buf, target.ip, target.port);
            if (cfg_.enable_tap) {
                tap_.emit(cfg_.relay_ip, bound_port(),
                          ipv4_to_string(pkt.yiaddr), target.port,
                          AppProtoHint::BOOTP, buf,
                          {0x02, 0x00, 0x00, 0xCC, 0xDD, 0x01}, pkt.get_mac());
            }
            if (verbose) {
                std::cout << "[BOOTP RELAY] Relayed BOOTREPLY (xid=0x"
                          << std::hex << pkt.xid << std::dec
                          << ", yiaddr=" << ipv4_to_string(pkt.yiaddr) << ") -> Client\n";
            }
        } catch (const std::exception&) {}
    }

    BootpRelayConfig cfg_;
    UdpSocket client_facing_;
    UdpSocket server_facing_;
    TapMirror tap_;
    std::atomic<bool> running_{false};
    std::mutex mu_;
    std::map<uint32_t, PendingClient> pending_;
};

// ============================================================================
// BOOTP Client State Machine (With Exponential Backoff Retransmission)
// ============================================================================
enum class BootpClientState {
    INIT,
    BOOTING,
    WAITING_REPLY,
    BOUND,
    FAILED
};

inline const char* bootp_state_name(BootpClientState s) {
    switch (s) {
        case BootpClientState::INIT:          return "INIT";
        case BootpClientState::BOOTING:       return "BOOTING";
        case BootpClientState::WAITING_REPLY: return "WAITING_REPLY";
        case BootpClientState::BOUND:         return "BOUND";
        case BootpClientState::FAILED:        return "FAILED";
    }
    return "UNKNOWN";
}

struct BootpClientOptions {
    std::string mac_str         = "00:1a:2b:3c:4d:5e";
    std::string target_ip       = "127.0.0.1";
    uint16_t target_port        = BOOTP_SERVER_PORT;
    uint16_t local_port         = 0;     // 0 = ephemeral
    uint32_t base_timeout_ms    = 300;   // Doubles on each retry
    uint32_t max_retries        = 4;
    bool broadcast              = false;
    bool enable_tap             = true;
    uint16_t tap_port           = TAP_SNIFFER_PORT;
    bool verbose                = true;
};

class BootpClient {
public:
    explicit BootpClient(BootpClientOptions opts = {})
        : opts_(std::move(opts)), tap_(opts_.tap_port) {}

    BootpClientState state() const { return state_; }
    uint32_t last_attempts() const { return attempts_taken_; }

    BootpNetworkConfig acquire_configuration() {
        BootpNetworkConfig config;
        state_ = BootpClientState::BOOTING;
        log_state("Initializing network interface MAC=" + opts_.mac_str);

        UdpSocket sock;
        sock.bind(opts_.local_port, "0.0.0.0");
        if (opts_.broadcast) {
            sock.enable_broadcast(true);
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        const uint32_t xid = gen();
        const auto mac = mac_from_string(opts_.mac_str);
        const auto boot_start = std::chrono::steady_clock::now();

        uint32_t timeout_ms = opts_.base_timeout_ms;
        attempts_taken_ = 0;

        for (uint32_t attempt = 1; attempt <= opts_.max_retries; ++attempt) {
            attempts_taken_ = attempt;
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - boot_start).count();

            BootpPacket req;
            req.op    = static_cast<uint8_t>(BootpOp::REQUEST);
            req.xid   = xid;
            req.secs  = static_cast<uint16_t>(elapsed);
            req.flags = opts_.broadcast ? 0x8000 : 0x0000;
            req.set_mac(mac);

            auto wire = req.serialize();
            sock.set_timeout_ms(timeout_ms);
            sock.send_to(wire, opts_.target_ip, opts_.target_port);

            if (opts_.enable_tap) {
                tap_.emit("0.0.0.0", sock.local_port(),
                          opts_.broadcast ? "255.255.255.255" : opts_.target_ip,
                          opts_.target_port, AppProtoHint::BOOTP, wire, mac);
            }

            state_ = BootpClientState::WAITING_REPLY;
            log_state("Attempt " + std::to_string(attempt) + "/" +
                      std::to_string(opts_.max_retries) + " -> Sent BOOTREQUEST (xid=0x" +
                      to_hex(xid) + ", timeout=" + std::to_string(timeout_ms) + "ms)");

            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            while (std::chrono::steady_clock::now() < deadline) {
                std::vector<uint8_t> rx_buf;
                std::string peer_ip;
                uint16_t peer_port = 0;
                int n = sock.recv_from(rx_buf, peer_ip, peer_port);
                if (n <= 0) break;

                try {
                    BootpPacket rep = BootpPacket::deserialize(rx_buf.data(), rx_buf.size());
                    if (rep.op != static_cast<uint8_t>(BootpOp::REPLY)) continue;
                    if (rep.xid != xid) {
                        log_state("Ignored BOOTREPLY with mismatched xid=0x" + to_hex(rep.xid));
                        continue;
                    }
                    if (rep.get_mac() != mac) continue;

                    config.valid       = true;
                    config.client_ip   = rep.yiaddr;
                    config.server_ip   = rep.siaddr;
                    config.relay_ip    = rep.giaddr;
                    config.server_name = rep.sname;
                    rep.get_ip_option(BootpOptionTag::SUBNET_MASK, config.subnet_mask);
                    rep.get_ip_option(BootpOptionTag::ROUTER, config.router_ip);
                    rep.get_ip_option(BootpOptionTag::DNS_SERVER, config.dns_ip);
                    rep.get_string_option(BootpOptionTag::HOSTNAME, config.hostname);
                    rep.get_string_option(BootpOptionTag::DOMAIN_NAME, config.domain_name);

                    uint32_t lease_val = 0;
                    if (rep.get_ip_option(BootpOptionTag::LEASE_TIME, lease_val)) {
                        config.lease_secs = lease_val;
                    }

                    state_ = BootpClientState::BOUND;
                    log_state("Received valid BOOTREPLY -> " + config.summary());
                    return config;
                } catch (const std::exception&) {}
            }

            // Exponential backoff
            timeout_ms *= 2;
        }

        state_ = BootpClientState::FAILED;
        log_state("BOOTP lease acquisition failed after all retries.");
        return config;
    }

private:
    void log_state(const std::string& msg) const {
        if (opts_.verbose) {
            std::cout << "[BOOTP CLIENT][" << bootp_state_name(state_) << "] " << msg << "\n";
        }
    }

    static std::string to_hex(uint32_t v) {
        std::ostringstream oss;
        oss << std::hex << v;
        return oss.str();
    }

    BootpClientOptions opts_;
    TapMirror tap_;
    BootpClientState state_ = BootpClientState::INIT;
    uint32_t attempts_taken_ = 0;
};

} // namespace netproto

