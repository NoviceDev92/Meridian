#pragma once

#include "protocol_headers.hpp"
#include "udp_socket.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace netproto {

// ============================================================================
// Domain & PTR Name Utilities
// ============================================================================
inline std::string normalize_domain(std::string name) {
    while (!name.empty() && name.back() == '.') {
        name.pop_back();
    }
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return name;
}

inline std::string ipv4_to_ptr_name(const std::string& ip_str) {
    uint32_t ip = ipv4_from_string(ip_str);
    std::ostringstream oss;
    oss << (ip & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.'
        << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 24) & 0xFF) << ".in-addr.arpa";
    return oss.str();
}

inline const char* dns_type_name(uint16_t t) {
    switch (static_cast<DnsType>(t)) {
        case DnsType::A:     return "A";
        case DnsType::NS:    return "NS";
        case DnsType::CNAME: return "CNAME";
        case DnsType::PTR:   return "PTR";
        case DnsType::TXT:   return "TXT";
    }
    return "UNKNOWN";
}

inline const char* dns_rcode_name(uint8_t rc) {
    switch (static_cast<DnsRCode>(rc)) {
        case DnsRCode::NO_ERR:   return "NOERROR";
        case DnsRCode::FORMERR:  return "FORMERR";
        case DnsRCode::SERVFAIL: return "SERVFAIL";
        case DnsRCode::NXDOMAIN: return "NXDOMAIN";
        case DnsRCode::NOTIMP:   return "NOTIMP";
    }
    return "UNKNOWN";
}

// ============================================================================
// Authoritative Zone Store (Supports A, CNAME chaining, PTR)
// ============================================================================
class DnsZoneStore {
public:
    void add_a(const std::string& domain, const std::string& ip_str, uint32_t ttl = 60) {
        std::string key = normalize_domain(domain);
        a_records_[key] = {ipv4_from_string(ip_str), ttl};
    }

    void add_cname(const std::string& alias, const std::string& target, uint32_t ttl = 60) {
        std::string key = normalize_domain(alias);
        cname_records_[key] = {normalize_domain(target), ttl};
    }

    void add_ptr(const std::string& ptr_or_ip, const std::string& hostname, uint32_t ttl = 60) {
        std::string key = normalize_domain(ptr_or_ip);
        if (key.find(".in-addr.arpa") == std::string::npos) {
            key = ipv4_to_ptr_name(key);
        }
        ptr_records_[key] = {normalize_domain(hostname), ttl};
    }

    // Loads simple zone entries:
    //   A     fileserver.lab.local  192.168.10.50  120
    //   CNAME fs.lab.local          fileserver.lab.local  60
    //   PTR   192.168.10.50         fileserver.lab.local  120
    bool load_from_file(const std::string& path) {
        std::ifstream fin(path);
        if (!fin.is_open()) return false;

        std::string line;
        while (std::getline(fin, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream iss(line);
            std::string type, name, value;
            uint32_t ttl = 60;
            if (!(iss >> type >> name >> value)) continue;
            if (!(iss >> ttl)) ttl = 60;

            std::transform(type.begin(), type.end(), type.begin(), ::toupper);
            if (type == "A") {
                add_a(name, value, ttl);
            } else if (type == "CNAME") {
                add_cname(name, value, ttl);
            } else if (type == "PTR") {
                add_ptr(name, value, ttl);
            }
        }
        return true;
    }

    bool resolve(const std::string& raw_qname,
                 uint16_t qtype,
                 std::vector<DnsResourceRecord>& out_answers) const {
        out_answers.clear();
        std::string current = normalize_domain(raw_qname);

        if (qtype == static_cast<uint16_t>(DnsType::PTR)) {
            auto it = ptr_records_.find(current);
            if (it != ptr_records_.end()) {
                out_answers.push_back(DnsMessage::make_cname_or_ptr(
                    current, DnsType::PTR, it->second.first, it->second.second));
                return true;
            }
            return false;
        }

        if (qtype == static_cast<uint16_t>(DnsType::CNAME)) {
            auto it = cname_records_.find(current);
            if (it != cname_records_.end()) {
                out_answers.push_back(DnsMessage::make_cname_or_ptr(
                    current, DnsType::CNAME, it->second.first, it->second.second));
                return true;
            }
            return false;
        }

        if (qtype == static_cast<uint16_t>(DnsType::A)) {
            // Follow CNAME chain up to 5 hops
            for (int depth = 0; depth < 5; ++depth) {
                auto a_it = a_records_.find(current);
                if (a_it != a_records_.end()) {
                    out_answers.push_back(DnsResourceRecord::make_a(
                        current, a_it->second.first, a_it->second.second));
                    return true;
                }
                auto c_it = cname_records_.find(current);
                if (c_it != cname_records_.end()) {
                    out_answers.push_back(DnsMessage::make_cname_or_ptr(
                        current, DnsType::CNAME, c_it->second.first, c_it->second.second));
                    current = c_it->second.first;
                    continue;
                }
                break;
            }
            out_answers.clear();
        }
        return false;
    }

private:
    std::map<std::string, std::pair<uint32_t, uint32_t>> a_records_;        // domain -> (ip, ttl)
    std::map<std::string, std::pair<std::string, uint32_t>> cname_records_; // alias -> (target, ttl)
    std::map<std::string, std::pair<std::string, uint32_t>> ptr_records_;   // arpa -> (host, ttl)
};

// ============================================================================
// TTL-Aware In-Memory DNS Cache
// ============================================================================
class DnsCache {
public:
    struct CacheEntry {
        std::vector<DnsResourceRecord> records;
        std::chrono::steady_clock::time_point expires_at;
    };

    void put(const std::string& qname,
             uint16_t qtype,
             const std::vector<DnsResourceRecord>& records) {
        if (records.empty()) return;
        uint32_t min_ttl = records.front().ttl;
        for (const auto& rr : records) {
            min_ttl = std::min(min_ttl, rr.ttl);
        }
        if (min_ttl == 0) return; // TTL=0 means do not cache

        std::lock_guard<std::mutex> lk(mu_);
        CacheKey key{normalize_domain(qname), qtype};
        CacheEntry entry;
        entry.records    = records;
        entry.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(min_ttl);
        entries_[key]    = std::move(entry);
    }

    bool get(const std::string& qname,
             uint16_t qtype,
             std::vector<DnsResourceRecord>& out_records) {
        std::lock_guard<std::mutex> lk(mu_);
        CacheKey key{normalize_domain(qname), qtype};
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;

        auto now = std::chrono::steady_clock::now();
        if (now >= it->second.expires_at) {
            entries_.erase(it);
            return false;
        }

        uint32_t remaining = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(it->second.expires_at - now).count());
        if (remaining == 0) remaining = 1;

        out_records = it->second.records;
        for (auto& rr : out_records) {
            rr.ttl = remaining; // Dynamically decrement TTL on wire
        }
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        entries_.clear();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return entries_.size();
    }

private:
    using CacheKey = std::pair<std::string, uint16_t>;
    mutable std::mutex mu_;
    std::map<CacheKey, CacheEntry> entries_;
};

// ============================================================================
// DNS Server (Authoritative + Recursive/Forwarder + TTL Cache)
// ============================================================================
struct DnsServerConfig {
    uint16_t listen_port     = DNS_SERVER_PORT;
    std::string bind_ip      = "127.0.0.1";
    std::string server_ip    = "192.168.10.2"; // Logical IP shown in Tap/Mini-Wireshark
    std::string upstream_ip  = "";             // Empty = purely authoritative
    uint16_t upstream_port   = DNS_UPSTREAM_PORT;
    std::string upstream_logical_ip = "8.8.8.8";
    uint32_t upstream_timeout_ms    = 400;
    uint32_t drop_rate_pct   = 0;
    bool enable_tap          = true;
    bool tap_on_receive      = false;
    uint16_t tap_port        = TAP_SNIFFER_PORT;
};

class DnsServer {
public:
    explicit DnsServer(DnsServerConfig cfg = {})
        : cfg_(std::move(cfg)),
          tap_(cfg_.tap_port),
          rng_(std::random_device{}()) {
        sock_.bind(cfg_.listen_port, cfg_.bind_ip);
        sock_.set_timeout_ms(100);
    }

    uint16_t bound_port() const { return sock_.local_port(); }
    DnsZoneStore& zones() { return zones_; }
    DnsCache& cache() { return cache_; }

    void run(bool verbose = true) {
        running_.store(true);
        if (verbose) {
            std::cout << "[DNS SERVER] Listening on " << cfg_.bind_ip << ":" << bound_port()
                      << " (LogicalIP=" << cfg_.server_ip
                      << (cfg_.upstream_ip.empty()
                              ? ", Mode=Authoritative"
                              : ", Forwarder->" + cfg_.upstream_ip + ":" + std::to_string(cfg_.upstream_port))
                      << ")\n";
        }

        while (running_.load()) {
            std::vector<uint8_t> rx_buf;
            std::string peer_ip;
            uint16_t peer_port = 0;
            int n = sock_.recv_from(rx_buf, peer_ip, peer_port);
            if (n <= 0) continue;

            try {
                handle_query(rx_buf, peer_ip, peer_port, verbose);
            } catch (const std::exception& ex) {
                if (verbose) {
                    std::cerr << "[DNS SERVER] Malformed DNS packet (" << ex.what() << ")\n";
                }
            }
        }
    }

    void stop() { running_.store(false); }

private:
    bool should_simulate_drop() {
        if (cfg_.drop_rate_pct == 0) return false;
        std::uniform_int_distribution<uint32_t> dist(1, 100);
        return dist(rng_) <= cfg_.drop_rate_pct;
    }

    bool forward_to_upstream(const DnsQuestion& q,
                             uint16_t orig_id,
                             std::vector<DnsResourceRecord>& out_answers,
                             uint8_t& out_rcode,
                             bool verbose) {
        UdpSocket up_sock;
        up_sock.bind(0, "127.0.0.1");
        up_sock.set_timeout_ms(cfg_.upstream_timeout_ms);

        DnsMessage fwd;
        fwd.id       = static_cast<uint16_t>(orig_id ^ 0x5A5A);
        fwd.flags.qr = false;
        fwd.flags.rd = true;
        fwd.questions.push_back(q);

        auto fwd_bytes = fwd.serialize();
        up_sock.send_to(fwd_bytes, cfg_.upstream_ip, cfg_.upstream_port);

        if (cfg_.enable_tap) {
            tap_.emit(cfg_.server_ip, up_sock.local_port(),
                      cfg_.upstream_logical_ip, cfg_.upstream_port,
                      AppProtoHint::DNS, fwd_bytes);
        }

        if (verbose) {
            std::cout << "[DNS SERVER]   -> Forwarding '" << q.qname
                      << "' (" << dns_type_name(q.qtype) << ") to Upstream "
                      << cfg_.upstream_ip << ":" << cfg_.upstream_port << "\n";
        }

        std::vector<uint8_t> up_rx;
        std::string up_src;
        uint16_t up_port = 0;
        int n = up_sock.recv_from(up_rx, up_src, up_port);
        if (n <= 0) {
            out_rcode = static_cast<uint8_t>(DnsRCode::SERVFAIL);
            return false;
        }

        DnsMessage up_resp = DnsMessage::deserialize(up_rx.data(), up_rx.size());
        if (up_resp.id != fwd.id || !up_resp.flags.qr) {
            out_rcode = static_cast<uint8_t>(DnsRCode::SERVFAIL);
            return false;
        }

        out_rcode   = up_resp.flags.rcode;
        out_answers = std::move(up_resp.answers);
        return true;
    }

    void handle_query(const std::vector<uint8_t>& rx_buf,
                      const std::string& peer_ip,
                      uint16_t peer_port,
                      bool verbose) {
        DnsMessage query = DnsMessage::deserialize(rx_buf.data(), rx_buf.size());
        if (query.flags.qr) return; // Ignore responses

        if (cfg_.enable_tap && cfg_.tap_on_receive) {
            tap_.emit(peer_ip, peer_port, cfg_.server_ip, bound_port(),
                      AppProtoHint::DNS, rx_buf);
        }

        if (should_simulate_drop()) {
            if (verbose) {
                std::cout << "[DNS SERVER] [DROP SIM] Dropped query id=0x"
                          << std::hex << query.id << std::dec << "\n";
            }
            return;
        }

        DnsMessage resp;
        resp.id          = query.id;
        resp.flags.qr    = true;
        resp.flags.rd    = query.flags.rd;
        resp.flags.ra    = !cfg_.upstream_ip.empty();
        resp.questions   = query.questions;

        if (query.questions.empty()) {
            resp.flags.rcode = static_cast<uint8_t>(DnsRCode::FORMERR);
            auto out = resp.serialize();
            sock_.send_to(out, peer_ip, peer_port);
            return;
        }

        const auto& q = query.questions[0];
        std::string source_tag = "LOCAL ZONE";

        // 1. Check Local Authoritative Zones
        if (zones_.resolve(q.qname, q.qtype, resp.answers)) {
            resp.flags.aa    = true;
            resp.flags.rcode = static_cast<uint8_t>(DnsRCode::NO_ERR);
        }
        // 2. Check TTL Cache
        else if (cache_.get(q.qname, q.qtype, resp.answers)) {
            resp.flags.aa    = false;
            resp.flags.rcode = static_cast<uint8_t>(DnsRCode::NO_ERR);
            source_tag = "CACHE HIT";
        }
        // 3. Forward Upstream if configured and RD=1
        else if (!cfg_.upstream_ip.empty() && query.flags.rd) {
            source_tag = "CACHE MISS -> UPSTREAM";
            uint8_t up_rc = static_cast<uint8_t>(DnsRCode::SERVFAIL);
            if (forward_to_upstream(q, query.id, resp.answers, up_rc, verbose)) {
                resp.flags.aa    = false;
                resp.flags.rcode = up_rc;
                if (up_rc == static_cast<uint8_t>(DnsRCode::NO_ERR) && !resp.answers.empty()) {
                    cache_.put(q.qname, q.qtype, resp.answers);
                }
            } else {
                resp.flags.rcode = static_cast<uint8_t>(DnsRCode::SERVFAIL);
            }
        }
        // 4. Not Found -> NXDOMAIN
        else {
            resp.flags.aa    = true;
            resp.flags.rcode = static_cast<uint8_t>(DnsRCode::NXDOMAIN);
            source_tag       = "NXDOMAIN";
        }

        auto resp_bytes = resp.serialize();
        sock_.send_to(resp_bytes, peer_ip, peer_port);

        if (cfg_.enable_tap) {
            tap_.emit(cfg_.server_ip, bound_port(), peer_ip, peer_port,
                      AppProtoHint::DNS, resp_bytes);
        }

        if (verbose) {
            std::cout << "[DNS SERVER] Query '" << q.qname << "' (" << dns_type_name(q.qtype)
                      << ") -> " << dns_rcode_name(resp.flags.rcode)
                      << " [" << source_tag << "]";
            if (!resp.answers.empty()) {
                std::cout << " Answers=" << resp.answers.size()
                          << " (TTL=" << resp.answers.back().ttl << "s)";
            }
            std::cout << "\n";
        }
    }

    DnsServerConfig cfg_;
    UdpSocket sock_;
    TapMirror tap_;
    DnsZoneStore zones_;
    DnsCache cache_;
    std::atomic<bool> running_{false};
    std::mt19937 rng_;
};

// ============================================================================
// DNS Client Resolver (Supports Retries, A/CNAME/PTR, Logical Tap IP)
// ============================================================================
struct DnsClientOptions {
    std::string server_ip          = "127.0.0.1";
    uint16_t server_port           = DNS_SERVER_PORT;
    std::string logical_client_ip  = "192.168.10.105"; // For Mini-Wireshark display
    std::string logical_server_ip  = "192.168.10.2";
    uint32_t timeout_ms            = 400;
    uint32_t max_retries           = 3;
    bool enable_tap                = true;
    uint16_t tap_port              = TAP_SNIFFER_PORT;
    bool verbose                   = true;
};

struct DnsLookupResult {
    bool success    = false;
    uint8_t rcode   = static_cast<uint8_t>(DnsRCode::SERVFAIL);
    bool authoritative = false;
    std::vector<DnsResourceRecord> answers;
    std::string resolved_ip;
    std::string resolved_name;
    uint32_t ttl    = 0;
};

class DnsClient {
public:
    explicit DnsClient(DnsClientOptions opts = {})
        : opts_(std::move(opts)), tap_(opts_.tap_port) {}

    DnsLookupResult resolve(const std::string& domain,
                            DnsType qtype = DnsType::A) {
        DnsLookupResult result;
        UdpSocket sock;
        sock.bind(0, "0.0.0.0");

        std::random_device rd;
        std::mt19937 gen(rd());
        uint16_t qid = static_cast<uint16_t>(gen() & 0xFFFF);

        DnsMessage query;
        query.id       = qid;
        query.flags.qr = false;
        query.flags.rd = true;
        query.questions.push_back({
            domain,
            static_cast<uint16_t>(qtype),
            static_cast<uint16_t>(DnsClass::INTERNET)
        });
        auto wire = query.serialize();

        for (uint32_t attempt = 1; attempt <= opts_.max_retries; ++attempt) {
            sock.set_timeout_ms(opts_.timeout_ms);
            sock.send_to(wire, opts_.server_ip, opts_.server_port);

            if (opts_.enable_tap) {
                tap_.emit(opts_.logical_client_ip, sock.local_port(),
                          opts_.logical_server_ip, opts_.server_port,
                          AppProtoHint::DNS, wire);
            }

            if (opts_.verbose) {
                std::cout << "[DNS CLIENT] Querying " << opts_.logical_server_ip
                          << " (" << opts_.server_ip << ":" << opts_.server_port
                          << ") for '" << domain << "' (" << dns_type_name(static_cast<uint16_t>(qtype))
                          << ", id=0x" << std::hex << qid << std::dec << ")\n";
            }

            std::vector<uint8_t> rx_buf;
            std::string peer_ip;
            uint16_t peer_port = 0;
            int n = sock.recv_from(rx_buf, peer_ip, peer_port);
            if (n <= 0) continue;

            try {
                DnsMessage resp = DnsMessage::deserialize(rx_buf.data(), rx_buf.size());
                if (!resp.flags.qr || resp.id != qid) continue;

                result.rcode         = resp.flags.rcode;
                result.authoritative = resp.flags.aa;
                result.answers       = std::move(resp.answers);
                result.success       = (result.rcode == static_cast<uint8_t>(DnsRCode::NO_ERR));

                for (const auto& rr : result.answers) {
                    result.ttl = rr.ttl;
                    if (rr.type == static_cast<uint16_t>(DnsType::A)) {
                        result.resolved_ip = rr.rdata_as_ipv4();
                    } else if (rr.type == static_cast<uint16_t>(DnsType::PTR) ||
                               rr.type == static_cast<uint16_t>(DnsType::CNAME)) {
                        PacketReader pr(rr.rdata);
                        result.resolved_name = decode_dns_name(pr);
                    }
                }
                return result;
            } catch (const std::exception&) {}
        }

        return result;
    }

private:
    DnsClientOptions opts_;
    TapMirror tap_;
};

} // namespace netproto

