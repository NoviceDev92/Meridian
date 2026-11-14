#pragma once
// ============================================================================
// Capture-level analysis (things that need MORE than one packet to work out)
//
//  * TransactionTracker : pairs DNS queries/responses (ID + client port) and
//                         BOOTP requests/replies (xid + hops), computes the
//                         round-trip time and flags retransmissions, exactly
//                         like Wireshark's "[Response In: N]" / "[Time: ...]".
//  * EndpointResolver   : our servers report the *socket* address they reply
//                         to (127.0.0.1), while clients report their *logical*
//                         lab IP. The resolver learns "logical IP owns port P"
//                         and rewrites loopback destinations, so a query
//                         192.168.10.100 -> 192.168.10.2 is answered by
//                         192.168.10.2 -> 192.168.10.100 (not -> 127.0.0.1).
//  * CaptureStatistics  : protocol hierarchy, DNS reply codes, mean RTT,
//                         BOOTP leases handed out, expert-info counts.
// ============================================================================

#include "dissector.hpp"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace netproto {

class TransactionTracker {
public:
    void reset() {
        open_requests_.clear();
        orphan_responses_.clear();
        first_request_.clear();
    }

    // Annotates packets[idx]; may also annotate an earlier packet in the
    // vector (the request) when its response arrives.
    void process(std::vector<DissectedPacket>& packets, size_t idx) {
        DissectedPacket& p = packets[idx];
        if (p.txn_kind == TxnKind::NONE) return;
        const Key key = make_key(p);

        if (!p.txn_response) {
            // Retransmission: same transaction key seen before as a request.
            auto first = first_request_.find(key);
            if (first != first_request_.end()) {
                p.retransmission_of = first->second;
                add_field(p, "retransmission", "1");
                if (p.txn_kind == TxnKind::DNS) {
                    p.fields.emplace("dns.retransmit_request_in", std::to_string(first->second));
                }
                add_note(p, "[Retransmitted request. Original request in: " +
                                std::to_string(first->second) + "]", first->second);
                p.add_expert(ExpertLevel::Note, "Retransmission of frame " + std::to_string(first->second));
                p.info = "[Retransmission] " + p.info;
            } else {
                first_request_[key] = p.number;
            }
            open_requests_[key] = idx;

            // Response that arrived (on the tap) before its request?
            auto orphan = orphan_responses_.find(key);
            if (orphan != orphan_responses_.end()) {
                link(packets, idx, orphan->second);
                orphan_responses_.erase(orphan);
                open_requests_.erase(key);
            }
        } else {
            auto req = open_requests_.find(key);
            if (req != open_requests_.end()) {
                link(packets, req->second, idx);
                open_requests_.erase(req);
            } else {
                orphan_responses_[key] = idx;
            }
        }
        PacketDissector::append_expert_node(p);
    }

    void process_all(std::vector<DissectedPacket>& packets) {
        reset();
        for (size_t i = 0; i < packets.size(); ++i) process(packets, i);
    }

private:
    using Key = std::pair<uint8_t, uint64_t>;

    static Key make_key(const DissectedPacket& p) {
        uint64_t k = (static_cast<uint64_t>(p.txn_id) << 16);
        if (p.txn_kind == TxnKind::DNS) k |= p.txn_client_port;
        else k |= p.txn_hops;
        return {static_cast<uint8_t>(p.txn_kind), k};
    }

    static std::string prefix(const DissectedPacket& p) {
        return p.txn_kind == TxnKind::DNS ? "dns." : "bootp.";
    }

    static void add_field(DissectedPacket& p, const std::string& name, const std::string& v) {
        p.fields.emplace(prefix(p) + name, v);
    }

    // Adds a clickable "[...]" line to the application-layer tree node.
    static void add_note(DissectedPacket& p, const std::string& text, uint32_t link_frame) {
        for (auto it = p.layers.rbegin(); it != p.layers.rend(); ++it) {
            if (it->field == "dns" || it->field == "bootp") {
                it->children.push_back({text, 0, 0, {}, prefix(p) + "analysis", link_frame});
                return;
            }
        }
    }

    static void link(std::vector<DissectedPacket>& packets, size_t req_idx, size_t resp_idx) {
        DissectedPacket& req  = packets[req_idx];
        DissectedPacket& resp = packets[resp_idx];
        double rtt = (static_cast<double>(resp.timestamp_us) - static_cast<double>(req.timestamp_us)) / 1e6;
        if (rtt < 0) rtt = 0;  // tap datagrams from two processes can arrive swapped

        req.response_in = resp.number;
        add_field(req, "response_in", std::to_string(resp.number));
        add_note(req, "[Response In: " + std::to_string(resp.number) + "]", resp.number);

        resp.request_in = req.number;
        resp.rtt_sec = rtt;
        add_field(resp, "response_to", std::to_string(req.number));
        add_field(resp, "time", fmt::seconds(rtt, 9));
        add_note(resp, "[Request In: " + std::to_string(req.number) + "]", req.number);
        add_note(resp, "[Time: " + fmt::seconds(rtt, 9) + " seconds]", 0);
    }

    std::map<Key, size_t> open_requests_;     // key -> index of unanswered request
    std::map<Key, size_t> orphan_responses_;  // key -> index of response w/o request
    std::map<Key, uint32_t> first_request_;   // key -> frame no. of first request
};

class EndpointResolver {
public:
    void reset() { port_owner_.clear(); }

    // Call with the tap envelope BEFORE the wire frame is synthesized.
    void resolve(TapEnvelope& env) {
        if (is_logical(env.src_ip)) port_owner_[env.src_port] = env.src_ip;
        if (is_loopback(env.dst_ip)) {
            auto it = port_owner_.find(env.dst_port);
            if (it != port_owner_.end()) env.dst_ip = it->second;
        }
    }

private:
    static bool is_loopback(uint32_t ip) { return (ip >> 24) == 127; }
    static bool is_logical(uint32_t ip) {
        return ip != 0 && ip != 0xFFFFFFFFu && !is_loopback(ip);
    }
    std::map<uint16_t, uint32_t> port_owner_;
};

struct CaptureStatistics {
    size_t frames = 0;
    uint64_t bytes = 0;
    double duration_sec = 0;
    std::map<std::string, size_t> by_protocol;
    std::map<std::string, size_t> dns_rcodes;
    size_t dns_queries = 0, dns_responses = 0, dns_unanswered = 0, retransmissions = 0;
    double dns_rtt_sum = 0; size_t dns_rtt_n = 0; double dns_rtt_max = 0;
    std::vector<std::string> leases;   // "mac -> ip"
    size_t expert_errors = 0, expert_warnings = 0, expert_notes = 0;

    static CaptureStatistics compute(const std::vector<DissectedPacket>& pkts) {
        CaptureStatistics s;
        s.frames = pkts.size();
        for (const auto& p : pkts) {
            s.bytes += p.raw_frame.size();
            s.by_protocol[p.protocol]++;
            if (p.retransmission_of) s.retransmissions++;
            switch (p.expert_level) {
                case ExpertLevel::Error: s.expert_errors++; break;
                case ExpertLevel::Warn:  s.expert_warnings++; break;
                case ExpertLevel::Note:  s.expert_notes++; break;
                default: break;
            }
            if (p.txn_kind == TxnKind::DNS) {
                if (p.txn_response) {
                    s.dns_responses++;
                    s.dns_rcodes[dns_rcode_name(static_cast<uint8_t>(
                        std::atoi(p.field_value("dns.flags.rcode").c_str())))]++;
                    if (p.rtt_sec >= 0) {
                        s.dns_rtt_sum += p.rtt_sec;
                        s.dns_rtt_n++;
                        s.dns_rtt_max = std::max(s.dns_rtt_max, p.rtt_sec);
                    }
                } else {
                    s.dns_queries++;
                    if (!p.response_in && !p.retransmission_of) s.dns_unanswered++;
                }
            }
            if (p.txn_kind == TxnKind::BOOTP && p.txn_response) {
                s.leases.push_back(p.field_value("bootp.hw.mac_addr") + " -> " +
                                   p.field_value("bootp.ip.your"));
            }
        }
        if (pkts.size() > 1) {
            s.duration_sec = (static_cast<double>(pkts.back().timestamp_us) -
                              static_cast<double>(pkts.front().timestamp_us)) / 1e6;
        }
        return s;
    }

    std::string to_string() const {
        std::ostringstream o;
        o << "Capture: " << frames << " frames, " << bytes << " bytes, "
          << fmt::seconds(duration_sec, 3) << " s\n\n";
        o << "Protocol hierarchy (by top-most dissected layer):\n";
        for (const auto& kv : by_protocol) {
            double pct = frames ? 100.0 * kv.second / frames : 0;
            o << "  " << kv.first << ": " << kv.second << " (" << fmt::seconds(pct, 1) << "%)\n";
        }
        o << "\nDNS: " << dns_queries << " queries, " << dns_responses << " responses";
        if (dns_unanswered) o << ", " << dns_unanswered << " unanswered";
        o << "\n";
        for (const auto& kv : dns_rcodes) o << "  rcode " << kv.first << ": " << kv.second << "\n";
        if (dns_rtt_n) {
            o << "  Response time: avg " << fmt::seconds(1000.0 * dns_rtt_sum / dns_rtt_n, 3)
              << " ms, max " << fmt::seconds(1000.0 * dns_rtt_max, 3) << " ms\n";
        }
        o << "\nBOOTP replies (leases):\n";
        if (leases.empty()) o << "  (none)\n";
        for (const auto& l : leases) o << "  " << l << "\n";
        o << "\nRetransmissions: " << retransmissions << "\n";
        o << "Expert info: " << expert_errors << " error(s), " << expert_warnings
          << " warning(s), " << expert_notes << " note(s)\n";
        return o.str();
    }
};

} // namespace netproto
