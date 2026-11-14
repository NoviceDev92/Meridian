#pragma once

#include "dns_engine.hpp"
#include "protocol_headers.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace netproto {

// ============================================================================
// Dissector Tree Node (Supports Collapsible Tree + Hex Byte Highlighting)
// ============================================================================
struct DissectNode {
    std::string label;
    size_t byte_offset = 0;
    size_t byte_length = 0;
    std::vector<DissectNode> children;
    std::string field;        // Wireshark-style abbreviation, e.g. "ip.src"
    uint32_t link_frame = 0;  // Non-zero: double-click jumps to this frame no.
};

// Expert-info severities (mirrors Wireshark's Note / Warning / Error levels)
enum class ExpertLevel : int { None = 0, Note = 1, Warn = 2, Error = 3 };

inline const char* expert_level_name(ExpertLevel lv) {
    switch (lv) {
        case ExpertLevel::Note:  return "Note";
        case ExpertLevel::Warn:  return "Warning";
        case ExpertLevel::Error: return "Error";
        default:                 return "None";
    }
}

// What the transaction tracker needs to pair requests with responses.
enum class TxnKind : uint8_t { NONE = 0, DNS = 1, BOOTP = 2 };

struct DissectedPacket {
    uint32_t number        = 0;
    uint64_t timestamp_us  = 0;
    double rel_time_sec    = 0.0;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port      = 0;
    uint16_t dst_port      = 0;
    std::string protocol;  // "BOOTP", "DHCP", "DNS", "UDP", "IPv4", "ETH"
    std::string info;
    std::vector<uint8_t> raw_frame;
    std::vector<DissectNode> layers;

    // Filterable fields: abbreviation -> value(s). Multi-valued fields such
    // as ip.addr or udp.port appear once per value (multimap).
    std::multimap<std::string, std::string> fields;

    // Expert info (malformed packets, bad checksums, retransmissions...)
    ExpertLevel expert_level = ExpertLevel::None;
    std::vector<std::string> expert_msgs;

    // Transaction tracking (filled by dissector, linked by TransactionTracker)
    TxnKind  txn_kind     = TxnKind::NONE;
    bool     txn_response = false;
    uint32_t txn_id       = 0;     // DNS ID or BOOTP xid
    uint16_t txn_client_port = 0;  // DNS: client's port (src of query)
    uint8_t  txn_hops     = 0;     // BOOTP: hops (separates relayed copies)
    uint32_t request_in   = 0;     // On responses: frame of matching request
    uint32_t response_in  = 0;     // On requests: frame of matching response
    uint32_t retransmission_of = 0;
    double   rtt_sec      = -1.0;

    bool has_field(const std::string& f) const { return fields.count(f) > 0; }

    std::string field_value(const std::string& f) const {
        auto it = fields.find(f);
        return it == fields.end() ? std::string() : it->second;
    }

    void add_expert(ExpertLevel lv, const std::string& msg) {
        if (static_cast<int>(lv) > static_cast<int>(expert_level)) expert_level = lv;
        expert_msgs.push_back(std::string(expert_level_name(lv)) + ": " + msg);
    }
};

// ============================================================================
// Small formatting helpers shared by the dissector and the GUI/CLI
// ============================================================================
namespace fmt {

inline std::string hex(uint32_t v, int width) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(width) << std::setfill('0') << v;
    return oss.str();
}

// Wireshark-style bitfield picture, e.g. bits(0x8180, 16, 15, 1) ->
// "1... .... .... ....". `hi` is the most significant bit of the field.
inline std::string bits(uint32_t value, int total_bits, int hi, int width) {
    std::string out;
    int lo = hi - width + 1;
    for (int b = total_bits - 1; b >= 0; --b) {
        if (b <= hi && b >= lo) out.push_back(((value >> b) & 1) ? '1' : '0');
        else out.push_back('.');
        if (b > 0 && b % 4 == 0) out.push_back(' ');
    }
    return out;
}

inline std::string utc_time(uint64_t ts_us) {
    std::time_t secs = static_cast<std::time_t>(ts_us / 1000000ULL);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &secs);
#else
    gmtime_r(&secs, &tmv);
#endif
    char date[64];
    std::strftime(date, sizeof(date), "%b %d, %Y %H:%M:%S", &tmv);
    std::ostringstream oss;
    oss << date << '.' << std::setw(6) << std::setfill('0') << (ts_us % 1000000ULL) << " UTC";
    return oss.str();
}

inline std::string seconds(double s, int prec = 6) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(prec) << s;
    return oss.str();
}

} // namespace fmt

// Extended record-type names (the dns_engine only implements a subset, but
// real captures opened from disk contain AAAA, HTTPS, OPT, ...)
inline const char* dns_type_label(uint16_t t) {
    switch (t) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 255: return "ANY";
        default: return nullptr;
    }
}

inline std::string dns_type_str(uint16_t t) {
    const char* n = dns_type_label(t);
    return n ? std::string(n) : ("TYPE" + std::to_string(t));
}

inline std::string dns_rcode_long(uint8_t rc) {
    switch (rc) {
        case 0: return "No error";
        case 1: return "Format error";
        case 2: return "Server failure";
        case 3: return "No such name";
        case 4: return "Not implemented";
        case 5: return "Refused";
        default: return "Unknown";
    }
}

inline const char* dhcp_msg_type_name(uint8_t t) {
    switch (t) {
        case 1: return "Discover";
        case 2: return "Offer";
        case 3: return "Request";
        case 4: return "Decline";
        case 5: return "ACK";
        case 6: return "NAK";
        case 7: return "Release";
        case 8: return "Inform";
        default: return "Unknown";
    }
}

// ============================================================================
// Layered Wire-Frame Dissector (Ethernet II -> IPv4 -> UDP -> BOOTP / DNS)
// ============================================================================
class PacketDissector {
public:
    static DissectedPacket dissect_wire_frame(uint32_t frame_no,
                                              uint64_t timestamp_us,
                                              double rel_time_sec,
                                              const std::vector<uint8_t>& frame,
                                              AppProtoHint hint = AppProtoHint::UNKNOWN) {
        DissectedPacket pkt;
        pkt.number       = frame_no;
        pkt.timestamp_us = timestamp_us;
        pkt.rel_time_sec = rel_time_sec;
        pkt.raw_frame    = frame;
        pkt.protocol     = "ETH";
        pkt.info         = "Raw Frame (" + std::to_string(frame.size()) + " bytes)";
        std::vector<std::string> proto_stack{"eth"};

        // --------------------------------------------------------------------
        // Frame summary (metadata, not bytes from the wire)
        // --------------------------------------------------------------------
        {
            std::ostringstream oss;
            oss << "Frame " << frame_no << ": " << frame.size()
                << " bytes on wire (" << (frame.size() * 8) << " bits)";
            DissectNode fnode{oss.str(), 0, frame.size(), {}, "frame", 0};
            fnode.children.push_back(leaf(pkt, "Arrival Time: " + fmt::utc_time(timestamp_us), 0, 0,
                                          "frame.time", fmt::utc_time(timestamp_us)));
            fnode.children.push_back(leaf(pkt, "Epoch Arrival Time: " +
                                          fmt::seconds(timestamp_us / 1e6), 0, 0,
                                          "frame.time_epoch", fmt::seconds(timestamp_us / 1e6)));
            fnode.children.push_back(leaf(pkt, "Time since reference or first frame: " +
                                          fmt::seconds(rel_time_sec, 9) + " seconds", 0, 0,
                                          "frame.time_relative", fmt::seconds(rel_time_sec, 9)));
            fnode.children.push_back(leaf(pkt, "Frame Number: " + std::to_string(frame_no), 0, 0,
                                          "frame.number", std::to_string(frame_no)));
            fnode.children.push_back(leaf(pkt, "Frame Length: " + std::to_string(frame.size()) + " bytes",
                                          0, frame.size(), "frame.len", std::to_string(frame.size())));
            pkt.layers.push_back(std::move(fnode));
            pkt.fields.emplace("frame", "");
        }

        if (frame.size() < 14) {
            pkt.info = "Malformed Ethernet II frame (<14 bytes)";
            mark_malformed(pkt, "Ethernet header truncated");
            finish_frame(pkt, proto_stack);
            return pkt;
        }

        // --------------------------------------------------------------------
        // Layer 2: Ethernet II (Offset 0..14)
        // --------------------------------------------------------------------
        std::array<uint8_t, 6> dst_mac{}, src_mac{};
        std::copy_n(frame.begin(), 6, dst_mac.begin());
        std::copy_n(frame.begin() + 6, 6, src_mac.begin());
        uint16_t ethertype = u16(frame, 12);
        const bool dst_bcast = std::all_of(dst_mac.begin(), dst_mac.end(),
                                           [](uint8_t b) { return b == 0xFF; });
        {
            DissectNode eth{
                "Ethernet II, Src: " + mac_to_string(src_mac) + ", Dst: " + mac_to_string(dst_mac) +
                    (dst_bcast ? " (Broadcast)" : ""),
                0, 14, {}, "eth", 0
            };
            DissectNode dst{"Destination: " + mac_to_string(dst_mac) + (dst_bcast ? " (Broadcast)" : ""),
                            0, 6, {}, "eth.dst", 0};
            dst.children.push_back({std::string(".... ..") + ((dst_mac[0] & 0x02) ? "1." : "0.") +
                                    " .... .... .... .... = LG bit: " +
                                    ((dst_mac[0] & 0x02) ? "Locally administered address"
                                                         : "Globally unique address (factory default)"),
                                    0, 1, {}, "eth.dst.lg", 0});
            dst.children.push_back({std::string(".... ...") + ((dst_mac[0] & 0x01) ? "1" : "0") +
                                    " .... .... .... .... = IG bit: " +
                                    ((dst_mac[0] & 0x01) ? "Group address (multicast/broadcast)"
                                                         : "Individual address (unicast)"),
                                    0, 1, {}, "eth.dst.ig", 0});
            eth.children.push_back(std::move(dst));
            eth.children.push_back({"Source: " + mac_to_string(src_mac), 6, 6, {}, "eth.src", 0});
            std::string type_name = ethertype == 0x0800 ? " (IPv4)" :
                                    ethertype == 0x86DD ? " (IPv6)" :
                                    ethertype == 0x0806 ? " (ARP)"  :
                                    ethertype == 0x8100 ? " (802.1Q VLAN)" : "";
            eth.children.push_back({"Type: " + fmt::hex(ethertype, 4) + type_name, 12, 2, {}, "eth.type", 0});
            pkt.layers.push_back(std::move(eth));

            pkt.fields.emplace("eth", "");
            pkt.fields.emplace("eth.dst", mac_to_string(dst_mac));
            pkt.fields.emplace("eth.src", mac_to_string(src_mac));
            pkt.fields.emplace("eth.addr", mac_to_string(dst_mac));
            pkt.fields.emplace("eth.addr", mac_to_string(src_mac));
            pkt.fields.emplace("eth.type", fmt::hex(ethertype, 4));
        }
        proto_stack.push_back("ethertype");

        if (ethertype != 0x0800) {
            pkt.info = "Ethernet frame, EtherType " + fmt::hex(ethertype, 4) + " (not dissected)";
            finish_frame(pkt, proto_stack);
            return pkt;
        }
        if (frame.size() < 34) {
            pkt.info = "Malformed IPv4 (frame too short)";
            mark_malformed(pkt, "IPv4 header truncated");
            finish_frame(pkt, proto_stack);
            return pkt;
        }

        // --------------------------------------------------------------------
        // Layer 3: IPv4 (Offset 14..)
        // --------------------------------------------------------------------
        const size_t ip_off = 14;
        uint8_t ver_ihl     = frame[ip_off];
        uint8_t version     = ver_ihl >> 4;
        uint8_t ihl_bytes   = static_cast<uint8_t>((ver_ihl & 0x0F) * 4);
        if (version != 4 || ihl_bytes < 20 || ip_off + ihl_bytes > frame.size()) {
            pkt.info = "Malformed IPv4 header";
            mark_malformed(pkt, "Bogus IPv4 version or header length");
            finish_frame(pkt, proto_stack);
            return pkt;
        }
        uint8_t  dsfield      = frame[ip_off + 1];
        uint16_t ip_total_len = u16(frame, ip_off + 2);
        uint16_t ip_id        = u16(frame, ip_off + 4);
        uint16_t ip_flags     = u16(frame, ip_off + 6);
        uint8_t  ip_ttl       = frame[ip_off + 8];
        uint8_t  ip_proto     = frame[ip_off + 9];
        uint16_t ip_csum      = u16(frame, ip_off + 10);
        uint32_t src_ip_u32   = u32(frame, ip_off + 12);
        uint32_t dst_ip_u32   = u32(frame, ip_off + 16);

        // Verify header checksum: summing a correct header incl. its checksum gives 0.
        uint16_t csum_check = checksum_finish(checksum_accumulate(frame.data() + ip_off, ihl_bytes));
        bool ip_csum_ok = (csum_check == 0);
        uint16_t ip_csum_expected = ip_csum;
        if (!ip_csum_ok) {
            std::vector<uint8_t> hdr(frame.begin() + ip_off, frame.begin() + ip_off + ihl_bytes);
            hdr[10] = hdr[11] = 0;
            ip_csum_expected = checksum_finish(checksum_accumulate(hdr.data(), hdr.size()));
        }

        // Where the IP datagram really ends (ignores Ethernet trailer padding)
        size_t ip_end = frame.size();
        if (ip_total_len >= ihl_bytes && ip_off + ip_total_len <= frame.size()) {
            ip_end = ip_off + ip_total_len;
        } else {
            pkt.add_expert(ExpertLevel::Warn, "IPv4 total length " + std::to_string(ip_total_len) +
                                              " does not match captured bytes");
        }

        pkt.src_ip   = ipv4_to_string(src_ip_u32);
        pkt.dst_ip   = ipv4_to_string(dst_ip_u32);
        pkt.protocol = "IPv4";
        proto_stack.push_back("ip");
        {
            DissectNode ip_node{
                "Internet Protocol Version 4, Src: " + pkt.src_ip + ", Dst: " + pkt.dst_ip,
                ip_off, ihl_bytes, {}, "ip", 0
            };
            ip_node.children.push_back(leaf(pkt, fmt::bits(ver_ihl, 8, 7, 4) + " = Version: " +
                                            std::to_string(version), ip_off, 1, "ip.version",
                                            std::to_string(version)));
            ip_node.children.push_back(leaf(pkt, fmt::bits(ver_ihl, 8, 3, 4) + " = Header Length: " +
                                            std::to_string(ihl_bytes) + " bytes (" +
                                            std::to_string(ihl_bytes / 4) + ")", ip_off, 1,
                                            "ip.hdr_len", std::to_string(ihl_bytes)));
            ip_node.children.push_back(leaf(pkt, "Differentiated Services Field: " + fmt::hex(dsfield, 2),
                                            ip_off + 1, 1, "ip.dsfield", std::to_string(dsfield)));
            ip_node.children.push_back(leaf(pkt, "Total Length: " + std::to_string(ip_total_len),
                                            ip_off + 2, 2, "ip.len", std::to_string(ip_total_len)));
            ip_node.children.push_back(leaf(pkt, "Identification: " + fmt::hex(ip_id, 4) + " (" +
                                            std::to_string(ip_id) + ")", ip_off + 4, 2, "ip.id",
                                            std::to_string(ip_id)));

            const bool df = (ip_flags & 0x4000) != 0;
            const bool mf = (ip_flags & 0x2000) != 0;
            const uint16_t frag = ip_flags & 0x1FFF;
            DissectNode fl{"Flags: " + fmt::hex(ip_flags >> 13, 1) +
                               (df ? ", Don't fragment" : "") + (mf ? ", More fragments" : ""),
                           ip_off + 6, 1, {}, "ip.flags", 0};
            fl.children.push_back(leaf(pkt, fmt::bits(ip_flags, 16, 15, 1) + " = Reserved bit: " +
                                       ((ip_flags & 0x8000) ? "Set" : "Not set"), ip_off + 6, 1,
                                       "ip.flags.rb", (ip_flags & 0x8000) ? "1" : "0"));
            fl.children.push_back(leaf(pkt, fmt::bits(ip_flags, 16, 14, 1) + " = Don't fragment: " +
                                       (df ? "Set" : "Not set"), ip_off + 6, 1, "ip.flags.df", df ? "1" : "0"));
            fl.children.push_back(leaf(pkt, fmt::bits(ip_flags, 16, 13, 1) + " = More fragments: " +
                                       (mf ? "Set" : "Not set"), ip_off + 6, 1, "ip.flags.mf", mf ? "1" : "0"));
            ip_node.children.push_back(std::move(fl));
            ip_node.children.push_back(leaf(pkt, fmt::bits(ip_flags, 16, 12, 13) + " = Fragment Offset: " +
                                            std::to_string(frag * 8), ip_off + 6, 2, "ip.frag_offset",
                                            std::to_string(frag * 8)));
            ip_node.children.push_back(leaf(pkt, "Time to Live: " + std::to_string(ip_ttl), ip_off + 8, 1,
                                            "ip.ttl", std::to_string(ip_ttl)));
            ip_node.children.push_back(leaf(pkt, "Protocol: " + std::string(ip_proto == 17 ? "UDP" :
                                                                            ip_proto == 6  ? "TCP" :
                                                                            ip_proto == 1  ? "ICMP" : "Other") +
                                            " (" + std::to_string(ip_proto) + ")", ip_off + 9, 1,
                                            "ip.proto", std::to_string(ip_proto)));

            DissectNode cs{"Header Checksum: " + fmt::hex(ip_csum, 4) +
                               (ip_csum_ok ? " [correct]" : " [incorrect, should be " +
                                                            fmt::hex(ip_csum_expected, 4) + "]"),
                           ip_off + 10, 2, {}, "ip.checksum", 0};
            cs.children.push_back(leaf(pkt, std::string("[Header checksum status: ") +
                                       (ip_csum_ok ? "Good" : "Bad") + "]", ip_off + 10, 2,
                                       "ip.checksum.status", ip_csum_ok ? "good" : "bad"));
            ip_node.children.push_back(std::move(cs));
            pkt.fields.emplace("ip.checksum", std::to_string(ip_csum));

            ip_node.children.push_back(leaf(pkt, "Source Address: " + pkt.src_ip, ip_off + 12, 4,
                                            "ip.src", pkt.src_ip));
            ip_node.children.push_back(leaf(pkt, "Destination Address: " + pkt.dst_ip, ip_off + 16, 4,
                                            "ip.dst", pkt.dst_ip));
            pkt.layers.push_back(std::move(ip_node));

            pkt.fields.emplace("ip", "");
            pkt.fields.emplace("ip.addr", pkt.src_ip);
            pkt.fields.emplace("ip.addr", pkt.dst_ip);
            if (!ip_csum_ok) pkt.add_expert(ExpertLevel::Error, "Bad IPv4 header checksum");
        }

        const size_t udp_off = ip_off + ihl_bytes;
        if (ip_proto != 17) {
            pkt.info = "IPv4 protocol " + std::to_string(ip_proto) + " (not dissected)";
            finish_frame(pkt, proto_stack);
            return pkt;
        }
        if (udp_off + 8 > ip_end) {
            pkt.info = "Malformed UDP (header truncated)";
            mark_malformed(pkt, "UDP header truncated");
            finish_frame(pkt, proto_stack);
            return pkt;
        }

        // --------------------------------------------------------------------
        // Layer 4: UDP (8 bytes)
        // --------------------------------------------------------------------
        uint16_t src_port = u16(frame, udp_off);
        uint16_t dst_port = u16(frame, udp_off + 2);
        uint16_t udp_len  = u16(frame, udp_off + 4);
        uint16_t udp_csum = u16(frame, udp_off + 6);

        size_t udp_end = ip_end;
        if (udp_len >= 8 && udp_off + udp_len <= ip_end) {
            udp_end = udp_off + udp_len;
        } else {
            pkt.add_expert(ExpertLevel::Warn, "UDP length " + std::to_string(udp_len) +
                                              " inconsistent with IP payload");
        }

        // 0 = sender did not compute a checksum (allowed for UDP over IPv4).
        std::string udp_status = "unverified";
        uint16_t udp_expected = 0;
        bool udp_partial = false;
        if (udp_csum != 0) {
            const size_t seg_len = udp_end - udp_off;
            udp_status = (udp_checksum_ipv4(src_ip_u32, dst_ip_u32, frame.data() + udp_off, seg_len) == 0)
                             ? "good" : "bad";
            if (udp_status == "bad") {
                std::vector<uint8_t> seg(frame.begin() + udp_off, frame.begin() + udp_end);
                seg[6] = seg[7] = 0;
                udp_expected = udp_checksum_ipv4(src_ip_u32, dst_ip_u32, seg.data(), seg.size());
                if (udp_expected == 0) udp_expected = 0xFFFF;

                // Checksum offload: the OS leaves only the folded pseudo-header
                // sum for the NIC to finish. Captured on the sending host (or on
                // loopback, where no NIC finishes it) it looks wrong but is not.
                uint32_t pseudo = ((src_ip_u32 >> 16) & 0xFFFF) + (src_ip_u32 & 0xFFFF) +
                                  ((dst_ip_u32 >> 16) & 0xFFFF) + (dst_ip_u32 & 0xFFFF) +
                                  17u + static_cast<uint32_t>(seg_len);
                while (pseudo >> 16) pseudo = (pseudo & 0xFFFF) + (pseudo >> 16);
                if (udp_csum == pseudo) {
                    udp_status  = "good";
                    udp_partial = true;
                    pkt.add_expert(ExpertLevel::Note,
                                   "Partial (pseudo header) checksum (likely caused by \"UDP checksum offload\")");
                } else {
                    pkt.add_expert(ExpertLevel::Error, "Bad UDP checksum");
                }
            }
        }

        pkt.src_port = src_port;
        pkt.dst_port = dst_port;
        pkt.protocol = "UDP";
        proto_stack.push_back("udp");

        const size_t app_off = udp_off + 8;
        const size_t app_len = udp_end - app_off;
        pkt.info = std::to_string(src_port) + " -> " + std::to_string(dst_port) +
                   " Len=" + std::to_string(app_len);
        {
            DissectNode udp_node{
                "User Datagram Protocol, Src Port: " + std::to_string(src_port) +
                    ", Dst Port: " + std::to_string(dst_port),
                udp_off, 8, {}, "udp", 0
            };
            udp_node.children.push_back(leaf(pkt, "Source Port: " + std::to_string(src_port), udp_off, 2,
                                             "udp.srcport", std::to_string(src_port)));
            udp_node.children.push_back(leaf(pkt, "Destination Port: " + std::to_string(dst_port), udp_off + 2, 2,
                                             "udp.dstport", std::to_string(dst_port)));
            udp_node.children.push_back(leaf(pkt, "Length: " + std::to_string(udp_len), udp_off + 4, 2,
                                             "udp.length", std::to_string(udp_len)));
            std::string cs_label = "Checksum: " + fmt::hex(udp_csum, 4);
            if (udp_partial) cs_label += " [correct] (matches partial checksum, not " +
                                          fmt::hex(udp_expected, 4) + ", likely caused by \"UDP checksum offload\")";
            else if (udp_status == "good") cs_label += " [correct]";
            else if (udp_status == "bad") cs_label += " [incorrect, should be " + fmt::hex(udp_expected, 4) + "]";
            else cs_label += " [zero-value ignored]";
            DissectNode cs{cs_label, udp_off + 6, 2, {}, "udp.checksum", 0};
            cs.children.push_back(leaf(pkt, "[Checksum Status: " + std::string(
                                           udp_status == "good" ? "Good" : udp_status == "bad" ? "Bad" : "Unverified") + "]",
                                       udp_off + 6, 2, "udp.checksum.status", udp_status));
            udp_node.children.push_back(std::move(cs));
            udp_node.children.push_back({"UDP payload (" + std::to_string(app_len) + " bytes)",
                                         app_off, app_len, {}, "udp.payload", 0});
            pkt.layers.push_back(std::move(udp_node));

            pkt.fields.emplace("udp", "");
            pkt.fields.emplace("udp.port", std::to_string(src_port));
            pkt.fields.emplace("udp.port", std::to_string(dst_port));
            pkt.fields.emplace("udp.checksum", std::to_string(udp_csum));
        }

        // --------------------------------------------------------------------
        // Layer 7: Application Dissector (port, tap hint, or heuristic)
        // --------------------------------------------------------------------
        if (is_bootp_port(src_port) || is_bootp_port(dst_port) ||
            hint == AppProtoHint::BOOTP || looks_like_bootp(frame, app_off, app_len)) {
            proto_stack.push_back("bootp");
            dissect_bootp(frame, app_off, app_len, pkt);
        } else if (is_dns_port(src_port) || is_dns_port(dst_port) ||
                   hint == AppProtoHint::DNS || looks_like_dns(frame, app_off, app_len)) {
            proto_stack.push_back("dns");
            dissect_dns(frame, app_off, app_len, pkt);
        }

        finish_frame(pkt, proto_stack);
        return pkt;
    }

    // Kept for source compatibility; real logic lives in display_filter.hpp
    // (CaptureSession::snapshot compiles the filter once instead).
    static bool matches_filter(const DissectedPacket& pkt, const std::string& raw_filter);

private:
    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------
    static DissectNode leaf(DissectedPacket& pkt, const std::string& label, size_t off, size_t len,
                            const std::string& field, const std::string& value) {
        pkt.fields.emplace(field, value);
        return DissectNode{label, off, len, {}, field, 0};
    }

    static void mark_malformed(DissectedPacket& pkt, const std::string& why) {
        pkt.fields.emplace("_ws.malformed", "");
        pkt.add_expert(ExpertLevel::Error, "Malformed Packet: " + why);
    }

    // Appends the protocol stack summary + an Expert Info node (if any).
    static void finish_frame(DissectedPacket& pkt, const std::vector<std::string>& stack) {
        std::string joined;
        for (size_t i = 0; i < stack.size(); ++i) {
            if (i) joined += ':';
            joined += stack[i];
        }
        pkt.fields.emplace("frame.protocols", joined);
        if (!pkt.layers.empty()) {
            pkt.layers.front().children.push_back(
                {"[Protocols in frame: " + joined + "]", 0, 0, {}, "frame.protocols", 0});
        }
        append_expert_node(pkt);
    }

public:
    // (Re)builds the trailing "Expert Info" layer from pkt.expert_msgs.
    static void append_expert_node(DissectedPacket& pkt) {
        if (!pkt.layers.empty() && pkt.layers.back().field == "_ws.expert") {
            pkt.layers.pop_back();
        }
        // Remove stale expert fields before re-adding
        pkt.fields.erase("_ws.expert");
        pkt.fields.erase("_ws.expert.severity");
        if (pkt.expert_msgs.empty()) return;

        DissectNode ex{"[Expert Info (" + std::string(expert_level_name(pkt.expert_level)) + "): " +
                           std::to_string(pkt.expert_msgs.size()) + " item(s)]",
                       0, 0, {}, "_ws.expert", 0};
        for (const auto& m : pkt.expert_msgs) {
            ex.children.push_back({"[" + m + "]", 0, 0, {}, "_ws.expert.message", 0});
        }
        pkt.layers.push_back(std::move(ex));
        pkt.fields.emplace("_ws.expert", "");
        std::string sev = pkt.expert_level == ExpertLevel::Error ? "error" :
                          pkt.expert_level == ExpertLevel::Warn  ? "warning" : "note";
        pkt.fields.emplace("_ws.expert.severity", sev);
    }

private:
    static bool is_bootp_port(uint16_t p) {
        return p == 67 || p == 68 || p == BOOTP_SERVER_PORT ||
               p == BOOTP_CLIENT_PORT || p == BOOTP_RELAY_PORT;
    }

    static bool is_dns_port(uint16_t p) {
        return p == 53 || p == 5353 || p == DNS_SERVER_PORT || p == DNS_UPSTREAM_PORT;
    }

    static bool looks_like_bootp(const std::vector<uint8_t>& f, size_t off, size_t len) {
        if (len < 240 || off + len > f.size()) return false;
        uint8_t op    = f[off];
        uint8_t htype = f[off + 1];
        uint8_t hlen  = f[off + 2];
        uint32_t cookie = u32(f, off + 236);
        return (op == 1 || op == 2) && htype == 1 && hlen == 6 &&
               cookie == BOOTP_MAGIC_COOKIE;
    }

    static bool looks_like_dns(const std::vector<uint8_t>& f, size_t off, size_t len) {
        if (len < 13 || off + len > f.size()) return false;
        uint16_t qd = u16(f, off + 4);
        uint16_t an = u16(f, off + 6);
        uint16_t ns = u16(f, off + 8);
        uint16_t ar = u16(f, off + 10);
        if (qd == 0 || qd > 4 || an > 16 || ns > 16 || ar > 16) return false;
        uint8_t first_label_len = f[off + 12];
        return first_label_len > 0 && first_label_len <= 63 &&
               (13u + static_cast<size_t>(first_label_len)) < len;
    }

    static uint16_t u16(const std::vector<uint8_t>& b, size_t off) {
        return static_cast<uint16_t>((static_cast<uint16_t>(b[off]) << 8) | b[off + 1]);
    }

    static uint32_t u32(const std::vector<uint8_t>& b, size_t off) {
        return (static_cast<uint32_t>(b[off]) << 24) |
               (static_cast<uint32_t>(b[off + 1]) << 16) |
               (static_cast<uint32_t>(b[off + 2]) << 8) |
               static_cast<uint32_t>(b[off + 3]);
    }

    static std::string read_cstr(const std::vector<uint8_t>& f, size_t off, size_t max_len) {
        std::string out;
        for (size_t i = 0; i < max_len && (off + i) < f.size(); ++i) {
            if (f[off + i] == 0) break;
            out.push_back(static_cast<char>(f[off + i]));
        }
        return out;
    }

    static std::string printable(const uint8_t* p, size_t n) {
        std::string s;
        for (size_t i = 0; i < n; ++i) {
            s.push_back((p[i] >= 32 && p[i] <= 126) ? static_cast<char>(p[i]) : '.');
        }
        return s;
    }

    // ------------------------------------------------------------------------
    // BOOTP / DHCP Dissector (RFC 951 fixed header + RFC 1048/2132 options)
    // ------------------------------------------------------------------------
    static void dissect_bootp(const std::vector<uint8_t>& frame,
                              size_t off,
                              size_t len,
                              DissectedPacket& pkt) {
        pkt.protocol = "BOOTP";
        pkt.fields.emplace("bootp", "");
        pkt.fields.emplace("dhcp", "");
        if (len < 236) {
            pkt.info = "Malformed BOOTP (<236 bytes)";
            mark_malformed(pkt, "BOOTP fixed header is 236 bytes, got " + std::to_string(len));
            return;
        }

        uint8_t op     = frame[off];
        uint8_t htype  = frame[off + 1];
        uint8_t hlen   = frame[off + 2];
        uint8_t hops   = frame[off + 3];
        uint32_t xid   = u32(frame, off + 4);
        uint16_t secs  = u16(frame, off + 8);
        uint16_t flags = u16(frame, off + 10);
        std::string ciaddr = ipv4_to_string(u32(frame, off + 12));
        std::string yiaddr = ipv4_to_string(u32(frame, off + 16));
        std::string siaddr = ipv4_to_string(u32(frame, off + 20));
        std::string giaddr = ipv4_to_string(u32(frame, off + 24));

        std::array<uint8_t, 6> mac{};
        std::copy_n(frame.begin() + off + 28, 6, mac.begin());
        std::string mac_str = mac_to_string(mac);

        pkt.txn_kind     = TxnKind::BOOTP;
        pkt.txn_response = (op == 2);
        pkt.txn_id       = xid;
        pkt.txn_hops     = hops;

        std::string op_str = (op == 1) ? "Boot Request (1)" :
                             (op == 2) ? "Boot Reply (2)" :
                                         ("Unknown (" + std::to_string(op) + ")");

        DissectNode root{
            "Bootstrap Protocol (" + std::string(op == 1 ? "BOOTREQUEST" : "BOOTREPLY") + ")",
            off, len, {}, "bootp", 0
        };
        auto add = [&](const std::string& label, size_t o, size_t l,
                       const std::string& f, const std::string& v) {
            root.children.push_back(leaf(pkt, label, o, l, f, v));
        };
        add("Message type: " + op_str, off, 1, "bootp.type", std::to_string(op));
        add("Hardware type: " + std::string(htype == 1 ? "Ethernet" : "Other") + " (" + fmt::hex(htype, 2) + ")",
            off + 1, 1, "bootp.hw.type", std::to_string(htype));
        add("Hardware address length: " + std::to_string(hlen), off + 2, 1, "bootp.hw.len", std::to_string(hlen));
        add("Hops: " + std::to_string(hops), off + 3, 1, "bootp.hops", std::to_string(hops));
        add("Transaction ID: " + fmt::hex(xid, 8), off + 4, 4, "bootp.id", std::to_string(xid));
        add("Seconds elapsed: " + std::to_string(secs), off + 8, 2, "bootp.secs", std::to_string(secs));

        DissectNode fl{"Bootp flags: " + fmt::hex(flags, 4) + ((flags & 0x8000) ? " (Broadcast)" : " (Unicast)"),
                       off + 10, 2, {}, "bootp.flags", 0};
        fl.children.push_back(leaf(pkt, fmt::bits(flags, 16, 15, 1) + " = Broadcast flag: " +
                                   ((flags & 0x8000) ? "Broadcast" : "Unicast"), off + 10, 2,
                                   "bootp.flags.bc", (flags & 0x8000) ? "1" : "0"));
        fl.children.push_back(leaf(pkt, fmt::bits(flags, 16, 14, 15) + " = Reserved flags: " +
                                   fmt::hex(flags & 0x7FFF, 4), off + 10, 2, "bootp.flags.reserved",
                                   std::to_string(flags & 0x7FFF)));
        root.children.push_back(std::move(fl));

        add("Client IP address: " + ciaddr, off + 12, 4, "bootp.ip.client", ciaddr);
        add("Your (client) IP address: " + yiaddr, off + 16, 4, "bootp.ip.your", yiaddr);
        add("Next server IP address: " + siaddr, off + 20, 4, "bootp.ip.server", siaddr);
        add("Relay agent IP address: " + giaddr, off + 24, 4, "bootp.ip.relay", giaddr);
        size_t hw_used = std::min<size_t>(hlen, 16);
        add("Client MAC address: " + mac_str, off + 28, hw_used, "bootp.hw.mac_addr", mac_str);
        if (hw_used < 16) {
            root.children.push_back({"Client hardware address padding: " + std::to_string(16 - hw_used) + " bytes",
                                     off + 28 + hw_used, 16 - hw_used, {}, "bootp.hw.addr_padding", 0});
        }

        std::string sname = read_cstr(frame, off + 44, 64);
        std::string file  = read_cstr(frame, off + 108, 128);
        add("Server host name: " + (sname.empty() ? "<not given>" : sname), off + 44, 64, "bootp.server", sname);
        add("Boot file name: " + (file.empty() ? "<not given>" : file), off + 108, 128, "bootp.file", file);

        std::string dns_summary;
        int dhcp_type = -1;
        if (len >= 240) {
            size_t v_off = off + 236;
            uint32_t cookie = u32(frame, v_off);
            DissectNode vend{"Vendor Extensions / Options", v_off, len - 236, {}, "bootp.vendor", 0};
            vend.children.push_back(leaf(pkt, "Magic cookie: " + std::string(cookie == BOOTP_MAGIC_COOKIE ? "DHCP" : "Unknown") +
                                         " (" + fmt::hex(cookie, 8) + ")", v_off, 4, "bootp.cookie",
                                         fmt::hex(cookie, 8)));

            if (cookie == BOOTP_MAGIC_COOKIE) {
                size_t p = v_off + 4;
                size_t end = off + len;
                size_t pad_count = 0;
                bool saw_end = false;
                while (p < end) {
                    uint8_t tag = frame[p];
                    if (tag == 0) { ++pad_count; ++p; continue; }
                    if (tag == 255) {
                        vend.children.push_back({"Option: (255) End", p, 1, {}, "bootp.option.end", 0});
                        saw_end = true;
                        ++p;
                        break;
                    }
                    if (p + 1 >= end) {
                        mark_malformed(pkt, "BOOTP option header runs past payload");
                        break;
                    }
                    uint8_t olen = frame[p + 1];
                    if (p + 2 + olen > end) {
                        mark_malformed(pkt, "BOOTP option " + std::to_string(tag) + " length exceeds payload");
                        break;
                    }
                    pkt.fields.emplace("bootp.option.type", std::to_string(tag));
                    vend.children.push_back(describe_bootp_option(pkt, tag, frame, p, olen, dns_summary, dhcp_type));
                    p += 2 + olen;
                }
                // Trailing zero padding after End (RFC 951 pads vendor area to 64 bytes)
                size_t trailer = (saw_end && p < end) ? (end - p) : 0;
                if (pad_count + trailer > 0) {
                    vend.children.push_back({"Padding: " + std::to_string(pad_count + trailer) + " byte(s)",
                                             saw_end ? p : v_off + 4, saw_end ? trailer : 0, {},
                                             "bootp.option.padding", 0});
                }
                if (!saw_end) pkt.add_expert(ExpertLevel::Warn, "BOOTP options missing End (255) marker");
            }
            root.children.push_back(std::move(vend));
        }

        // Real captures carry DHCP (option 53). Wireshark then calls it "DHCP".
        if (dhcp_type >= 0) pkt.protocol = "DHCP";

        pkt.layers.push_back(std::move(root));

        std::ostringstream info;
        if (dhcp_type >= 0) {
            info << "DHCP " << dhcp_msg_type_name(static_cast<uint8_t>(dhcp_type))
                 << " - Transaction ID " << fmt::hex(xid, 8);
            if (op == 2) info << ", yiaddr=" << yiaddr;
        } else if (op == 1) {
            info << "Boot Request from " << mac_str << " (xid=" << fmt::hex(xid, 8) << ")";
            if (hops > 0) info << " [hops=" << static_cast<int>(hops) << ", giaddr=" << giaddr << "]";
        } else {
            info << "Boot Reply -> yiaddr=" << yiaddr << " (xid=" << fmt::hex(xid, 8) << ")";
            if (!dns_summary.empty()) info << ", DNS=" << dns_summary;
        }
        pkt.info = info.str();
    }

    static DissectNode describe_bootp_option(DissectedPacket& pkt, uint8_t tag,
                                             const std::vector<uint8_t>& f,
                                             size_t opt_off, uint8_t olen,
                                             std::string& out_dns_ip, int& out_dhcp_type) {
        const size_t val_off = opt_off + 2;
        const size_t total = static_cast<size_t>(2 + olen);
        auto ip_at = [&](size_t i) { return ipv4_to_string(u32(f, val_off + i)); };
        auto str = [&]() { return printable(f.data() + val_off, olen); };

        std::string name, value, field;
        switch (tag) {
            case 1:  name = "Subnet Mask";             field = "bootp.option.subnet_mask";
                     value = olen >= 4 ? ip_at(0) : "?"; break;
            case 3:  name = "Router";                  field = "bootp.option.router";
                     value = olen >= 4 ? ip_at(0) : "?"; break;
            case 6: {
                name = "Domain Name Server"; field = "bootp.option.domain_name_server";
                for (size_t i = 0; i + 4 <= olen; i += 4) {
                    if (i) value += ", ";
                    std::string ip = ip_at(i);
                    value += ip;
                    pkt.fields.emplace(field, ip);
                }
                if (olen >= 4) out_dns_ip = ip_at(0);
                field.clear(); // already added per-address
                break;
            }
            case 12: name = "Host Name";               field = "bootp.option.hostname";   value = str(); break;
            case 15: name = "Domain Name";             field = "bootp.option.domain_name"; value = str(); break;
            case 28: name = "Broadcast Address";       field = "bootp.option.broadcast_address";
                     value = olen >= 4 ? ip_at(0) : "?"; break;
            case 50: name = "Requested IP Address";    field = "bootp.option.requested_ip_address";
                     value = olen >= 4 ? ip_at(0) : "?"; break;
            case 51: name = "IP Address Lease Time";   field = "bootp.option.ip_address_lease_time";
                     value = std::to_string(olen >= 4 ? u32(f, val_off) : 0); break;
            case 53:
                name = "DHCP Message Type"; field = "bootp.option.dhcp";
                if (olen >= 1) {
                    out_dhcp_type = f[val_off];
                    value = std::to_string(f[val_off]);
                    pkt.fields.emplace(field, value);
                    field.clear();
                    value = std::string(dhcp_msg_type_name(f[val_off])) + " (" + value + ")";
                }
                break;
            case 54: name = "DHCP Server Identifier";  field = "bootp.option.dhcp_server_id";
                     value = olen >= 4 ? ip_at(0) : "?"; break;
            case 55: {
                name = "Parameter Request List";
                for (size_t i = 0; i < olen; ++i) {
                    if (i) value += ",";
                    value += std::to_string(f[val_off + i]);
                }
                break;
            }
            case 58: name = "Renewal Time Value";      value = std::to_string(olen >= 4 ? u32(f, val_off) : 0) + "s"; break;
            case 59: name = "Rebinding Time Value";    value = std::to_string(olen >= 4 ? u32(f, val_off) : 0) + "s"; break;
            case 61: {
                name = "Client identifier";
                std::ostringstream oss;
                for (size_t i = 0; i < olen; ++i) {
                    if (i) oss << ':';
                    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(f[val_off + i]);
                }
                value = oss.str();
                break;
            }
            default:
                name = "Unknown"; value = std::to_string(olen) + " byte(s)";
        }
        if (!field.empty()) pkt.fields.emplace(field, value);
        if (tag == 51) value += "s"; // field keeps the bare number for numeric filters

        DissectNode node{"Option: (" + std::to_string(tag) + ") " + name + (value.empty() ? "" : ": " + value),
                         opt_off, total, {}, "bootp.option.type", 0};
        node.children.push_back({"Option: (" + std::to_string(tag) + ")", opt_off, 1, {}, "bootp.option.type", 0});
        node.children.push_back({"Length: " + std::to_string(olen), opt_off + 1, 1, {}, "bootp.option.length", 0});
        if (olen > 0) {
            node.children.push_back({"Value: " + value, val_off, olen, {}, "bootp.option.value", 0});
        }
        return node;
    }

    // ------------------------------------------------------------------------
    // DNS Dissector (RFC 1035)
    // ------------------------------------------------------------------------
    static void dissect_dns(const std::vector<uint8_t>& frame,
                            size_t off,
                            size_t len,
                            DissectedPacket& pkt) {
        pkt.protocol = "DNS";
        pkt.fields.emplace("dns", "");
        if (len < 12) {
            pkt.info = "Malformed DNS (<12 bytes)";
            mark_malformed(pkt, "DNS header is 12 bytes, got " + std::to_string(len));
            return;
        }

        uint16_t id      = u16(frame, off);
        uint16_t fl_raw  = u16(frame, off + 2);
        DnsFlags flags   = DnsFlags::unpack(fl_raw);
        uint8_t  z       = static_cast<uint8_t>((fl_raw >> 4) & 0x7);
        uint16_t qdcount = u16(frame, off + 4);
        uint16_t ancount = u16(frame, off + 6);
        uint16_t nscount = u16(frame, off + 8);
        uint16_t arcount = u16(frame, off + 10);

        pkt.txn_kind     = TxnKind::DNS;
        pkt.txn_response = flags.qr;
        pkt.txn_id       = id;
        pkt.txn_client_port = flags.qr ? pkt.dst_port : pkt.src_port;

        DissectNode root{
            std::string("Domain Name System (") + (flags.qr ? "response" : "query") + ")",
            off, len, {}, "dns", 0
        };
        root.children.push_back(leaf(pkt, "Transaction ID: " + fmt::hex(id, 4), off, 2, "dns.id", std::to_string(id)));

        // Wireshark-style bit-by-bit breakdown of the 16-bit flags word
        DissectNode fl_node{
            "Flags: " + fmt::hex(fl_raw, 4) + (flags.qr ? " Standard query response, " : " Standard query") +
                (flags.qr ? dns_rcode_long(flags.rcode) : ""),
            off + 2, 2, {}, "dns.flags", 0
        };
        auto bit = [&](int hi, int w, const std::string& text, const std::string& f, unsigned v) {
            fl_node.children.push_back(leaf(pkt, fmt::bits(fl_raw, 16, hi, w) + " = " + text,
                                            off + 2, 2, f, std::to_string(v)));
        };
        bit(15, 1, std::string("Response: ") + (flags.qr ? "Message is a response" : "Message is a query"),
            "dns.flags.response", flags.qr);
        bit(14, 4, "Opcode: " + std::string(flags.opcode == 0 ? "Standard query" : "Other") +
                       " (" + std::to_string(flags.opcode) + ")", "dns.flags.opcode", flags.opcode);
        if (flags.qr) {
            bit(10, 1, std::string("Authoritative: ") + (flags.aa ? "Server is an authority for domain"
                                                                   : "Server is not an authority for domain"),
                "dns.flags.authoritative", flags.aa);
        }
        bit(9, 1, std::string("Truncated: ") + (flags.tc ? "Message is truncated" : "Message is not truncated"),
            "dns.flags.truncated", flags.tc);
        bit(8, 1, std::string("Recursion desired: ") + (flags.rd ? "Do query recursively" : "Don't do query recursively"),
            "dns.flags.recdesired", flags.rd);
        if (flags.qr) {
            bit(7, 1, std::string("Recursion available: ") + (flags.ra ? "Server can do recursive queries"
                                                                         : "Server can't do recursive queries"),
                "dns.flags.recavail", flags.ra);
        }
        bit(6, 3, "Z: reserved (" + std::to_string(z) + ")", "dns.flags.z", z);
        if (flags.qr) {
            bit(3, 4, "Reply code: " + dns_rcode_long(flags.rcode) + " (" + std::to_string(flags.rcode) + ")",
                "dns.flags.rcode", flags.rcode);
        }
        root.children.push_back(std::move(fl_node));

        root.children.push_back(leaf(pkt, "Questions: " + std::to_string(qdcount), off + 4, 2,
                                     "dns.count.queries", std::to_string(qdcount)));
        root.children.push_back(leaf(pkt, "Answer RRs: " + std::to_string(ancount), off + 6, 2,
                                     "dns.count.answers", std::to_string(ancount)));
        root.children.push_back(leaf(pkt, "Authority RRs: " + std::to_string(nscount), off + 8, 2,
                                     "dns.count.auth_rr", std::to_string(nscount)));
        root.children.push_back(leaf(pkt, "Additional RRs: " + std::to_string(arcount), off + 10, 2,
                                     "dns.count.add_rr", std::to_string(arcount)));

        // PacketReader scoped to the DNS payload so compression pointers
        // (offsets from the start of the DNS message) resolve correctly.
        PacketReader r(frame.data() + off, len);
        r.skip(12);

        std::string first_qname;
        std::string first_qtype;
        std::string answer_summary;

        try {
            if (qdcount > 0) {
                size_t qsec_start = r.pos();
                DissectNode q_sec{"Queries", off + qsec_start, 0, {}, "dns.qry", 0};
                for (uint16_t i = 0; i < qdcount; ++i) {
                    size_t q_start   = r.pos();
                    std::string qname = decode_dns_name(r);
                    size_t name_end  = r.pos();
                    uint16_t qtype   = r.read_u16();
                    uint16_t qclass  = r.read_u16();
                    size_t q_end     = r.pos();

                    if (i == 0) {
                        first_qname = qname;
                        first_qtype = dns_type_str(qtype);
                    }
                    DissectNode qnode{
                        qname + ": type " + dns_type_str(qtype) + ", class " + (qclass == 1 ? "IN" : fmt::hex(qclass, 4)),
                        off + q_start, q_end - q_start, {}, "dns.qry", 0
                    };
                    qnode.children.push_back(leaf(pkt, "Name: " + qname, off + q_start, name_end - q_start,
                                                  "dns.qry.name", qname));
                    qnode.children.push_back({"[Name Length: " + std::to_string(qname.size()) + "]", 0, 0, {},
                                              "dns.qry.name.len", 0});
                    qnode.children.push_back(leaf(pkt, "Type: " + dns_type_str(qtype) + " (" + std::to_string(qtype) + ")",
                                                  off + name_end, 2, "dns.qry.type", std::to_string(qtype)));
                    qnode.children.push_back(leaf(pkt, "Class: IN (" + fmt::hex(qclass, 4) + ")", off + name_end + 2, 2,
                                                  "dns.qry.class", std::to_string(qclass)));
                    q_sec.children.push_back(std::move(qnode));
                }
                q_sec.byte_length = r.pos() - qsec_start;
                root.children.push_back(std::move(q_sec));
            }

            auto parse_rr_section = [&](const std::string& title, uint16_t count, bool collect_summary) {
                if (count == 0) return;
                size_t sec_start = r.pos();
                DissectNode sec{title, off + sec_start, 0, {}, "", 0};
                for (uint16_t i = 0; i < count; ++i) {
                    size_t rr_start  = r.pos();
                    std::string name = decode_dns_name(r);
                    size_t name_end  = r.pos();
                    uint16_t rtype   = r.read_u16();
                    uint16_t rclass  = r.read_u16();
                    uint32_t ttl     = r.read_u32();
                    uint16_t rdlen   = r.read_u16();
                    size_t rdata_off = r.pos();
                    if (r.remaining() < rdlen) {
                        mark_malformed(pkt, "RDATA length " + std::to_string(rdlen) + " exceeds message");
                        break;
                    }

                    std::string rdata_str, rdata_field;
                    const uint8_t* rd = frame.data() + off + rdata_off;
                    if (rtype == 1 && rdlen == 4) {
                        rdata_str = ipv4_to_string(u32(frame, off + rdata_off));
                        rdata_field = "dns.a";
                        r.skip(4);
                    } else if (rtype == 28 && rdlen == 16) {
                        std::ostringstream oss;
                        oss << std::hex;
                        for (int g = 0; g < 8; ++g) {
                            if (g) oss << ':';
                            oss << ((rd[g * 2] << 8) | rd[g * 2 + 1]);
                        }
                        rdata_str = oss.str();
                        rdata_field = "dns.aaaa";
                        r.skip(16);
                    } else if (rtype == 5 || rtype == 12 || rtype == 2) {
                        rdata_str = decode_dns_name(r);
                        rdata_field = rtype == 5 ? "dns.cname" : rtype == 12 ? "dns.ptr.domain_name" : "dns.ns";
                        r.seek(rdata_off + rdlen);
                    } else if (rtype == 15 && rdlen >= 3) {
                        uint16_t pref = r.read_u16();
                        rdata_str = "preference " + std::to_string(pref) + ", " + decode_dns_name(r);
                        rdata_field = "dns.mx.mail_exchange";
                        r.seek(rdata_off + rdlen);
                    } else if (rtype == 16 && rdlen >= 1) {
                        size_t tl = std::min<size_t>(rd[0], rdlen - 1u);
                        rdata_str = "\"" + printable(rd + 1, tl) + "\"";
                        rdata_field = "dns.txt";
                        r.skip(rdlen);
                    } else if (rtype == 6) {
                        rdata_str = "primary NS " + decode_dns_name(r);
                        r.seek(rdata_off + rdlen);
                    } else if (rtype == 41) {
                        rdata_str = "EDNS0, UDP payload size " + std::to_string(rclass);
                        r.skip(rdlen);
                    } else {
                        rdata_str = std::to_string(rdlen) + " bytes";
                        r.skip(rdlen);
                    }
                    size_t rr_end = r.pos();

                    if (collect_summary) {
                        if (!answer_summary.empty()) answer_summary += ", ";
                        answer_summary += dns_type_str(rtype) + " " + rdata_str;
                    }
                    if (!rdata_field.empty()) pkt.fields.emplace(rdata_field, rdata_str);
                    pkt.fields.emplace("dns.resp.name", name);
                    pkt.fields.emplace("dns.resp.type", std::to_string(rtype));
                    if (rtype != 41) pkt.fields.emplace("dns.resp.ttl", std::to_string(ttl));

                    DissectNode rnode{
                        (name.empty() ? "<Root>" : name) + ": type " + dns_type_str(rtype) + ", " + rdata_str +
                            (rtype == 41 ? "" : " (TTL " + std::to_string(ttl) + "s)"),
                        off + rr_start, rr_end - rr_start, {}, "dns.resp", 0
                    };
                    rnode.children.push_back({"Name: " + (name.empty() ? "<Root>" : name), off + rr_start,
                                              name_end - rr_start, {}, "dns.resp.name", 0});
                    rnode.children.push_back({"Type: " + dns_type_str(rtype) + " (" + std::to_string(rtype) + ")",
                                              off + name_end, 2, {}, "dns.resp.type", 0});
                    rnode.children.push_back({"Class: " + std::string(rclass == 1 ? "IN " : "") + "(" + fmt::hex(rclass, 4) + ")",
                                              off + name_end + 2, 2, {}, "dns.resp.class", 0});
                    rnode.children.push_back({"Time to live: " + std::to_string(ttl) + " seconds",
                                              off + name_end + 4, 4, {}, "dns.resp.ttl", 0});
                    rnode.children.push_back({"Data length: " + std::to_string(rdlen),
                                              off + name_end + 8, 2, {}, "dns.resp.len", 0});
                    rnode.children.push_back({dns_type_str(rtype) + " RDATA: " + rdata_str,
                                              off + rdata_off, rdlen, {}, rdata_field, 0});
                    sec.children.push_back(std::move(rnode));
                }
                sec.byte_length = r.pos() - sec_start;
                root.children.push_back(std::move(sec));
            };

            parse_rr_section("Answers", ancount, true);
            parse_rr_section("Authoritative nameservers", nscount, false);
            parse_rr_section("Additional records", arcount, false);
        } catch (const std::exception& ex) {
            // Previously swallowed silently; now surfaced like Wireshark does.
            mark_malformed(pkt, std::string("DNS ") + ex.what());
        }

        if (flags.qr && flags.rcode != 0) {
            pkt.add_expert(ExpertLevel::Note, "DNS reply code " + std::string(dns_rcode_name(flags.rcode)));
        }

        pkt.layers.push_back(std::move(root));

        std::ostringstream info;
        info << (flags.qr ? "Standard query response " : "Standard query ")
             << fmt::hex(id, 4) << " " << first_qtype << " " << first_qname;
        if (flags.qr) {
            if (flags.rcode != static_cast<uint8_t>(DnsRCode::NO_ERR)) {
                info << " [" << dns_rcode_name(flags.rcode) << "]";
            } else if (!answer_summary.empty()) {
                info << " -> " << answer_summary;
            }
        }
        pkt.info = info.str();
    }
};

} // namespace netproto

// Display-filter engine + matches_filter() implementation
#include "display_filter.hpp"
