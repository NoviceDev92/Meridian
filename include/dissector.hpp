#pragma once

#include "dns_engine.hpp"
#include "protocol_headers.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
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
};

struct DissectedPacket {
    uint32_t number        = 0;
    uint64_t timestamp_us  = 0;
    double rel_time_sec    = 0.0;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port      = 0;
    uint16_t dst_port      = 0;
    std::string protocol;  // "BOOTP", "DNS", "UDP", "IPv4", "ETH"
    std::string info;
    std::vector<uint8_t> raw_frame;
    std::vector<DissectNode> layers;
};

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

        // Frame summary layer
        {
            std::ostringstream oss;
            oss << "Frame " << frame_no << ": " << frame.size()
                << " bytes on wire (" << (frame.size() * 8) << " bits)";
            DissectNode fnode{oss.str(), 0, frame.size(), {}};
            fnode.children.push_back({"Arrival Time (rel): " + format_time(rel_time_sec), 0, 0, {}});
            fnode.children.push_back({"Frame Length: " + std::to_string(frame.size()) + " bytes", 0, frame.size(), {}});
            pkt.layers.push_back(std::move(fnode));
        }

        if (frame.size() < 14) {
            pkt.info = "Malformed Ethernet II frame (<14 bytes)";
            return pkt;
        }

        // --------------------------------------------------------------------
        // Layer 2: Ethernet II (Offset 0..14)
        // --------------------------------------------------------------------
        std::array<uint8_t, 6> dst_mac{}, src_mac{};
        std::copy_n(frame.begin(), 6, dst_mac.begin());
        std::copy_n(frame.begin() + 6, 6, src_mac.begin());
        uint16_t ethertype = read_u16_at(frame, 12);

        {
            DissectNode eth{
                "Ethernet II, Src: " + mac_to_string(src_mac) + ", Dst: " + mac_to_string(dst_mac),
                0, 14, {}
            };
            eth.children.push_back({"Destination: " + mac_to_string(dst_mac), 0, 6, {}});
            eth.children.push_back({"Source: " + mac_to_string(src_mac), 6, 6, {}});
            eth.children.push_back({"Type: " + hex16(ethertype) + (ethertype == 0x0800 ? " (IPv4)" : ""), 12, 2, {}});
            pkt.layers.push_back(std::move(eth));
        }

        if (ethertype != 0x0800 || frame.size() < 34) {
            return pkt;
        }

        // --------------------------------------------------------------------
        // Layer 3: IPv4 (Offset 14..)
        // --------------------------------------------------------------------
        const size_t ip_off = 14;
        uint8_t ver_ihl     = frame[ip_off];
        uint8_t ihl_bytes   = static_cast<uint8_t>((ver_ihl & 0x0F) * 4);
        if (ihl_bytes < 20 || ip_off + ihl_bytes > frame.size()) {
            pkt.info = "Malformed IPv4 header";
            return pkt;
        }
        uint16_t ip_total_len = read_u16_at(frame, ip_off + 2);
        uint16_t ip_id        = read_u16_at(frame, ip_off + 4);
        uint16_t ip_flags     = read_u16_at(frame, ip_off + 6);
        uint8_t  ip_ttl       = frame[ip_off + 8];
        uint8_t  ip_proto     = frame[ip_off + 9];
        uint16_t ip_csum      = read_u16_at(frame, ip_off + 10);
        uint32_t src_ip_u32   = read_u32_at(frame, ip_off + 12);
        uint32_t dst_ip_u32   = read_u32_at(frame, ip_off + 16);

        pkt.src_ip   = ipv4_to_string(src_ip_u32);
        pkt.dst_ip   = ipv4_to_string(dst_ip_u32);
        pkt.protocol = "IPv4";

        {
            DissectNode ip_node{
                "Internet Protocol Version 4, Src: " + pkt.src_ip + ", Dst: " + pkt.dst_ip,
                ip_off, ihl_bytes, {}
            };
            ip_node.children.push_back({"Version: 4, Header Length: " + std::to_string(ihl_bytes) + " bytes", ip_off, 1, {}});
            ip_node.children.push_back({"Total Length: " + std::to_string(ip_total_len), ip_off + 2, 2, {}});
            ip_node.children.push_back({"Identification: " + hex16(ip_id), ip_off + 4, 2, {}});
            ip_node.children.push_back({"Flags/Fragment: " + hex16(ip_flags), ip_off + 6, 2, {}});
            ip_node.children.push_back({"Time to Live: " + std::to_string(ip_ttl), ip_off + 8, 1, {}});
            ip_node.children.push_back({"Protocol: " + std::to_string(ip_proto) + (ip_proto == 17 ? " (UDP)" : ""), ip_off + 9, 1, {}});
            ip_node.children.push_back({"Header Checksum: " + hex16(ip_csum), ip_off + 10, 2, {}});
            ip_node.children.push_back({"Source Address: " + pkt.src_ip, ip_off + 12, 4, {}});
            ip_node.children.push_back({"Destination Address: " + pkt.dst_ip, ip_off + 16, 4, {}});
            pkt.layers.push_back(std::move(ip_node));
        }

        const size_t udp_off = ip_off + ihl_bytes;
        if (ip_proto != 17 || udp_off + 8 > frame.size()) {
            return pkt;
        }

        // --------------------------------------------------------------------
        // Layer 4: UDP (8 bytes)
        // --------------------------------------------------------------------
        uint16_t src_port = read_u16_at(frame, udp_off);
        uint16_t dst_port = read_u16_at(frame, udp_off + 2);
        uint16_t udp_len  = read_u16_at(frame, udp_off + 4);
        uint16_t udp_csum = read_u16_at(frame, udp_off + 6);

        pkt.src_port = src_port;
        pkt.dst_port = dst_port;
        pkt.protocol = "UDP";
        pkt.info     = std::to_string(src_port) + " -> " + std::to_string(dst_port) +
                       " Len=" + std::to_string(udp_len);

        const size_t app_off = udp_off + 8;
        const size_t app_len = frame.size() - app_off;

        {
            DissectNode udp_node{
                "User Datagram Protocol, Src Port: " + std::to_string(src_port) +
                    ", Dst Port: " + std::to_string(dst_port),
                udp_off, 8, {}
            };
            udp_node.children.push_back({"Source Port: " + std::to_string(src_port), udp_off, 2, {}});
            udp_node.children.push_back({"Destination Port: " + std::to_string(dst_port), udp_off + 2, 2, {}});
            udp_node.children.push_back({"Length: " + std::to_string(udp_len), udp_off + 4, 2, {}});
            udp_node.children.push_back({"Checksum: " + hex16(udp_csum), udp_off + 6, 2, {}});
            udp_node.children.push_back({"UDP Payload (" + std::to_string(app_len) + " bytes)", app_off, app_len, {}});
            pkt.layers.push_back(std::move(udp_node));
        }

        // --------------------------------------------------------------------
        // Layer 7: Application Dissector (BOOTP / DNS: Port, Hint, or Heuristic)
        // --------------------------------------------------------------------
        if (is_bootp_port(src_port) || is_bootp_port(dst_port) ||
            hint == AppProtoHint::BOOTP || looks_like_bootp(frame, app_off, app_len)) {
            dissect_bootp(frame, app_off, app_len, pkt);
        } else if (is_dns_port(src_port) || is_dns_port(dst_port) ||
                   hint == AppProtoHint::DNS || looks_like_dns(frame, app_off, app_len)) {
            dissect_dns(frame, app_off, app_len, pkt);
        }

        return pkt;
    }

    static bool matches_filter(const DissectedPacket& pkt, const std::string& raw_filter) {
        std::string f = trim_lower(raw_filter);
        if (f.empty()) return true;

        std::string proto_low = to_lower(pkt.protocol);
        if (f == "bootp" || f == "dns" || f == "udp" || f == "ipv4" || f == "eth") {
            if (f == "udp" && (proto_low == "udp" || proto_low == "bootp" || proto_low == "dns")) return true;
            if (f == "ipv4" && (proto_low != "eth")) return true;
            return proto_low == f;
        }
        if (f.rfind("ip==", 0) == 0 || f.rfind("ip ==", 0) == 0) {
            std::string target = trim_lower(f.substr(f.find("==") + 2));
            return pkt.src_ip == target || pkt.dst_ip == target;
        }
        if (f.rfind("port==", 0) == 0 || f.rfind("port ==", 0) == 0) {
            std::string target = trim_lower(f.substr(f.find("==") + 2));
            return std::to_string(pkt.src_port) == target || std::to_string(pkt.dst_port) == target;
        }

        // Fallback: substring search across protocol, IPs, and info
        return proto_low.find(f) != std::string::npos ||
               pkt.src_ip.find(f) != std::string::npos ||
               pkt.dst_ip.find(f) != std::string::npos ||
               to_lower(pkt.info).find(f) != std::string::npos;
    }

private:
    static bool is_bootp_port(uint16_t p) {
        return p == 67 || p == 68 || p == BOOTP_SERVER_PORT ||
               p == BOOTP_CLIENT_PORT || p == BOOTP_RELAY_PORT;
    }

    static bool is_dns_port(uint16_t p) {
        return p == 53 || p == DNS_SERVER_PORT || p == DNS_UPSTREAM_PORT;
    }

    static bool looks_like_bootp(const std::vector<uint8_t>& f, size_t off, size_t len) {
        if (len < 240 || off + len > f.size()) return false;
        uint8_t op    = f[off];
        uint8_t htype = f[off + 1];
        uint8_t hlen  = f[off + 2];
        uint32_t cookie = read_u32_at(f, off + 236);
        return (op == 1 || op == 2) && htype == 1 && hlen == 6 &&
               cookie == BOOTP_MAGIC_COOKIE;
    }

    static bool looks_like_dns(const std::vector<uint8_t>& f, size_t off, size_t len) {
        if (len < 13 || off + len > f.size()) return false;
        uint16_t qd = read_u16_at(f, off + 4);
        uint16_t an = read_u16_at(f, off + 6);
        uint16_t ns = read_u16_at(f, off + 8);
        uint16_t ar = read_u16_at(f, off + 10);
        if (qd == 0 || qd > 4 || an > 16 || ns > 16 || ar > 16) return false;
        uint8_t first_label_len = f[off + 12];
        return first_label_len > 0 && first_label_len <= 63 &&
               (13u + static_cast<size_t>(first_label_len)) < len;
    }

    static uint16_t read_u16_at(const std::vector<uint8_t>& b, size_t off) {
        return static_cast<uint16_t>((static_cast<uint16_t>(b[off]) << 8) | b[off + 1]);
    }

    static uint32_t read_u32_at(const std::vector<uint8_t>& b, size_t off) {
        return (static_cast<uint32_t>(b[off]) << 24) |
               (static_cast<uint32_t>(b[off + 1]) << 16) |
               (static_cast<uint32_t>(b[off + 2]) << 8) |
               static_cast<uint32_t>(b[off + 3]);
    }

    static std::string hex16(uint16_t v) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << v;
        return oss.str();
    }

    static std::string hex32(uint32_t v) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << v;
        return oss.str();
    }

    static std::string format_time(double sec) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(6) << sec << "s";
        return oss.str();
    }

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    static std::string trim_lower(std::string s) {
        size_t l = 0;
        while (l < s.size() && std::isspace(static_cast<unsigned char>(s[l]))) ++l;
        size_t r = s.size();
        while (r > l && std::isspace(static_cast<unsigned char>(s[r - 1]))) --r;
        return to_lower(s.substr(l, r - l));
    }

    // ------------------------------------------------------------------------
    // BOOTP Dissector
    // ------------------------------------------------------------------------
    static void dissect_bootp(const std::vector<uint8_t>& frame,
                              size_t off,
                              size_t len,
                              DissectedPacket& pkt) {
        pkt.protocol = "BOOTP";
        if (len < 236) {
            pkt.info = "Malformed BOOTP (<236 bytes)";
            return;
        }

        uint8_t op     = frame[off];
        uint8_t htype  = frame[off + 1];
        uint8_t hlen   = frame[off + 2];
        uint8_t hops   = frame[off + 3];
        uint32_t xid   = read_u32_at(frame, off + 4);
        uint16_t secs  = read_u16_at(frame, off + 8);
        uint16_t flags = read_u16_at(frame, off + 10);
        std::string ciaddr = ipv4_to_string(read_u32_at(frame, off + 12));
        std::string yiaddr = ipv4_to_string(read_u32_at(frame, off + 16));
        std::string siaddr = ipv4_to_string(read_u32_at(frame, off + 20));
        std::string giaddr = ipv4_to_string(read_u32_at(frame, off + 24));

        std::array<uint8_t, 6> mac{};
        std::copy_n(frame.begin() + off + 28, 6, mac.begin());
        std::string mac_str = mac_to_string(mac);

        std::string op_str = (op == 1) ? "Boot Request (1)" :
                             (op == 2) ? "Boot Reply (2)" :
                                         ("Unknown (" + std::to_string(op) + ")");

        DissectNode root{
            "Bootstrap Protocol (" + std::string(op == 1 ? "BOOTREQUEST" : "BOOTREPLY") + ")",
            off, len, {}
        };
        root.children.push_back({"Message type: " + op_str, off, 1, {}});
        root.children.push_back({"Hardware type: Ethernet (0x" + std::to_string(htype) + ")", off + 1, 1, {}});
        root.children.push_back({"Hardware address length: " + std::to_string(hlen), off + 2, 1, {}});
        root.children.push_back({"Hops: " + std::to_string(hops), off + 3, 1, {}});
        root.children.push_back({"Transaction ID: " + hex32(xid), off + 4, 4, {}});
        root.children.push_back({"Seconds elapsed: " + std::to_string(secs), off + 8, 2, {}});
        root.children.push_back({"Bootp flags: " + hex16(flags) + (flags & 0x8000 ? " (Broadcast)" : " (Unicast)"), off + 10, 2, {}});
        root.children.push_back({"Client IP address: " + ciaddr, off + 12, 4, {}});
        root.children.push_back({"Your (client) IP address: " + yiaddr, off + 16, 4, {}});
        root.children.push_back({"Next server IP address: " + siaddr, off + 20, 4, {}});
        root.children.push_back({"Relay agent IP address: " + giaddr, off + 24, 4, {}});
        root.children.push_back({"Client MAC address: " + mac_str, off + 28, 16, {}});

        std::string sname = read_cstr(frame, off + 44, 64);
        std::string file  = read_cstr(frame, off + 108, 128);
        root.children.push_back({"Server host name: " + (sname.empty() ? "<not given>" : sname), off + 44, 64, {}});
        root.children.push_back({"Boot file name: " + (file.empty() ? "<not given>" : file), off + 108, 128, {}});

        std::string dns_summary;
        if (len >= 240) {
            size_t v_off = off + 236;
            uint32_t cookie = read_u32_at(frame, v_off);
            DissectNode vend{"Vendor Extensions", v_off, len - 236, {}};
            vend.children.push_back({"Magic cookie: " + hex32(cookie), v_off, 4, {}});

            if (cookie == BOOTP_MAGIC_COOKIE) {
                size_t p = v_off + 4;
                size_t end = off + len;
                while (p < end) {
                    uint8_t tag = frame[p];
                    if (tag == 0) { ++p; continue; }
                    if (tag == 255) {
                        vend.children.push_back({"Option: (255) End", p, 1, {}});
                        break;
                    }
                    if (p + 1 >= end) break;
                    uint8_t olen = frame[p + 1];
                    if (p + 2 + olen > end) break;

                    std::string val_desc = describe_bootp_option(tag, frame, p + 2, olen, dns_summary);
                    vend.children.push_back({val_desc, p, static_cast<size_t>(2 + olen), {}});
                    p += 2 + olen;
                }
            }
            root.children.push_back(std::move(vend));
        }

        pkt.layers.push_back(std::move(root));

        std::ostringstream info;
        if (op == 1) {
            info << "Boot Request from " << mac_str << " (xid=" << hex32(xid) << ")";
            if (hops > 0) info << " [hops=" << static_cast<int>(hops) << ", giaddr=" << giaddr << "]";
        } else {
            info << "Boot Reply -> yiaddr=" << yiaddr << " (xid=" << hex32(xid) << ")";
            if (!dns_summary.empty()) info << ", DNS=" << dns_summary;
        }
        pkt.info = info.str();
    }

    static std::string read_cstr(const std::vector<uint8_t>& f, size_t off, size_t max_len) {
        std::string out;
        for (size_t i = 0; i < max_len && (off + i) < f.size(); ++i) {
            if (f[off + i] == 0) break;
            out.push_back(static_cast<char>(f[off + i]));
        }
        return out;
    }

    static std::string describe_bootp_option(uint8_t tag,
                                             const std::vector<uint8_t>& f,
                                             size_t val_off,
                                             uint8_t olen,
                                             std::string& out_dns_ip) {
        auto read_ip = [&]() {
            return (olen >= 4) ? ipv4_to_string(read_u32_at(f, val_off)) : std::string("?");
        };
        auto read_str = [&]() {
            return std::string(reinterpret_cast<const char*>(f.data() + val_off), olen);
        };

        switch (static_cast<BootpOptionTag>(tag)) {
            case BootpOptionTag::SUBNET_MASK: return "Option: (1) Subnet Mask: " + read_ip();
            case BootpOptionTag::ROUTER:      return "Option: (3) Router: " + read_ip();
            case BootpOptionTag::DNS_SERVER:
                out_dns_ip = read_ip();
                return "Option: (6) Domain Name Server: " + out_dns_ip;
            case BootpOptionTag::HOSTNAME:    return "Option: (12) Host Name: " + read_str();
            case BootpOptionTag::DOMAIN_NAME: return "Option: (15) Domain Name: " + read_str();
            case BootpOptionTag::LEASE_TIME: {
                uint32_t sec = (olen >= 4) ? read_u32_at(f, val_off) : 0;
                return "Option: (51) IP Address Lease Time: " + std::to_string(sec) + "s";
            }
            default:
                return "Option: (" + std::to_string(tag) + ") Len=" + std::to_string(olen);
        }
    }

    // ------------------------------------------------------------------------
    // DNS Dissector
    // ------------------------------------------------------------------------
    static void dissect_dns(const std::vector<uint8_t>& frame,
                            size_t off,
                            size_t len,
                            DissectedPacket& pkt) {
        pkt.protocol = "DNS";
        if (len < 12) {
            pkt.info = "Malformed DNS (<12 bytes)";
            return;
        }

        uint16_t id      = read_u16_at(frame, off);
        uint16_t fl_raw  = read_u16_at(frame, off + 2);
        DnsFlags flags   = DnsFlags::unpack(fl_raw);
        uint16_t qdcount = read_u16_at(frame, off + 4);
        uint16_t ancount = read_u16_at(frame, off + 6);
        uint16_t nscount = read_u16_at(frame, off + 8);
        uint16_t arcount = read_u16_at(frame, off + 10);

        DissectNode root{
            std::string("Domain Name System (") + (flags.qr ? "response" : "query") + ")",
            off, len, {}
        };
        root.children.push_back({"Transaction ID: " + hex16(id), off, 2, {}});

        DissectNode fl_node{
            "Flags: " + hex16(fl_raw) + (flags.qr ? " Standard query response, " : " Standard query, ") +
                dns_rcode_name(flags.rcode),
            off + 2, 2, {}
        };
        fl_node.children.push_back({std::string("Response (QR): ") + (flags.qr ? "Message is a response (1)" : "Message is a query (0)"), off + 2, 1, {}});
        fl_node.children.push_back({std::string("Authoritative (AA): ") + (flags.aa ? "Server is authoritative (1)" : "Not authoritative (0)"), off + 2, 1, {}});
        fl_node.children.push_back({std::string("Recursion Desired (RD): ") + (flags.rd ? "1" : "0"), off + 2, 1, {}});
        fl_node.children.push_back({std::string("Recursion Available (RA): ") + (flags.ra ? "1" : "0"), off + 3, 1, {}});
        fl_node.children.push_back({std::string("Reply code (RCODE): ") + dns_rcode_name(flags.rcode), off + 3, 1, {}});
        root.children.push_back(std::move(fl_node));

        root.children.push_back({"Questions: " + std::to_string(qdcount), off + 4, 2, {}});
        root.children.push_back({"Answer RRs: " + std::to_string(ancount), off + 6, 2, {}});
        root.children.push_back({"Authority RRs: " + std::to_string(nscount), off + 8, 2, {}});
        root.children.push_back({"Additional RRs: " + std::to_string(arcount), off + 10, 2, {}});

        // Use PacketReader scoped to DNS payload [off, off + len)
        PacketReader r(frame.data() + off, len);
        r.skip(12);

        std::string first_qname;
        std::string first_qtype;
        std::string answer_summary;

        try {
            if (qdcount > 0) {
                size_t qsec_start = r.pos();
                DissectNode q_sec{"Queries", off + qsec_start, 0, {}};
                for (uint16_t i = 0; i < qdcount; ++i) {
                    size_t q_start   = r.pos();
                    std::string qname = decode_dns_name(r);
                    size_t name_end  = r.pos();
                    uint16_t qtype   = r.read_u16();
                    uint16_t qclass  = r.read_u16();
                    size_t q_end     = r.pos();

                    if (i == 0) {
                        first_qname = qname;
                        first_qtype = dns_type_name(qtype);
                    }
                    DissectNode qnode{
                        qname + ": type " + dns_type_name(qtype) + ", class IN",
                        off + q_start, q_end - q_start, {}
                    };
                    qnode.children.push_back({"Name: " + qname, off + q_start, name_end - q_start, {}});
                    qnode.children.push_back({"Type: " + std::string(dns_type_name(qtype)) + " (" + std::to_string(qtype) + ")", off + name_end, 2, {}});
                    qnode.children.push_back({"Class: IN (" + hex16(qclass) + ")", off + name_end + 2, 2, {}});
                    q_sec.children.push_back(std::move(qnode));
                }
                q_sec.byte_length = r.pos() - qsec_start;
                root.children.push_back(std::move(q_sec));
            }

            auto parse_rr_section = [&](const std::string& title, uint16_t count, bool collect_summary) {
                if (count == 0) return;
                size_t sec_start = r.pos();
                DissectNode sec{title, off + sec_start, 0, {}};
                for (uint16_t i = 0; i < count; ++i) {
                    size_t rr_start  = r.pos();
                    std::string name = decode_dns_name(r);
                    size_t name_end  = r.pos();
                    uint16_t rtype   = r.read_u16();
                    uint16_t rclass  = r.read_u16();
                    uint32_t ttl     = r.read_u32();
                    uint16_t rdlen   = r.read_u16();
                    size_t rdata_off = r.pos();
                    if (r.remaining() < rdlen) break;

                    std::string rdata_str;
                    if (rtype == static_cast<uint16_t>(DnsType::A) && rdlen == 4) {
                        rdata_str = ipv4_to_string(read_u32_at(frame, off + rdata_off));
                        r.skip(4);
                    } else if (rtype == static_cast<uint16_t>(DnsType::CNAME) ||
                               rtype == static_cast<uint16_t>(DnsType::PTR) ||
                               rtype == static_cast<uint16_t>(DnsType::NS)) {
                        rdata_str = decode_dns_name(r);
                        r.seek(rdata_off + rdlen);
                    } else {
                        rdata_str = std::to_string(rdlen) + " bytes";
                        r.skip(rdlen);
                    }
                    size_t rr_end = r.pos();

                    if (collect_summary) {
                        if (!answer_summary.empty()) answer_summary += ", ";
                        answer_summary += std::string(dns_type_name(rtype)) + " " + rdata_str;
                    }

                    DissectNode rnode{
                        name + ": type " + dns_type_name(rtype) + ", " + rdata_str + " (TTL " + std::to_string(ttl) + "s)",
                        off + rr_start, rr_end - rr_start, {}
                    };
                    rnode.children.push_back({"Name: " + name, off + rr_start, name_end - rr_start, {}});
                    rnode.children.push_back({"Type: " + std::string(dns_type_name(rtype)), off + name_end, 2, {}});
                    rnode.children.push_back({"Class: IN (" + hex16(rclass) + ")", off + name_end + 2, 2, {}});
                    rnode.children.push_back({"Time to live: " + std::to_string(ttl) + " seconds", off + name_end + 4, 4, {}});
                    rnode.children.push_back({"Data length: " + std::to_string(rdlen), off + name_end + 8, 2, {}});
                    rnode.children.push_back({"RDATA: " + rdata_str, off + rdata_off, rdlen, {}});
                    sec.children.push_back(std::move(rnode));
                }
                sec.byte_length = r.pos() - sec_start;
                root.children.push_back(std::move(sec));
            };

            parse_rr_section("Answers", ancount, true);
            parse_rr_section("Authoritative nameservers", nscount, false);
            parse_rr_section("Additional records", arcount, false);
        } catch (const std::exception&) {}

        pkt.layers.push_back(std::move(root));

        std::ostringstream info;
        info << (flags.qr ? "Standard query response " : "Standard query ")
             << hex16(id) << " " << first_qtype << " " << first_qname;
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
