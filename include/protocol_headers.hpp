#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace netproto {

// ============================================================================
// Constants & Port Configuration (Custom Lab Ports to avoid Admin Privileges)
// ============================================================================
constexpr uint16_t BOOTP_SERVER_PORT = 9067;  // Mirrors standard UDP 67
constexpr uint16_t BOOTP_CLIENT_PORT = 9068;  // Mirrors standard UDP 68
constexpr uint16_t BOOTP_RELAY_PORT  = 9069;  // Relay agent port
constexpr uint16_t DNS_SERVER_PORT   = 9053;  // Mirrors standard UDP 53
constexpr uint16_t DNS_UPSTREAM_PORT = 9153;  // Authoritative upstream DNS
constexpr uint16_t TAP_SNIFFER_PORT  = 9999;  // Mini-Wireshark listener port

constexpr uint32_t BOOTP_MAGIC_COOKIE = 0x63825363; // RFC 1048 Magic Cookie

// ============================================================================
// IPv4 & MAC Formatting Utilities
// ============================================================================
inline uint32_t ipv4_from_string(const std::string& ip) {
    uint32_t a = 0, b = 0, c = 0, d = 0;
    char dot1 = 0, dot2 = 0, dot3 = 0;
    std::istringstream iss(ip);
    if (!(iss >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d) ||
        dot1 != '.' || dot2 != '.' || dot3 != '.' ||
        a > 255 || b > 255 || c > 255 || d > 255) {
        throw std::invalid_argument("Invalid IPv4 address: " + ip);
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

inline std::string ipv4_to_string(uint32_t ip_host_order) {
    std::ostringstream oss;
    oss << ((ip_host_order >> 24) & 0xFF) << '.'
        << ((ip_host_order >> 16) & 0xFF) << '.'
        << ((ip_host_order >> 8) & 0xFF) << '.'
        << (ip_host_order & 0xFF);
    return oss.str();
}

inline std::string mac_to_string(const std::array<uint8_t, 6>& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(mac[i]);
    }
    return oss.str();
}

inline std::array<uint8_t, 6> mac_from_string(const std::string& str) {
    std::array<uint8_t, 6> mac{};
    std::istringstream iss(str);
    std::string byte_str;
    size_t idx = 0;
    while (std::getline(iss, byte_str, ':') && idx < 6) {
        mac[idx++] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    if (idx != 6) {
        throw std::invalid_argument("Invalid MAC address: " + str);
    }
    return mac;
}

// ============================================================================
// Bounds-Checked Big-Endian Wire Buffer Reader / Writer
// ============================================================================
class PacketWriter {
public:
    void write_u8(uint8_t v) { buf_.push_back(v); }

    void write_u16(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf_.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    void write_u32(uint32_t v) {
        buf_.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf_.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    void write_bytes(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    void write_fixed_string(const std::string& s, size_t fixed_len) {
        size_t copy_len = std::min(s.size(), fixed_len);
        for (size_t i = 0; i < copy_len; ++i) {
            buf_.push_back(static_cast<uint8_t>(s[i]));
        }
        for (size_t i = copy_len; i < fixed_len; ++i) {
            buf_.push_back(0);
        }
    }

    void write_zeros(size_t count) {
        buf_.insert(buf_.end(), count, 0);
    }

    void patch_u16(size_t offset, uint16_t v) {
        if (offset + 2 > buf_.size()) throw std::out_of_range("patch_u16 OOB");
        buf_[offset]     = static_cast<uint8_t>((v >> 8) & 0xFF);
        buf_[offset + 1] = static_cast<uint8_t>(v & 0xFF);
    }

    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t>& mutable_data() { return buf_; }
    size_t size() const { return buf_.size(); }

private:
    std::vector<uint8_t> buf_;
};

class PacketReader {
public:
    PacketReader(const uint8_t* data, size_t len) : data_(data), len_(len), pos_(0) {}
    explicit PacketReader(const std::vector<uint8_t>& buf)
        : data_(buf.data()), len_(buf.size()), pos_(0) {}

    size_t pos() const { return pos_; }
    size_t remaining() const { return len_ - pos_; }
    bool eof() const { return pos_ >= len_; }

    uint8_t read_u8() {
        ensure(1);
        return data_[pos_++];
    }

    uint16_t read_u16() {
        ensure(2);
        uint16_t v = (static_cast<uint16_t>(data_[pos_]) << 8) |
                     static_cast<uint16_t>(data_[pos_ + 1]);
        pos_ += 2;
        return v;
    }

    uint32_t read_u32() {
        ensure(4);
        uint32_t v = (static_cast<uint32_t>(data_[pos_]) << 24) |
                     (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                     static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return v;
    }

    void read_bytes(uint8_t* out, size_t count) {
        ensure(count);
        std::memcpy(out, data_ + pos_, count);
        pos_ += count;
    }

    std::string read_fixed_string(size_t fixed_len) {
        ensure(fixed_len);
        size_t actual_len = 0;
        while (actual_len < fixed_len && data_[pos_ + actual_len] != 0) {
            ++actual_len;
        }
        std::string s(reinterpret_cast<const char*>(data_ + pos_), actual_len);
        pos_ += fixed_len;
        return s;
    }

    void skip(size_t count) {
        ensure(count);
        pos_ += count;
    }

    void seek(size_t offset) {
        if (offset > len_) throw std::out_of_range("PacketReader seek OOB");
        pos_ = offset;
    }

    const uint8_t* raw() const { return data_; }
    size_t total_len() const { return len_; }

private:
    void ensure(size_t n) const {
        if (pos_ + n > len_) {
            throw std::runtime_error("Packet truncated while reading wire bytes");
        }
    }

    const uint8_t* data_;
    size_t len_;
    size_t pos_;
};

// ============================================================================
// PROTOCOL 1: Custom BOOTP (Bootstrap Protocol, RFC 951 + RFC 1048 Extensions)
// ============================================================================
enum class BootpOp : uint8_t {
    REQUEST = 1,
    REPLY   = 2
};

enum class BootpOptionTag : uint8_t {
    PAD         = 0,
    SUBNET_MASK = 1,
    ROUTER      = 3,
    DNS_SERVER  = 6,   // Critical link between BOOTP and DNS!
    HOSTNAME    = 12,
    DOMAIN_NAME = 15,
    LEASE_TIME  = 51,  // Custom extension: lease duration in seconds
    END         = 255
};

struct BootpOption {
    uint8_t tag = 0;
    std::vector<uint8_t> value;
};

struct BootpPacket {
    // Fixed 236-byte header + 64-byte vendor area = 300 bytes standard minimum
    uint8_t  op     = static_cast<uint8_t>(BootpOp::REQUEST);
    uint8_t  htype  = 1;   // Ethernet
    uint8_t  hlen   = 6;   // MAC length
    uint8_t  hops   = 0;   // Relay hop count
    uint32_t xid    = 0;   // Transaction ID
    uint16_t secs   = 0;   // Seconds elapsed
    uint16_t flags  = 0;   // Broadcast flag (0x8000)
    uint32_t ciaddr = 0;   // Client IP address
    uint32_t yiaddr = 0;   // 'Your' (assigned) IP address
    uint32_t siaddr = 0;   // Next server IP address
    uint32_t giaddr = 0;   // Relay agent IP address
    std::array<uint8_t, 16> chaddr{}; // Client hardware address (first 6 = MAC)
    std::string sname;     // Server host name (64 bytes on wire)
    std::string file;      // Boot file name (128 bytes on wire)

    uint32_t magic_cookie = BOOTP_MAGIC_COOKIE;
    std::vector<BootpOption> options;

    // Helper getters/setters for MAC & common options
    void set_mac(const std::array<uint8_t, 6>& mac) {
        chaddr.fill(0);
        std::copy(mac.begin(), mac.end(), chaddr.begin());
    }

    std::array<uint8_t, 6> get_mac() const {
        std::array<uint8_t, 6> mac{};
        std::copy_n(chaddr.begin(), 6, mac.begin());
        return mac;
    }

    void add_ip_option(BootpOptionTag tag, uint32_t ip_host_order) {
        BootpOption opt;
        opt.tag = static_cast<uint8_t>(tag);
        opt.value = {
            static_cast<uint8_t>((ip_host_order >> 24) & 0xFF),
            static_cast<uint8_t>((ip_host_order >> 16) & 0xFF),
            static_cast<uint8_t>((ip_host_order >> 8) & 0xFF),
            static_cast<uint8_t>(ip_host_order & 0xFF)
        };
        options.push_back(std::move(opt));
    }

    void add_u32_option(BootpOptionTag tag, uint32_t val) {
        add_ip_option(tag, val);
    }

    void add_string_option(BootpOptionTag tag, const std::string& text) {
        BootpOption opt;
        opt.tag = static_cast<uint8_t>(tag);
        opt.value.assign(text.begin(), text.end());
        options.push_back(std::move(opt));
    }

    bool get_ip_option(BootpOptionTag tag, uint32_t& out_ip) const {
        for (const auto& opt : options) {
            if (opt.tag == static_cast<uint8_t>(tag) && opt.value.size() >= 4) {
                out_ip = (static_cast<uint32_t>(opt.value[0]) << 24) |
                         (static_cast<uint32_t>(opt.value[1]) << 16) |
                         (static_cast<uint32_t>(opt.value[2]) << 8) |
                         static_cast<uint32_t>(opt.value[3]);
                return true;
            }
        }
        return false;
    }

    bool get_string_option(BootpOptionTag tag, std::string& out_str) const {
        for (const auto& opt : options) {
            if (opt.tag == static_cast<uint8_t>(tag)) {
                out_str.assign(opt.value.begin(), opt.value.end());
                return true;
            }
        }
        return false;
    }

    std::vector<uint8_t> serialize() const {
        PacketWriter w;
        w.write_u8(op);
        w.write_u8(htype);
        w.write_u8(hlen);
        w.write_u8(hops);
        w.write_u32(xid);
        w.write_u16(secs);
        w.write_u16(flags);
        w.write_u32(ciaddr);
        w.write_u32(yiaddr);
        w.write_u32(siaddr);
        w.write_u32(giaddr);
        w.write_bytes(chaddr.data(), chaddr.size());
        w.write_fixed_string(sname, 64);
        w.write_fixed_string(file, 128);

        // 64-byte Vendor Extensions area (minimum RFC 951 padding to 300 bytes)
        size_t vend_start = w.size();
        w.write_u32(magic_cookie);
        for (const auto& opt : options) {
            if (opt.tag == static_cast<uint8_t>(BootpOptionTag::PAD) ||
                opt.tag == static_cast<uint8_t>(BootpOptionTag::END)) {
                continue;
            }
            w.write_u8(opt.tag);
            w.write_u8(static_cast<uint8_t>(opt.value.size()));
            w.write_bytes(opt.value.data(), opt.value.size());
        }
        w.write_u8(static_cast<uint8_t>(BootpOptionTag::END));

        size_t vend_len = w.size() - vend_start;
        if (vend_len < 64) {
            w.write_zeros(64 - vend_len);
        }
        return w.data();
    }

    static BootpPacket deserialize(const uint8_t* data, size_t len) {
        if (len < 236) {
            throw std::runtime_error("BOOTP packet too short (<236 bytes)");
        }
        PacketReader r(data, len);
        BootpPacket pkt;
        pkt.op     = r.read_u8();
        pkt.htype  = r.read_u8();
        pkt.hlen   = r.read_u8();
        pkt.hops   = r.read_u8();
        pkt.xid    = r.read_u32();
        pkt.secs   = r.read_u16();
        pkt.flags  = r.read_u16();
        pkt.ciaddr = r.read_u32();
        pkt.yiaddr = r.read_u32();
        pkt.siaddr = r.read_u32();
        pkt.giaddr = r.read_u32();
        r.read_bytes(pkt.chaddr.data(), pkt.chaddr.size());
        pkt.sname  = r.read_fixed_string(64);
        pkt.file   = r.read_fixed_string(128);

        if (r.remaining() >= 4) {
            pkt.magic_cookie = r.read_u32();
            if (pkt.magic_cookie == BOOTP_MAGIC_COOKIE) {
                while (!r.eof()) {
                    uint8_t tag = r.read_u8();
                    if (tag == static_cast<uint8_t>(BootpOptionTag::PAD)) {
                        continue;
                    }
                    if (tag == static_cast<uint8_t>(BootpOptionTag::END)) {
                        break;
                    }
                    if (r.eof()) break;
                    uint8_t opt_len = r.read_u8();
                    if (r.remaining() < opt_len) break;
                    BootpOption opt;
                    opt.tag = tag;
                    opt.value.resize(opt_len);
                    r.read_bytes(opt.value.data(), opt_len);
                    pkt.options.push_back(std::move(opt));
                }
            }
        }
        return pkt;
    }
};

// ============================================================================
// PROTOCOL 2: Custom DNS (Domain Name System, RFC 1035)
// ============================================================================
enum class DnsType : uint16_t {
    A     = 1,
    NS    = 2,
    CNAME = 5,
    PTR   = 12,
    TXT   = 16
};

enum class DnsClass : uint16_t {
    INTERNET = 1
};

enum class DnsRCode : uint8_t {
    NO_ERR   = 0,
    FORMERR  = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP   = 4
};

struct DnsFlags {
    bool qr = false;       // 0 = Query, 1 = Response
    uint8_t opcode = 0;    // 0 = Standard query
    bool aa = false;       // Authoritative Answer
    bool tc = false;       // Truncated
    bool rd = true;        // Recursion Desired
    bool ra = false;       // Recursion Available
    uint8_t rcode = 0;     // Response Code (DnsRCode)

    uint16_t pack() const {
        uint16_t f = 0;
        if (qr) f |= (1 << 15);
        f |= static_cast<uint16_t>((opcode & 0x0F) << 11);
        if (aa) f |= (1 << 10);
        if (tc) f |= (1 << 9);
        if (rd) f |= (1 << 8);
        if (ra) f |= (1 << 7);
        f |= static_cast<uint16_t>(rcode & 0x0F);
        return f;
    }

    static DnsFlags unpack(uint16_t f) {
        DnsFlags flags;
        flags.qr     = ((f >> 15) & 1) != 0;
        flags.opcode = static_cast<uint8_t>((f >> 11) & 0x0F);
        flags.aa     = ((f >> 10) & 1) != 0;
        flags.tc     = ((f >> 9) & 1) != 0;
        flags.rd     = ((f >> 8) & 1) != 0;
        flags.ra     = ((f >> 7) & 1) != 0;
        flags.rcode  = static_cast<uint8_t>(f & 0x0F);
        return flags;
    }
};

struct DnsQuestion {
    std::string qname;
    uint16_t qtype  = static_cast<uint16_t>(DnsType::A);
    uint16_t qclass = static_cast<uint16_t>(DnsClass::INTERNET);
};

struct DnsResourceRecord {
    std::string name;
    uint16_t type   = static_cast<uint16_t>(DnsType::A);
    uint16_t rclass = static_cast<uint16_t>(DnsClass::INTERNET);
    uint32_t ttl    = 60;
    std::vector<uint8_t> rdata;

    // Convenience factories
    static DnsResourceRecord make_a(const std::string& domain, uint32_t ip_host, uint32_t ttl_sec = 60) {
        DnsResourceRecord rr;
        rr.name = domain;
        rr.type = static_cast<uint16_t>(DnsType::A);
        rr.ttl  = ttl_sec;
        rr.rdata = {
            static_cast<uint8_t>((ip_host >> 24) & 0xFF),
            static_cast<uint8_t>((ip_host >> 16) & 0xFF),
            static_cast<uint8_t>((ip_host >> 8) & 0xFF),
            static_cast<uint8_t>(ip_host & 0xFF)
        };
        return rr;
    }

    std::string rdata_as_ipv4() const {
        if (rdata.size() < 4) return "0.0.0.0";
        uint32_t ip = (static_cast<uint32_t>(rdata[0]) << 24) |
                      (static_cast<uint32_t>(rdata[1]) << 16) |
                      (static_cast<uint32_t>(rdata[2]) << 8) |
                      static_cast<uint32_t>(rdata[3]);
        return ipv4_to_string(ip);
    }
};

inline void encode_dns_name(PacketWriter& w, const std::string& name) {
    if (name.empty() || name == ".") {
        w.write_u8(0);
        return;
    }
    std::istringstream iss(name);
    std::string label;
    while (std::getline(iss, label, '.')) {
        if (label.empty()) continue;
        if (label.size() > 63) throw std::invalid_argument("DNS label > 63 chars");
        w.write_u8(static_cast<uint8_t>(label.size()));
        w.write_bytes(reinterpret_cast<const uint8_t*>(label.data()), label.size());
    }
    w.write_u8(0);
}

inline std::string decode_dns_name(PacketReader& r) {
    std::string result;
    size_t jumps = 0;
    size_t return_pos = 0;
    bool jumped = false;

    while (!r.eof()) {
        uint8_t len = r.read_u8();
        if (len == 0) {
            break;
        }
        // Check for RFC 1035 pointer compression (top 2 bits == 11)
        if ((len & 0xC0) == 0xC0) {
            uint8_t low = r.read_u8();
            uint16_t offset = static_cast<uint16_t>(((len & 0x3F) << 8) | low);
            if (!jumped) {
                return_pos = r.pos();
                jumped = true;
            }
            if (++jumps > 16) {
                throw std::runtime_error("DNS name compression pointer loop");
            }
            r.seek(offset);
            continue;
        }
        if (r.remaining() < len) {
            throw std::runtime_error("Truncated DNS label");
        }
        if (!result.empty()) result.push_back('.');
        std::vector<uint8_t> label_bytes(len);
        r.read_bytes(label_bytes.data(), len);
        result.append(reinterpret_cast<const char*>(label_bytes.data()), len);
    }

    if (jumped) {
        r.seek(return_pos);
    }
    return result;
}

struct DnsMessage {
    uint16_t id = 0;
    DnsFlags flags;
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;

    static DnsResourceRecord make_cname_or_ptr(const std::string& owner, DnsType t, const std::string& target, uint32_t ttl_sec = 60) {
        DnsResourceRecord rr;
        rr.name = owner;
        rr.type = static_cast<uint16_t>(t);
        rr.ttl  = ttl_sec;
        PacketWriter pw;
        encode_dns_name(pw, target);
        rr.rdata = pw.data();
        return rr;
    }

    std::vector<uint8_t> serialize() const {
        PacketWriter w;
        w.write_u16(id);
        w.write_u16(flags.pack());
        w.write_u16(static_cast<uint16_t>(questions.size()));
        w.write_u16(static_cast<uint16_t>(answers.size()));
        w.write_u16(static_cast<uint16_t>(authorities.size()));
        w.write_u16(static_cast<uint16_t>(additionals.size()));

        for (const auto& q : questions) {
            encode_dns_name(w, q.qname);
            w.write_u16(q.qtype);
            w.write_u16(q.qclass);
        }

        auto write_rr_list = [&](const std::vector<DnsResourceRecord>& rrs) {
            for (const auto& rr : rrs) {
                encode_dns_name(w, rr.name);
                w.write_u16(rr.type);
                w.write_u16(rr.rclass);
                w.write_u32(rr.ttl);
                w.write_u16(static_cast<uint16_t>(rr.rdata.size()));
                w.write_bytes(rr.rdata.data(), rr.rdata.size());
            }
        };

        write_rr_list(answers);
        write_rr_list(authorities);
        write_rr_list(additionals);
        return w.data();
    }

    static DnsMessage deserialize(const uint8_t* data, size_t len) {
        if (len < 12) {
            throw std::runtime_error("DNS packet too short (<12 bytes)");
        }
        PacketReader r(data, len);
        DnsMessage msg;
        msg.id    = r.read_u16();
        msg.flags = DnsFlags::unpack(r.read_u16());
        uint16_t qdcount = r.read_u16();
        uint16_t ancount = r.read_u16();
        uint16_t nscount = r.read_u16();
        uint16_t arcount = r.read_u16();

        for (uint16_t i = 0; i < qdcount; ++i) {
            DnsQuestion q;
            q.qname  = decode_dns_name(r);
            q.qtype  = r.read_u16();
            q.qclass = r.read_u16();
            msg.questions.push_back(std::move(q));
        }

        auto read_rr_list = [&](uint16_t count, std::vector<DnsResourceRecord>& out) {
            for (uint16_t i = 0; i < count; ++i) {
                DnsResourceRecord rr;
                rr.name   = decode_dns_name(r);
                rr.type   = r.read_u16();
                rr.rclass = r.read_u16();
                rr.ttl    = r.read_u32();
                uint16_t rdlen = r.read_u16();
                if (rr.type == static_cast<uint16_t>(DnsType::CNAME) ||
                    rr.type == static_cast<uint16_t>(DnsType::PTR) ||
                    rr.type == static_cast<uint16_t>(DnsType::NS)) {
                    size_t end_pos = r.pos() + rdlen;
                    if (end_pos > r.total_len()) {
                        throw std::runtime_error("Truncated DNS RDATA");
                    }
                    std::string target = decode_dns_name(r);
                    PacketWriter pw;
                    encode_dns_name(pw, target);
                    rr.rdata = pw.data();
                    r.seek(end_pos);
                } else {
                    rr.rdata.resize(rdlen);
                    r.read_bytes(rr.rdata.data(), rdlen);
                }
                out.push_back(std::move(rr));
            }
        };

        read_rr_list(ancount, msg.answers);
        read_rr_list(nscount, msg.authorities);
        read_rr_list(arcount, msg.additionals);
        return msg;
    }
};

// ============================================================================
// TAP / MINI-WIRESHARK CAPTURE ENVELOPE (Synthetic Ethernet + IPv4 + UDP)
// Allows our Mini-Wireshark to dissect L2/L3/L4/L7 AND export valid .pcap!
// ============================================================================
enum class AppProtoHint : uint8_t {
    UNKNOWN = 0,
    BOOTP   = 1,
    DNS     = 2
};

struct TapEnvelope {
    uint64_t timestamp_us = 0;
    uint32_t src_ip       = 0;
    uint32_t dst_ip       = 0;
    uint16_t src_port     = 0;
    uint16_t dst_port     = 0;
    uint8_t  proto_hint   = 0; // AppProtoHint
    std::array<uint8_t, 6> src_mac{0x00, 0x1A, 0x2B, 0x00, 0x00, 0x01};
    std::array<uint8_t, 6> dst_mac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    std::vector<uint8_t> payload;

    static constexpr uint32_t TAP_MAGIC = 0x54415031; // "TAP1"

    // Build a genuine Ethernet (14B) + IPv4 (20B) + UDP (8B) + Payload wire frame
    std::vector<uint8_t> to_wire_frame() const {
        PacketWriter w;
        // 1. Ethernet II Header (14 bytes)
        w.write_bytes(dst_mac.data(), 6);
        w.write_bytes(src_mac.data(), 6);
        w.write_u16(0x0800); // EtherType: IPv4

        // 2. IPv4 Header (20 bytes)
        uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
        uint16_t ip_total_len = static_cast<uint16_t>(20 + udp_len);
        size_t ip_start = w.size();
        w.write_u8(0x45);           // Version=4, IHL=5 (20 bytes)
        w.write_u8(0x00);           // DSCP/ECN
        w.write_u16(ip_total_len);
        w.write_u16(0x1234);        // Identification
        w.write_u16(0x4000);        // Flags: Don't Fragment
        w.write_u8(64);             // TTL
        w.write_u8(17);             // Protocol: UDP (17)
        size_t ip_csum_pos = w.size();
        w.write_u16(0);             // Checksum placeholder
        w.write_u32(src_ip);
        w.write_u32(dst_ip);

        // Compute IPv4 Header Checksum
        uint32_t sum = 0;
        const auto& raw = w.data();
        for (size_t i = ip_start; i < ip_start + 20; i += 2) {
            sum += (static_cast<uint16_t>(raw[i]) << 8) | raw[i + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        w.patch_u16(ip_csum_pos, static_cast<uint16_t>(~sum & 0xFFFF));

        // 3. UDP Header (8 bytes)
        w.write_u16(src_port);
        w.write_u16(dst_port);
        w.write_u16(udp_len);
        w.write_u16(0x0000); // Optional checksum (0 = disabled for IPv4)

        // 4. Application Payload (BOOTP / DNS)
        w.write_bytes(payload.data(), payload.size());
        return w.data();
    }

    std::vector<uint8_t> serialize_tap() const {
        PacketWriter w;
        w.write_u32(TAP_MAGIC);
        w.write_u32(static_cast<uint32_t>(timestamp_us >> 32));
        w.write_u32(static_cast<uint32_t>(timestamp_us & 0xFFFFFFFF));
        w.write_u32(src_ip);
        w.write_u32(dst_ip);
        w.write_u16(src_port);
        w.write_u16(dst_port);
        w.write_u8(proto_hint);
        w.write_bytes(src_mac.data(), 6);
        w.write_bytes(dst_mac.data(), 6);
        w.write_u16(static_cast<uint16_t>(payload.size()));
        w.write_bytes(payload.data(), payload.size());
        return w.data();
    }

    static TapEnvelope deserialize_tap(const uint8_t* data, size_t len) {
        PacketReader r(data, len);
        uint32_t magic = r.read_u32();
        if (magic != TAP_MAGIC) {
            throw std::runtime_error("Invalid TAP magic header");
        }
        TapEnvelope env;
        uint64_t hi = r.read_u32();
        uint64_t lo = r.read_u32();
        env.timestamp_us = (hi << 32) | lo;
        env.src_ip       = r.read_u32();
        env.dst_ip       = r.read_u32();
        env.src_port     = r.read_u16();
        env.dst_port     = r.read_u16();
        env.proto_hint   = r.read_u8();
        r.read_bytes(env.src_mac.data(), 6);
        r.read_bytes(env.dst_mac.data(), 6);
        uint16_t plen    = r.read_u16();
        env.payload.resize(plen);
        r.read_bytes(env.payload.data(), plen);
        return env;
    }
};

// ============================================================================
// Hex Dump Helper for Console Inspection
// ============================================================================
inline std::string format_hex_dump(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); i += 16) {
        oss << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < bytes.size()) {
                oss << std::setw(2) << static_cast<unsigned>(bytes[i + j]) << ' ';
            } else {
                oss << "   ";
            }
            if (j == 7) oss << ' ';
        }
        oss << " |";
        for (size_t j = 0; j < 16 && (i + j) < bytes.size(); ++j) {
            uint8_t c = bytes[i + j];
            oss << ((c >= 32 && c <= 126) ? static_cast<char>(c) : '.');
        }
        oss << "|\n";
    }
    return oss.str();
}

} // namespace netproto
