#pragma once
// ============================================================================
// Capture file I/O
//   save: classic libpcap (.pcap), microsecond timestamps, LINKTYPE_ETHERNET
//   load: classic .pcap (either byte order, micro- or nanosecond timestamps)
//         and pcapng (Wireshark's default "Save As" format since v1.8)
// ============================================================================

#include "dissector.hpp"

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace netproto {

class PcapStorage {
public:
    static constexpr uint32_t PCAP_MAGIC_USEC = 0xA1B2C3D4;
    static constexpr uint32_t PCAP_MAGIC_NSEC = 0xA1B23C4D;
    static constexpr uint32_t PCAPNG_SHB      = 0x0A0D0D0A;
    static constexpr uint32_t PCAPNG_BOM      = 0x1A2B3C4D;
    static constexpr uint32_t LINKTYPE_ETHERNET = 1;
    static constexpr uint32_t SNAPLEN = 65535;

    // Raw frame + its timestamp, before dissection.
    struct RawRecord {
        uint64_t ts_us = 0;
        std::vector<uint8_t> frame;
    };

    static bool save_pcap(const std::string& path,
                          const std::vector<DissectedPacket>& packets) {
        std::ofstream fout(path, std::ios::binary);
        if (!fout.is_open()) return false;

        // Global header (24 bytes). Written explicitly little-endian so the
        // file is identical on any host; readers detect order from the magic.
        std::vector<uint8_t> gh;
        put32(gh, PCAP_MAGIC_USEC);
        put16(gh, 2);              // version major
        put16(gh, 4);              // version minor
        put32(gh, 0);              // thiszone (GMT offset)
        put32(gh, 0);              // sigfigs
        put32(gh, SNAPLEN);        // snaplen
        put32(gh, LINKTYPE_ETHERNET);
        fout.write(reinterpret_cast<const char*>(gh.data()), static_cast<std::streamsize>(gh.size()));

        for (const auto& pkt : packets) {
            std::vector<uint8_t> ph;  // per-record header (16 bytes)
            put32(ph, static_cast<uint32_t>(pkt.timestamp_us / 1000000ULL));
            put32(ph, static_cast<uint32_t>(pkt.timestamp_us % 1000000ULL));
            put32(ph, static_cast<uint32_t>(pkt.raw_frame.size()));  // incl_len
            put32(ph, static_cast<uint32_t>(pkt.raw_frame.size()));  // orig_len
            fout.write(reinterpret_cast<const char*>(ph.data()), static_cast<std::streamsize>(ph.size()));
            if (!pkt.raw_frame.empty()) {
                fout.write(reinterpret_cast<const char*>(pkt.raw_frame.data()),
                           static_cast<std::streamsize>(pkt.raw_frame.size()));
            }
        }
        return fout.good();
    }

    // Reads .pcap or .pcapng into raw records. On failure returns false and
    // sets `error` to a human-readable reason.
    static bool read_records(const std::string& path, std::vector<RawRecord>& out, std::string& error) {
        std::ifstream fin(path, std::ios::binary);
        if (!fin.is_open()) { error = "cannot open file"; return false; }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        out.clear();
        if (data.size() < 24) { error = "file too short to be a capture"; return false; }

        uint32_t m_le = le32(data, 0);
        if (m_le == PCAPNG_SHB) return read_pcapng(data, out, error);

        bool swapped = false, nsec = false;
        if (m_le == PCAP_MAGIC_USEC) {}
        else if (m_le == PCAP_MAGIC_NSEC) nsec = true;
        else if (be32(data, 0) == PCAP_MAGIC_USEC) swapped = true;
        else if (be32(data, 0) == PCAP_MAGIC_NSEC) { swapped = true; nsec = true; }
        else { error = "unknown file format (not pcap/pcapng)"; return false; }

        auto rd32 = [&](size_t o) { return swapped ? be32(data, o) : le32(data, o); };
        uint32_t linktype = rd32(20) & 0x0FFFFFFF;
        if (linktype != LINKTYPE_ETHERNET) {
            error = "unsupported link type " + std::to_string(linktype) + " (only Ethernet)";
            return false;
        }
        size_t p = 24;
        while (p + 16 <= data.size()) {
            uint32_t ts_sec = rd32(p), ts_frac = rd32(p + 4), incl = rd32(p + 8);
            p += 16;
            if (incl > 262144 || p + incl > data.size()) break;  // truncated last record
            RawRecord rec;
            rec.ts_us = static_cast<uint64_t>(ts_sec) * 1000000ULL + (nsec ? ts_frac / 1000 : ts_frac);
            rec.frame.assign(data.begin() + static_cast<std::ptrdiff_t>(p),
                             data.begin() + static_cast<std::ptrdiff_t>(p + incl));
            out.push_back(std::move(rec));
            p += incl;
        }
        return true;
    }

    // Backwards-compatible helper: read + dissect (no transaction tracking).
    static bool load_pcap(const std::string& path, std::vector<DissectedPacket>& out_packets) {
        std::vector<RawRecord> recs;
        std::string err;
        if (!read_records(path, recs, err)) return false;
        out_packets.clear();
        uint64_t first = recs.empty() ? 0 : recs.front().ts_us;
        uint32_t idx = 1;
        for (const auto& r : recs) {
            double rel = (static_cast<double>(r.ts_us) - static_cast<double>(first)) / 1e6;
            out_packets.push_back(PacketDissector::dissect_wire_frame(idx++, r.ts_us, rel, r.frame));
        }
        return true;
    }

private:
    // pcapng: a sequence of blocks [type][total_len][body...][total_len].
    // We need SHB (byte order), IDB (link type + timestamp resolution),
    // EPB (enhanced packet) and SPB (simple packet). Others are skipped.
    static bool read_pcapng(const std::vector<uint8_t>& d, std::vector<RawRecord>& out, std::string& error) {
        struct Iface { uint32_t linktype = 0; uint64_t ticks_per_sec = 1000000; };
        std::vector<Iface> ifaces;
        bool swapped = false;
        size_t p = 0;
        auto rd32 = [&](size_t o) { return swapped ? be32(d, o) : le32(d, o); };
        auto rd16 = [&](size_t o) {
            return swapped ? static_cast<uint16_t>((d[o] << 8) | d[o + 1])
                           : static_cast<uint16_t>(d[o] | (d[o + 1] << 8));
        };

        while (p + 12 <= d.size()) {
            uint32_t type = le32(d, p);  // SHB type is palindromic, safe either way
            if (type == PCAPNG_SHB) {
                if (p + 12 > d.size()) break;
                uint32_t bom = le32(d, p + 8);
                if (bom == PCAPNG_BOM) swapped = false;
                else if (be32(d, p + 8) == PCAPNG_BOM) swapped = true;
                else { error = "bad pcapng byte-order magic"; return false; }
                ifaces.clear();  // interface IDs are per section
            }
            uint32_t blen = rd32(p + 4);
            if (blen < 12 || p + blen > d.size()) break;
            type = rd32(p);

            if (type == 1 && blen >= 20) {                 // Interface Description Block
                Iface ifc;
                ifc.linktype = rd16(p + 8);
                // Options start at p+16: look for if_tsresol (code 9)
                size_t o = p + 16, end = p + blen - 4;
                while (o + 4 <= end) {
                    uint16_t code = rd16(o), len = rd16(o + 2);
                    if (code == 0) break;
                    if (code == 9 && len >= 1) {
                        uint8_t res = d[o + 4];
                        uint64_t t = 1;
                        if (res & 0x80) { for (int i = 0; i < (res & 0x7F) && i < 63; ++i) t *= 2; }
                        else            { for (int i = 0; i < res && i < 19; ++i) t *= 10; }
                        ifc.ticks_per_sec = t;
                    }
                    o += 4 + ((len + 3u) & ~3u);
                }
                ifaces.push_back(ifc);
            } else if (type == 6 && blen >= 32) {          // Enhanced Packet Block
                uint32_t if_id = rd32(p + 8);
                uint64_t ts = (static_cast<uint64_t>(rd32(p + 12)) << 32) | rd32(p + 16);
                uint32_t cap = rd32(p + 20);
                if (if_id < ifaces.size() && ifaces[if_id].linktype == LINKTYPE_ETHERNET &&
                    p + 28 + cap <= d.size()) {
                    RawRecord rec;
                    uint64_t tps = ifaces[if_id].ticks_per_sec;
                    rec.ts_us = (ts / tps) * 1000000ULL + ((ts % tps) * 1000000ULL) / tps;
                    rec.frame.assign(d.begin() + static_cast<std::ptrdiff_t>(p + 28),
                                     d.begin() + static_cast<std::ptrdiff_t>(p + 28 + cap));
                    out.push_back(std::move(rec));
                }
            } else if (type == 3 && blen >= 16) {          // Simple Packet Block (no timestamp)
                uint32_t orig = rd32(p + 8);
                uint32_t cap = std::min<uint32_t>(orig, blen - 16);
                if (!ifaces.empty() && ifaces[0].linktype == LINKTYPE_ETHERNET) {
                    RawRecord rec;
                    rec.frame.assign(d.begin() + static_cast<std::ptrdiff_t>(p + 12),
                                     d.begin() + static_cast<std::ptrdiff_t>(p + 12 + cap));
                    out.push_back(std::move(rec));
                }
            }
            p += blen;
        }
        if (out.empty() && !ifaces.empty() && ifaces[0].linktype != LINKTYPE_ETHERNET) {
            error = "unsupported link type " + std::to_string(ifaces[0].linktype) + " (only Ethernet)";
            return false;
        }
        return true;
    }

    static void put16(std::vector<uint8_t>& b, uint16_t v) {
        b.push_back(static_cast<uint8_t>(v & 0xFF));
        b.push_back(static_cast<uint8_t>(v >> 8));
    }
    static void put32(std::vector<uint8_t>& b, uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
    static uint32_t le32(const std::vector<uint8_t>& b, size_t o) {
        return static_cast<uint32_t>(b[o]) | (static_cast<uint32_t>(b[o + 1]) << 8) |
               (static_cast<uint32_t>(b[o + 2]) << 16) | (static_cast<uint32_t>(b[o + 3]) << 24);
    }
    static uint32_t be32(const std::vector<uint8_t>& b, size_t o) {
        return (static_cast<uint32_t>(b[o]) << 24) | (static_cast<uint32_t>(b[o + 1]) << 16) |
               (static_cast<uint32_t>(b[o + 2]) << 8) | static_cast<uint32_t>(b[o + 3]);
    }
};

} // namespace netproto
