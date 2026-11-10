#pragma once

#include "dissector.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace netproto {

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number  = 0xA1B2C3D4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 65535;
    uint32_t network       = 1; // LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
    uint32_t ts_sec   = 0;
    uint32_t ts_usec  = 0;
    uint32_t incl_len = 0;
    uint32_t orig_len = 0;
};
#pragma pack(pop)

class PcapStorage {
public:
    static bool save_pcap(const std::string& path,
                          const std::vector<DissectedPacket>& packets) {
        std::ofstream fout(path, std::ios::binary);
        if (!fout.is_open()) return false;

        PcapGlobalHeader gh;
        fout.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

        for (const auto& pkt : packets) {
            PcapPacketHeader ph;
            ph.ts_sec   = static_cast<uint32_t>(pkt.timestamp_us / 1000000ULL);
            ph.ts_usec  = static_cast<uint32_t>(pkt.timestamp_us % 1000000ULL);
            ph.incl_len = static_cast<uint32_t>(pkt.raw_frame.size());
            ph.orig_len = ph.incl_len;
            fout.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
            if (!pkt.raw_frame.empty()) {
                fout.write(reinterpret_cast<const char*>(pkt.raw_frame.data()),
                           static_cast<std::streamsize>(pkt.raw_frame.size()));
            }
        }
        return fout.good();
    }

    static bool load_pcap(const std::string& path,
                          std::vector<DissectedPacket>& out_packets) {
        std::ifstream fin(path, std::ios::binary);
        if (!fin.is_open()) return false;

        PcapGlobalHeader gh{};
        fin.read(reinterpret_cast<char*>(&gh), sizeof(gh));
        if (!fin || gh.magic_number != 0xA1B2C3D4) {
            return false;
        }

        out_packets.clear();
        uint64_t first_ts_us = 0;
        uint32_t idx = 1;

        while (fin.peek() != EOF) {
            PcapPacketHeader ph{};
            fin.read(reinterpret_cast<char*>(&ph), sizeof(ph));
            if (!fin) break;
            if (ph.incl_len > 65535) return false;

            std::vector<uint8_t> frame(ph.incl_len);
            if (ph.incl_len > 0) {
                fin.read(reinterpret_cast<char*>(frame.data()),
                         static_cast<std::streamsize>(ph.incl_len));
                if (!fin) break;
            }

            uint64_t ts_us = static_cast<uint64_t>(ph.ts_sec) * 1000000ULL + ph.ts_usec;
            if (idx == 1) first_ts_us = ts_us;
            double rel_sec = static_cast<double>(ts_us - first_ts_us) / 1000000.0;

            out_packets.push_back(PacketDissector::dissect_wire_frame(
                idx++, ts_us, rel_sec, frame));
        }
        return true;
    }
};

} // namespace netproto

