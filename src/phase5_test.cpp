// ============================================================================
// Phase 5 tests: Wireshark-fidelity features of the Mini-Wireshark engine
//   1. Display-filter language (parse errors, operators, legacy syntax)
//   2. Live capture: real epoch timestamps, consistent logical addresses,
//      IPv4 + UDP checksums, DNS/BOOTP request <-> response pairing
//   3. Retransmission detection (BOOTP client retrying an unanswered xid)
//   4. Expert info: corrupted checksum + malformed DNS
//   5. Real-world DHCP option decoding (option 53 -> "DHCP Discover")
//   6. Capture files: pcap (swapped + nanosecond) and pcapng import
// ============================================================================
#include "bootp_engine.hpp"
#include "capture_session.hpp"
#include "dns_engine.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <thread>

using namespace netproto;

static int g_failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::cerr << "  [FAIL] " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; \
            ++g_failures;                                                          \
        }                                                                          \
    } while (0)

static size_t count_matching(const std::vector<DissectedPacket>& pkts, const std::string& f) {
    DisplayFilter df = DisplayFilter::compile(f);
    size_t n = 0;
    for (const auto& p : pkts) n += df.matches(p) ? 1 : 0;
    return n;
}

static void test_filter_language() {
    std::cout << "[TEST 1] Display-filter parser...\n";
    CHECK(DisplayFilter::compile("").empty());
    CHECK(DisplayFilter::compile("dns").valid());
    CHECK(DisplayFilter::compile("dns && dns.flags.rcode == 3").valid());
    CHECK(DisplayFilter::compile("!(bootp || dns) and udp").valid());
    CHECK(DisplayFilter::compile("ip.addr == 192.168.10.0/24").valid());
    CHECK(DisplayFilter::compile("dns.qry.name contains \"lab\"").valid());
    CHECK(DisplayFilter::compile("dns.qry.name matches \"^dept\\\\.\"").valid());
    CHECK(DisplayFilter::compile("dhcp.option.domain_name_server == 192.168.10.2").valid()); // dhcp alias
    CHECK(DisplayFilter::compile("ip == 8.8.8.8").valid());     // legacy
    CHECK(DisplayFilter::compile("port == 9053").valid());      // legacy
    CHECK(DisplayFilter::compile("ipv4").valid());              // legacy

    auto bad1 = DisplayFilter::compile("dns.qry.nme == x");
    CHECK(!bad1.valid());
    CHECK(bad1.error().find("neither a field nor a protocol") != std::string::npos);
    CHECK(!DisplayFilter::compile("(dns").valid());
    CHECK(!DisplayFilter::compile("dns ==").valid());
    CHECK(!DisplayFilter::compile("dns &&").valid());
    std::cout << "  -> valid/invalid expressions classified, error text: \"" << bad1.error() << "\"\n";
}

int main() {
    try {
        SocketRuntime runtime;
        test_filter_language();

        // --------------------------------------------------------------------
        std::cout << "[TEST 2] Live capture: timestamps, addressing, checksums, pairing...\n";
        CaptureSession session(0, "127.0.0.1");
        session.start();
        uint16_t tap = session.bound_port();

        DnsServerConfig up_cfg;
        up_cfg.listen_port = 0; up_cfg.server_ip = "8.8.8.8"; up_cfg.tap_port = tap;
        DnsServer upstream(up_cfg);
        upstream.zones().add_a("dept.university.edu", "10.20.30.40", 60);
        std::thread up_t([&]() { upstream.run(false); });

        DnsServerConfig loc_cfg;
        loc_cfg.listen_port = 0; loc_cfg.server_ip = "192.168.10.2";
        loc_cfg.upstream_ip = "127.0.0.1"; loc_cfg.upstream_port = upstream.bound_port();
        loc_cfg.tap_port = tap;
        DnsServer local_dns(loc_cfg);
        local_dns.zones().add_a("nas01.lab.local", "192.168.10.50", 120);
        local_dns.zones().add_cname("fileserver.lab.local", "nas01.lab.local", 120);
        std::thread loc_t([&]() { local_dns.run(false); });

        BootpServerConfig bcfg;
        bcfg.listen_port = 0; bcfg.bind_ip = "127.0.0.1"; bcfg.tap_port = tap;
        BootpServer bootp_srv(bcfg);
        std::thread b_t([&]() { bootp_srv.run(false); });

        BootpClientOptions bo;
        bo.target_port = bootp_srv.bound_port(); bo.tap_port = tap; bo.verbose = false;
        BootpClient bcli(bo);
        auto net = bcli.acquire_configuration();
        CHECK(net.valid);

        DnsClientOptions dopts;
        dopts.logical_client_ip = ipv4_to_string(net.client_ip);
        dopts.logical_server_ip = ipv4_to_string(net.dns_ip);
        dopts.server_port = local_dns.bound_port(); dopts.tap_port = tap; dopts.verbose = false;
        DnsClient dcli(dopts);
        CHECK(dcli.resolve("fileserver.lab.local").success);
        CHECK(dcli.resolve("dept.university.edu").success);
        CHECK(!dcli.resolve("missing.lab.local").success);   // NXDOMAIN

        // A BOOTP client aimed at a dead port: same xid sent 3 times, no reply
        BootpClientOptions lost;
        lost.mac_str = "aa:bb:cc:00:00:99";
        {
            UdpSocket probe; probe.bind(0, "127.0.0.1");
            lost.target_port = probe.local_port();          // closed once probe goes out of scope
        }
        lost.base_timeout_ms = 40; lost.max_retries = 3; lost.tap_port = tap; lost.verbose = false;
        BootpClient lost_cli(lost);
        CHECK(!lost_cli.acquire_configuration().valid);

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bootp_srv.stop(); local_dns.stop(); upstream.stop();
        b_t.join(); loc_t.join(); up_t.join();
        session.stop();

        auto pkts = session.snapshot();
        std::cout << "  -> Captured " << pkts.size() << " frames\n";
        for (const auto& p : pkts) {
            std::cout << "     #" << p.number << " " << p.protocol << " " << p.src_ip << " -> "
                      << p.dst_ip << " | " << p.info << "\n";
        }
        CHECK(pkts.size() == 2 + 2 + 4 + 4 + 3);  // BOOTP pair, local A, forwarded A, forwarded NXDOMAIN, 3 lost

        // Real wall-clock timestamps (2024-01-01 = 1704067200 s)
        CHECK(pkts.front().timestamp_us / 1000000ULL > 1704067200ULL);
        // Frames are in timestamp order with non-negative relative times
        for (size_t i = 1; i < pkts.size(); ++i) {
            CHECK(pkts[i].timestamp_us >= pkts[i - 1].timestamp_us);
            CHECK(pkts[i].rel_time_sec >= 0.0);
        }
        // No loopback transport addresses leak into the logical lab view
        CHECK(count_matching(pkts, "ip.addr == 127.0.0.0/8") == 0);
        // Every synthesized frame carries correct IPv4 and UDP checksums
        CHECK(count_matching(pkts, "ip.checksum.status == good") == pkts.size());
        CHECK(count_matching(pkts, "udp.checksum.status == good") == pkts.size());

        // Request/response pairing
        size_t dns_answered = count_matching(pkts, "dns.flags.response == 0 && dns.response_in");
        size_t dns_paired   = count_matching(pkts, "dns.response_to && dns.time >= 0");
        CHECK(dns_answered == 5);   // 3 client queries + 2 forwarded upstream
        CHECK(dns_paired == 5);
        CHECK(count_matching(pkts, "bootp.response_in") == 1);
        CHECK(count_matching(pkts, "bootp.response_to") == 1);
        for (const auto& p : pkts) {
            if (p.request_in) {
                const auto& req = pkts[p.request_in - 1];
                CHECK(req.response_in == p.number);
                CHECK(req.txn_id == p.txn_id);
                CHECK(p.rtt_sec >= 0.0);
            }
        }
        std::cout << "  -> DNS paired=" << dns_paired << ", BOOTP paired=1, all checksums good, "
                  << "no 127.x addresses\n";

        // --------------------------------------------------------------------
        std::cout << "[TEST 3] Retransmission detection...\n";
        auto retx = session.snapshot("bootp.retransmission");
        CHECK(retx.size() == 2);
        for (const auto& p : retx) {
            CHECK(p.retransmission_of != 0);
            CHECK(p.info.rfind("[Retransmission]", 0) == 0);
            CHECK(p.expert_level == ExpertLevel::Note);
        }
        CHECK(count_matching(pkts, "dns.flags.rcode == 3") == 2);    // upstream + relayed
        CHECK(count_matching(pkts, "dns && dns.flags.rcode == 3 && dns.flags.authoritative == 1") == 1);
        CHECK(count_matching(pkts, "dns.qry.name contains \"university\"") == 4);
        CHECK(count_matching(pkts, "dns.cname == nas01.lab.local") == 1);
        CHECK(count_matching(pkts, "dns.a == 10.20.30.40") == 2);
        CHECK(count_matching(pkts, "frame.len > 300") == count_matching(pkts, "bootp"));
        CHECK(count_matching(pkts, "dns.qry.name matches \"^DEPT\\\\.\"") == 4);  // case-insensitive regex
        CHECK(count_matching(pkts, "ip == 8.8.8.8") == 4);                       // legacy syntax
        CHECK(count_matching(pkts, "nxdomain") == 2);                            // legacy text search
        CHECK(count_matching(pkts, "ip.addr != 8.8.8.8 && dns") == 6);
        std::cout << "  -> 2 retransmissions of an unanswered xid flagged; operators verified\n";

        auto stats = session.statistics();
        CHECK(stats.frames == pkts.size());
        CHECK(stats.retransmissions == 2);
        CHECK(stats.dns_queries == 5 && stats.dns_responses == 5);
        CHECK(stats.dns_rcodes["NXDOMAIN"] == 2);
        CHECK(stats.leases.size() == 1);

        // --------------------------------------------------------------------
        std::cout << "[TEST 4] Expert info: bad checksums + malformed DNS...\n";
        const DissectedPacket* any_dns = nullptr;
        for (const auto& p : pkts) if (p.protocol == "DNS") { any_dns = &p; break; }
        CHECK(any_dns != nullptr);
        if (any_dns) {
            auto frame = any_dns->raw_frame;
            frame[14 + 8] ^= 0x01;                     // flip a TTL bit -> IPv4 checksum wrong
            auto bad = PacketDissector::dissect_wire_frame(1, 0, 0, frame);
            CHECK(bad.field_value("ip.checksum.status") == "bad");
            CHECK(bad.expert_level == ExpertLevel::Error);

            frame = any_dns->raw_frame;
            frame.back() ^= 0xFF;                      // corrupt payload -> UDP checksum wrong
            bad = PacketDissector::dissect_wire_frame(1, 0, 0, frame);
            CHECK(bad.field_value("ip.checksum.status") == "good");
            CHECK(bad.field_value("udp.checksum.status") == "bad");
            CHECK(DisplayFilter::compile("udp.checksum.status == bad").matches(bad));

            // Checksum offload: field holds only the folded pseudo-header sum
            frame = any_dns->raw_frame;
            uint32_t sip = (frame[26] << 24) | (frame[27] << 16) | (frame[28] << 8) | frame[29];
            uint32_t dip = (frame[30] << 24) | (frame[31] << 16) | (frame[32] << 8) | frame[33];
            uint32_t ulen = (frame[38] << 8) | frame[39];
            uint32_t ps = (sip >> 16) + (sip & 0xFFFF) + (dip >> 16) + (dip & 0xFFFF) + 17 + ulen;
            while (ps >> 16) ps = (ps & 0xFFFF) + (ps >> 16);
            frame[40] = static_cast<uint8_t>(ps >> 8);
            frame[41] = static_cast<uint8_t>(ps);
            auto off = PacketDissector::dissect_wire_frame(1, 0, 0, frame);
            CHECK(off.field_value("udp.checksum.status") == "good");
            CHECK(off.expert_level == ExpertLevel::Note);

            // Truncated DNS: claim 1 answer but provide none
            DnsMessage m; m.id = 0x1234; m.flags.qr = true;
            m.questions.push_back({"x.lab.local", 1, 1});
            auto dns_bytes = m.serialize();
            dns_bytes[7] = 1;                          // ANCOUNT = 1, no answer bytes follow
            TapEnvelope env;
            env.src_ip = ipv4_from_string("192.168.10.2"); env.dst_ip = ipv4_from_string("192.168.10.100");
            env.src_port = 53; env.dst_port = 40000; env.payload = dns_bytes;
            auto mal = PacketDissector::dissect_wire_frame(1, 0, 0, env.to_wire_frame());
            CHECK(mal.has_field("_ws.malformed"));
            CHECK(DisplayFilter::compile("_ws.malformed").matches(mal));
            std::cout << "  -> bad IP/UDP checksum and malformed DNS raise Expert Info errors\n";
        }

        // --------------------------------------------------------------------
        std::cout << "[TEST 5] Real DHCP options (as found in real Wireshark captures)...\n";
        {
            BootpPacket d;
            d.xid = 0xCAFEBABE;
            d.set_mac(mac_from_string("00:11:22:33:44:55"));
            d.options.push_back({53, {1}});                          // DHCP Discover
            d.options.push_back({55, {1, 3, 6, 15}});                // Parameter Request List
            d.options.push_back({61, {1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
            TapEnvelope env;
            env.src_ip = 0; env.dst_ip = 0xFFFFFFFF; env.src_port = 68; env.dst_port = 67;
            env.payload = d.serialize();
            auto pk = PacketDissector::dissect_wire_frame(1, 0, 0, env.to_wire_frame());
            CHECK(pk.protocol == "DHCP");
            CHECK(pk.info.find("DHCP Discover") != std::string::npos);
            CHECK(DisplayFilter::compile("dhcp.option.dhcp == 1").matches(pk));
            CHECK(DisplayFilter::compile("bootp").matches(pk));
            std::cout << "  -> " << pk.info << "\n";
        }

        // --------------------------------------------------------------------
        std::cout << "[TEST 6] Capture files: pcap (LE/BE, usec/nsec) + pcapng...\n";
        const std::string base = "group_project/build/phase5";
        CHECK(session.export_pcap(base + ".pcap"));
        {
            CaptureSession re;
            std::string err;
            CHECK(re.import_pcap(base + ".pcap", &err));
            auto rp = re.snapshot();
            CHECK(rp.size() == pkts.size());
            for (size_t i = 0; i < rp.size() && i < pkts.size(); ++i) {
                CHECK(rp[i].raw_frame == pkts[i].raw_frame);
                CHECK(rp[i].timestamp_us == pkts[i].timestamp_us);
                CHECK(rp[i].info == pkts[i].info);
                CHECK(rp[i].response_in == pkts[i].response_in);
            }
        }

        auto be32 = [](std::vector<uint8_t>& b, uint32_t v) {
            for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
        };
        auto le32 = [](std::vector<uint8_t>& b, uint32_t v) {
            for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
        };
        auto le16 = [](std::vector<uint8_t>& b, uint16_t v) {
            b.push_back(static_cast<uint8_t>(v)); b.push_back(static_cast<uint8_t>(v >> 8));
        };
        auto write_file = [](const std::string& path, const std::vector<uint8_t>& b) {
            std::ofstream f(path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
        };

        // Big-endian, nanosecond-resolution classic pcap
        {
            std::vector<uint8_t> b;
            be32(b, 0xA1B23C4D); b.push_back(0); b.push_back(2); b.push_back(0); b.push_back(4);
            be32(b, 0); be32(b, 0); be32(b, 65535); be32(b, 1);
            for (const auto& p : pkts) {
                be32(b, static_cast<uint32_t>(p.timestamp_us / 1000000));
                be32(b, static_cast<uint32_t>((p.timestamp_us % 1000000) * 1000));
                be32(b, static_cast<uint32_t>(p.raw_frame.size()));
                be32(b, static_cast<uint32_t>(p.raw_frame.size()));
                b.insert(b.end(), p.raw_frame.begin(), p.raw_frame.end());
            }
            write_file(base + "_be_nsec.pcap", b);
            CaptureSession re;
            CHECK(re.import_pcap(base + "_be_nsec.pcap"));
            auto rp = re.snapshot();
            CHECK(rp.size() == pkts.size());
            if (!rp.empty()) CHECK(rp.back().timestamp_us == pkts.back().timestamp_us);
        }

        // pcapng: SHB + IDB (if_tsresol = 9 -> nanoseconds) + EPBs
        {
            std::vector<uint8_t> b;
            le32(b, 0x0A0D0D0A); le32(b, 28); le32(b, 0x1A2B3C4D); le16(b, 1); le16(b, 0);
            le32(b, 0xFFFFFFFF); le32(b, 0xFFFFFFFF); le32(b, 28);                     // SHB
            le32(b, 1); le32(b, 32); le16(b, 1); le16(b, 0); le32(b, 65535);
            le16(b, 9); le16(b, 1); b.push_back(9); b.push_back(0); b.push_back(0); b.push_back(0);
            le16(b, 0); le16(b, 0); le32(b, 32);                                          // IDB
            for (const auto& p : pkts) {
                uint32_t cap = static_cast<uint32_t>(p.raw_frame.size());
                uint32_t padded = (cap + 3) & ~3u;
                uint32_t blen = 32 + padded;
                uint64_t ns = p.timestamp_us * 1000ULL;
                le32(b, 6); le32(b, blen); le32(b, 0);
                le32(b, static_cast<uint32_t>(ns >> 32)); le32(b, static_cast<uint32_t>(ns));
                le32(b, cap); le32(b, cap);
                b.insert(b.end(), p.raw_frame.begin(), p.raw_frame.end());
                b.insert(b.end(), padded - cap, 0);
                le32(b, blen);                                                            // EPB
            }
            write_file(base + ".pcapng", b);
            CaptureSession re;
            std::string err;
            CHECK(re.import_pcap(base + ".pcapng", &err));
            auto rp = re.snapshot();
            CHECK(rp.size() == pkts.size());
            for (size_t i = 0; i < rp.size() && i < pkts.size(); ++i) {
                CHECK(rp[i].raw_frame == pkts[i].raw_frame);
                CHECK(rp[i].timestamp_us == pkts[i].timestamp_us);
            }
            CHECK(re.snapshot("dns.response_in").size() == 5);
        }
        {
            CaptureSession re;
            std::string err;
            write_file(base + "_junk.pcap", std::vector<uint8_t>(64, 0x42));
            CHECK(!re.import_pcap(base + "_junk.pcap", &err));
            CHECK(err.find("unknown file format") != std::string::npos);
        }
        std::cout << "  -> pcap LE/usec, pcap BE/nsec and pcapng (ns resolution) all re-import identically\n";

        if (g_failures) {
            std::cerr << "=== PHASE 5: " << g_failures << " CHECK(S) FAILED ===\n";
            return 1;
        }
        std::cout << "=== ALL PHASE 5 TESTS PASSED ===\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Exception: " << ex.what() << "\n";
        return 1;
    }
}
