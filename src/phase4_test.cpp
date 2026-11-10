#include "bootp_engine.hpp"
#include "capture_session.hpp"
#include "dns_engine.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

using namespace netproto;

static void verify_node_bounds(const DissectNode& node, size_t frame_len) {
    assert(node.byte_offset <= frame_len);
    assert(node.byte_offset + node.byte_length <= frame_len);
    for (const auto& child : node.children) {
        verify_node_bounds(child, frame_len);
    }
}

int main() {
    try {
        SocketRuntime runtime;
        std::cout << "[PHASE 4 TEST] Starting Live CaptureSession + BOOTP + DNS + PCAP Roundtrip...\n";

        // 1. Start CaptureSession on ephemeral Tap port
        CaptureSession session(0, "127.0.0.1");
        session.start();
        uint16_t tap_port = session.bound_port();

        // 2. Start Upstream & Local DNS Servers with Tap enabled
        DnsServerConfig up_cfg;
        up_cfg.listen_port = 0;
        up_cfg.server_ip   = "8.8.8.8";
        up_cfg.tap_port    = tap_port;
        DnsServer upstream(up_cfg);
        assert(upstream.zones().load_from_file("group_project/config/upstream_zones.conf"));
        std::thread up_thread([&]() { upstream.run(false); });

        DnsServerConfig loc_cfg;
        loc_cfg.listen_port   = 0;
        loc_cfg.server_ip     = "192.168.10.2";
        loc_cfg.upstream_ip   = "127.0.0.1";
        loc_cfg.upstream_port = upstream.bound_port();
        loc_cfg.tap_port      = tap_port;
        DnsServer local_dns(loc_cfg);
        assert(local_dns.zones().load_from_file("group_project/config/local_zones.conf"));
        std::thread loc_thread([&]() { local_dns.run(false); });

        // 3. Start BOOTP Server with Tap enabled
        BootpServerConfig bcfg;
        bcfg.listen_port = 0;
        bcfg.bind_ip     = "127.0.0.1";
        bcfg.dns_ip      = "192.168.10.2";
        bcfg.tap_port    = tap_port;
        BootpServer bootp_srv(bcfg);
        std::thread bootp_thread([&]() { bootp_srv.run(false); });

        // 4. Execute Bootstrapped Client Flow (BOOTP -> Local DNS -> Upstream -> Cache)
        BootpClientOptions bopts;
        bopts.mac_str     = "00:1a:2b:3c:4d:5e";
        bopts.target_port = bootp_srv.bound_port();
        bopts.tap_port    = tap_port;
        bopts.verbose     = false;
        BootpClient bcli(bopts);
        auto net_cfg = bcli.acquire_configuration();
        assert(net_cfg.valid);

        DnsClientOptions dopts;
        dopts.logical_client_ip = ipv4_to_string(net_cfg.client_ip);
        dopts.logical_server_ip = ipv4_to_string(net_cfg.dns_ip);
        dopts.server_ip         = "127.0.0.1";
        dopts.server_port       = local_dns.bound_port();
        dopts.tap_port          = tap_port;
        dopts.verbose           = false;
        DnsClient dcli(dopts);

        auto r1 = dcli.resolve("fileserver.lab.local", DnsType::A);
        assert(r1.success && r1.resolved_ip == "192.168.10.50");

        auto r2 = dcli.resolve("dept.university.edu", DnsType::A);
        assert(r2.success && r2.resolved_ip == "10.20.30.40");

        // Allow tap UDP packets to drain into CaptureSession
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        bootp_srv.stop();
        local_dns.stop();
        upstream.stop();
        bootp_thread.join();
        loc_thread.join();
        up_thread.join();
        session.stop();

        // Expected packets (emit-on-send):
        // 1: BOOTREQUEST (Client -> Server)
        // 2: BOOTREPLY   (Server -> Client)
        // 3: DNS Query   (Client -> Local DNS: fileserver.lab.local)
        // 4: DNS Resp    (Local DNS -> Client: fileserver.lab.local)
        // 5: DNS Query   (Client -> Local DNS: dept.university.edu)
        // 6: DNS Query   (Local DNS -> Upstream: dept.university.edu)
        // 7: DNS Resp    (Upstream -> Local DNS: dept.university.edu)
        // 8: DNS Resp    (Local DNS -> Client: dept.university.edu)
        auto all_pkts = session.snapshot();
        std::cout << "  -> Captured " << all_pkts.size() << " packets:\n";
        for (const auto& p : all_pkts) {
            std::cout << "     #" << p.number << " [" << p.protocol << "] "
                      << p.src_ip << ":" << p.src_port << " -> "
                      << p.dst_ip << ":" << p.dst_port << " | " << p.info << "\n";
            assert(p.layers.size() == 5); // Frame, Eth, IPv4, UDP, BOOTP/DNS
            for (const auto& layer : p.layers) {
                verify_node_bounds(layer, p.raw_frame.size());
            }
        }
        assert(all_pkts.size() == 8);

        // Verify display filters
        auto bootp_pkts = session.snapshot("bootp");
        auto dns_pkts   = session.snapshot("dns");
        auto up_pkts    = session.snapshot("ip == 8.8.8.8");
        assert(bootp_pkts.size() == 2);
        assert(dns_pkts.size() == 6);
        assert(up_pkts.size() == 2);

        // Export to .pcap and reload
        const std::string pcap_path = "group_project/build/phase4_capture.pcap";
        assert(session.export_pcap(pcap_path));

        CaptureSession reloaded;
        assert(reloaded.import_pcap(pcap_path));
        auto reloaded_pkts = reloaded.snapshot();
        assert(reloaded_pkts.size() == all_pkts.size());
        for (size_t i = 0; i < all_pkts.size(); ++i) {
            assert(reloaded_pkts[i].protocol == all_pkts[i].protocol);
            assert(reloaded_pkts[i].info == all_pkts[i].info);
            assert(reloaded_pkts[i].raw_frame == all_pkts[i].raw_frame);
        }

        std::cout << "  -> Verified Dissector byte offsets, Filters (bootp=2, dns=6, ip==8.8.8.8=2)\n";
        std::cout << "  -> Exported & Reloaded PCAP: " << pcap_path << " (" << reloaded_pkts.size() << " frames)\n";
        std::cout << "=== ALL PHASE 4 TESTS PASSED ===\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Exception: " << ex.what() << "\n";
        return 1;
    }
}

