#include "bootp_engine.hpp"
#include "dns_engine.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

using namespace netproto;

static void test_zone_records_and_nxdomain() {
    std::cout << "[TEST 1] DNS Authoritative Zone File, CNAME Chain, PTR & NXDOMAIN...\n";
    DnsServerConfig cfg;
    cfg.listen_port = 0;
    cfg.enable_tap  = false;
    DnsServer srv(cfg);
    bool loaded = srv.zones().load_from_file("group_project/config/local_zones.conf");
    assert(loaded);
    uint16_t port = srv.bound_port();
    std::thread t([&]() { srv.run(false); });

    DnsClientOptions copts;
    copts.server_port = port;
    copts.enable_tap  = false;
    copts.verbose     = false;
    DnsClient client(copts);

    // 1. CNAME -> A chain + Case insensitivity
    auto r1 = client.resolve("FileServer.LAB.local", DnsType::A);
    assert(r1.success);
    assert(r1.authoritative);
    assert(r1.answers.size() == 2); // CNAME + A
    assert(r1.resolved_ip == "192.168.10.50");

    // 2. Reverse PTR lookup
    auto r2 = client.resolve(ipv4_to_ptr_name("192.168.10.80"), DnsType::PTR);
    assert(r2.success);
    assert(r2.resolved_name == "web.lab.local");

    // 3. NXDOMAIN
    auto r3 = client.resolve("doesnotexist.lab.local", DnsType::A);
    assert(!r3.success);
    assert(r3.rcode == static_cast<uint8_t>(DnsRCode::NXDOMAIN));

    srv.stop();
    t.join();
    std::cout << "  -> CNAME+A=" << r1.resolved_ip
              << " | PTR(.80)=" << r2.resolved_name
              << " | Missing=" << dns_rcode_name(r3.rcode) << "\n";
    std::cout << "  [PASS]\n\n";
}

static void test_forwarding_and_ttl_cache_expiry() {
    std::cout << "[TEST 2] Recursive Forwarding, Cache Hit & TTL Expiry...\n";

    // Upstream authoritative server with 2-second TTL record
    DnsServerConfig up_cfg;
    up_cfg.listen_port = 0;
    up_cfg.enable_tap  = false;
    DnsServer upstream(up_cfg);
    upstream.zones().add_a("shortttl.university.edu", "10.20.30.99", 2);
    uint16_t up_port = upstream.bound_port();
    std::thread up_thread([&]() { upstream.run(false); });

    // Local forwarding + caching DNS server
    DnsServerConfig loc_cfg;
    loc_cfg.listen_port   = 0;
    loc_cfg.upstream_ip   = "127.0.0.1";
    loc_cfg.upstream_port = up_port;
    loc_cfg.enable_tap    = false;
    DnsServer local(loc_cfg);
    uint16_t loc_port = local.bound_port();
    std::thread loc_thread([&]() { local.run(false); });

    DnsClientOptions copts;
    copts.server_port = loc_port;
    copts.timeout_ms  = 250;
    copts.max_retries = 1;
    copts.enable_tap  = false;
    copts.verbose     = false;
    DnsClient client(copts);

    // Query 1: Cache miss -> Upstream
    auto q1 = client.resolve("shortttl.university.edu", DnsType::A);
    assert(q1.success);
    assert(!q1.authoritative);
    assert(q1.resolved_ip == "10.20.30.99");
    assert(local.cache().size() == 1);

    // Stop upstream to prove Query 2 is genuinely served from cache!
    upstream.stop();
    up_thread.join();

    // Query 2: Must succeed from cache while upstream is down
    auto q2 = client.resolve("shortttl.university.edu", DnsType::A);
    assert(q2.success);
    assert(q2.resolved_ip == "10.20.30.99");

    // Wait > 2s for TTL to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));

    // Query 3: Cache expired, upstream unreachable -> SERVFAIL
    auto q3 = client.resolve("shortttl.university.edu", DnsType::A);
    assert(!q3.success);
    assert(q3.rcode == static_cast<uint8_t>(DnsRCode::SERVFAIL));

    local.stop();
    loc_thread.join();
    std::cout << "  -> Cache Hit verified with upstream offline; TTL expiration verified\n";
    std::cout << "  [PASS]\n\n";
}

static void test_end_to_end_bootp_to_dns_handoff() {
    std::cout << "[TEST 3] End-to-End Zero-Config Handoff (BOOTP -> DNS)...\n";

    // Start Upstream DNS
    DnsServerConfig up_cfg;
    up_cfg.listen_port = 0;
    up_cfg.enable_tap  = false;
    DnsServer upstream(up_cfg);
    assert(upstream.zones().load_from_file("group_project/config/upstream_zones.conf"));
    std::thread up_thread([&]() { upstream.run(false); });

    // Start Local DNS
    DnsServerConfig loc_cfg;
    loc_cfg.listen_port   = 0;
    loc_cfg.upstream_ip   = "127.0.0.1";
    loc_cfg.upstream_port = upstream.bound_port();
    loc_cfg.enable_tap    = false;
    DnsServer local_dns(loc_cfg);
    assert(local_dns.zones().load_from_file("group_project/config/local_zones.conf"));
    std::thread loc_thread([&]() { local_dns.run(false); });

    // Start BOOTP Server advertising DNS Option 6
    BootpServerConfig bcfg;
    bcfg.listen_port = 0;
    bcfg.bind_ip     = "127.0.0.1";
    bcfg.dns_ip      = "192.168.10.2";
    bcfg.enable_tap  = false;
    BootpServer bootp_srv(bcfg);
    std::thread bootp_thread([&]() { bootp_srv.run(false); });

    // Stage 1: Client acquires network config via BOOTP
    BootpClientOptions bopts;
    bopts.mac_str     = "aa:bb:cc:dd:ee:99";
    bopts.target_port = bootp_srv.bound_port();
    bopts.enable_tap  = false;
    bopts.verbose     = false;
    BootpClient bootp_cli(bopts);
    BootpNetworkConfig net_cfg = bootp_cli.acquire_configuration();
    assert(net_cfg.valid);
    assert(ipv4_to_string(net_cfg.dns_ip) == "192.168.10.2");

    // Stage 2: Dynamically configure DNS client using BOOTP Option 6
    DnsClientOptions dopts;
    dopts.logical_client_ip = ipv4_to_string(net_cfg.client_ip);
    dopts.logical_server_ip = ipv4_to_string(net_cfg.dns_ip);
    dopts.server_ip         = "127.0.0.1"; // Loopback transport
    dopts.server_port       = local_dns.bound_port();
    dopts.enable_tap        = false;
    dopts.verbose           = false;
    DnsClient dns_cli(dopts);

    auto res_local = dns_cli.resolve("web.lab.local", DnsType::A);
    assert(res_local.success && res_local.resolved_ip == "192.168.10.80");

    auto res_ext = dns_cli.resolve("moodle.university.edu", DnsType::A);
    assert(res_ext.success && res_ext.resolved_ip == "10.20.30.45");

    bootp_srv.stop();
    local_dns.stop();
    upstream.stop();
    bootp_thread.join();
    loc_thread.join();
    up_thread.join();

    std::cout << "  -> BOOTP assigned IP=" << ipv4_to_string(net_cfg.client_ip)
              << ", DNS=" << ipv4_to_string(net_cfg.dns_ip)
              << " -> Resolved web.lab.local=" << res_local.resolved_ip
              << ", moodle.university.edu=" << res_ext.resolved_ip << "\n";
    std::cout << "  [PASS]\n\n";
}

int main() {
    try {
        SocketRuntime runtime;
        test_zone_records_and_nxdomain();
        test_forwarding_and_ttl_cache_expiry();
        test_end_to_end_bootp_to_dns_handoff();
        std::cout << "=== ALL PHASE 3 TESTS PASSED ===\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Exception: " << ex.what() << "\n";
        return 1;
    }
}

