#include "bootp_engine.hpp"

#include <cassert>
#include <iostream>
#include <thread>

using namespace netproto;

static void test_static_and_dynamic_allocation() {
    std::cout << "[TEST 1] Static Reservation, Dynamic Pool & Idempotency...\n";
    BootpServerConfig scfg;
    scfg.listen_port = 0; // Ephemeral port
    scfg.bind_ip     = "127.0.0.1";
    scfg.dns_ip      = "192.168.10.2";
    scfg.enable_tap  = false;

    BootpServer server(scfg);
    server.add_static_reservation("00:1a:2b:3c:4d:5e", "192.168.10.50", "workstation-1");
    uint16_t srv_port = server.bound_port();
    std::thread srv_thread([&]() { server.run(false); });

    // 1. Static client
    BootpClientOptions c1_opts;
    c1_opts.mac_str     = "00:1a:2b:3c:4d:5e";
    c1_opts.target_port = srv_port;
    c1_opts.enable_tap  = false;
    c1_opts.verbose     = false;
    BootpClient c1(c1_opts);
    auto cfg1 = c1.acquire_configuration();
    assert(cfg1.valid);
    assert(c1.state() == BootpClientState::BOUND);
    assert(ipv4_to_string(cfg1.client_ip) == "192.168.10.50");
    assert(ipv4_to_string(cfg1.dns_ip) == "192.168.10.2");
    assert(cfg1.hostname == "workstation-1");

    // 2. Dynamic client A -> .100
    BootpClientOptions c2_opts = c1_opts;
    c2_opts.mac_str = "aa:bb:cc:00:00:01";
    BootpClient c2(c2_opts);
    auto cfg2 = c2.acquire_configuration();
    assert(cfg2.valid);
    assert(ipv4_to_string(cfg2.client_ip) == "192.168.10.100");

    // 3. Dynamic client B -> .101
    BootpClientOptions c3_opts = c1_opts;
    c3_opts.mac_str = "aa:bb:cc:00:00:02";
    BootpClient c3(c3_opts);
    auto cfg3 = c3.acquire_configuration();
    assert(cfg3.valid);
    assert(ipv4_to_string(cfg3.client_ip) == "192.168.10.101");

    // 4. Retry from client A -> idempotent .100
    BootpClient c2_retry(c2_opts);
    auto cfg2_again = c2_retry.acquire_configuration();
    assert(cfg2_again.valid);
    assert(ipv4_to_string(cfg2_again.client_ip) == "192.168.10.100");

    server.stop();
    srv_thread.join();
    std::cout << "  -> Static=" << ipv4_to_string(cfg1.client_ip)
              << ", Dyn1=" << ipv4_to_string(cfg2.client_ip)
              << ", Dyn2=" << ipv4_to_string(cfg3.client_ip)
              << ", DNS Opt=" << ipv4_to_string(cfg1.dns_ip) << "\n";
    std::cout << "  [PASS]\n\n";
}

static void test_exponential_backoff_on_packet_loss() {
    std::cout << "[TEST 2] Exponential Backoff Retransmission under 50% Packet Drop...\n";
    BootpServerConfig scfg;
    scfg.listen_port   = 0;
    scfg.bind_ip       = "127.0.0.1";
    scfg.drop_rate_pct = 50;
    scfg.enable_tap    = false;

    BootpServer server(scfg);
    uint16_t srv_port = server.bound_port();
    std::thread srv_thread([&]() { server.run(false); });

    BootpClientOptions copts;
    copts.mac_str         = "11:22:33:44:55:66";
    copts.target_port     = srv_port;
    copts.base_timeout_ms = 60;
    copts.max_retries     = 8; // >99.6% success probability under 50% drop
    copts.enable_tap      = false;
    copts.verbose         = false;

    BootpClient client(copts);
    auto cfg = client.acquire_configuration();
    assert(cfg.valid);
    assert(client.state() == BootpClientState::BOUND);

    server.stop();
    srv_thread.join();
    std::cout << "  -> Acquired " << ipv4_to_string(cfg.client_ip)
              << " in " << client.last_attempts() << " attempt(s)\n";
    std::cout << "  [PASS]\n\n";
}

static void test_bootp_relay_agent() {
    std::cout << "[TEST 3] Cross-Subnet BOOTP Relay Agent (giaddr=10.0.2.1)...\n";
    BootpServerConfig scfg;
    scfg.listen_port = 0;
    scfg.bind_ip     = "127.0.0.1";
    scfg.enable_tap  = false;
    BootpServer server(scfg);
    uint16_t srv_port = server.bound_port();

    BootpRelayConfig rcfg;
    rcfg.listen_port = 0;
    rcfg.bind_ip     = "127.0.0.1";
    rcfg.relay_ip    = "10.0.2.1";
    rcfg.server_port = srv_port;
    rcfg.enable_tap  = false;
    BootpRelay relay(rcfg);
    uint16_t relay_port = relay.bound_port();

    std::thread srv_thread([&]() { server.run(false); });
    std::thread relay_thread([&]() { relay.run(false); });

    BootpClientOptions copts;
    copts.mac_str     = "de:ad:be:ef:00:01";
    copts.target_port = relay_port; // Client talks to Relay on Subnet B
    copts.enable_tap  = false;
    copts.verbose     = false;

    BootpClient client(copts);
    auto cfg = client.acquire_configuration();
    assert(cfg.valid);
    assert(ipv4_to_string(cfg.client_ip) == "10.0.2.100");
    assert(ipv4_to_string(cfg.relay_ip) == "10.0.2.1");
    assert(ipv4_to_string(cfg.router_ip) == "10.0.2.1");

    relay.stop();
    server.stop();
    relay_thread.join();
    srv_thread.join();
    std::cout << "  -> Relayed IP=" << ipv4_to_string(cfg.client_ip)
              << " | giaddr=" << ipv4_to_string(cfg.relay_ip) << "\n";
    std::cout << "  [PASS]\n\n";
}

static void test_pool_exhaustion() {
    std::cout << "[TEST 4] IP Pool Exhaustion & Client Failure State...\n";
    BootpServerConfig scfg;
    scfg.listen_port = 0;
    scfg.bind_ip     = "127.0.0.1";
    scfg.enable_tap  = false;
    scfg.default_pool.pool_start = ipv4_from_string("192.168.10.250");
    scfg.default_pool.pool_end   = ipv4_from_string("192.168.10.250"); // Size = 1

    BootpServer server(scfg);
    uint16_t srv_port = server.bound_port();
    std::thread srv_thread([&]() { server.run(false); });

    BootpClientOptions opts;
    opts.mac_str         = "01:02:03:04:05:01";
    opts.target_port     = srv_port;
    opts.base_timeout_ms = 50;
    opts.max_retries     = 2;
    opts.enable_tap      = false;
    opts.verbose         = false;

    BootpClient c1(opts);
    auto cfg1 = c1.acquire_configuration();
    assert(cfg1.valid);
    assert(ipv4_to_string(cfg1.client_ip) == "192.168.10.250");

    opts.mac_str = "01:02:03:04:05:02";
    BootpClient c2(opts);
    auto cfg2 = c2.acquire_configuration();
    assert(!cfg2.valid);
    assert(c2.state() == BootpClientState::FAILED);

    server.stop();
    srv_thread.join();
    std::cout << "  -> Client 1 bound .250; Client 2 gracefully entered FAILED state\n";
    std::cout << "  [PASS]\n\n";
}

int main() {
    try {
        SocketRuntime runtime;
        test_static_and_dynamic_allocation();
        test_exponential_backoff_on_packet_loss();
        test_bootp_relay_agent();
        test_pool_exhaustion();
        std::cout << "=== ALL PHASE 2 TESTS PASSED ===\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Exception: " << ex.what() << "\n";
        return 1;
    }
}

