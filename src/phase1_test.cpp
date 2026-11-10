#include "protocol_headers.hpp"
#include "udp_socket.hpp"

#include <cassert>
#include <iostream>

using namespace netproto;

static void test_bootp_roundtrip() {
    std::cout << "[TEST 1] BOOTP Request & Reply Serialization...\n";

    // 1. Build BOOTREQUEST
    BootpPacket req;
    req.op    = static_cast<uint8_t>(BootpOp::REQUEST);
    req.xid   = 0x3A8F1201;
    req.flags = 0x8000; // Broadcast
    req.set_mac(mac_from_string("00:1a:2b:3c:4d:5e"));

    auto req_bytes = req.serialize();
    assert(req_bytes.size() == 300); // RFC 951 standard minimum 300 bytes

    BootpPacket req_dec = BootpPacket::deserialize(req_bytes.data(), req_bytes.size());
    assert(req_dec.op == static_cast<uint8_t>(BootpOp::REQUEST));
    assert(req_dec.xid == 0x3A8F1201);
    assert(mac_to_string(req_dec.get_mac()) == "00:1a:2b:3c:4d:5e");

    // 2. Build BOOTREPLY with Vendor Extensions (Subnet, Router, DNS Server, Domain)
    BootpPacket rep;
    rep.op     = static_cast<uint8_t>(BootpOp::REPLY);
    rep.xid    = req.xid;
    rep.yiaddr = ipv4_from_string("192.168.10.105");
    rep.siaddr = ipv4_from_string("192.168.10.1");
    rep.set_mac(req.get_mac());
    rep.sname  = "bootp-srv.lab.local";
    rep.add_ip_option(BootpOptionTag::SUBNET_MASK, ipv4_from_string("255.255.255.0"));
    rep.add_ip_option(BootpOptionTag::ROUTER, ipv4_from_string("192.168.10.1"));
    rep.add_ip_option(BootpOptionTag::DNS_SERVER, ipv4_from_string("192.168.10.2"));
    rep.add_string_option(BootpOptionTag::DOMAIN_NAME, "lab.local");
    rep.add_u32_option(BootpOptionTag::LEASE_TIME, 3600);

    auto rep_bytes = rep.serialize();
    assert(rep_bytes.size() >= 300);

    BootpPacket rep_dec = BootpPacket::deserialize(rep_bytes.data(), rep_bytes.size());
    assert(rep_dec.op == static_cast<uint8_t>(BootpOp::REPLY));
    assert(ipv4_to_string(rep_dec.yiaddr) == "192.168.10.105");
    assert(rep_dec.sname == "bootp-srv.lab.local");

    uint32_t dns_ip = 0, subnet = 0;
    std::string domain;
    assert(rep_dec.get_ip_option(BootpOptionTag::DNS_SERVER, dns_ip));
    assert(ipv4_to_string(dns_ip) == "192.168.10.2");
    assert(rep_dec.get_ip_option(BootpOptionTag::SUBNET_MASK, subnet));
    assert(ipv4_to_string(subnet) == "255.255.255.0");
    assert(rep_dec.get_string_option(BootpOptionTag::DOMAIN_NAME, domain));
    assert(domain == "lab.local");

    std::cout << "  -> Assigned IP: " << ipv4_to_string(rep_dec.yiaddr)
              << ", DNS Server Option (Tag 6): " << ipv4_to_string(dns_ip) << "\n";
    std::cout << "  -> BOOTREPLY Hex Dump (first 64 bytes):\n";
    std::vector<uint8_t> preview(rep_bytes.begin(), rep_bytes.begin() + 64);
    std::cout << format_hex_dump(preview);
    std::cout << "  [PASS]\n\n";
}

static void test_dns_roundtrip() {
    std::cout << "[TEST 2] DNS Query & Response Serialization...\n";

    // 1. Build DNS Query
    DnsMessage query;
    query.id       = 0xABCD;
    query.flags.qr = false;
    query.flags.rd = true;
    query.questions.push_back({"fileserver.lab.local", static_cast<uint16_t>(DnsType::A), 1});

    auto q_bytes = query.serialize();
    DnsMessage q_dec = DnsMessage::deserialize(q_bytes.data(), q_bytes.size());
    assert(q_dec.id == 0xABCD);
    assert(q_dec.flags.qr == false);
    assert(q_dec.questions.size() == 1);
    assert(q_dec.questions[0].qname == "fileserver.lab.local");

    // 2. Build DNS Response (CNAME + A record)
    DnsMessage resp;
    resp.id          = query.id;
    resp.flags.qr    = true;
    resp.flags.aa    = true;
    resp.flags.rd    = true;
    resp.flags.ra    = true;
    resp.flags.rcode = static_cast<uint8_t>(DnsRCode::NO_ERR);
    resp.questions   = query.questions;
    resp.answers.push_back(DnsMessage::make_cname_or_ptr(
        "fileserver.lab.local", DnsType::CNAME, "nas01.lab.local", 120));
    resp.answers.push_back(DnsResourceRecord::make_a(
        "nas01.lab.local", ipv4_from_string("192.168.10.50"), 120));

    auto r_bytes = resp.serialize();
    DnsMessage r_dec = DnsMessage::deserialize(r_bytes.data(), r_bytes.size());
    assert(r_dec.id == 0xABCD);
    assert(r_dec.flags.qr == true);
    assert(r_dec.flags.aa == true);
    assert(r_dec.answers.size() == 2);
    assert(r_dec.answers[1].rdata_as_ipv4() == "192.168.10.50");
    assert(r_dec.answers[1].ttl == 120);

    std::cout << "  -> Query: " << q_dec.questions[0].qname
              << " | Answer IP: " << r_dec.answers[1].rdata_as_ipv4()
              << " (TTL=" << r_dec.answers[1].ttl << "s)\n";
    std::cout << "  -> DNS Response Wire Frame Hex Dump:\n" << format_hex_dump(r_bytes);
    std::cout << "  [PASS]\n\n";
}

static void test_tap_and_udp_loopback() {
    std::cout << "[TEST 3] UDP Loopback + Tap Envelope Wire Frame...\n";
    SocketRuntime runtime;

    UdpSocket server;
    server.bind(0, "127.0.0.1"); // Ephemeral loopback port
    server.set_timeout_ms(1000);
    uint16_t srv_port = server.local_port();

    UdpSocket client;
    client.bind(0, "127.0.0.1");

    DnsMessage query;
    query.id = 0x1122;
    query.questions.push_back({"web.lab.local", static_cast<uint16_t>(DnsType::A), 1});
    auto payload = query.serialize();

    assert(client.send_to(payload, "127.0.0.1", srv_port));

    std::vector<uint8_t> rx_buf;
    std::string src_ip;
    uint16_t src_port = 0;
    int n = server.recv_from(rx_buf, src_ip, src_port);
    if (n != static_cast<int>(payload.size())) {
        std::cerr << "  [DEBUG] srv_port=" << srv_port
                  << ", client_port=" << client.local_port()
                  << ", recv_from returned n=" << n
                  << ", expected=" << payload.size() << std::endl;
    }
    assert(n == static_cast<int>(payload.size()));

    // Wrap into TapEnvelope & build Ethernet+IPv4+UDP frame
    TapEnvelope env;
    env.timestamp_us = current_time_us();
    env.src_ip       = ipv4_from_string("192.168.10.105");
    env.dst_ip       = ipv4_from_string("192.168.10.2");
    env.src_port     = src_port;
    env.dst_port     = DNS_SERVER_PORT;
    env.proto_hint   = static_cast<uint8_t>(AppProtoHint::DNS);
    env.payload      = rx_buf;

    auto tap_bytes = env.serialize_tap();
    TapEnvelope env_dec = TapEnvelope::deserialize_tap(tap_bytes.data(), tap_bytes.size());
    assert(env_dec.src_port == src_port);
    assert(env_dec.dst_port == DNS_SERVER_PORT);

    auto eth_frame = env_dec.to_wire_frame();
    // 14 (Eth) + 20 (IPv4) + 8 (UDP) + payload
    assert(eth_frame.size() == 42 + rx_buf.size());
    assert(eth_frame[12] == 0x08 && eth_frame[13] == 0x00); // EtherType IPv4
    assert(eth_frame[23] == 17);                            // IP Protocol UDP

    std::cout << "  -> Loopback UDP received " << n << " bytes from " << src_ip << ":" << src_port << "\n";
    std::cout << "  -> Synthesized L2/L3/L4/L7 Frame: " << eth_frame.size() << " bytes (Eth+IPv4+UDP+DNS)\n";
    std::cout << "  [PASS]\n\n";
}

int main() {
    try {
        test_bootp_roundtrip();
        test_dns_roundtrip();
        test_tap_and_udp_loopback();
        std::cout << "=== ALL PHASE 1 TESTS PASSED ===\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Exception: " << ex.what() << "\n";
        return 1;
    }
}
