#include "bootp_engine.hpp"
#include "dns_engine.hpp"

#include <chrono>
#include <iostream>
#include <thread>

using namespace netproto;

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        BootpClientOptions b_opts;
        uint16_t dns_port = DNS_SERVER_PORT;
        bool local_sim    = true; // Maps virtual lab DNS IP (192.168.10.2) -> 127.0.0.1 transport
        bool interactive  = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--mac" && i + 1 < argc) {
                b_opts.mac_str = argv[++i];
            } else if (arg == "--bootp-ip" && i + 1 < argc) {
                b_opts.target_ip = argv[++i];
            } else if (arg == "--bootp-port" && i + 1 < argc) {
                b_opts.target_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--dns-port" && i + 1 < argc) {
                dns_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--lan") {
                local_sim = false;
            } else if (arg == "--interactive") {
                interactive = true;
            }
        }

        std::cout << "============================================================\n";
        std::cout << "  STAGE 1: ZERO-CONFIG BOOTSTRAP (Custom BOOTP Client)\n";
        std::cout << "============================================================\n";
        BootpClient bootp_client(b_opts);
        BootpNetworkConfig net_cfg = bootp_client.acquire_configuration();

        if (!net_cfg.valid) {
            std::cerr << "[NODE] Cannot proceed to DNS: BOOTP bootstrap failed.\n";
            return 1;
        }

        std::string acquired_ip  = ipv4_to_string(net_cfg.client_ip);
        std::string acquired_dns = ipv4_to_string(net_cfg.dns_ip);

        std::cout << "\n============================================================\n";
        std::cout << "  STAGE 2: DYNAMIC HANDOFF TO DNS CLIENT\n";
        std::cout << "  Learned IP=" << acquired_ip
                  << " | Learned DNS Server=" << acquired_dns << "\n";
        std::cout << "============================================================\n";

        DnsClientOptions d_opts;
        d_opts.logical_client_ip = acquired_ip;
        d_opts.logical_server_ip = acquired_dns;
        d_opts.server_ip         = local_sim ? "127.0.0.1" : acquired_dns;
        d_opts.server_port       = dns_port;
        DnsClient dns_client(d_opts);

        auto print_lookup = [&](const std::string& qname, DnsType qt) {
            DnsLookupResult r = dns_client.resolve(qname, qt);
            std::cout << "  => Status=" << dns_rcode_name(r.rcode)
                      << " | AA=" << (r.authoritative ? "Yes" : "No");
            if (!r.resolved_ip.empty())   std::cout << " | IP=" << r.resolved_ip;
            if (!r.resolved_name.empty()) std::cout << " | Name=" << r.resolved_name;
            if (r.ttl > 0)                std::cout << " | TTL=" << r.ttl << "s";
            std::cout << "\n\n";
        };

        // Demo sequence showing CNAME+A, Upstream Forwarding + Cache Hit, PTR, NXDOMAIN
        print_lookup("fileserver.lab.local", DnsType::A);
        print_lookup("dept.university.edu", DnsType::A);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        std::cout << "[NODE] Re-querying 'dept.university.edu' after 2s (should hit cache & decrement TTL):\n";
        print_lookup("dept.university.edu", DnsType::A);
        print_lookup(ipv4_to_ptr_name("192.168.10.50"), DnsType::PTR);
        print_lookup("unknown.lab.local", DnsType::A);

        if (interactive) {
            std::cout << "Interactive DNS shell ready (type domain or 'quit'):\n";
            std::string line;
            while (std::cout << "dns> " && std::getline(std::cin, line)) {
                if (line == "quit" || line == "exit") break;
                if (line.empty()) continue;
                print_lookup(line, DnsType::A);
            }
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

