#include "bootp_engine.hpp"

#include <iostream>

using namespace netproto;

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        BootpClientOptions opts;

        for (int i = 1; i + 1 < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--mac") {
                opts.mac_str = argv[++i];
            } else if (arg == "--server") {
                opts.target_ip = argv[++i];
            } else if (arg == "--port") {
                opts.target_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--retries") {
                opts.max_retries = static_cast<uint32_t>(std::stoi(argv[++i]));
            }
        }

        BootpClient client(opts);
        BootpNetworkConfig cfg = client.acquire_configuration();
        if (!cfg.valid) {
            return 1;
        }

        std::cout << "\n--- Acquired Network Profile ---\n"
                  << "  Hostname   : " << cfg.hostname << "\n"
                  << "  IPv4 Addr  : " << ipv4_to_string(cfg.client_ip) << "\n"
                  << "  Subnet Mask: " << ipv4_to_string(cfg.subnet_mask) << "\n"
                  << "  Gateway    : " << ipv4_to_string(cfg.router_ip) << "\n"
                  << "  DNS Server : " << ipv4_to_string(cfg.dns_ip) << "\n"
                  << "  Domain     : " << cfg.domain_name << "\n"
                  << "  Lease Time : " << cfg.lease_secs << "s\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

