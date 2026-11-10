#include "dns_engine.hpp"

#include <csignal>
#include <iostream>

using namespace netproto;

static DnsServer* g_dns = nullptr;
static void handle_sigint(int) {
    if (g_dns) g_dns->stop();
}

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        DnsServerConfig cfg;
        std::string zone_file = "group_project/config/local_zones.conf";

        for (int i = 1; i + 1 < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--port") {
                cfg.listen_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--zones") {
                zone_file = argv[++i];
            } else if (arg == "--upstream") {
                cfg.upstream_ip = argv[++i];
            } else if (arg == "--upstream-port") {
                cfg.upstream_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--server-ip") {
                cfg.server_ip = argv[++i];
            }
        }

        DnsServer server(cfg);
        if (!server.zones().load_from_file(zone_file)) {
            std::cerr << "[WARN] Could not load zone file '" << zone_file
                      << "'; using built-in defaults.\n";
            server.zones().add_a("nas01.lab.local", "192.168.10.50", 120);
            server.zones().add_cname("fileserver.lab.local", "nas01.lab.local", 120);
            server.zones().add_a("web.lab.local", "192.168.10.80", 60);
        } else {
            std::cout << "[DNS SERVER] Loaded zone file: " << zone_file << "\n";
        }

        g_dns = &server;
        std::signal(SIGINT, handle_sigint);
        std::cout << "Press Ctrl+C to stop DNS Server.\n";
        server.run(true);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

