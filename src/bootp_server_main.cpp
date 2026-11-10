#include "bootp_engine.hpp"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>

using namespace netproto;

static BootpServer* g_server = nullptr;
static void handle_sigint(int) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        BootpServerConfig cfg;

        for (int i = 1; i + 1 < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--port") {
                cfg.listen_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--dns") {
                cfg.dns_ip = argv[++i];
            } else if (arg == "--drop-rate") {
                cfg.drop_rate_pct = static_cast<uint32_t>(std::stoi(argv[++i]));
            } else if (arg == "--server-ip") {
                cfg.server_ip = argv[++i];
            }
        }

        BootpServer server(cfg);
        // Pre-configured static lab reservations
        server.add_static_reservation("00:1a:2b:3c:4d:5e", "192.168.10.50", "lab-workstation-1");
        server.add_static_reservation("aa:bb:cc:dd:ee:01", "192.168.10.51", "lab-printer");

        g_server = &server;
        std::signal(SIGINT, handle_sigint);
        std::cout << "Press Ctrl+C to stop BOOTP Server.\n";
        server.run(true);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

