#include "bootp_engine.hpp"

#include <csignal>
#include <iostream>

using namespace netproto;

static BootpRelay* g_relay = nullptr;
static void handle_sigint(int) {
    if (g_relay) g_relay->stop();
}

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        BootpRelayConfig cfg;

        for (int i = 1; i + 1 < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--port") {
                cfg.listen_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--server-port") {
                cfg.server_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--relay-ip") {
                cfg.relay_ip = argv[++i];
            }
        }

        BootpRelay relay(cfg);
        g_relay = &relay;
        std::signal(SIGINT, handle_sigint);
        std::cout << "Press Ctrl+C to stop BOOTP Relay Agent.\n";
        relay.run(true);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

