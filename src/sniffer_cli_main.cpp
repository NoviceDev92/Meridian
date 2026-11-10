#include "capture_session.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <thread>

using namespace netproto;

static std::atomic<bool> g_keep_running{true};
static void handle_sigint(int) { g_keep_running.store(false); }

static void print_tree(const DissectNode& node, int depth = 0) {
    for (int i = 0; i < depth; ++i) std::cout << "  ";
    std::cout << "+ " << node.label << "  [off=" << node.byte_offset
              << ", len=" << node.byte_length << "]\n";
    for (const auto& child : node.children) {
        print_tree(child, depth + 1);
    }
}

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        uint16_t tap_port = TAP_SNIFFER_PORT;
        std::string pcap_out = "group_project/build/capture.pcap";
        std::string filter;
        bool verbose_tree = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--port" && i + 1 < argc) {
                tap_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--out" && i + 1 < argc) {
                pcap_out = argv[++i];
            } else if (arg == "--filter" && i + 1 < argc) {
                filter = argv[++i];
            } else if (arg == "--tree") {
                verbose_tree = true;
            }
        }

        CaptureSession session(tap_port);
        std::cout << "====================================================================================\n";
        std::cout << "  MINI-WIRESHARK CLI CAPTURE (Listening on 127.0.0.1:" << tap_port << ")\n";
        std::cout << "  Output PCAP: " << pcap_out << " | Press Ctrl+C to stop & save.\n";
        std::cout << "====================================================================================\n";
        std::cout << std::left
                  << std::setw(5)  << "No."
                  << std::setw(11) << "Time"
                  << std::setw(17) << "Source"
                  << std::setw(17) << "Destination"
                  << std::setw(8)  << "Proto"
                  << std::setw(6)  << "Len"
                  << "Info\n";
        std::cout << std::string(90, '-') << "\n";

        session.start([&](const DissectedPacket& pkt) {
            if (!filter.empty() && !PacketDissector::matches_filter(pkt, filter)) {
                return;
            }
            std::ostringstream tstr;
            tstr << std::fixed << std::setprecision(4) << pkt.rel_time_sec << "s";
            std::cout << std::left
                      << std::setw(5)  << pkt.number
                      << std::setw(11) << tstr.str()
                      << std::setw(17) << pkt.src_ip
                      << std::setw(17) << pkt.dst_ip
                      << std::setw(8)  << pkt.protocol
                      << std::setw(6)  << pkt.raw_frame.size()
                      << pkt.info << "\n";

            if (verbose_tree) {
                for (const auto& layer : pkt.layers) {
                    print_tree(layer, 1);
                }
                std::cout << "\n";
            }
        });

        std::signal(SIGINT, handle_sigint);
        while (g_keep_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        session.stop();
        if (session.export_pcap(pcap_out)) {
            std::cout << "\n[SNIFFER] Saved " << session.count()
                      << " packet(s) to " << pcap_out << "\n";
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

