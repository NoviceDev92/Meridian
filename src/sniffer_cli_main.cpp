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
    std::cout << "+ " << node.label;
    if (node.byte_length > 0) {
        std::cout << "  [off=" << node.byte_offset << ", len=" << node.byte_length << "]";
    }
    if (!node.field.empty()) std::cout << "  {" << node.field << "}";
    std::cout << "\n";
    for (const auto& child : node.children) {
        print_tree(child, depth + 1);
    }
}

static void print_header() {
    std::cout << std::left
              << std::setw(5)  << "No."
              << std::setw(11) << "Time"
              << std::setw(17) << "Source"
              << std::setw(17) << "Destination"
              << std::setw(8)  << "Proto"
              << std::setw(6)  << "Len"
              << "Info\n";
    std::cout << std::string(90, '-') << "\n";
}

static void print_row(const DissectedPacket& pkt, bool tree) {
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
    if (tree) {
        for (const auto& layer : pkt.layers) print_tree(layer, 1);
        std::cout << "\n";
    }
}

static void usage() {
    std::cout <<
        "Usage: sniffer_cli [--port N] [--out file.pcap] [--filter EXPR] [--tree] [--stats]\n"
        "       sniffer_cli --read file.pcap|file.pcapng [--filter EXPR] [--tree] [--stats]\n\n"
        "Filter examples (Wireshark syntax):\n"
        "  dns && dns.flags.rcode == 3            NXDOMAIN responses\n"
        "  bootp.hops > 0 || bootp.ip.relay != 0.0.0.0\n"
        "  ip.addr == 192.168.10.0/24 && !dns\n"
        "  dns.qry.name contains \"university\"\n"
        "  dns.time > 0.001                         slow DNS answers\n"
        "  udp.checksum.status == bad || _ws.malformed\n";
}

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        uint16_t tap_port = TAP_SNIFFER_PORT;
        std::string pcap_out = "group_project/build/capture.pcap";
        std::string read_path;
        std::string filter_text;
        bool verbose_tree = false;
        bool show_stats = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--port" && i + 1 < argc) {
                tap_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--out" && i + 1 < argc) {
                pcap_out = argv[++i];
            } else if (arg == "--read" && i + 1 < argc) {
                read_path = argv[++i];
            } else if (arg == "--filter" && i + 1 < argc) {
                filter_text = argv[++i];
            } else if (arg == "--tree") {
                verbose_tree = true;
            } else if (arg == "--stats") {
                show_stats = true;
            } else if (arg == "--help" || arg == "-h") {
                usage();
                return 0;
            }
        }

        DisplayFilter filter = DisplayFilter::compile(filter_text);
        if (!filter.valid()) {
            std::cerr << "[FILTER] " << filter.error()
                      << " -- falling back to plain text search for \"" << filter.text() << "\"\n";
        }

        // ------------------------------------------------------------------
        // Offline mode: read a capture file (ours or one saved by Wireshark)
        // ------------------------------------------------------------------
        if (!read_path.empty()) {
            CaptureSession session;
            std::string err;
            if (!session.import_pcap(read_path, &err)) {
                std::cerr << "[FATAL] Cannot read " << read_path << ": " << err << "\n";
                return 1;
            }
            auto pkts = session.snapshot(filter);
            std::cout << "Read " << session.count() << " frame(s) from " << read_path
                      << ", displaying " << pkts.size() << "\n";
            print_header();
            for (const auto& p : pkts) print_row(p, verbose_tree);
            if (show_stats) std::cout << "\n" << session.statistics().to_string();
            return 0;
        }

        // ------------------------------------------------------------------
        // Live mode: listen on the tap port
        // ------------------------------------------------------------------
        CaptureSession session(tap_port);
        std::cout << "====================================================================================\n";
        std::cout << "  MINI-WIRESHARK CLI CAPTURE (Listening on 127.0.0.1:" << tap_port << ")\n";
        std::cout << "  Output PCAP: " << pcap_out << " | Press Ctrl+C to stop & save.\n";
        std::cout << "====================================================================================\n";
        print_header();

        session.start([&](const DissectedPacket& pkt) {
            if (filter.matches(pkt)) print_row(pkt, verbose_tree);
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
        if (show_stats) std::cout << "\n" << session.statistics().to_string();
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}
