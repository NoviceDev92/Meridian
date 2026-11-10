#include "dns_engine.hpp"

#include <iostream>

using namespace netproto;

int main(int argc, char* argv[]) {
    try {
        SocketRuntime runtime;
        DnsClientOptions opts;
        std::string query_name = "fileserver.lab.local";
        DnsType qtype = DnsType::A;

        for (int i = 1; i + 1 < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--server") {
                opts.server_ip = argv[++i];
            } else if (arg == "--port") {
                opts.server_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--query") {
                query_name = argv[++i];
            } else if (arg == "--type") {
                std::string t = argv[++i];
                if (t == "PTR") {
                    qtype = DnsType::PTR;
                    if (query_name.find(".in-addr.arpa") == std::string::npos) {
                        query_name = ipv4_to_ptr_name(query_name);
                    }
                } else if (t == "CNAME") {
                    qtype = DnsType::CNAME;
                }
            }
        }

        DnsClient client(opts);
        DnsLookupResult res = client.resolve(query_name, qtype);
        std::cout << "\n--- DNS Resolution Result ---\n"
                  << "  Status        : " << dns_rcode_name(res.rcode) << "\n"
                  << "  Authoritative : " << (res.authoritative ? "Yes" : "No (Cached/Recursive)") << "\n";
        for (const auto& rr : res.answers) {
            std::cout << "  Record        : " << rr.name << "  "
                      << dns_type_name(rr.type) << "  TTL=" << rr.ttl << "s  -> ";
            if (rr.type == static_cast<uint16_t>(DnsType::A)) {
                std::cout << rr.rdata_as_ipv4();
            } else {
                PacketReader pr(rr.rdata);
                std::cout << decode_dns_name(pr);
            }
            std::cout << "\n";
        }
        return res.success ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
}

