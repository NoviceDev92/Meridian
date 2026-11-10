# Custom BOOTP + DNS Protocol Suite & Mini-Wireshark

A modular C++17 networking lab project implementing **BOOTP** and **DNS** from scratch over UDP sockets, paired with a tailored **Mini-Wireshark** packet dissector and `.pcap` exporter.

## Project Phases

1. **Phase 1 — Protocol Wire Formats & Socket/Tap Foundation** *(Completed)*
   - `include/protocol_headers.hpp`: Big-endian wire serialization/deserialization for BOOTP (RFC 951/1048), DNS (RFC 1035), and the Mini-Wireshark `TapEnvelope` (synthesizing Ethernet II + IPv4 + UDP headers).
   - `include/udp_socket.hpp`: Cross-platform RAII UDP socket wrapper (`Winsock2` on Windows) and `TapMirror` emitter.
   - `src/phase1_test.cpp`: Unit & loopback tests verifying binary roundtrips and hex dumps.

2. **Phase 2 — Custom BOOTP Engine** *(Completed)*
   - `include/bootp_engine.hpp`: `BootpServer` (static MAC reservations, dynamic subnet pools, Option 6 DNS Server, packet drop simulation), `BootpRelay` (`giaddr` & `hops` cross-subnet forwarding), and `BootpClient` (state machine + exponential backoff).
   - `src/bootp_server_main.cpp`, `src/bootp_relay_main.cpp`, `src/bootp_client_main.cpp`, `src/phase2_test.cpp`.

3. **Phase 3 — Custom DNS Engine & End-to-End Bootstrapped Client** *(Completed)*
   - `include/dns_engine.hpp`: `DnsZoneStore` (`A`, `CNAME` chaining, `PTR`), `DnsCache` (TTL-aware with dynamic remaining-TTL countdown), `DnsServer` (Authoritative + Recursive Forwarding), and `DnsClient`.
   - `config/local_zones.conf`, `config/upstream_zones.conf`: Sample zone files.
   - `src/dns_server_main.cpp`, `src/dns_client_main.cpp`, `src/node_client_main.cpp` (full BOOTP → DNS zero-config client), `src/phase3_test.cpp`.

4. **Phase 4 — Mini-Wireshark Dissector Engine & `.pcap` Exporter** *(Completed)*
   - `include/dissector.hpp`: Layered L2/L3/L4/L7 dissector (`Ethernet II` → `IPv4` → `UDP` → `BOOTP` / `DNS`) with byte-offset tracking for hex highlighting and Wireshark-like display filters (`bootp`, `dns`, `ip == ...`, `port == ...`).
   - `include/pcap_writer.hpp`: Standard libpcap `.pcap` export & import (`LINKTYPE_ETHERNET`).
   - `include/capture_session.hpp`: Thread-safe live Tap sniffer & packet store.
   - `src/sniffer_cli_main.cpp`, `src/phase4_test.cpp`.

5. **Phase 5 — Mini-Wireshark 3-Pane Visual UI** *(Completed)*
   - `src/mini_wireshark_main.cpp`: Native Win32 3-pane GUI (`mini_wireshark.exe`) featuring:
     - **Pane 1 (Packet List)**: Color-coded rows (`BOOTP` mint-green, `DNS` sky-blue, errors light-red) + live capture auto-scroll.
     - **Pane 2 (Protocol Dissector Tree)**: Collapsible layers (`Frame`, `Ethernet II`, `IPv4`, `UDP`, `BOOTP`/`DNS`).
     - **Pane 3 (Hex + ASCII Inspector)**: Custom GDI hex/ASCII view that highlights exact byte ranges when selecting any tree field.
     - **Toolbar & Filter**: Start/Stop Capture, Clear, Open/Save `.pcap`, Display Filter (`bootp`, `dns`, `ip == ...`, `port == ...`), and one-click **Run BOOTP+DNS Demo** button.

## Building All Targets (Windows MSYS2 / MinGW g++)

```powershell
./group_project/build_all.ps1
```

## Live Demo Quick-Start

1. **All-in-One GUI Demo**: Launch `./group_project/build/mini_wireshark.exe` and click **Run BOOTP+DNS Demo** (or run the standalone servers + `node_client.exe` in separate terminals while `mini_wireshark.exe` captures on `127.0.0.1:9999`).
2. **Multi-Terminal CLI Demo**:
   - Terminal 1: `./group_project/build/mini_wireshark.exe`
   - Terminal 2: `./group_project/build/dns_server.exe --port 9153 --zones group_project/config/upstream_zones.conf --server-ip 8.8.8.8`
   - Terminal 3: `./group_project/build/dns_server.exe --port 9053 --zones group_project/config/local_zones.conf --upstream 127.0.0.1 --upstream-port 9153`
   - Terminal 4: `./group_project/build/bootp_server.exe`
   - Terminal 5: `./group_project/build/node_client.exe --interactive`

