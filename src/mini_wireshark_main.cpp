#include "bootp_engine.hpp"
#include "capture_session.hpp"
#include "dns_engine.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace netproto;

namespace {

constexpr UINT WM_APP_NEW_PACKET = WM_APP + 1;

enum ControlId : int {
    ID_BTN_TOGGLE_CAP = 1001,
    ID_BTN_CLEAR      = 1002,
    ID_BTN_OPEN_PCAP  = 1003,
    ID_BTN_SAVE_PCAP  = 1004,
    ID_BTN_RUN_DEMO   = 1005,
    ID_EDIT_FILTER    = 1006,
    ID_BTN_APPLY_FLT  = 1007,
    ID_BTN_CLEAR_FLT  = 1008,
    ID_LIST_PACKETS   = 1009,
    ID_TREE_DISSECT   = 1010,
    ID_HEX_VIEW       = 1011,
    ID_STATUS_BAR     = 1012
};

struct ByteSpan {
    size_t offset = 0;
    size_t length = 0;
};

struct AppState {
    CaptureSession session{TAP_SNIFFER_PORT, "127.0.0.1"};
    std::vector<DissectedPacket> displayed;
    std::vector<std::unique_ptr<ByteSpan>> tree_spans;
    std::string active_filter;

    int selected_row        = -1;
    size_t highlight_offset = 0;
    size_t highlight_length = 0;
    bool demo_running       = false;

    HWND hwnd_main    = nullptr;
    HWND hwnd_btn_cap = nullptr;
    HWND hwnd_btn_clr = nullptr;
    HWND hwnd_btn_opn = nullptr;
    HWND hwnd_btn_sav = nullptr;
    HWND hwnd_btn_dem = nullptr;
    HWND hwnd_flt_lbl = nullptr;
    HWND hwnd_flt_edt = nullptr;
    HWND hwnd_btn_apl = nullptr;
    HWND hwnd_btn_clf = nullptr;
    HWND hwnd_list    = nullptr;
    HWND hwnd_tree    = nullptr;
    HWND hwnd_hex     = nullptr;
    HWND hwnd_status  = nullptr;

    HFONT ui_font   = nullptr;
    HFONT mono_font = nullptr;
};

AppState* g_app = nullptr;
WNDPROC g_orig_edit_proc = nullptr;

LRESULT CALLBACK FilterEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        SendMessage(g_app->hwnd_main, WM_COMMAND, ID_BTN_APPLY_FLT, 0);
        return 0;
    }
    return CallWindowProcA(g_orig_edit_proc, hwnd, msg, wParam, lParam);
}

// ============================================================================
// Custom GDI Hex + ASCII Dump Panel (Pane 3) with Exact Byte Highlighting
// ============================================================================
constexpr const char* HEX_VIEW_CLASS = "MiniWiresharkHexView";

void update_hex_scrollbar(HWND hwnd) {
    if (!g_app) return;
    RECT rc{};
    GetClientRect(hwnd, &rc);
    int line_h = 18;
    int visible_lines = std::max(1, static_cast<int>((rc.bottom - rc.top) / line_h));

    size_t byte_len = 0;
    if (g_app->selected_row >= 0 &&
        g_app->selected_row < static_cast<int>(g_app->displayed.size())) {
        byte_len = g_app->displayed[g_app->selected_row].raw_frame.size();
    }
    int total_lines = static_cast<int>((byte_len + 15) / 16);

    SCROLLINFO si{};
    si.cbSize = sizeof(si);
    si.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin   = 0;
    si.nMax   = std::max(0, total_lines - 1);
    si.nPage  = static_cast<UINT>(visible_lines);
    GetScrollInfo(hwnd, SB_VERT, &si);
    si.fMask  = SIF_RANGE | SIF_PAGE;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

void scroll_hex_to_highlight(HWND hwnd) {
    if (!g_app || g_app->highlight_length == 0) return;
    int target_line = static_cast<int>(g_app->highlight_offset / 16);

    SCROLLINFO si{};
    si.cbSize = sizeof(si);
    si.fMask  = SIF_POS | SIF_PAGE | SIF_RANGE;
    GetScrollInfo(hwnd, SB_VERT, &si);

    int pos = si.nPos;
    int page = static_cast<int>(si.nPage);
    if (target_line < pos || target_line >= pos + page) {
        si.fMask = SIF_POS;
        si.nPos  = std::max(0, target_line - 1);
        SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
    }
}

LRESULT CALLBACK HexViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_VSCROLL: {
            SCROLLINFO si{};
            si.cbSize = sizeof(si);
            si.fMask  = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            int pos = si.nPos;
            switch (LOWORD(wParam)) {
                case SB_LINEUP:        pos -= 1; break;
                case SB_LINEDOWN:      pos += 1; break;
                case SB_PAGEUP:        pos -= static_cast<int>(si.nPage); break;
                case SB_PAGEDOWN:      pos += static_cast<int>(si.nPage); break;
                case SB_THUMBTRACK:    pos = si.nTrackPos; break;
                default: break;
            }
            pos = std::max(si.nMin, std::min(pos, si.nMax));
            si.fMask = SIF_POS;
            si.nPos  = pos;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
            InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
        }
        case WM_MOUSEWHEEL: {
            int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            SendMessage(hwnd, WM_VSCROLL, (delta > 0) ? SB_LINEUP : SB_LINEDOWN, 0);
            return 0;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC hdc = BeginPaint(hwnd, &ps);

            RECT rc{};
            GetClientRect(hwnd, &rc);
            HBRUSH bg = CreateSolidBrush(RGB(252, 252, 254));
            FillRect(hdc, &rc, bg);
            DeleteObject(bg);

            if (!g_app || g_app->selected_row < 0 ||
                g_app->selected_row >= static_cast<int>(g_app->displayed.size())) {
                SelectObject(hdc, g_app->ui_font);
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, RGB(120, 125, 135));
                RECT trc = rc;
                trc.left += 12;
                trc.top += 10;
                DrawTextA(hdc, "Select a packet to inspect raw hex bytes and ASCII payload.", -1, &trc, DT_LEFT);
                EndPaint(hwnd, &ps);
                return 0;
            }

            const auto& frame = g_app->displayed[g_app->selected_row].raw_frame;
            HFONT old_font = static_cast<HFONT>(SelectObject(hdc, g_app->mono_font));
            TEXTMETRICA tm{};
            GetTextMetricsA(hdc, &tm);
            int char_w = tm.tmAveCharWidth;
            int line_h = std::max(18, static_cast<int>(tm.tmHeight + 4));

            SCROLLINFO si{};
            si.cbSize = sizeof(si);
            si.fMask  = SIF_POS;
            GetScrollInfo(hwnd, SB_VERT, &si);
            int first_line = si.nPos;
            int total_lines = static_cast<int>((frame.size() + 15) / 16);
            int max_vis = static_cast<int>((rc.bottom - rc.top) / line_h) + 2;

            size_t hl_start = g_app->highlight_offset;
            size_t hl_end   = hl_start + g_app->highlight_length;

            HBRUSH hl_brush = CreateSolidBrush(RGB(45, 125, 225));
            for (int line = first_line; line < total_lines && line < first_line + max_vis; ++line) {
                int y = (line - first_line) * line_h + 4;
                size_t base = static_cast<size_t>(line) * 16;

                // Offset column
                char off_buf[16];
                std::snprintf(off_buf, sizeof(off_buf), "%04X", static_cast<unsigned>(base));
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, RGB(100, 110, 130));
                TextOutA(hdc, 10, y, off_buf, 4);

                int hex_x_base   = 10 + char_w * 7;
                int ascii_x_base = hex_x_base + char_w * 51;

                for (size_t j = 0; j < 16 && (base + j) < frame.size(); ++j) {
                    size_t idx = base + j;
                    bool highlighted = (g_app->highlight_length > 0 && idx >= hl_start && idx < hl_end);

                    int hx = hex_x_base + static_cast<int>(j * 3 + (j >= 8 ? 1 : 0)) * char_w;
                    int ax = ascii_x_base + static_cast<int>(j) * char_w;

                    char hbuf[4];
                    std::snprintf(hbuf, sizeof(hbuf), "%02X", frame[idx]);
                    char abuf[2] = {
                        (frame[idx] >= 32 && frame[idx] <= 126) ? static_cast<char>(frame[idx]) : '.',
                        '\0'
                    };

                    if (highlighted) {
                        RECT hrc{hx - 1, y - 1, hx + char_w * 2 + 1, y + line_h - 3};
                        FillRect(hdc, &hrc, hl_brush);
                        RECT arc{ax, y - 1, ax + char_w, y + line_h - 3};
                        FillRect(hdc, &arc, hl_brush);
                        SetTextColor(hdc, RGB(255, 255, 255));
                    } else {
                        SetTextColor(hdc, RGB(25, 30, 40));
                    }

                    TextOutA(hdc, hx, y, hbuf, 2);
                    TextOutA(hdc, ax, y, abuf, 1);
                }
            }
            DeleteObject(hl_brush);
            SelectObject(hdc, old_font);
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
}

// ============================================================================
// UI Population & Synchronization Helpers
// ============================================================================
void update_status_bar() {
    if (!g_app || !g_app->hwnd_status) return;
    std::ostringstream oss;
    oss << (g_app->session.is_running()
                ? ("Capturing on 127.0.0.1:" + std::to_string(g_app->session.bound_port()))
                : "Capture Stopped")
        << "   |   Total Packets: " << g_app->session.count()
        << "   |   Displayed: " << g_app->displayed.size();
    if (g_app->highlight_length > 0) {
        oss << "   |   Selected Bytes: offset=" << g_app->highlight_offset
            << ", len=" << g_app->highlight_length;
    }
    SendMessageA(g_app->hwnd_status, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>(oss.str().c_str()));
}

void insert_tree_node(HTREEITEM parent, const DissectNode& node, bool expand) {
    auto span = std::make_unique<ByteSpan>(ByteSpan{node.byte_offset, node.byte_length});
    LPARAM lparam = reinterpret_cast<LPARAM>(span.get());
    g_app->tree_spans.push_back(std::move(span));

    TVINSERTSTRUCTA tvis{};
    tvis.hParent      = parent;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask    = TVIF_TEXT | TVIF_PARAM;
    tvis.item.pszText = const_cast<char*>(node.label.c_str());
    tvis.item.lParam  = lparam;

    HTREEITEM item = TreeView_InsertItem(g_app->hwnd_tree, &tvis);
    for (const auto& child : node.children) {
        insert_tree_node(item, child, false);
    }
    if (expand) {
        TreeView_Expand(g_app->hwnd_tree, item, TVE_EXPAND);
    }
}

void populate_dissector_for_row(int row) {
    g_app->selected_row     = row;
    g_app->highlight_offset = 0;
    g_app->highlight_length = 0;

    TreeView_DeleteAllItems(g_app->hwnd_tree);
    g_app->tree_spans.clear();

    if (row >= 0 && row < static_cast<int>(g_app->displayed.size())) {
        const auto& pkt = g_app->displayed[row];
        for (size_t i = 0; i < pkt.layers.size(); ++i) {
            // Auto-expand the application protocol layer (last layer: BOOTP / DNS)
            bool auto_expand = (i + 1 == pkt.layers.size());
            insert_tree_node(TVI_ROOT, pkt.layers[i], auto_expand);
        }
    }

    update_hex_scrollbar(g_app->hwnd_hex);
    InvalidateRect(g_app->hwnd_hex, nullptr, TRUE);
    update_status_bar();
}

void append_listview_row(const DissectedPacket& pkt, int row_idx) {
    char num_buf[16];
    std::snprintf(num_buf, sizeof(num_buf), "%u", pkt.number);
    char time_buf[32];
    std::snprintf(time_buf, sizeof(time_buf), "%.6f", pkt.rel_time_sec);
    char len_buf[16];
    std::snprintf(len_buf, sizeof(len_buf), "%zu", pkt.raw_frame.size());

    LVITEMA lvi{};
    lvi.mask     = LVIF_TEXT;
    lvi.iItem    = row_idx;
    lvi.iSubItem = 0;
    lvi.pszText  = num_buf;
    ListView_InsertItem(g_app->hwnd_list, &lvi);

    ListView_SetItemText(g_app->hwnd_list, row_idx, 1, time_buf);
    ListView_SetItemText(g_app->hwnd_list, row_idx, 2, const_cast<char*>(pkt.src_ip.c_str()));
    ListView_SetItemText(g_app->hwnd_list, row_idx, 3, const_cast<char*>(pkt.dst_ip.c_str()));
    ListView_SetItemText(g_app->hwnd_list, row_idx, 4, const_cast<char*>(pkt.protocol.c_str()));
    ListView_SetItemText(g_app->hwnd_list, row_idx, 5, len_buf);
    ListView_SetItemText(g_app->hwnd_list, row_idx, 6, const_cast<char*>(pkt.info.c_str()));
}

void refresh_packet_list(bool preserve_selection = true) {
    uint32_t prev_num = 0;
    if (preserve_selection && g_app->selected_row >= 0 &&
        g_app->selected_row < static_cast<int>(g_app->displayed.size())) {
        prev_num = g_app->displayed[g_app->selected_row].number;
    }

    g_app->displayed = g_app->session.snapshot(g_app->active_filter);

    SendMessage(g_app->hwnd_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_app->hwnd_list);
    int new_sel = -1;
    for (size_t i = 0; i < g_app->displayed.size(); ++i) {
        append_listview_row(g_app->displayed[i], static_cast<int>(i));
        if (prev_num != 0 && g_app->displayed[i].number == prev_num) {
            new_sel = static_cast<int>(i);
        }
    }
    if (new_sel >= 0) {
        ListView_SetItemState(g_app->hwnd_list, new_sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else {
        populate_dissector_for_row(-1);
    }
    SendMessage(g_app->hwnd_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_app->hwnd_list, nullptr, TRUE);
    update_status_bar();
}

void sync_new_packets() {
    auto latest = g_app->session.snapshot(g_app->active_filter);
    if (latest.size() < g_app->displayed.size()) {
        refresh_packet_list(false);
        return;
    }
    for (size_t i = g_app->displayed.size(); i < latest.size(); ++i) {
        g_app->displayed.push_back(latest[i]);
        append_listview_row(latest[i], static_cast<int>(i));
    }
    if (!g_app->displayed.empty()) {
        ListView_EnsureVisible(g_app->hwnd_list, static_cast<int>(g_app->displayed.size()) - 1, FALSE);
    }
    update_status_bar();
}

// ============================================================================
// Built-in One-Click Live Demo Scenario (Runs BOOTP + Local DNS + Upstream)
// ============================================================================
void trigger_builtin_demo() {
    if (g_app->demo_running) return;
    g_app->demo_running = true;
    EnableWindow(g_app->hwnd_btn_dem, FALSE);

    std::thread([]() {
        try {
            DnsServerConfig up_cfg;
            up_cfg.listen_port = 0;
            up_cfg.server_ip   = "8.8.8.8";
            up_cfg.tap_port    = g_app->session.bound_port();
            DnsServer upstream(up_cfg);
            upstream.zones().add_a("dept.university.edu", "10.20.30.40", 60);
            std::thread up_t([&]() { upstream.run(false); });

            DnsServerConfig loc_cfg;
            loc_cfg.listen_port   = 0;
            loc_cfg.server_ip     = "192.168.10.2";
            loc_cfg.upstream_ip   = "127.0.0.1";
            loc_cfg.upstream_port = upstream.bound_port();
            loc_cfg.tap_port      = g_app->session.bound_port();
            DnsServer local_dns(loc_cfg);
            local_dns.zones().add_a("nas01.lab.local", "192.168.10.50", 120);
            local_dns.zones().add_cname("fileserver.lab.local", "nas01.lab.local", 120);
            local_dns.zones().add_ptr("192.168.10.50", "nas01.lab.local", 120);
            std::thread loc_t([&]() { local_dns.run(false); });

            BootpServerConfig bcfg;
            bcfg.listen_port = 0;
            bcfg.bind_ip     = "127.0.0.1";
            bcfg.dns_ip      = "192.168.10.2";
            bcfg.tap_port    = g_app->session.bound_port();
            BootpServer bootp_srv(bcfg);
            std::thread bootp_t([&]() { bootp_srv.run(false); });

            BootpClientOptions bopts;
            bopts.mac_str     = "00:1a:2b:3c:4d:5e";
            bopts.target_port = bootp_srv.bound_port();
            bopts.tap_port    = g_app->session.bound_port();
            bopts.verbose     = false;
            BootpClient bcli(bopts);
            auto net_cfg = bcli.acquire_configuration();

            if (net_cfg.valid) {
                DnsClientOptions dopts;
                dopts.logical_client_ip = ipv4_to_string(net_cfg.client_ip);
                dopts.logical_server_ip = ipv4_to_string(net_cfg.dns_ip);
                dopts.server_ip         = "127.0.0.1";
                dopts.server_port       = local_dns.bound_port();
                dopts.tap_port          = g_app->session.bound_port();
                dopts.verbose           = false;
                DnsClient dcli(dopts);

                dcli.resolve("fileserver.lab.local", DnsType::A);
                dcli.resolve("dept.university.edu", DnsType::A);
                dcli.resolve("dept.university.edu", DnsType::A); // Cache hit
                dcli.resolve(ipv4_to_ptr_name("192.168.10.50"), DnsType::PTR);
                dcli.resolve("unknown.lab.local", DnsType::A);  // NXDOMAIN
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            bootp_srv.stop();
            local_dns.stop();
            upstream.stop();
            bootp_t.join();
            loc_t.join();
            up_t.join();
        } catch (...) {}

        g_app->demo_running = false;
        if (g_app->hwnd_btn_dem) {
            EnableWindow(g_app->hwnd_btn_dem, TRUE);
        }
    }).detach();
}

// ============================================================================
// Layout & File Dialogs
// ============================================================================
void layout_controls(int w, int h) {
    if (!g_app || w <= 0 || h <= 0) return;

    SendMessage(g_app->hwnd_status, WM_SIZE, 0, 0);
    RECT sbar_rc{};
    GetWindowRect(g_app->hwnd_status, &sbar_rc);
    int status_h = sbar_rc.bottom - sbar_rc.top;

    const int pad = 6;
    const int bar_h = 28;
    int y = pad;

    // Row 1: Action Toolbar
    MoveWindow(g_app->hwnd_btn_cap, pad, y, 105, bar_h, TRUE);
    MoveWindow(g_app->hwnd_btn_clr, pad + 111, y, 70, bar_h, TRUE);
    MoveWindow(g_app->hwnd_btn_opn, pad + 187, y, 95, bar_h, TRUE);
    MoveWindow(g_app->hwnd_btn_sav, pad + 288, y, 95, bar_h, TRUE);
    MoveWindow(g_app->hwnd_btn_dem, pad + 395, y, 145, bar_h, TRUE);

    // Row 2: Display Filter Bar
    y += bar_h + pad;
    MoveWindow(g_app->hwnd_flt_lbl, pad, y + 4, 88, 22, TRUE);
    int btn_w = 65;
    int edit_w = std::max(120, w - pad * 4 - 88 - btn_w * 2 - 8);
    MoveWindow(g_app->hwnd_flt_edt, pad + 90, y + 1, edit_w, 24, TRUE);
    MoveWindow(g_app->hwnd_btn_apl, pad + 96 + edit_w, y, btn_w, 26, TRUE);
    MoveWindow(g_app->hwnd_btn_clf, pad + 96 + edit_w + btn_w + 4, y, btn_w, 26, TRUE);

    // Remaining vertical space split across 3 classic Wireshark panes (38% / 34% / 28%)
    int top_y = y + bar_h + pad;
    int avail_h = std::max(150, h - top_y - status_h - pad * 3);
    int pane1_h = (avail_h * 38) / 100;
    int pane2_h = (avail_h * 34) / 100;
    int pane3_h = avail_h - pane1_h - pane2_h;
    int pane_w  = std::max(200, w - pad * 2);

    MoveWindow(g_app->hwnd_list, pad, top_y, pane_w, pane1_h, TRUE);
    MoveWindow(g_app->hwnd_tree, pad, top_y + pane1_h + pad, pane_w, pane2_h, TRUE);
    MoveWindow(g_app->hwnd_hex,  pad, top_y + pane1_h + pad + pane2_h + pad, pane_w, pane3_h, TRUE);

    // Stretch Info column to fill remaining list width
    int fixed_cols = 45 + 82 + 125 + 125 + 65 + 58;
    int info_w = std::max(180, pane_w - fixed_cols - 24);
    ListView_SetColumnWidth(g_app->hwnd_list, 6, info_w);
    update_hex_scrollbar(g_app->hwnd_hex);
}

void start_capture() {
    g_app->session.start([](const DissectedPacket&) {
        if (g_app && g_app->hwnd_main) {
            PostMessage(g_app->hwnd_main, WM_APP_NEW_PACKET, 0, 0);
        }
    });
    SetWindowTextA(g_app->hwnd_btn_cap, "Stop Capture");
    update_status_bar();
}

void stop_capture() {
    g_app->session.stop();
    SetWindowTextA(g_app->hwnd_btn_cap, "Start Capture");
    update_status_bar();
}

void open_pcap_dialog() {
    char file_buf[MAX_PATH] = "";
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_app->hwnd_main;
    ofn.lpstrFilter = "PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = file_buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) {
        if (g_app->session.import_pcap(file_buf)) {
            refresh_packet_list(false);
        } else {
            MessageBoxA(g_app->hwnd_main, "Failed to load .pcap file.", "Mini-Wireshark", MB_ICONERROR);
        }
    }
}

void save_pcap_dialog() {
    char file_buf[MAX_PATH] = "capture.pcap";
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_app->hwnd_main;
    ofn.lpstrFilter = "PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = file_buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = "pcap";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (GetSaveFileNameA(&ofn)) {
        if (!g_app->session.export_pcap(file_buf)) {
            MessageBoxA(g_app->hwnd_main, "Failed to save .pcap file.", "Mini-Wireshark", MB_ICONERROR);
        }
    }
}

// ============================================================================
// Main Window Procedure
// ============================================================================
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_app->hwnd_main = hwnd;
            HINSTANCE hInst = GetModuleHandle(nullptr);

            g_app->ui_font = CreateFontA(
                16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
            g_app->mono_font = CreateFontA(
                16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

            auto make_ctrl = [&](const char* cls, const char* txt, DWORD style, DWORD ex, int id) {
                HWND h = CreateWindowExA(ex, cls, txt, WS_CHILD | WS_VISIBLE | style,
                                         0, 0, 10, 10, hwnd,
                                         reinterpret_cast<HMENU>(static_cast<intptr_t>(id)),
                                         hInst, nullptr);
                SendMessage(h, WM_SETFONT, reinterpret_cast<WPARAM>(g_app->ui_font), TRUE);
                return h;
            };

            g_app->hwnd_btn_cap = make_ctrl("BUTTON", "Stop Capture", BS_PUSHBUTTON, 0, ID_BTN_TOGGLE_CAP);
            g_app->hwnd_btn_clr = make_ctrl("BUTTON", "Clear", BS_PUSHBUTTON, 0, ID_BTN_CLEAR);
            g_app->hwnd_btn_opn = make_ctrl("BUTTON", "Open .pcap", BS_PUSHBUTTON, 0, ID_BTN_OPEN_PCAP);
            g_app->hwnd_btn_sav = make_ctrl("BUTTON", "Save .pcap", BS_PUSHBUTTON, 0, ID_BTN_SAVE_PCAP);
            g_app->hwnd_btn_dem = make_ctrl("BUTTON", "Run BOOTP+DNS Demo", BS_PUSHBUTTON, 0, ID_BTN_RUN_DEMO);

            g_app->hwnd_flt_lbl = make_ctrl("STATIC", "Display Filter:", SS_LEFT, 0, 0);
            g_app->hwnd_flt_edt = make_ctrl("EDIT", "", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_EDIT_FILTER);
            g_orig_edit_proc = reinterpret_cast<WNDPROC>(
                SetWindowLongPtrA(g_app->hwnd_flt_edt, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(FilterEditProc)));
            SendMessageA(g_app->hwnd_flt_edt, EM_SETCUEBANNER, TRUE,
                         reinterpret_cast<LPARAM>(L"e.g. bootp, dns, ip == 192.168.10.2, port == 9053"));
            g_app->hwnd_btn_apl = make_ctrl("BUTTON", "Apply", BS_PUSHBUTTON, 0, ID_BTN_APPLY_FLT);
            g_app->hwnd_btn_clf = make_ctrl("BUTTON", "Reset", BS_PUSHBUTTON, 0, ID_BTN_CLEAR_FLT);

            g_app->hwnd_list = make_ctrl(
                WC_LISTVIEWA, "",
                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER,
                WS_EX_CLIENTEDGE, ID_LIST_PACKETS);
            ListView_SetExtendedListViewStyle(
                g_app->hwnd_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

            const char* cols[] = {"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
            const int widths[] = {45, 82, 125, 125, 65, 58, 360};
            for (int c = 0; c < 7; ++c) {
                LVCOLUMNA lvc{};
                lvc.mask    = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
                lvc.cx      = widths[c];
                lvc.pszText = const_cast<char*>(cols[c]);
                ListView_InsertColumn(g_app->hwnd_list, c, &lvc);
            }

            g_app->hwnd_tree = make_ctrl(
                WC_TREEVIEWA, "",
                TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | WS_BORDER,
                WS_EX_CLIENTEDGE, ID_TREE_DISSECT);

            g_app->hwnd_hex = CreateWindowExA(
                WS_EX_CLIENTEDGE, HEX_VIEW_CLASS, "",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL,
                0, 0, 10, 10, hwnd,
                reinterpret_cast<HMENU>(static_cast<intptr_t>(ID_HEX_VIEW)),
                hInst, nullptr);

            g_app->hwnd_status = CreateWindowExA(
                0, STATUSCLASSNAMEA, "",
                WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                0, 0, 0, 0, hwnd,
                reinterpret_cast<HMENU>(static_cast<intptr_t>(ID_STATUS_BAR)),
                hInst, nullptr);

            start_capture();
            return 0;
        }
        case WM_SIZE: {
            layout_controls(LOWORD(lParam), HIWORD(lParam));
            return 0;
        }
        case WM_APP_NEW_PACKET: {
            sync_new_packets();
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BTN_TOGGLE_CAP:
                    if (g_app->session.is_running()) stop_capture();
                    else start_capture();
                    break;
                case ID_BTN_CLEAR:
                    g_app->session.clear();
                    refresh_packet_list(false);
                    break;
                case ID_BTN_OPEN_PCAP:
                    open_pcap_dialog();
                    break;
                case ID_BTN_SAVE_PCAP:
                    save_pcap_dialog();
                    break;
                case ID_BTN_RUN_DEMO:
                    if (!g_app->session.is_running()) start_capture();
                    trigger_builtin_demo();
                    break;
                case ID_BTN_APPLY_FLT: {
                    char buf[256]{};
                    GetWindowTextA(g_app->hwnd_flt_edt, buf, sizeof(buf));
                    g_app->active_filter = buf;
                    refresh_packet_list(false);
                    break;
                }
                case ID_BTN_CLEAR_FLT:
                    SetWindowTextA(g_app->hwnd_flt_edt, "");
                    g_app->active_filter.clear();
                    refresh_packet_list(false);
                    break;
            }
            return 0;
        }
        case WM_NOTIFY: {
            NMHDR* nm = reinterpret_cast<NMHDR*>(lParam);
            if (nm->idFrom == ID_LIST_PACKETS) {
                if (nm->code == LVN_ITEMCHANGED) {
                    NMLISTVIEW* pnmv = reinterpret_cast<NMLISTVIEW*>(lParam);
                    if ((pnmv->uNewState & LVIS_SELECTED) && !(pnmv->uOldState & LVIS_SELECTED)) {
                        populate_dissector_for_row(pnmv->iItem);
                    }
                } else if (nm->code == NM_CUSTOMDRAW) {
                    NMLVCUSTOMDRAW* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
                    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) {
                        return CDRF_NOTIFYITEMDRAW;
                    }
                    if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                        int idx = static_cast<int>(cd->nmcd.dwItemSpec);
                        if (idx >= 0 && idx < static_cast<int>(g_app->displayed.size())) {
                            const auto& pkt = g_app->displayed[idx];
                            if (pkt.info.find("NXDOMAIN") != std::string::npos ||
                                pkt.info.find("SERVFAIL") != std::string::npos) {
                                cd->clrTextBk = RGB(255, 224, 224); // Light red for errors
                            } else if (pkt.protocol == "BOOTP") {
                                cd->clrTextBk = RGB(232, 248, 225); // Wireshark mint-green for BOOTP
                            } else if (pkt.protocol == "DNS") {
                                cd->clrTextBk = RGB(224, 240, 255); // Wireshark sky-blue for DNS
                            } else {
                                cd->clrTextBk = RGB(242, 242, 248);
                            }
                            cd->clrText = RGB(20, 25, 35);
                        }
                        return CDRF_NEWFONT;
                    }
                }
            } else if (nm->idFrom == ID_TREE_DISSECT && nm->code == TVN_SELCHANGED) {
                NMTREEVIEWA* ptv = reinterpret_cast<NMTREEVIEWA*>(lParam);
                auto* span = reinterpret_cast<ByteSpan*>(ptv->itemNew.lParam);
                if (span) {
                    g_app->highlight_offset = span->offset;
                    g_app->highlight_length = span->length;
                    scroll_hex_to_highlight(g_app->hwnd_hex);
                    InvalidateRect(g_app->hwnd_hex, nullptr, TRUE);
                    update_status_bar();
                }
            }
            return 0;
        }
        case WM_DESTROY: {
            g_app->session.stop();
            if (g_app->ui_font) DeleteObject(g_app->ui_font);
            if (g_app->mono_font) DeleteObject(g_app->mono_font);
            PostQuitMessage(0);
            return 0;
        }
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
}

} // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;

    SetProcessDPIAware();
    SocketRuntime runtime;

    INITCOMMONCONTROLSEX icex{};
    icex.dwSize = sizeof(icex);
    icex.dwICC  = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    AppState app;
    g_app = &app;

    WNDCLASSA hex_wc{};
    hex_wc.lpfnWndProc   = HexViewProc;
    hex_wc.hInstance     = hInstance;
    hex_wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    hex_wc.lpszClassName = HEX_VIEW_CLASS;
    RegisterClassA(&hex_wc);

    WNDCLASSA main_wc{};
    main_wc.lpfnWndProc   = MainWndProc;
    main_wc.hInstance     = hInstance;
    main_wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    main_wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    main_wc.lpszClassName = "MiniWiresharkMain";
    RegisterClassA(&main_wc);

    HWND hwnd = CreateWindowExA(
        0, "MiniWiresharkMain",
        "Mini-Wireshark — Custom BOOTP & DNS Protocol Analyzer",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1120, 760,
        nullptr, nullptr, hInstance, nullptr);

    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return static_cast<int>(msg.wParam);
}
