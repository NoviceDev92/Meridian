#pragma once

#include "protocol_headers.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socket_handle_t = SOCKET;
  constexpr socket_handle_t INVALID_SOCK = INVALID_SOCKET;
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using socket_handle_t = int;
  constexpr socket_handle_t INVALID_SOCK = -1;
#endif

namespace netproto {

class SocketRuntime {
public:
    SocketRuntime() {
#ifdef _WIN32
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }
    ~SocketRuntime() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
    SocketRuntime(const SocketRuntime&) = delete;
    SocketRuntime& operator=(const SocketRuntime&) = delete;
};

inline uint64_t current_time_us() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

class UdpSocket {
public:
    UdpSocket() {
        sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_ == INVALID_SOCK) {
            throw std::runtime_error("Failed to create UDP socket");
        }
        int opt = 1;
#ifdef _WIN32
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    }

    ~UdpSocket() { close(); }

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    UdpSocket(UdpSocket&& other) noexcept : sock_(other.sock_) {
        other.sock_ = INVALID_SOCK;
    }

    UdpSocket& operator=(UdpSocket&& other) noexcept {
        if (this != &other) {
            close();
            sock_ = other.sock_;
            other.sock_ = INVALID_SOCK;
        }
        return *this;
    }

    void close() {
        if (sock_ != INVALID_SOCK) {
#ifdef _WIN32
            closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCK;
        }
    }

    void bind(uint16_t port, const std::string& ip = "0.0.0.0") {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (ip == "0.0.0.0" || ip.empty()) {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        }
        if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            throw std::runtime_error("Failed to bind UDP socket on port " + std::to_string(port));
        }
    }

    void enable_broadcast(bool enable = true) {
        int val = enable ? 1 : 0;
#ifdef _WIN32
        setsockopt(sock_, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&val), sizeof(val));
#else
        setsockopt(sock_, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
#endif
    }

    void set_timeout_ms(uint32_t timeout_ms) {
#ifdef _WIN32
        DWORD tv = timeout_ms;
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        timeval tv{};
        tv.tv_sec  = static_cast<long>(timeout_ms / 1000);
        tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    bool send_to(const std::vector<uint8_t>& data, const std::string& dst_ip, uint16_t dst_port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(dst_port);
        inet_pton(AF_INET, dst_ip.c_str(), &addr.sin_addr);

        int sent = ::sendto(sock_,
                            reinterpret_cast<const char*>(data.data()),
                            static_cast<int>(data.size()),
                            0,
                            reinterpret_cast<sockaddr*>(&addr),
                            sizeof(addr));
        return sent == static_cast<int>(data.size());
    }

    // Returns bytes received, 0 on timeout, -1 on error
    int recv_from(std::vector<uint8_t>& out_buf,
                  std::string& out_src_ip,
                  uint16_t& out_src_port,
                  size_t max_len = 4096) {
        out_buf.resize(max_len);
        sockaddr_in sender{};
#ifdef _WIN32
        int sender_len = sizeof(sender);
#else
        socklen_t sender_len = sizeof(sender);
#endif
        int recvd = ::recvfrom(sock_,
                               reinterpret_cast<char*>(out_buf.data()),
                               static_cast<int>(max_len),
                               0,
                               reinterpret_cast<sockaddr*>(&sender),
                               &sender_len);
        if (recvd < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                out_buf.clear();
                return 0;
            }
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                out_buf.clear();
                return 0;
            }
#endif
            out_buf.clear();
            return -1;
        }
        out_buf.resize(static_cast<size_t>(recvd));
        char ip_str[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &sender.sin_addr, ip_str, sizeof(ip_str));
        out_src_ip   = ip_str;
        out_src_port = ntohs(sender.sin_port);
        return recvd;
    }

    uint16_t local_port() const {
        sockaddr_in addr{};
#ifdef _WIN32
        int len = sizeof(addr);
#else
        socklen_t len = sizeof(addr);
#endif
        if (getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
            return ntohs(addr.sin_port);
        }
        return 0;
    }

private:
    socket_handle_t sock_ = INVALID_SOCK;
};

// ============================================================================
// Software Tap Client: Mirrors packets to Mini-Wireshark on 127.0.0.1:9999
// ============================================================================
class TapMirror {
public:
    explicit TapMirror(uint16_t sniffer_port = TAP_SNIFFER_PORT,
                       std::string sniffer_ip = "127.0.0.1")
        : sniffer_port_(sniffer_port), sniffer_ip_(std::move(sniffer_ip)) {}

    void emit(const std::string& src_ip,
              uint16_t src_port,
              const std::string& dst_ip,
              uint16_t dst_port,
              AppProtoHint hint,
              const std::vector<uint8_t>& payload,
              const std::array<uint8_t, 6>& src_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
              const std::array<uint8_t, 6>& dst_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
        TapEnvelope env;
        env.timestamp_us = current_time_us();
        env.src_ip       = ipv4_from_string(src_ip);
        env.dst_ip       = ipv4_from_string(dst_ip);
        env.src_port     = src_port;
        env.dst_port     = dst_port;
        env.proto_hint   = static_cast<uint8_t>(hint);
        env.src_mac      = src_mac;
        env.dst_mac      = dst_mac;
        env.payload      = payload;

        sock_.send_to(env.serialize_tap(), sniffer_ip_, sniffer_port_);
    }

private:
    UdpSocket sock_;
    uint16_t sniffer_port_;
    std::string sniffer_ip_;
};

} // namespace netproto

