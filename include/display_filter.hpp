#pragma once
// ============================================================================
// Wireshark-style Display Filter Engine
// ----------------------------------------------------------------------------
// Grammar (recursive descent, lowest precedence first):
//
//   expr       := or_expr
//   or_expr    := and_expr  ( ("||" | "or")  and_expr )*
//   and_expr   := unary     ( ("&&" | "and") unary    )*
//   unary      := ("!" | "not") unary | primary
//   primary    := "(" expr ")" | test
//   test       := FIELD [ RELOP VALUE ]
//   RELOP      := == | != | > | < | >= | <= | eq | ne | gt | lt | ge | le
//               | contains | matches
//
// A bare FIELD is a presence test ("dns", "bootp.option.router").
// Values may be numbers (10, 0x1a), IPv4 addresses, CIDR blocks
// (192.168.10.0/24), MAC addresses, bare words or "quoted strings".
//
// Semantics follow Wireshark: a field can occur several times in a packet
// (ip.addr = source AND destination), "==" is true if ANY occurrence matches,
// "!=" is true only if the field is present and NO occurrence matches.
//
// Backwards compatible with the original Mini-Wireshark syntax:
//   "ipv4" -> ip,  "ip == X" -> ip.addr == X,  "port == N" -> udp.port == N,
//   bare "eth" -> !ip (frames not dissected beyond Ethernet, as before),
//   and any text that is not a valid filter falls back to a substring search.
// ============================================================================

#include "dissector.hpp"

#include <cstdlib>
#include <memory>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace netproto {

class DisplayFilter {
public:
    DisplayFilter() = default;

    // Never throws: check valid() / error() afterwards.
    static DisplayFilter compile(const std::string& text) {
        DisplayFilter f;
        f.text_ = trim(text);
        if (f.text_.empty()) return f;
        // Legacy: in the original Mini-Wireshark the bare filter "eth" meant
        // "frames with nothing dissected above Ethernet". Keep that meaning
        // (in Wireshark syntax: !ip) so old usage behaves exactly as before.
        std::string source = (lower(f.text_) == "eth") ? std::string("!ip") : f.text_;
        try {
            Parser p(tokenize(source));
            f.root_ = p.parse_expr();
            if (!p.at_end()) {
                throw std::runtime_error("Unexpected \"" + p.peek().text + "\"");
            }
        } catch (const std::exception& ex) {
            f.root_.reset();
            f.error_ = ex.what();
        }
        return f;
    }

    bool empty() const { return text_.empty(); }
    bool valid() const { return error_.empty(); }
    const std::string& error() const { return error_; }
    const std::string& text() const { return text_; }

    bool matches(const DissectedPacket& pkt) const {
        if (empty()) return true;
        if (!valid()) return legacy_text_search(pkt, text_);
        return eval(*root_, pkt);
    }

    // Original Mini-Wireshark fallback: substring over protocol/IPs/info.
    static bool legacy_text_search(const DissectedPacket& pkt, const std::string& raw) {
        std::string f = lower(trim(raw));
        return lower(pkt.protocol).find(f) != std::string::npos ||
               pkt.src_ip.find(f) != std::string::npos ||
               pkt.dst_ip.find(f) != std::string::npos ||
               lower(pkt.info).find(f) != std::string::npos;
    }

    // Every field abbreviation the dissector/tracker can emit.
    static const std::set<std::string>& known_fields() {
        static const std::set<std::string> k = {
            "frame", "frame.time", "frame.time_epoch", "frame.time_relative", "frame.number",
            "frame.len", "frame.protocols",
            "eth", "eth.dst", "eth.src", "eth.addr", "eth.type",
            "ip", "ip.version", "ip.hdr_len", "ip.dsfield", "ip.len", "ip.id", "ip.flags.rb",
            "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto", "ip.checksum",
            "ip.checksum.status", "ip.src", "ip.dst", "ip.addr",
            "udp", "udp.srcport", "udp.dstport", "udp.port", "udp.length", "udp.checksum",
            "udp.checksum.status",
            "bootp", "dhcp", "bootp.type", "bootp.hw.type", "bootp.hw.len", "bootp.hops", "bootp.id",
            "bootp.secs", "bootp.flags.bc", "bootp.flags.reserved", "bootp.ip.client", "bootp.ip.your",
            "bootp.ip.server", "bootp.ip.relay", "bootp.hw.mac_addr", "bootp.server", "bootp.file",
            "bootp.cookie", "bootp.option.type", "bootp.option.subnet_mask", "bootp.option.router",
            "bootp.option.domain_name_server", "bootp.option.hostname", "bootp.option.domain_name",
            "bootp.option.broadcast_address", "bootp.option.requested_ip_address",
            "bootp.option.ip_address_lease_time", "bootp.option.dhcp", "bootp.option.dhcp_server_id",
            "bootp.response_in", "bootp.response_to", "bootp.time", "bootp.retransmission",
            "dns", "dns.id", "dns.flags.response", "dns.flags.opcode", "dns.flags.authoritative",
            "dns.flags.truncated", "dns.flags.recdesired", "dns.flags.recavail", "dns.flags.z",
            "dns.flags.rcode", "dns.count.queries", "dns.count.answers", "dns.count.auth_rr",
            "dns.count.add_rr", "dns.qry.name", "dns.qry.type", "dns.qry.class", "dns.a", "dns.aaaa",
            "dns.cname", "dns.ptr.domain_name", "dns.ns", "dns.mx.mail_exchange", "dns.txt",
            "dns.resp.name", "dns.resp.type", "dns.resp.ttl",
            "dns.response_in", "dns.response_to", "dns.time", "dns.retransmission",
            "dns.retransmit_request_in",
            "_ws.malformed", "_ws.expert", "_ws.expert.severity",
        };
        return k;
    }

private:
    // ------------------------------------------------------------------------
    // AST
    // ------------------------------------------------------------------------
    struct Node {
        enum class Kind { AND, OR, NOT, TEST } kind = Kind::TEST;
        std::string field;   // TEST
        std::string op;      // TEST: "", "==", "!=", ">", "<", ">=", "<=", "contains", "matches"
        std::string value;   // TEST
        std::shared_ptr<std::regex> re;
        std::shared_ptr<Node> a, b;
    };

    struct Token {
        enum class Type { WORD, STRING, OP, LPAREN, RPAREN, AND, OR, NOT, END } type = Type::END;
        std::string text;
    };

    // ------------------------------------------------------------------------
    // Tokenizer
    // ------------------------------------------------------------------------
    static std::vector<Token> tokenize(const std::string& s) {
        std::vector<Token> out;
        size_t i = 0;
        auto is_word_ch = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' ||
                   c == ':' || c == '/' || c == '-';
        };
        while (i < s.size()) {
            char c = s[i];
            if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
            if (c == '(') { out.push_back({Token::Type::LPAREN, "("}); ++i; continue; }
            if (c == ')') { out.push_back({Token::Type::RPAREN, ")"}); ++i; continue; }
            if (s.compare(i, 2, "&&") == 0) { out.push_back({Token::Type::AND, "&&"}); i += 2; continue; }
            if (s.compare(i, 2, "||") == 0) { out.push_back({Token::Type::OR, "||"}); i += 2; continue; }
            if (s.compare(i, 2, "==") == 0 || s.compare(i, 2, "!=") == 0 ||
                s.compare(i, 2, ">=") == 0 || s.compare(i, 2, "<=") == 0) {
                out.push_back({Token::Type::OP, s.substr(i, 2)}); i += 2; continue;
            }
            if (c == '!') { out.push_back({Token::Type::NOT, "!"}); ++i; continue; }
            if (c == '>' || c == '<') { out.push_back({Token::Type::OP, std::string(1, c)}); ++i; continue; }
            if (c == '=') { out.push_back({Token::Type::OP, "=="}); ++i; continue; } // tolerate single '='
            if (c == '"') {
                std::string v;
                ++i;
                while (i < s.size() && s[i] != '"') {
                    if (s[i] == '\\' && i + 1 < s.size()) ++i;
                    v.push_back(s[i++]);
                }
                if (i >= s.size()) throw std::runtime_error("Missing closing quote");
                ++i;
                out.push_back({Token::Type::STRING, v});
                continue;
            }
            if (is_word_ch(c)) {
                size_t j = i;
                while (j < s.size() && is_word_ch(s[j])) ++j;
                std::string w = s.substr(i, j - i);
                std::string lw = lower(w);
                if (lw == "and")      out.push_back({Token::Type::AND, w});
                else if (lw == "or")  out.push_back({Token::Type::OR, w});
                else if (lw == "not") out.push_back({Token::Type::NOT, w});
                else if (lw == "eq")  out.push_back({Token::Type::OP, "=="});
                else if (lw == "ne")  out.push_back({Token::Type::OP, "!="});
                else if (lw == "gt")  out.push_back({Token::Type::OP, ">"});
                else if (lw == "lt")  out.push_back({Token::Type::OP, "<"});
                else if (lw == "ge")  out.push_back({Token::Type::OP, ">="});
                else if (lw == "le")  out.push_back({Token::Type::OP, "<="});
                else if (lw == "contains") out.push_back({Token::Type::OP, "contains"});
                else if (lw == "matches")  out.push_back({Token::Type::OP, "matches"});
                else out.push_back({Token::Type::WORD, w});
                i = j;
                continue;
            }
            throw std::runtime_error(std::string("Unexpected character '") + c + "'");
        }
        return out;
    }

    // ------------------------------------------------------------------------
    // Parser
    // ------------------------------------------------------------------------
    class Parser {
    public:
        explicit Parser(std::vector<Token> t) : toks_(std::move(t)) {}

        bool at_end() const { return pos_ >= toks_.size(); }
        const Token& peek() const {
            static const Token end_tok{};
            return at_end() ? end_tok : toks_[pos_];
        }

        std::shared_ptr<Node> parse_expr() { return parse_or(); }

    private:
        std::shared_ptr<Node> parse_or() {
            auto left = parse_and();
            while (peek().type == Token::Type::OR) {
                ++pos_;
                auto n = std::make_shared<Node>();
                n->kind = Node::Kind::OR;
                n->a = left;
                n->b = parse_and();
                left = n;
            }
            return left;
        }

        std::shared_ptr<Node> parse_and() {
            auto left = parse_unary();
            while (peek().type == Token::Type::AND) {
                ++pos_;
                auto n = std::make_shared<Node>();
                n->kind = Node::Kind::AND;
                n->a = left;
                n->b = parse_unary();
                left = n;
            }
            return left;
        }

        std::shared_ptr<Node> parse_unary() {
            if (peek().type == Token::Type::NOT) {
                ++pos_;
                auto n = std::make_shared<Node>();
                n->kind = Node::Kind::NOT;
                n->a = parse_unary();
                return n;
            }
            return parse_primary();
        }

        std::shared_ptr<Node> parse_primary() {
            if (at_end()) throw std::runtime_error("Unexpected end of filter");
            if (peek().type == Token::Type::LPAREN) {
                ++pos_;
                auto inner = parse_or();
                if (peek().type != Token::Type::RPAREN) throw std::runtime_error("Missing closing ')'");
                ++pos_;
                return inner;
            }
            if (peek().type != Token::Type::WORD) {
                throw std::runtime_error("Expected a field name, got \"" + peek().text + "\"");
            }
            auto n = std::make_shared<Node>();
            n->kind = Node::Kind::TEST;
            std::string raw = toks_[pos_++].text;
            bool has_op = (peek().type == Token::Type::OP);
            n->field = resolve_field(raw, has_op);
            if (has_op) {
                n->op = toks_[pos_++].text;
                if (at_end() || (peek().type != Token::Type::WORD && peek().type != Token::Type::STRING)) {
                    throw std::runtime_error("Missing value after \"" + n->op + "\"");
                }
                n->value = toks_[pos_++].text;
                if (n->op == "matches") {
                    try {
                        n->re = std::make_shared<std::regex>(n->value, std::regex::icase);
                    } catch (const std::regex_error&) {
                        throw std::runtime_error("Invalid regular expression \"" + n->value + "\"");
                    }
                }
            }
            return n;
        }

        static std::string resolve_field(const std::string& raw, bool has_op) {
            std::string f = lower(raw);
            // Legacy / convenience aliases
            if (f == "ipv4") f = "ip";
            if (f == "ip" && has_op) f = "ip.addr";
            if (f == "port") f = "udp.port";
            if (f == "eth" && has_op) f = "eth.addr";
            if (f.rfind("dhcp.", 0) == 0) f = "bootp." + f.substr(5);
            if (!known_fields().count(f)) {
                throw std::runtime_error("\"" + raw + "\" is neither a field nor a protocol name");
            }
            return f;
        }

        std::vector<Token> toks_;
        size_t pos_ = 0;
    };

    // ------------------------------------------------------------------------
    // Evaluation
    // ------------------------------------------------------------------------
    static bool eval(const Node& n, const DissectedPacket& pkt) {
        switch (n.kind) {
            case Node::Kind::AND: return eval(*n.a, pkt) && eval(*n.b, pkt);
            case Node::Kind::OR:  return eval(*n.a, pkt) || eval(*n.b, pkt);
            case Node::Kind::NOT: return !eval(*n.a, pkt);
            case Node::Kind::TEST: break;
        }
        auto range = pkt.fields.equal_range(n.field);
        if (range.first == range.second) return false;  // absent field: every test fails
        if (n.op.empty()) return true;                   // presence test

        if (n.op == "!=") {
            for (auto it = range.first; it != range.second; ++it) {
                if (equals(it->second, n.value)) return false;
            }
            return true;
        }
        for (auto it = range.first; it != range.second; ++it) {
            if (compare(it->second, n)) return true;
        }
        return false;
    }

    static bool compare(const std::string& fv, const Node& n) {
        if (n.op == "==") return equals(fv, n.value);
        if (n.op == "contains") return fv.find(n.value) != std::string::npos;
        if (n.op == "matches") return n.re && std::regex_search(fv, *n.re);
        double a = 0, b = 0;
        if (!to_number(fv, a) || !to_number(n.value, b)) return false;
        if (n.op == ">")  return a > b;
        if (n.op == "<")  return a < b;
        if (n.op == ">=") return a >= b;
        if (n.op == "<=") return a <= b;
        return false;
    }

    static bool equals(const std::string& fv, const std::string& want) {
        // CIDR block: ip.addr == 192.168.10.0/24
        auto slash = want.find('/');
        if (slash != std::string::npos) {
            uint32_t net = 0, ip = 0;
            int bits = std::atoi(want.c_str() + slash + 1);
            if (parse_ip(want.substr(0, slash), net) && parse_ip(fv, ip) && bits >= 0 && bits <= 32) {
                uint32_t mask = bits == 0 ? 0 : (0xFFFFFFFFu << (32 - bits));
                return (ip & mask) == (net & mask);
            }
        }
        double a = 0, b = 0;
        if (to_number(fv, a) && to_number(want, b)) return a == b;
        return lower(fv) == lower(want);
    }

    static bool parse_ip(const std::string& s, uint32_t& out) {
        try { out = ipv4_from_string(s); return true; } catch (...) { return false; }
    }

    static bool to_number(const std::string& s, double& out) {
        if (s.empty()) return false;
        std::string l = lower(s);
        if (l == "true")  { out = 1; return true; }
        if (l == "false") { out = 0; return true; }
        char* end = nullptr;
        if (l.size() > 2 && l[0] == '0' && l[1] == 'x') {
            unsigned long long v = std::strtoull(l.c_str() + 2, &end, 16);
            if (*end != '\0') return false;
            out = static_cast<double>(v);
            return true;
        }
        out = std::strtod(l.c_str(), &end);
        return end && *end == '\0';
    }

    static std::string lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    static std::string trim(const std::string& s) {
        size_t l = 0, r = s.size();
        while (l < r && std::isspace(static_cast<unsigned char>(s[l]))) ++l;
        while (r > l && std::isspace(static_cast<unsigned char>(s[r - 1]))) --r;
        return s.substr(l, r - l);
    }

    std::string text_;
    std::string error_;
    std::shared_ptr<Node> root_;
};

inline bool PacketDissector::matches_filter(const DissectedPacket& pkt, const std::string& raw_filter) {
    return DisplayFilter::compile(raw_filter).matches(pkt);
}

} // namespace netproto
