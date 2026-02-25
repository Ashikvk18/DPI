// DPI Engine v3.0 - With Web Dashboard, Threat Detection & Bandwidth Monitoring
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <unordered_set>
#include <algorithm>
#include <thread>
#include <chrono>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include "threat_detector.h"
#include "bandwidth_monitor.h"
#include "report_exporter.h"
#include "web_server.h"

using namespace PacketAnalyzer;
using namespace DPI;

// ============================================================================
// Simplified connection tracking (same as main_working.cpp)
// ============================================================================
struct Flow {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
};

// ============================================================================
// Blocking rules
// ============================================================================
class BlockingRules {
public:
    std::unordered_set<uint32_t> blocked_ips;
    std::unordered_set<AppType> blocked_apps;
    std::vector<std::string> blocked_domains;
    mutable std::mutex mutex_;

    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t addr = parseIP(ip);
        blocked_ips.insert(addr);
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }

    void unblockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t addr = parseIP(ip);
        blocked_ips.erase(addr);
        std::cout << "[Rules] Unblocked IP: " << ip << "\n";
    }

    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }

    void unblockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps.erase(static_cast<AppType>(i));
                std::cout << "[Rules] Unblocked app: " << app << "\n";
                return;
            }
        }
    }

    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }

    void unblockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find(blocked_domains.begin(), blocked_domains.end(), domain);
        if (it != blocked_domains.end()) {
            blocked_domains.erase(it);
            std::cout << "[Rules] Unblocked domain: " << domain << "\n";
        }
    }

    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips.count(src_ip)) return true;
        if (blocked_apps.count(app)) return true;
        for (const auto& dom : blocked_domains) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

    std::vector<std::string> getBlockedIPStrings() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        for (uint32_t ip : blocked_ips) {
            result.push_back(ipToStr(ip));
        }
        return result;
    }

    std::vector<std::string> getBlockedAppStrings() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        for (auto app : blocked_apps) {
            result.push_back(appTypeToString(app));
        }
        return result;
    }

    std::vector<std::string> getBlockedDomainStrings() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_domains;
    }

    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }

    static std::string ipToStr(uint32_t ip) {
        std::ostringstream ss;
        ss << ((ip >> 0) & 0xFF) << "."
           << ((ip >> 8) & 0xFF) << "."
           << ((ip >> 16) & 0xFF) << "."
           << ((ip >> 24) & 0xFF);
        return ss.str();
    }
};

// ============================================================================
// Global state accessible by web server
// ============================================================================
struct GlobalState {
    DPIStats stats;
    BlockingRules rules;
    ThreatDetector threat_detector;
    BandwidthMonitor bandwidth_monitor;
    std::vector<Connection> connections;
    mutable std::mutex conn_mutex;
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;
    mutable std::mutex flow_mutex;
    bool processing_done = false;

    void updateConnections() {
        std::lock_guard<std::mutex> lock_f(flow_mutex);
        std::lock_guard<std::mutex> lock_c(conn_mutex);
        connections.clear();
        for (const auto& [tuple, flow] : flows) {
            Connection c;
            c.tuple = tuple;
            c.app_type = flow.app_type;
            c.sni = flow.sni;
            c.packets_out = flow.packets;
            c.bytes_out = flow.bytes;
            if (flow.blocked) {
                c.state = ConnectionState::BLOCKED;
            } else if (flow.app_type != AppType::UNKNOWN) {
                c.state = ConnectionState::CLASSIFIED;
            } else {
                c.state = ConnectionState::ESTABLISHED;
            }
            connections.push_back(c);
        }
    }

    std::vector<Connection> getConnections() const {
        std::lock_guard<std::mutex> lock(conn_mutex);
        return connections;
    }
};

// ============================================================================
// Usage
// ============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine v3.0 - Deep Packet Inspection with Web Dashboard
=============================================================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --port <port>          Web dashboard port (default: 8080)
  --no-dashboard         Run without web dashboard

Example:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube --port 8080
)";
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];
    int web_port = 8080;
    bool use_dashboard = true;

    GlobalState state;

    // Parse options
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            state.rules.blockIP(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            state.rules.blockApp(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            state.rules.blockDomain(argv[++i]);
        } else if (arg == "--port" && i + 1 < argc) {
            web_port = std::stoi(argv[++i]);
        } else if (arg == "--no-dashboard") {
            use_dashboard = false;
        }
    }

    std::cout << "\n";
    std::cout << "================================================================\n";
    std::cout << "       DPI ENGINE v3.0 - Deep Packet Inspection System\n";
    std::cout << "       With Threat Detection, Bandwidth Monitor & Web UI\n";
    std::cout << "================================================================\n\n";

    // --- Set up web server callbacks ---
    WebServerCallbacks callbacks;
    callbacks.getStats = [&]() -> StatsSnapshot {
        StatsSnapshot snap;
        snap.total_packets = state.stats.total_packets.load();
        snap.total_bytes = state.stats.total_bytes.load();
        snap.forwarded_packets = state.stats.forwarded_packets.load();
        snap.dropped_packets = state.stats.dropped_packets.load();
        snap.tcp_packets = state.stats.tcp_packets.load();
        snap.udp_packets = state.stats.udp_packets.load();
        snap.other_packets = state.stats.other_packets.load();
        snap.active_connections = state.stats.active_connections.load();
        return snap;
    };
    callbacks.getAlerts = [&]() { return state.threat_detector.getAlerts(); };
    callbacks.getThreatStats = [&]() { return state.threat_detector.getStats(); };
    callbacks.getAppBandwidth = [&]() { return state.bandwidth_monitor.getAppBandwidth(); };
    callbacks.getTopTalkers = [&]() { return state.bandwidth_monitor.getTopTalkers(10); };
    callbacks.getProtocolStats = [&]() { return state.bandwidth_monitor.getProtocolStats(); };
    callbacks.getOverallStats = [&]() { return state.bandwidth_monitor.getOverallStats(); };
    callbacks.getTimeSeries = [&]() { return state.bandwidth_monitor.getTimeSeries(); };
    callbacks.getConnections = [&]() { return state.getConnections(); };
    callbacks.getBlockedIPs = [&]() { return state.rules.getBlockedIPStrings(); };
    callbacks.getBlockedApps = [&]() { return state.rules.getBlockedAppStrings(); };
    callbacks.getBlockedDomains = [&]() { return state.rules.getBlockedDomainStrings(); };
    callbacks.blockIP = [&](const std::string& ip) { state.rules.blockIP(ip); };
    callbacks.unblockIP = [&](const std::string& ip) { state.rules.unblockIP(ip); };
    callbacks.blockApp = [&](const std::string& app) { state.rules.blockApp(app); };
    callbacks.unblockApp = [&](const std::string& app) { state.rules.unblockApp(app); };
    callbacks.blockDomain = [&](const std::string& dom) { state.rules.blockDomain(dom); };
    callbacks.unblockDomain = [&](const std::string& dom) { state.rules.unblockDomain(dom); };

    // --- Start web dashboard ---
    std::unique_ptr<WebServer> web_server;
    if (use_dashboard) {
        web_server = std::make_unique<WebServer>(web_port, callbacks);
        if (!web_server->start()) {
            std::cerr << "[Warning] Web dashboard failed to start, continuing without it.\n";
            web_server.reset();
        }
    }

    // --- Open input PCAP ---
    PcapReader reader;
    if (!reader.open(input_file)) {
        return 1;
    }

    // --- Open output file ---
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Error: Cannot open output file\n";
        return 1;
    }

    // Write PCAP header
    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));

    // --- Process packets ---
    uint64_t total_packets = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    std::unordered_map<AppType, uint64_t> app_stats;

    RawPacket raw;
    ParsedPacket parsed;

    std::cout << "[Engine] Processing " << input_file << " ...\n\n";

    while (reader.readNextPacket(raw)) {
        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip) continue;

        total_packets++;

        // Build five-tuple
        FiveTuple tuple;
        tuple.src_ip = BlockingRules::parseIP(parsed.src_ip);
        tuple.dst_ip = BlockingRules::parseIP(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        // Get or create flow
        Flow* flow;
        {
            std::lock_guard<std::mutex> lock(state.flow_mutex);
            flow = &state.flows[tuple];
        }
        flow->tuple = tuple;
        flow->packets++;
        flow->bytes += raw.data.size();

        // Try SNI extraction for HTTPS traffic
        if (parsed.has_tcp && parsed.dest_port == 443 && parsed.payload_length > 0) {
            auto sni = SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (sni) {
                flow->sni = *sni;
                flow->app_type = sniToAppType(*sni);
            }
        }

        // Try HTTP Host header
        if (parsed.has_tcp && parsed.dest_port == 80 && parsed.payload_length > 0) {
            auto host = HTTPHostExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (host) {
                flow->sni = *host;
                flow->app_type = sniToAppType(*host);
            }
        }

        // Try DNS extraction
        if ((parsed.has_udp && (parsed.dest_port == 53 || parsed.src_port == 53)) &&
            parsed.payload_length > 0) {
            auto domain = DNSExtractor::extractQuery(parsed.payload_data, parsed.payload_length);
            if (domain) {
                flow->sni = *domain;
                flow->app_type = AppType::DNS;
            }
        }

        // Port-based fallback classification
        if (flow->app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 80) flow->app_type = AppType::HTTP;
            else if (parsed.dest_port == 443) flow->app_type = AppType::HTTPS;
        }

        app_stats[flow->app_type]++;

        // --- Threat Detection ---
        state.threat_detector.analyzePacket(
            tuple.src_ip, tuple.dst_port, tuple.protocol,
            parsed.tcp_flags,
            parsed.payload_data, parsed.payload_length,
            raw.header.ts_sec
        );

        // --- Bandwidth Monitoring ---
        state.bandwidth_monitor.recordPacket(
            tuple.src_ip, tuple.dst_ip,
            flow->app_type, tuple.protocol,
            raw.data.size(), raw.header.ts_sec
        );

        // --- Check blocking rules ---
        bool block = state.rules.isBlocked(tuple.src_ip, flow->app_type, flow->sni);
        if (block) {
            flow->blocked = true;
            dropped++;
            state.stats.dropped_packets++;
        } else {
            // Write to output
            output.write(reinterpret_cast<const char*>(&raw.header), sizeof(raw.header));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
            forwarded++;
            state.stats.forwarded_packets++;
        }

        // Update global stats
        state.stats.total_packets++;
        state.stats.total_bytes += raw.data.size();
        if (parsed.has_tcp) state.stats.tcp_packets++;
        if (parsed.has_udp) state.stats.udp_packets++;

        // Update connections snapshot periodically
        if (total_packets % 100 == 0) {
            state.updateConnections();
        }
    }

    // Final connection update
    state.updateConnections();
    state.processing_done = true;

    reader.close();
    output.close();

    // --- Print final report ---
    std::cout << "\n";
    std::cout << "================================================================\n";
    std::cout << "                     PROCESSING REPORT\n";
    std::cout << "================================================================\n";
    std::cout << "  Total Packets:      " << std::setw(12) << total_packets << "\n";
    std::cout << "  Forwarded:          " << std::setw(12) << forwarded << "\n";
    std::cout << "  Dropped/Blocked:    " << std::setw(12) << dropped << "\n";

    if (total_packets > 0) {
        double drop_pct = 100.0 * dropped / total_packets;
        std::cout << "  Drop Rate:          " << std::setw(11) << std::fixed
                  << std::setprecision(2) << drop_pct << "%\n";
    }

    std::cout << "\n  APPLICATION BREAKDOWN:\n";

    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& [app, count] : sorted_apps) {
        double pct = total_packets > 0 ? (100.0 * count / total_packets) : 0;
        int bar = static_cast<int>(pct / 5);
        std::string bar_str(bar, '#');
        std::cout << "    " << std::setw(15) << std::left << appTypeToString(app)
                  << std::setw(8) << std::right << count
                  << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                  << bar_str << "\n";
    }

    // Threat summary
    auto threat_stats = state.threat_detector.getStats();
    std::cout << "\n  THREAT DETECTION:\n";
    std::cout << "    Total Alerts:     " << std::setw(12) << threat_stats.total_alerts << "\n";
    std::cout << "    Port Scans:       " << std::setw(12) << threat_stats.port_scans << "\n";
    std::cout << "    DDoS Floods:      " << std::setw(12) << threat_stats.ddos_floods << "\n";
    std::cout << "    DNS Tunneling:    " << std::setw(12) << threat_stats.dns_tunneling << "\n";
    std::cout << "    SYN Floods:       " << std::setw(12) << threat_stats.syn_floods << "\n";

    // Bandwidth summary
    auto overall = state.bandwidth_monitor.getOverallStats();
    std::cout << "\n  BANDWIDTH SUMMARY:\n";
    std::cout << "    Total Data:       " << std::setw(12) << BandwidthMonitor::formatBytes(overall.total_bytes) << "\n";
    std::cout << "    Duration:         " << std::setw(11) << std::fixed << std::setprecision(1) << overall.duration_sec << "s\n";
    std::cout << "    Avg Throughput:   " << std::setw(12) << BandwidthMonitor::formatBytes(static_cast<uint64_t>(overall.avg_bps / 8)) << "/s\n";
    std::cout << "    Unique Src IPs:   " << std::setw(12) << overall.unique_src_ips << "\n";
    std::cout << "    Unique Dst IPs:   " << std::setw(12) << overall.unique_dst_ips << "\n";

    std::cout << "\n================================================================\n";
    std::cout << "  Output written to: " << output_file << "\n";

    // --- Keep web server running if dashboard is active ---
    if (web_server && web_server->isRunning()) {
        std::cout << "\n  Web Dashboard is running at http://localhost:" << web_port << "\n";
        std::cout << "  Press Enter to stop the server and exit...\n";
        std::cin.get();
        web_server->stop();
    }

    return 0;
}
