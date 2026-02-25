#include "report_exporter.h"
#include <sstream>
#include <fstream>
#include <iomanip>

namespace DPI {

std::string ReportExporter::jsonEscape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 10);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:   result += c;
        }
    }
    return result;
}

std::string ReportExporter::csvEscape(const std::string& s) {
    if (s.find(',') != std::string::npos || s.find('"') != std::string::npos) {
        std::string escaped = "\"";
        for (char c : s) {
            if (c == '"') escaped += "\"\"";
            else escaped += c;
        }
        escaped += "\"";
        return escaped;
    }
    return s;
}

// ============================================================================
// JSON Generation
// ============================================================================

std::string ReportExporter::statsToJSON(
    const SimpleStats& stats,
    const std::vector<AppBandwidth>& app_bw,
    const std::vector<IPBandwidth>& top_talkers,
    const BandwidthMonitor::ProtocolStats& proto_stats,
    const BandwidthMonitor::OverallStats& overall) {

    std::ostringstream ss;
    ss << "{\n";

    // Packet stats
    ss << "  \"packet_stats\": {\n";
    ss << "    \"total_packets\": " << stats.total_packets << ",\n";
    ss << "    \"total_bytes\": " << stats.total_bytes << ",\n";
    ss << "    \"tcp_packets\": " << stats.tcp_packets << ",\n";
    ss << "    \"udp_packets\": " << stats.udp_packets << ",\n";
    ss << "    \"forwarded\": " << stats.forwarded_packets << ",\n";
    ss << "    \"dropped\": " << stats.dropped_packets << "\n";
    ss << "  },\n";

    // Overall bandwidth stats
    ss << "  \"bandwidth\": {\n";
    ss << "    \"total_bytes\": " << overall.total_bytes << ",\n";
    ss << "    \"total_packets\": " << overall.total_packets << ",\n";
    ss << "    \"unique_src_ips\": " << overall.unique_src_ips << ",\n";
    ss << "    \"unique_dst_ips\": " << overall.unique_dst_ips << ",\n";
    ss << "    \"duration_sec\": " << std::fixed << std::setprecision(2) << overall.duration_sec << ",\n";
    ss << "    \"avg_bps\": " << std::fixed << std::setprecision(2) << overall.avg_bps << ",\n";
    ss << "    \"avg_pps\": " << std::fixed << std::setprecision(2) << overall.avg_pps << ",\n";
    ss << "    \"avg_packet_size\": " << std::fixed << std::setprecision(2) << overall.avg_packet_size << "\n";
    ss << "  },\n";

    // Protocol distribution
    ss << "  \"protocols\": {\n";
    ss << "    \"tcp_bytes\": " << proto_stats.tcp_bytes << ",\n";
    ss << "    \"udp_bytes\": " << proto_stats.udp_bytes << ",\n";
    ss << "    \"other_bytes\": " << proto_stats.other_bytes << ",\n";
    ss << "    \"tcp_packets\": " << proto_stats.tcp_packets << ",\n";
    ss << "    \"udp_packets\": " << proto_stats.udp_packets << ",\n";
    ss << "    \"other_packets\": " << proto_stats.other_packets << "\n";
    ss << "  },\n";

    // App bandwidth
    ss << "  \"app_bandwidth\": " << appBandwidthToJSON(app_bw) << ",\n";

    // Top talkers
    ss << "  \"top_talkers\": " << topTalkersToJSON(top_talkers) << "\n";

    ss << "}";
    return ss.str();
}

std::string ReportExporter::threatsToJSON(const std::vector<ThreatAlert>& alerts,
                                           const ThreatDetector::ThreatStats& stats) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"stats\": {\n";
    ss << "    \"total_alerts\": " << stats.total_alerts << ",\n";
    ss << "    \"port_scans\": " << stats.port_scans << ",\n";
    ss << "    \"ddos_floods\": " << stats.ddos_floods << ",\n";
    ss << "    \"dns_tunneling\": " << stats.dns_tunneling << ",\n";
    ss << "    \"syn_floods\": " << stats.syn_floods << "\n";
    ss << "  },\n";

    ss << "  \"alerts\": [\n";
    for (size_t i = 0; i < alerts.size(); i++) {
        const auto& a = alerts[i];
        ss << "    {\n";
        ss << "      \"type\": \"" << jsonEscape(threatTypeToString(a.type)) << "\",\n";
        ss << "      \"severity\": \"" << jsonEscape(severityToString(a.severity)) << "\",\n";
        ss << "      \"source_ip\": \"" << jsonEscape(a.source_ip) << "\",\n";
        ss << "      \"description\": \"" << jsonEscape(a.description) << "\",\n";
        ss << "      \"timestamp\": " << a.timestamp_sec << ",\n";
        ss << "      \"related_count\": " << a.related_count << "\n";
        ss << "    }";
        if (i < alerts.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "  ]\n";
    ss << "}";
    return ss.str();
}

std::string ReportExporter::connectionsToJSON(const std::vector<Connection>& connections) {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < connections.size(); i++) {
        const auto& c = connections[i];
        ss << "  {\n";
        ss << "    \"five_tuple\": \"" << jsonEscape(c.tuple.toString()) << "\",\n";
        ss << "    \"state\": \"";
        switch (c.state) {
            case ConnectionState::NEW:        ss << "NEW"; break;
            case ConnectionState::ESTABLISHED: ss << "ESTABLISHED"; break;
            case ConnectionState::CLASSIFIED:  ss << "CLASSIFIED"; break;
            case ConnectionState::BLOCKED:     ss << "BLOCKED"; break;
            case ConnectionState::CLOSED:      ss << "CLOSED"; break;
        }
        ss << "\",\n";
        ss << "    \"app_type\": \"" << jsonEscape(appTypeToString(c.app_type)) << "\",\n";
        ss << "    \"sni\": \"" << jsonEscape(c.sni) << "\",\n";
        ss << "    \"packets_in\": " << c.packets_in << ",\n";
        ss << "    \"packets_out\": " << c.packets_out << ",\n";
        ss << "    \"bytes_in\": " << c.bytes_in << ",\n";
        ss << "    \"bytes_out\": " << c.bytes_out << "\n";
        ss << "  }";
        if (i < connections.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "]";
    return ss.str();
}

std::string ReportExporter::timeSeriesJSON(const std::vector<TimeSeriesPoint>& series) {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < series.size(); i++) {
        const auto& pt = series[i];
        ss << "  {\"timestamp\": " << pt.timestamp_sec
           << ", \"bytes\": " << pt.bytes
           << ", \"packets\": " << pt.packets << "}";
        if (i < series.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "]";
    return ss.str();
}

std::string ReportExporter::rulesToJSON(const std::vector<std::string>& blocked_ips,
                                         const std::vector<std::string>& blocked_apps,
                                         const std::vector<std::string>& blocked_domains) {
    std::ostringstream ss;
    ss << "{\n";

    ss << "  \"blocked_ips\": [";
    for (size_t i = 0; i < blocked_ips.size(); i++) {
        ss << "\"" << jsonEscape(blocked_ips[i]) << "\"";
        if (i < blocked_ips.size() - 1) ss << ", ";
    }
    ss << "],\n";

    ss << "  \"blocked_apps\": [";
    for (size_t i = 0; i < blocked_apps.size(); i++) {
        ss << "\"" << jsonEscape(blocked_apps[i]) << "\"";
        if (i < blocked_apps.size() - 1) ss << ", ";
    }
    ss << "],\n";

    ss << "  \"blocked_domains\": [";
    for (size_t i = 0; i < blocked_domains.size(); i++) {
        ss << "\"" << jsonEscape(blocked_domains[i]) << "\"";
        if (i < blocked_domains.size() - 1) ss << ", ";
    }
    ss << "]\n";

    ss << "}";
    return ss.str();
}

std::string ReportExporter::appBandwidthToJSON(const std::vector<AppBandwidth>& app_bw) {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < app_bw.size(); i++) {
        const auto& bw = app_bw[i];
        ss << "    {\n";
        ss << "      \"app\": \"" << jsonEscape(bw.app_name) << "\",\n";
        ss << "      \"bytes\": " << bw.bytes_total << ",\n";
        ss << "      \"packets\": " << bw.packets_total << ",\n";
        ss << "      \"connections\": " << bw.connections << "\n";
        ss << "    }";
        if (i < app_bw.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "  ]";
    return ss.str();
}

std::string ReportExporter::topTalkersToJSON(const std::vector<IPBandwidth>& talkers) {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < talkers.size(); i++) {
        const auto& t = talkers[i];
        ss << "    {\n";
        ss << "      \"ip\": \"" << jsonEscape(t.ip_str) << "\",\n";
        ss << "      \"bytes_sent\": " << t.bytes_sent << ",\n";
        ss << "      \"bytes_received\": " << t.bytes_received << ",\n";
        ss << "      \"packets_sent\": " << t.packets_sent << ",\n";
        ss << "      \"packets_received\": " << t.packets_received << ",\n";
        ss << "      \"connections\": " << t.connections << "\n";
        ss << "    }";
        if (i < talkers.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "  ]";
    return ss.str();
}

// ============================================================================
// CSV Generation
// ============================================================================

std::string ReportExporter::connectionsToCSV(const std::vector<Connection>& connections) {
    std::ostringstream ss;
    ss << "Five-Tuple,State,AppType,SNI,PacketsIn,PacketsOut,BytesIn,BytesOut\n";
    for (const auto& c : connections) {
        std::string state;
        switch (c.state) {
            case ConnectionState::NEW:        state = "NEW"; break;
            case ConnectionState::ESTABLISHED: state = "ESTABLISHED"; break;
            case ConnectionState::CLASSIFIED:  state = "CLASSIFIED"; break;
            case ConnectionState::BLOCKED:     state = "BLOCKED"; break;
            case ConnectionState::CLOSED:      state = "CLOSED"; break;
        }
        ss << csvEscape(c.tuple.toString()) << ","
           << state << ","
           << csvEscape(appTypeToString(c.app_type)) << ","
           << csvEscape(c.sni) << ","
           << c.packets_in << ","
           << c.packets_out << ","
           << c.bytes_in << ","
           << c.bytes_out << "\n";
    }
    return ss.str();
}

std::string ReportExporter::appBandwidthToCSV(const std::vector<AppBandwidth>& app_bw) {
    std::ostringstream ss;
    ss << "Application,Bytes,Packets,Connections\n";
    for (const auto& bw : app_bw) {
        ss << csvEscape(bw.app_name) << ","
           << bw.bytes_total << ","
           << bw.packets_total << ","
           << bw.connections << "\n";
    }
    return ss.str();
}

std::string ReportExporter::threatsToCSV(const std::vector<ThreatAlert>& alerts) {
    std::ostringstream ss;
    ss << "Type,Severity,SourceIP,Description,Timestamp,RelatedCount\n";
    for (const auto& a : alerts) {
        ss << csvEscape(threatTypeToString(a.type)) << ","
           << csvEscape(severityToString(a.severity)) << ","
           << csvEscape(a.source_ip) << ","
           << csvEscape(a.description) << ","
           << a.timestamp_sec << ","
           << a.related_count << "\n";
    }
    return ss.str();
}

std::string ReportExporter::topTalkersToCSV(const std::vector<IPBandwidth>& talkers) {
    std::ostringstream ss;
    ss << "IP,BytesSent,BytesReceived,PacketsSent,PacketsReceived,Connections\n";
    for (const auto& t : talkers) {
        ss << csvEscape(t.ip_str) << ","
           << t.bytes_sent << ","
           << t.bytes_received << ","
           << t.packets_sent << ","
           << t.packets_received << ","
           << t.connections << "\n";
    }
    return ss.str();
}

bool ReportExporter::saveToFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    file << content;
    file.close();
    return true;
}

} // namespace DPI
