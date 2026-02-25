#ifndef REPORT_EXPORTER_H
#define REPORT_EXPORTER_H

#include "types.h"
#include "threat_detector.h"
#include "bandwidth_monitor.h"
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace DPI {

// ============================================================================
// Report Exporter - JSON and CSV export for all DPI data
// ============================================================================

class ReportExporter {
public:
    // --- JSON Generation (for API responses) ---

    // Simple copyable stats for JSON export (avoids atomic issues)
    struct SimpleStats {
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;
        uint64_t forwarded_packets = 0;
        uint64_t dropped_packets = 0;
        uint64_t tcp_packets = 0;
        uint64_t udp_packets = 0;
    };

    // Generate full JSON stats response
    static std::string statsToJSON(
        const SimpleStats& stats,
        const std::vector<AppBandwidth>& app_bw,
        const std::vector<IPBandwidth>& top_talkers,
        const BandwidthMonitor::ProtocolStats& proto_stats,
        const BandwidthMonitor::OverallStats& overall
    );

    // Generate threats JSON
    static std::string threatsToJSON(const std::vector<ThreatAlert>& alerts,
                                      const ThreatDetector::ThreatStats& stats);

    // Generate connections JSON
    static std::string connectionsToJSON(const std::vector<Connection>& connections);

    // Generate bandwidth time series JSON
    static std::string timeSeriesJSON(const std::vector<TimeSeriesPoint>& series);

    // Generate rules JSON
    static std::string rulesToJSON(const std::vector<std::string>& blocked_ips,
                                    const std::vector<std::string>& blocked_apps,
                                    const std::vector<std::string>& blocked_domains);

    // Generate app bandwidth JSON
    static std::string appBandwidthToJSON(const std::vector<AppBandwidth>& app_bw);

    // Generate top talkers JSON
    static std::string topTalkersToJSON(const std::vector<IPBandwidth>& talkers);

    // --- CSV Export ---

    // Export connections to CSV
    static std::string connectionsToCSV(const std::vector<Connection>& connections);

    // Export app bandwidth to CSV
    static std::string appBandwidthToCSV(const std::vector<AppBandwidth>& app_bw);

    // Export threats to CSV
    static std::string threatsToCSV(const std::vector<ThreatAlert>& alerts);

    // Export top talkers to CSV
    static std::string topTalkersToCSV(const std::vector<IPBandwidth>& talkers);

    // Save string content to file
    static bool saveToFile(const std::string& filename, const std::string& content);

private:
    // JSON helper: escape a string for JSON
    static std::string jsonEscape(const std::string& s);

    // CSV helper: escape a field for CSV
    static std::string csvEscape(const std::string& s);
};

} // namespace DPI

#endif // REPORT_EXPORTER_H
