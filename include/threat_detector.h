#ifndef THREAT_DETECTOR_H
#define THREAT_DETECTOR_H

#include "types.h"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>

namespace DPI {

// ============================================================================
// Threat/Anomaly Detection Module
// ============================================================================
// Detects:
// 1. Port Scanning   - Single IP hitting many different ports quickly
// 2. DDoS Patterns   - Abnormal packet rates from a single source
// 3. DNS Tunneling   - Unusually long DNS query names (data exfiltration)
// 4. SYN Flood       - Excessive SYN packets without completing handshakes
// ============================================================================

enum class ThreatType {
    PORT_SCAN,
    DDOS_FLOOD,
    DNS_TUNNELING,
    SYN_FLOOD,
    UNKNOWN_THREAT
};

inline std::string threatTypeToString(ThreatType t) {
    switch (t) {
        case ThreatType::PORT_SCAN:     return "Port Scan";
        case ThreatType::DDOS_FLOOD:    return "DDoS Flood";
        case ThreatType::DNS_TUNNELING: return "DNS Tunneling";
        case ThreatType::SYN_FLOOD:     return "SYN Flood";
        default:                        return "Unknown";
    }
}

enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

inline std::string severityToString(ThreatSeverity s) {
    switch (s) {
        case ThreatSeverity::LOW:      return "LOW";
        case ThreatSeverity::MEDIUM:   return "MEDIUM";
        case ThreatSeverity::HIGH:     return "HIGH";
        case ThreatSeverity::CRITICAL: return "CRITICAL";
        default:                       return "UNKNOWN";
    }
}

struct ThreatAlert {
    ThreatType type;
    ThreatSeverity severity;
    std::string source_ip;
    std::string description;
    uint64_t timestamp_sec;
    uint64_t related_count;  // e.g., number of ports scanned, packet rate, etc.
};

class ThreatDetector {
public:
    struct Config {
        // Port Scan Detection
        int port_scan_threshold = 15;        // distinct ports in window = port scan
        int port_scan_window_sec = 10;       // time window in seconds

        // DDoS Detection
        int ddos_pps_threshold = 500;        // packets-per-second from one IP
        int ddos_window_sec = 5;             // time window in seconds

        // DNS Tunneling Detection
        int dns_query_max_length = 60;       // domain names longer than this are suspicious
        int dns_tunnel_threshold = 5;        // number of long queries to trigger alert

        // SYN Flood Detection
        int syn_flood_threshold = 100;       // SYN packets without ACK in window
        int syn_flood_window_sec = 10;       // time window in seconds
    };

    ThreatDetector();
    ThreatDetector(const Config& config);

    // Call for every packet processed
    void analyzePacket(uint32_t src_ip, uint16_t dst_port, uint8_t protocol,
                       uint8_t tcp_flags, const uint8_t* payload,
                       size_t payload_len, uint32_t timestamp_sec);

    // Get all alerts (thread-safe)
    std::vector<ThreatAlert> getAlerts() const;

    // Get alerts since last call (consumes them)
    std::vector<ThreatAlert> consumeNewAlerts();

    // Get count of alerts by type
    struct ThreatStats {
        uint64_t total_alerts = 0;
        uint64_t port_scans = 0;
        uint64_t ddos_floods = 0;
        uint64_t dns_tunneling = 0;
        uint64_t syn_floods = 0;
    };

    ThreatStats getStats() const;

    // Clear all state
    void reset();

    // Helper: convert uint32 IP to string
    static std::string ipToString(uint32_t ip);

private:
    Config config_;

    // --- Port Scan Tracking ---
    struct PortScanState {
        std::unordered_set<uint16_t> ports_hit;
        uint32_t window_start_sec = 0;
        bool alerted = false;
    };
    std::unordered_map<uint32_t, PortScanState> port_scan_tracker_;

    // --- DDoS Tracking ---
    struct FloodState {
        uint64_t packet_count = 0;
        uint32_t window_start_sec = 0;
        bool alerted = false;
    };
    std::unordered_map<uint32_t, FloodState> flood_tracker_;

    // --- DNS Tunneling Tracking ---
    struct DNSTunnelState {
        int long_query_count = 0;
        uint32_t window_start_sec = 0;
        bool alerted = false;
    };
    std::unordered_map<uint32_t, DNSTunnelState> dns_tunnel_tracker_;

    // --- SYN Flood Tracking ---
    struct SYNFloodState {
        uint64_t syn_count = 0;
        uint64_t ack_count = 0;
        uint32_t window_start_sec = 0;
        bool alerted = false;
    };
    std::unordered_map<uint32_t, SYNFloodState> syn_flood_tracker_;

    // Alerts storage
    std::vector<ThreatAlert> all_alerts_;
    std::vector<ThreatAlert> new_alerts_;
    mutable std::mutex alert_mutex_;
    mutable std::mutex tracker_mutex_;

    ThreatStats stats_;

    // Internal detection methods
    void detectPortScan(uint32_t src_ip, uint16_t dst_port, uint32_t ts);
    void detectDDoS(uint32_t src_ip, uint32_t ts);
    void detectDNSTunneling(uint32_t src_ip, const uint8_t* payload,
                            size_t payload_len, uint32_t ts);
    void detectSYNFlood(uint32_t src_ip, uint8_t tcp_flags, uint32_t ts);

    void addAlert(ThreatAlert alert);
};

} // namespace DPI

#endif // THREAT_DETECTOR_H
