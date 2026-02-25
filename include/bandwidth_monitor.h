#ifndef BANDWIDTH_MONITOR_H
#define BANDWIDTH_MONITOR_H

#include "types.h"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <atomic>
#include <algorithm>

namespace DPI {

// ============================================================================
// Bandwidth Monitor - Tracks per-app and per-IP data usage
// ============================================================================
// Features:
// 1. Per-application bandwidth tracking (bytes in/out per app)
// 2. Per-IP bandwidth tracking (top talkers)
// 3. Protocol distribution (TCP vs UDP bytes)
// 4. Time-series data for charting (buckets per second)
// ============================================================================

struct AppBandwidth {
    AppType app;
    std::string app_name;
    uint64_t bytes_total = 0;
    uint64_t packets_total = 0;
    uint64_t connections = 0;
};

struct IPBandwidth {
    uint32_t ip;
    std::string ip_str;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t connections = 0;
};

struct TimeSeriesPoint {
    uint32_t timestamp_sec;
    uint64_t bytes;
    uint64_t packets;
};

class BandwidthMonitor {
public:
    BandwidthMonitor() = default;

    // Record a packet's bandwidth contribution
    void recordPacket(uint32_t src_ip, uint32_t dst_ip,
                      AppType app, uint8_t protocol,
                      size_t packet_size, uint32_t timestamp_sec);

    // Record a new connection being established
    void recordConnection(uint32_t src_ip, AppType app);

    // --- Per-App Queries ---
    std::vector<AppBandwidth> getAppBandwidth() const;
    uint64_t getAppBytes(AppType app) const;

    // --- Per-IP Queries (Top Talkers) ---
    std::vector<IPBandwidth> getTopTalkers(size_t limit = 10) const;
    IPBandwidth getIPBandwidth(uint32_t ip) const;

    // --- Protocol Distribution ---
    struct ProtocolStats {
        uint64_t tcp_bytes = 0;
        uint64_t udp_bytes = 0;
        uint64_t other_bytes = 0;
        uint64_t tcp_packets = 0;
        uint64_t udp_packets = 0;
        uint64_t other_packets = 0;
    };
    ProtocolStats getProtocolStats() const;

    // --- Time Series (for charts) ---
    std::vector<TimeSeriesPoint> getTimeSeries() const;

    // --- Overall Stats ---
    struct OverallStats {
        uint64_t total_bytes = 0;
        uint64_t total_packets = 0;
        uint64_t unique_src_ips = 0;
        uint64_t unique_dst_ips = 0;
        uint32_t first_timestamp = 0;
        uint32_t last_timestamp = 0;
        double avg_packet_size = 0.0;
        double duration_sec = 0.0;
        double avg_bps = 0.0;      // bits per second
        double avg_pps = 0.0;      // packets per second
    };
    OverallStats getOverallStats() const;

    // Clear all data
    void reset();

    // Helper
    static std::string ipToString(uint32_t ip);
    static std::string formatBytes(uint64_t bytes);

private:
    mutable std::mutex mutex_;

    // Per-app tracking
    std::unordered_map<AppType, AppBandwidth> app_bandwidth_;

    // Per-IP tracking (source IPs)
    struct IPState {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint64_t connections = 0;
    };
    std::unordered_map<uint32_t, IPState> ip_bandwidth_;

    // Unique destination IPs
    std::unordered_set<uint32_t> unique_dst_ips_;

    // Protocol bytes
    ProtocolStats protocol_stats_;

    // Time series (one point per second)
    std::unordered_map<uint32_t, TimeSeriesPoint> time_series_;

    // Overall
    uint64_t total_bytes_ = 0;
    uint64_t total_packets_ = 0;
    uint32_t first_ts_ = 0;
    uint32_t last_ts_ = 0;
};

} // namespace DPI

#endif // BANDWIDTH_MONITOR_H
