#include "bandwidth_monitor.h"
#include <sstream>
#include <iomanip>
#include <cmath>

namespace DPI {

std::string BandwidthMonitor::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

std::string BandwidthMonitor::formatBytes(uint64_t bytes) {
    std::ostringstream ss;
    if (bytes >= 1073741824ULL) {
        ss << std::fixed << std::setprecision(2) << (bytes / 1073741824.0) << " GB";
    } else if (bytes >= 1048576ULL) {
        ss << std::fixed << std::setprecision(2) << (bytes / 1048576.0) << " MB";
    } else if (bytes >= 1024ULL) {
        ss << std::fixed << std::setprecision(2) << (bytes / 1024.0) << " KB";
    } else {
        ss << bytes << " B";
    }
    return ss.str();
}

void BandwidthMonitor::recordPacket(uint32_t src_ip, uint32_t dst_ip,
                                     AppType app, uint8_t protocol,
                                     size_t packet_size, uint32_t timestamp_sec) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Overall stats
    total_bytes_ += packet_size;
    total_packets_++;
    if (first_ts_ == 0 || timestamp_sec < first_ts_) first_ts_ = timestamp_sec;
    if (timestamp_sec > last_ts_) last_ts_ = timestamp_sec;

    // Per-app tracking
    auto& ab = app_bandwidth_[app];
    ab.app = app;
    ab.app_name = appTypeToString(app);
    ab.bytes_total += packet_size;
    ab.packets_total++;

    // Per-IP tracking (source)
    auto& ip_state = ip_bandwidth_[src_ip];
    ip_state.bytes_sent += packet_size;
    ip_state.packets_sent++;

    // Track destination IP receiving
    auto& dst_state = ip_bandwidth_[dst_ip];
    dst_state.bytes_received += packet_size;
    dst_state.packets_received++;

    // Unique dest IPs
    unique_dst_ips_.insert(dst_ip);

    // Protocol distribution
    if (protocol == 6) {
        protocol_stats_.tcp_bytes += packet_size;
        protocol_stats_.tcp_packets++;
    } else if (protocol == 17) {
        protocol_stats_.udp_bytes += packet_size;
        protocol_stats_.udp_packets++;
    } else {
        protocol_stats_.other_bytes += packet_size;
        protocol_stats_.other_packets++;
    }

    // Time series
    auto& ts_point = time_series_[timestamp_sec];
    ts_point.timestamp_sec = timestamp_sec;
    ts_point.bytes += packet_size;
    ts_point.packets++;
}

void BandwidthMonitor::recordConnection(uint32_t src_ip, AppType app) {
    std::lock_guard<std::mutex> lock(mutex_);
    app_bandwidth_[app].connections++;
    ip_bandwidth_[src_ip].connections++;
}

std::vector<AppBandwidth> BandwidthMonitor::getAppBandwidth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AppBandwidth> result;
    result.reserve(app_bandwidth_.size());
    for (const auto& [app, bw] : app_bandwidth_) {
        result.push_back(bw);
    }
    // Sort by bytes descending
    std::sort(result.begin(), result.end(),
              [](const AppBandwidth& a, const AppBandwidth& b) {
                  return a.bytes_total > b.bytes_total;
              });
    return result;
}

uint64_t BandwidthMonitor::getAppBytes(AppType app) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = app_bandwidth_.find(app);
    return (it != app_bandwidth_.end()) ? it->second.bytes_total : 0;
}

std::vector<IPBandwidth> BandwidthMonitor::getTopTalkers(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IPBandwidth> result;
    result.reserve(ip_bandwidth_.size());

    for (const auto& [ip, state] : ip_bandwidth_) {
        IPBandwidth bw;
        bw.ip = ip;
        bw.ip_str = ipToString(ip);
        bw.bytes_sent = state.bytes_sent;
        bw.bytes_received = state.bytes_received;
        bw.packets_sent = state.packets_sent;
        bw.packets_received = state.packets_received;
        bw.connections = state.connections;
        result.push_back(bw);
    }

    // Sort by total bytes (sent + received) descending
    std::sort(result.begin(), result.end(),
              [](const IPBandwidth& a, const IPBandwidth& b) {
                  return (a.bytes_sent + a.bytes_received) > (b.bytes_sent + b.bytes_received);
              });

    if (result.size() > limit) {
        result.resize(limit);
    }
    return result;
}

IPBandwidth BandwidthMonitor::getIPBandwidth(uint32_t ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    IPBandwidth bw;
    bw.ip = ip;
    bw.ip_str = ipToString(ip);
    auto it = ip_bandwidth_.find(ip);
    if (it != ip_bandwidth_.end()) {
        bw.bytes_sent = it->second.bytes_sent;
        bw.bytes_received = it->second.bytes_received;
        bw.packets_sent = it->second.packets_sent;
        bw.packets_received = it->second.packets_received;
        bw.connections = it->second.connections;
    }
    return bw;
}

BandwidthMonitor::ProtocolStats BandwidthMonitor::getProtocolStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return protocol_stats_;
}

std::vector<TimeSeriesPoint> BandwidthMonitor::getTimeSeries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TimeSeriesPoint> result;
    result.reserve(time_series_.size());
    for (const auto& [ts, point] : time_series_) {
        result.push_back(point);
    }
    std::sort(result.begin(), result.end(),
              [](const TimeSeriesPoint& a, const TimeSeriesPoint& b) {
                  return a.timestamp_sec < b.timestamp_sec;
              });
    return result;
}

BandwidthMonitor::OverallStats BandwidthMonitor::getOverallStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    OverallStats stats;
    stats.total_bytes = total_bytes_;
    stats.total_packets = total_packets_;
    stats.unique_src_ips = ip_bandwidth_.size();
    stats.unique_dst_ips = unique_dst_ips_.size();
    stats.first_timestamp = first_ts_;
    stats.last_timestamp = last_ts_;

    if (total_packets_ > 0) {
        stats.avg_packet_size = static_cast<double>(total_bytes_) / total_packets_;
    }

    if (last_ts_ > first_ts_) {
        stats.duration_sec = static_cast<double>(last_ts_ - first_ts_);
        stats.avg_bps = (total_bytes_ * 8.0) / stats.duration_sec;
        stats.avg_pps = static_cast<double>(total_packets_) / stats.duration_sec;
    }

    return stats;
}

void BandwidthMonitor::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    app_bandwidth_.clear();
    ip_bandwidth_.clear();
    unique_dst_ips_.clear();
    protocol_stats_ = ProtocolStats{};
    time_series_.clear();
    total_bytes_ = 0;
    total_packets_ = 0;
    first_ts_ = 0;
    last_ts_ = 0;
}

} // namespace DPI
