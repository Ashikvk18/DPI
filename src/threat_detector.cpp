#include "threat_detector.h"
#include <sstream>
#include <iostream>
#include <algorithm>

namespace DPI {

ThreatDetector::ThreatDetector() : config_(Config{}) {}
ThreatDetector::ThreatDetector(const Config& config) : config_(config) {}

std::string ThreatDetector::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

void ThreatDetector::analyzePacket(uint32_t src_ip, uint16_t dst_port,
                                    uint8_t protocol, uint8_t tcp_flags,
                                    const uint8_t* payload, size_t payload_len,
                                    uint32_t timestamp_sec) {
    std::lock_guard<std::mutex> lock(tracker_mutex_);

    // 1. Port Scan Detection (TCP/UDP)
    detectPortScan(src_ip, dst_port, timestamp_sec);

    // 2. DDoS / Flood Detection
    detectDDoS(src_ip, timestamp_sec);

    // 3. DNS Tunneling Detection (UDP port 53)
    if ((protocol == 17 && dst_port == 53) || (protocol == 17 && dst_port == 5353)) {
        detectDNSTunneling(src_ip, payload, payload_len, timestamp_sec);
    }

    // 4. SYN Flood Detection (TCP only)
    if (protocol == 6) {
        detectSYNFlood(src_ip, tcp_flags, timestamp_sec);
    }
}

void ThreatDetector::detectPortScan(uint32_t src_ip, uint16_t dst_port, uint32_t ts) {
    auto& state = port_scan_tracker_[src_ip];

    // Reset window if expired
    if (state.window_start_sec == 0 || (ts - state.window_start_sec) > static_cast<uint32_t>(config_.port_scan_window_sec)) {
        state.ports_hit.clear();
        state.window_start_sec = ts;
        state.alerted = false;
    }

    state.ports_hit.insert(dst_port);

    if (!state.alerted && static_cast<int>(state.ports_hit.size()) >= config_.port_scan_threshold) {
        state.alerted = true;

        ThreatSeverity sev = ThreatSeverity::MEDIUM;
        if (state.ports_hit.size() > 50) sev = ThreatSeverity::CRITICAL;
        else if (state.ports_hit.size() > 30) sev = ThreatSeverity::HIGH;

        std::ostringstream desc;
        desc << "IP " << ipToString(src_ip) << " scanned " << state.ports_hit.size()
             << " distinct ports in " << config_.port_scan_window_sec << "s window";

        addAlert({ThreatType::PORT_SCAN, sev, ipToString(src_ip),
                  desc.str(), ts, state.ports_hit.size()});
    }
}

void ThreatDetector::detectDDoS(uint32_t src_ip, uint32_t ts) {
    auto& state = flood_tracker_[src_ip];

    // Reset window if expired
    if (state.window_start_sec == 0 || (ts - state.window_start_sec) > static_cast<uint32_t>(config_.ddos_window_sec)) {
        state.packet_count = 0;
        state.window_start_sec = ts;
        state.alerted = false;
    }

    state.packet_count++;

    uint64_t pps = state.packet_count;
    uint32_t elapsed = ts - state.window_start_sec;
    if (elapsed > 0) {
        pps = state.packet_count / elapsed;
    }

    if (!state.alerted && static_cast<int>(pps) >= config_.ddos_pps_threshold) {
        state.alerted = true;

        ThreatSeverity sev = ThreatSeverity::HIGH;
        if (pps > 2000) sev = ThreatSeverity::CRITICAL;

        std::ostringstream desc;
        desc << "IP " << ipToString(src_ip) << " sending ~" << pps
             << " packets/sec (threshold: " << config_.ddos_pps_threshold << ")";

        addAlert({ThreatType::DDOS_FLOOD, sev, ipToString(src_ip),
                  desc.str(), ts, pps});
    }
}

void ThreatDetector::detectDNSTunneling(uint32_t src_ip, const uint8_t* payload,
                                         size_t payload_len, uint32_t ts) {
    if (!payload || payload_len < 12) return;

    // DNS header is 12 bytes, then questions section
    // Extract the query name length (rough estimate)
    size_t offset = 12;
    size_t name_len = 0;
    while (offset < payload_len && payload[offset] != 0) {
        uint8_t label_len = payload[offset];
        if (label_len > 63) break;  // compression pointer or invalid
        name_len += label_len + 1;  // label + dot
        offset += label_len + 1;
    }

    if (static_cast<int>(name_len) > config_.dns_query_max_length) {
        auto& state = dns_tunnel_tracker_[src_ip];

        if (state.window_start_sec == 0 || (ts - state.window_start_sec) > 60) {
            state.long_query_count = 0;
            state.window_start_sec = ts;
            state.alerted = false;
        }

        state.long_query_count++;

        if (!state.alerted && state.long_query_count >= config_.dns_tunnel_threshold) {
            state.alerted = true;

            ThreatSeverity sev = ThreatSeverity::HIGH;

            std::ostringstream desc;
            desc << "IP " << ipToString(src_ip) << " sent " << state.long_query_count
                 << " DNS queries with unusually long names (>" << config_.dns_query_max_length
                 << " chars) - possible DNS tunneling/exfiltration";

            addAlert({ThreatType::DNS_TUNNELING, sev, ipToString(src_ip),
                      desc.str(), ts, static_cast<uint64_t>(state.long_query_count)});
        }
    }
}

void ThreatDetector::detectSYNFlood(uint32_t src_ip, uint8_t tcp_flags, uint32_t ts) {
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;

    auto& state = syn_flood_tracker_[src_ip];

    // Reset window if expired
    if (state.window_start_sec == 0 || (ts - state.window_start_sec) > static_cast<uint32_t>(config_.syn_flood_window_sec)) {
        state.syn_count = 0;
        state.ack_count = 0;
        state.window_start_sec = ts;
        state.alerted = false;
    }

    if ((tcp_flags & SYN) && !(tcp_flags & ACK)) {
        state.syn_count++;
    }
    if (tcp_flags & ACK) {
        state.ack_count++;
    }

    // SYN flood: many SYNs but very few ACKs (incomplete handshakes)
    if (!state.alerted && static_cast<int>(state.syn_count) >= config_.syn_flood_threshold) {
        // Only alert if ratio of SYN to ACK is very skewed
        double ratio = (state.ack_count > 0) ? (double)state.syn_count / state.ack_count : state.syn_count;
        if (ratio > 5.0) {
            state.alerted = true;

            ThreatSeverity sev = ThreatSeverity::CRITICAL;

            std::ostringstream desc;
            desc << "IP " << ipToString(src_ip) << " sent " << state.syn_count
                 << " SYN packets with only " << state.ack_count << " ACKs in "
                 << config_.syn_flood_window_sec << "s - possible SYN flood attack";

            addAlert({ThreatType::SYN_FLOOD, sev, ipToString(src_ip),
                      desc.str(), ts, state.syn_count});
        }
    }
}

void ThreatDetector::addAlert(ThreatAlert alert) {
    std::lock_guard<std::mutex> lock(alert_mutex_);

    // Update stats
    stats_.total_alerts++;
    switch (alert.type) {
        case ThreatType::PORT_SCAN:     stats_.port_scans++; break;
        case ThreatType::DDOS_FLOOD:    stats_.ddos_floods++; break;
        case ThreatType::DNS_TUNNELING: stats_.dns_tunneling++; break;
        case ThreatType::SYN_FLOOD:     stats_.syn_floods++; break;
        default: break;
    }

    std::cout << "[THREAT] " << severityToString(alert.severity) << " - "
              << threatTypeToString(alert.type) << ": " << alert.description << "\n";

    new_alerts_.push_back(alert);
    all_alerts_.push_back(std::move(alert));
}

std::vector<ThreatAlert> ThreatDetector::getAlerts() const {
    std::lock_guard<std::mutex> lock(alert_mutex_);
    return all_alerts_;
}

std::vector<ThreatAlert> ThreatDetector::consumeNewAlerts() {
    std::lock_guard<std::mutex> lock(alert_mutex_);
    std::vector<ThreatAlert> result;
    result.swap(new_alerts_);
    return result;
}

ThreatDetector::ThreatStats ThreatDetector::getStats() const {
    std::lock_guard<std::mutex> lock(alert_mutex_);
    return stats_;
}

void ThreatDetector::reset() {
    {
        std::lock_guard<std::mutex> lock(tracker_mutex_);
        port_scan_tracker_.clear();
        flood_tracker_.clear();
        dns_tunnel_tracker_.clear();
        syn_flood_tracker_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(alert_mutex_);
        all_alerts_.clear();
        new_alerts_.clear();
        stats_ = ThreatStats{};
    }
}

} // namespace DPI
