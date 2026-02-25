#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "types.h"
#include "threat_detector.h"
#include "bandwidth_monitor.h"
#include "report_exporter.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include "fast_path.h"
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define INVALID_SOCK INVALID_SOCKET
#define CLOSE_SOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
typedef int socket_t;
#define INVALID_SOCK -1
#define CLOSE_SOCKET close
#endif

namespace DPI {

// ============================================================================
// Minimal Embedded HTTP Web Server
// ============================================================================
// Serves:
// 1. Static HTML/CSS/JS dashboard (embedded)
// 2. REST API endpoints for real-time data
//
// API Endpoints:
//   GET /api/stats        - Overall DPI statistics + bandwidth
//   GET /api/threats      - Threat alerts
//   GET /api/connections  - Active connections
//   GET /api/bandwidth    - App bandwidth breakdown
//   GET /api/timeseries   - Time series data for charts
//   GET /api/rules        - Current blocking rules
//   GET /api/top-talkers  - Top bandwidth consumers
//   POST /api/rules/block-ip     - Block an IP
//   POST /api/rules/block-app    - Block an app
//   POST /api/rules/block-domain - Block a domain
//   POST /api/rules/unblock-ip     - Unblock an IP
//   POST /api/rules/unblock-app    - Unblock an app
//   POST /api/rules/unblock-domain - Unblock a domain
//   GET /api/export/json  - Export full report as JSON
//   GET /api/export/csv   - Export as CSV (connections)
// ============================================================================

struct HTTPRequest {
    std::string method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
};

struct HTTPResponse {
    int status_code = 200;
    std::string content_type = "application/json";
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

// Simple copyable snapshot of DPIStats (no atomics)
struct StatsSnapshot {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t forwarded_packets = 0;
    uint64_t dropped_packets = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t other_packets = 0;
    uint64_t active_connections = 0;
};

// Callback types for getting data from the DPI engine
struct WebServerCallbacks {
    std::function<StatsSnapshot()> getStats;
    std::function<std::vector<ThreatAlert>()> getAlerts;
    std::function<ThreatDetector::ThreatStats()> getThreatStats;
    std::function<std::vector<AppBandwidth>()> getAppBandwidth;
    std::function<std::vector<IPBandwidth>()> getTopTalkers;
    std::function<BandwidthMonitor::ProtocolStats()> getProtocolStats;
    std::function<BandwidthMonitor::OverallStats()> getOverallStats;
    std::function<std::vector<TimeSeriesPoint>()> getTimeSeries;
    std::function<std::vector<Connection>()> getConnections;
    std::function<std::vector<std::string>()> getBlockedIPs;
    std::function<std::vector<std::string>()> getBlockedApps;
    std::function<std::vector<std::string>()> getBlockedDomains;
    std::function<void(const std::string&)> blockIP;
    std::function<void(const std::string&)> unblockIP;
    std::function<void(const std::string&)> blockApp;
    std::function<void(const std::string&)> unblockApp;
    std::function<void(const std::string&)> blockDomain;
    std::function<void(const std::string&)> unblockDomain;
};

class WebServer {
public:
    WebServer(int port, const WebServerCallbacks& callbacks);
    ~WebServer();

    // Start the web server in a background thread
    bool start();

    // Stop the web server
    void stop();

    // Check if running
    bool isRunning() const { return running_; }

    // Get the port
    int getPort() const { return port_; }

private:
    int port_;
    WebServerCallbacks callbacks_;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
    socket_t server_socket_ = INVALID_SOCK;

    // Server main loop
    void serverLoop();

    // Handle a single client connection
    void handleClient(socket_t client_socket);

    // Parse HTTP request
    HTTPRequest parseRequest(const std::string& raw_request);

    // Route request to handler
    HTTPResponse routeRequest(const HTTPRequest& req);

    // Send HTTP response
    void sendResponse(socket_t client_socket, const HTTPResponse& response);

    // --- API Handlers ---
    HTTPResponse handleGetStats();
    HTTPResponse handleGetThreats();
    HTTPResponse handleGetConnections();
    HTTPResponse handleGetBandwidth();
    HTTPResponse handleGetTimeSeries();
    HTTPResponse handleGetRules();
    HTTPResponse handleGetTopTalkers();
    HTTPResponse handleBlockIP(const HTTPRequest& req);
    HTTPResponse handleUnblockIP(const HTTPRequest& req);
    HTTPResponse handleBlockApp(const HTTPRequest& req);
    HTTPResponse handleUnblockApp(const HTTPRequest& req);
    HTTPResponse handleBlockDomain(const HTTPRequest& req);
    HTTPResponse handleUnblockDomain(const HTTPRequest& req);
    HTTPResponse handleExportJSON();
    HTTPResponse handleExportCSV();

    // Serve the dashboard HTML
    HTTPResponse serveDashboard();

    // Get the embedded HTML dashboard
    static std::string getDashboardHTML();

    // Helper: extract value from JSON body
    static std::string extractJSONValue(const std::string& json, const std::string& key);

    // Initialize sockets (Windows needs WSAStartup)
    static bool initSockets();
    static void cleanupSockets();
};

} // namespace DPI

#endif // WEB_SERVER_H
