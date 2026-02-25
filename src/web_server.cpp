#include "web_server.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace DPI {

// ============================================================================
// Socket Initialization
// ============================================================================

bool WebServer::initSockets() {
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
#else
    return true;
#endif
}

void WebServer::cleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

WebServer::WebServer(int port, const WebServerCallbacks& callbacks)
    : port_(port), callbacks_(callbacks) {}

WebServer::~WebServer() {
    stop();
}

// ============================================================================
// Start / Stop
// ============================================================================

bool WebServer::start() {
    if (running_) return true;

    if (!initSockets()) {
        std::cerr << "[WebServer] Failed to initialize sockets\n";
        return false;
    }

    server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket_ == INVALID_SOCK) {
        std::cerr << "[WebServer] Failed to create socket\n";
        return false;
    }

    // Allow port reuse
    int opt = 1;
#ifdef _WIN32
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port_));

    if (bind(server_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[WebServer] Failed to bind to port " << port_ << "\n";
        CLOSE_SOCKET(server_socket_);
        return false;
    }

    if (listen(server_socket_, 10) < 0) {
        std::cerr << "[WebServer] Failed to listen\n";
        CLOSE_SOCKET(server_socket_);
        return false;
    }

    running_ = true;
    server_thread_ = std::thread(&WebServer::serverLoop, this);

    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║              DPI Web Dashboard Running                        ║\n";
    std::cout << "║              http://localhost:" << port_ << "                            ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    return true;
}

void WebServer::stop() {
    if (!running_) return;
    running_ = false;

    if (server_socket_ != INVALID_SOCK) {
        CLOSE_SOCKET(server_socket_);
        server_socket_ = INVALID_SOCK;
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    cleanupSockets();
    std::cout << "[WebServer] Stopped\n";
}

// ============================================================================
// Server Loop
// ============================================================================

void WebServer::serverLoop() {
    while (running_) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int client_len = sizeof(client_addr);
#else
        socklen_t client_len = sizeof(client_addr);
#endif

        socket_t client = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        if (client == INVALID_SOCK) {
            if (running_) {
                // Brief pause before retrying
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            continue;
        }

        // Handle client in current thread (simple approach)
        handleClient(client);
        CLOSE_SOCKET(client);
    }
}

void WebServer::handleClient(socket_t client_socket) {
    // Read request
    char buffer[8192];
    memset(buffer, 0, sizeof(buffer));

#ifdef _WIN32
    int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#else
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#endif

    if (bytes_read <= 0) return;

    std::string raw_request(buffer, bytes_read);

    // If we have Content-Length but haven't read all body yet, read more
    auto cl_pos = raw_request.find("Content-Length:");
    if (cl_pos != std::string::npos) {
        auto header_end = raw_request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            size_t body_start = header_end + 4;
            auto cl_line_end = raw_request.find("\r\n", cl_pos);
            std::string cl_val = raw_request.substr(cl_pos + 15, cl_line_end - cl_pos - 15);
            // trim
            cl_val.erase(0, cl_val.find_first_not_of(" "));
            int content_length = std::stoi(cl_val);
            size_t body_received = raw_request.size() - body_start;
            while (static_cast<int>(body_received) < content_length) {
                memset(buffer, 0, sizeof(buffer));
#ifdef _WIN32
                bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#else
                bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#endif
                if (bytes_read <= 0) break;
                raw_request.append(buffer, bytes_read);
                body_received += bytes_read;
            }
        }
    }

    HTTPRequest req = parseRequest(raw_request);
    HTTPResponse resp = routeRequest(req);
    sendResponse(client_socket, resp);
}

// ============================================================================
// HTTP Parsing
// ============================================================================

HTTPRequest WebServer::parseRequest(const std::string& raw) {
    HTTPRequest req;
    std::istringstream stream(raw);
    std::string line;

    // Parse request line
    if (std::getline(stream, line)) {
        // Remove trailing \r
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream req_line(line);
        req_line >> req.method >> req.path;
    }

    // Parse query parameters
    auto qpos = req.path.find('?');
    if (qpos != std::string::npos) {
        std::string query = req.path.substr(qpos + 1);
        req.path = req.path.substr(0, qpos);
        // Simple query parameter parsing
        std::istringstream qs(query);
        std::string param;
        while (std::getline(qs, param, '&')) {
            auto eq = param.find('=');
            if (eq != std::string::npos) {
                req.query_params[param.substr(0, eq)] = param.substr(eq + 1);
            }
        }
    }

    // Parse headers
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            val.erase(0, val.find_first_not_of(" "));
            req.headers[key] = val;
        }
    }

    // Parse body
    auto body_pos = raw.find("\r\n\r\n");
    if (body_pos != std::string::npos) {
        req.body = raw.substr(body_pos + 4);
    }

    return req;
}

// ============================================================================
// Routing
// ============================================================================

HTTPResponse WebServer::routeRequest(const HTTPRequest& req) {
    // Serve dashboard
    if (req.path == "/" || req.path == "/index.html") {
        return serveDashboard();
    }

    // API routes
    if (req.method == "GET") {
        if (req.path == "/api/stats")        return handleGetStats();
        if (req.path == "/api/threats")      return handleGetThreats();
        if (req.path == "/api/connections")  return handleGetConnections();
        if (req.path == "/api/bandwidth")    return handleGetBandwidth();
        if (req.path == "/api/timeseries")   return handleGetTimeSeries();
        if (req.path == "/api/rules")        return handleGetRules();
        if (req.path == "/api/top-talkers")  return handleGetTopTalkers();
        if (req.path == "/api/export/json")  return handleExportJSON();
        if (req.path == "/api/export/csv")   return handleExportCSV();
    }

    if (req.method == "POST") {
        if (req.path == "/api/rules/block-ip")       return handleBlockIP(req);
        if (req.path == "/api/rules/unblock-ip")     return handleUnblockIP(req);
        if (req.path == "/api/rules/block-app")      return handleBlockApp(req);
        if (req.path == "/api/rules/unblock-app")    return handleUnblockApp(req);
        if (req.path == "/api/rules/block-domain")   return handleBlockDomain(req);
        if (req.path == "/api/rules/unblock-domain") return handleUnblockDomain(req);
    }

    // 404
    HTTPResponse resp;
    resp.status_code = 404;
    resp.body = "{\"error\": \"Not Found\"}";
    return resp;
}

void WebServer::sendResponse(socket_t client_socket, const HTTPResponse& resp) {
    std::ostringstream ss;
    ss << "HTTP/1.1 " << resp.status_code << " ";
    switch (resp.status_code) {
        case 200: ss << "OK"; break;
        case 404: ss << "Not Found"; break;
        case 400: ss << "Bad Request"; break;
        case 500: ss << "Internal Server Error"; break;
        default:  ss << "Unknown"; break;
    }
    ss << "\r\n";
    ss << "Content-Type: " << resp.content_type << "\r\n";
    ss << "Content-Length: " << resp.body.size() << "\r\n";
    ss << "Access-Control-Allow-Origin: *\r\n";
    ss << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    ss << "Access-Control-Allow-Headers: Content-Type\r\n";
    ss << "Connection: close\r\n";
    for (const auto& [key, val] : resp.headers) {
        ss << key << ": " << val << "\r\n";
    }
    ss << "\r\n";
    ss << resp.body;

    std::string response_str = ss.str();
    send(client_socket, response_str.c_str(), static_cast<int>(response_str.size()), 0);
}

// ============================================================================
// JSON value extractor (simple)
// ============================================================================

std::string WebServer::extractJSONValue(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos++;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        // String value
        pos++;
        auto end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    } else {
        // Number or other
        auto end = json.find_first_of(",}\n\r", pos);
        if (end == std::string::npos) end = json.size();
        std::string val = json.substr(pos, end - pos);
        // Trim
        val.erase(val.find_last_not_of(" \t\r\n") + 1);
        return val;
    }
}

// ============================================================================
// API Handlers
// ============================================================================

HTTPResponse WebServer::handleGetStats() {
    HTTPResponse resp;
    try {
        auto snap = callbacks_.getStats();
        ReportExporter::SimpleStats ss;
        ss.total_packets = snap.total_packets;
        ss.total_bytes = snap.total_bytes;
        ss.forwarded_packets = snap.forwarded_packets;
        ss.dropped_packets = snap.dropped_packets;
        ss.tcp_packets = snap.tcp_packets;
        ss.udp_packets = snap.udp_packets;
        auto app_bw = callbacks_.getAppBandwidth();
        auto talkers = callbacks_.getTopTalkers();
        auto proto = callbacks_.getProtocolStats();
        auto overall = callbacks_.getOverallStats();
        resp.body = ReportExporter::statsToJSON(ss, app_bw, talkers, proto, overall);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleGetThreats() {
    HTTPResponse resp;
    try {
        auto alerts = callbacks_.getAlerts();
        auto stats = callbacks_.getThreatStats();
        resp.body = ReportExporter::threatsToJSON(alerts, stats);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleGetConnections() {
    HTTPResponse resp;
    try {
        auto conns = callbacks_.getConnections();
        resp.body = ReportExporter::connectionsToJSON(conns);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleGetBandwidth() {
    HTTPResponse resp;
    try {
        auto bw = callbacks_.getAppBandwidth();
        resp.body = ReportExporter::appBandwidthToJSON(bw);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleGetTimeSeries() {
    HTTPResponse resp;
    try {
        auto ts = callbacks_.getTimeSeries();
        resp.body = ReportExporter::timeSeriesJSON(ts);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleGetRules() {
    HTTPResponse resp;
    try {
        auto ips = callbacks_.getBlockedIPs();
        auto apps_raw = callbacks_.getBlockedApps();
        auto domains = callbacks_.getBlockedDomains();
        resp.body = ReportExporter::rulesToJSON(ips, apps_raw, domains);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleGetTopTalkers() {
    HTTPResponse resp;
    try {
        auto talkers = callbacks_.getTopTalkers();
        resp.body = ReportExporter::topTalkersToJSON(talkers);
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Internal error\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleBlockIP(const HTTPRequest& req) {
    HTTPResponse resp;
    std::string ip = extractJSONValue(req.body, "ip");
    if (ip.empty()) {
        resp.status_code = 400;
        resp.body = "{\"error\": \"Missing 'ip' field\"}";
        return resp;
    }
    callbacks_.blockIP(ip);
    resp.body = "{\"status\": \"ok\", \"blocked_ip\": \"" + ip + "\"}";
    return resp;
}

HTTPResponse WebServer::handleUnblockIP(const HTTPRequest& req) {
    HTTPResponse resp;
    std::string ip = extractJSONValue(req.body, "ip");
    if (ip.empty()) {
        resp.status_code = 400;
        resp.body = "{\"error\": \"Missing 'ip' field\"}";
        return resp;
    }
    callbacks_.unblockIP(ip);
    resp.body = "{\"status\": \"ok\", \"unblocked_ip\": \"" + ip + "\"}";
    return resp;
}

HTTPResponse WebServer::handleBlockApp(const HTTPRequest& req) {
    HTTPResponse resp;
    std::string app = extractJSONValue(req.body, "app");
    if (app.empty()) {
        resp.status_code = 400;
        resp.body = "{\"error\": \"Missing 'app' field\"}";
        return resp;
    }
    callbacks_.blockApp(app);
    resp.body = "{\"status\": \"ok\", \"blocked_app\": \"" + app + "\"}";
    return resp;
}

HTTPResponse WebServer::handleUnblockApp(const HTTPRequest& req) {
    HTTPResponse resp;
    std::string app = extractJSONValue(req.body, "app");
    if (app.empty()) {
        resp.status_code = 400;
        resp.body = "{\"error\": \"Missing 'app' field\"}";
        return resp;
    }
    callbacks_.unblockApp(app);
    resp.body = "{\"status\": \"ok\", \"unblocked_app\": \"" + app + "\"}";
    return resp;
}

HTTPResponse WebServer::handleBlockDomain(const HTTPRequest& req) {
    HTTPResponse resp;
    std::string domain = extractJSONValue(req.body, "domain");
    if (domain.empty()) {
        resp.status_code = 400;
        resp.body = "{\"error\": \"Missing 'domain' field\"}";
        return resp;
    }
    callbacks_.blockDomain(domain);
    resp.body = "{\"status\": \"ok\", \"blocked_domain\": \"" + domain + "\"}";
    return resp;
}

HTTPResponse WebServer::handleUnblockDomain(const HTTPRequest& req) {
    HTTPResponse resp;
    std::string domain = extractJSONValue(req.body, "domain");
    if (domain.empty()) {
        resp.status_code = 400;
        resp.body = "{\"error\": \"Missing 'domain' field\"}";
        return resp;
    }
    callbacks_.unblockDomain(domain);
    resp.body = "{\"status\": \"ok\", \"unblocked_domain\": \"" + domain + "\"}";
    return resp;
}

HTTPResponse WebServer::handleExportJSON() {
    HTTPResponse resp;
    try {
        auto snap = callbacks_.getStats();
        ReportExporter::SimpleStats ss;
        ss.total_packets = snap.total_packets;
        ss.total_bytes = snap.total_bytes;
        ss.forwarded_packets = snap.forwarded_packets;
        ss.dropped_packets = snap.dropped_packets;
        ss.tcp_packets = snap.tcp_packets;
        ss.udp_packets = snap.udp_packets;
        auto app_bw = callbacks_.getAppBandwidth();
        auto talkers = callbacks_.getTopTalkers();
        auto proto = callbacks_.getProtocolStats();
        auto overall = callbacks_.getOverallStats();
        resp.body = ReportExporter::statsToJSON(ss, app_bw, talkers, proto, overall);
        resp.headers["Content-Disposition"] = "attachment; filename=\"dpi_report.json\"";
    } catch (...) {
        resp.status_code = 500;
        resp.body = "{\"error\": \"Export failed\"}";
    }
    return resp;
}

HTTPResponse WebServer::handleExportCSV() {
    HTTPResponse resp;
    resp.content_type = "text/csv";
    try {
        auto conns = callbacks_.getConnections();
        resp.body = ReportExporter::connectionsToCSV(conns);
        resp.headers["Content-Disposition"] = "attachment; filename=\"dpi_connections.csv\"";
    } catch (...) {
        resp.status_code = 500;
        resp.content_type = "application/json";
        resp.body = "{\"error\": \"Export failed\"}";
    }
    return resp;
}

HTTPResponse WebServer::serveDashboard() {
    HTTPResponse resp;
    resp.content_type = "text/html; charset=utf-8";
    resp.body = getDashboardHTML();
    return resp;
}

// ============================================================================
// Embedded Dashboard HTML
// ============================================================================

std::string WebServer::getDashboardHTML() {
    return R"DASHBOARD(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DPI Engine Dashboard</title>
<style>
    :root {
        --bg-primary: #0f172a;
        --bg-secondary: #1e293b;
        --bg-card: #1e293b;
        --bg-card-hover: #334155;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --accent-blue: #3b82f6;
        --accent-green: #22c55e;
        --accent-red: #ef4444;
        --accent-yellow: #eab308;
        --accent-purple: #a855f7;
        --accent-cyan: #06b6d4;
        --border: #334155;
        --shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        min-height: 100vh;
    }

    .header {
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        padding: 16px 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .header h1 {
        font-size: 20px;
        font-weight: 700;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .header h1 .logo {
        width: 32px; height: 32px;
        background: var(--accent-blue);
        border-radius: 8px;
        display: flex; align-items: center; justify-content: center;
        font-size: 16px;
    }

    .status-badge {
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }

    .status-live { background: rgba(34,197,94,0.15); color: var(--accent-green); }

    .nav {
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        padding: 0 24px;
        display: flex;
        gap: 0;
        overflow-x: auto;
    }

    .nav-btn {
        padding: 12px 20px;
        background: none;
        border: none;
        color: var(--text-secondary);
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        white-space: nowrap;
        transition: all 0.2s;
    }

    .nav-btn:hover { color: var(--text-primary); background: rgba(255,255,255,0.03); }
    .nav-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }

    .main { padding: 20px 24px; }

    .grid { display: grid; gap: 16px; }
    .grid-4 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
    .grid-2 { grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); }
    .grid-1 { grid-template-columns: 1fr; }

    .card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        box-shadow: var(--shadow);
    }

    .card-title {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: var(--text-secondary);
        margin-bottom: 8px;
    }

    .stat-value {
        font-size: 28px;
        font-weight: 700;
        line-height: 1.2;
    }

    .stat-sub {
        font-size: 12px;
        color: var(--text-secondary);
        margin-top: 4px;
    }

    .section { margin-top: 20px; }

    .section-title {
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }

    th {
        text-align: left;
        padding: 10px 12px;
        background: rgba(255,255,255,0.03);
        color: var(--text-secondary);
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        border-bottom: 1px solid var(--border);
    }

    td {
        padding: 10px 12px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
    }

    tr:hover td { background: rgba(255,255,255,0.02); }

    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 10px;
        font-size: 11px;
        font-weight: 600;
    }

    .badge-green { background: rgba(34,197,94,0.15); color: var(--accent-green); }
    .badge-red { background: rgba(239,68,68,0.15); color: var(--accent-red); }
    .badge-yellow { background: rgba(234,179,8,0.15); color: var(--accent-yellow); }
    .badge-blue { background: rgba(59,130,246,0.15); color: var(--accent-blue); }
    .badge-purple { background: rgba(168,85,247,0.15); color: var(--accent-purple); }

    .bar-chart { margin-top: 12px; }

    .bar-row {
        display: flex;
        align-items: center;
        margin-bottom: 8px;
        gap: 10px;
    }

    .bar-label {
        width: 120px;
        font-size: 13px;
        text-align: right;
        color: var(--text-secondary);
        flex-shrink: 0;
    }

    .bar-track {
        flex: 1;
        height: 24px;
        background: rgba(255,255,255,0.05);
        border-radius: 6px;
        overflow: hidden;
    }

    .bar-fill {
        height: 100%;
        border-radius: 6px;
        display: flex;
        align-items: center;
        padding-left: 8px;
        font-size: 11px;
        font-weight: 600;
        color: white;
        min-width: fit-content;
        transition: width 0.5s ease;
    }

    .bar-value {
        width: 80px;
        font-size: 12px;
        color: var(--text-secondary);
        flex-shrink: 0;
    }

    .colors-0 { background: var(--accent-blue); }
    .colors-1 { background: var(--accent-green); }
    .colors-2 { background: var(--accent-purple); }
    .colors-3 { background: var(--accent-cyan); }
    .colors-4 { background: var(--accent-yellow); }
    .colors-5 { background: var(--accent-red); }

    .form-row {
        display: flex;
        gap: 8px;
        margin-bottom: 8px;
    }

    input[type="text"] {
        padding: 8px 12px;
        background: var(--bg-primary);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--text-primary);
        font-size: 13px;
        flex: 1;
        outline: none;
    }

    input[type="text"]:focus { border-color: var(--accent-blue); }

    select {
        padding: 8px 12px;
        background: var(--bg-primary);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--text-primary);
        font-size: 13px;
        outline: none;
    }

    button.btn {
        padding: 8px 16px;
        border: none;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: opacity 0.2s;
    }

    button.btn:hover { opacity: 0.85; }
    .btn-blue { background: var(--accent-blue); color: white; }
    .btn-red { background: var(--accent-red); color: white; }
    .btn-green { background: var(--accent-green); color: white; }

    .rule-tag {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        background: rgba(239,68,68,0.1);
        border: 1px solid rgba(239,68,68,0.3);
        border-radius: 20px;
        font-size: 12px;
        margin: 4px;
    }

    .rule-tag .remove {
        cursor: pointer;
        color: var(--accent-red);
        font-weight: bold;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .threat-card {
        padding: 12px 16px;
        border-left: 3px solid var(--accent-red);
        background: rgba(239,68,68,0.05);
        border-radius: 0 8px 8px 0;
        margin-bottom: 8px;
    }

    .threat-card.severity-MEDIUM { border-left-color: var(--accent-yellow); background: rgba(234,179,8,0.05); }
    .threat-card.severity-HIGH { border-left-color: #f97316; background: rgba(249,115,22,0.05); }
    .threat-card.severity-CRITICAL { border-left-color: var(--accent-red); background: rgba(239,68,68,0.08); }
    .threat-card.severity-LOW { border-left-color: var(--accent-blue); background: rgba(59,130,246,0.05); }

    .threat-header { display: flex; justify-content: space-between; align-items: center; }
    .threat-type { font-weight: 600; font-size: 14px; }
    .threat-desc { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }

    .export-btns { display: flex; gap: 8px; margin-top: 12px; }

    .canvas-container {
        width: 100%;
        height: 200px;
        position: relative;
        margin-top: 12px;
    }

    .canvas-container canvas {
        width: 100%;
        height: 100%;
    }

    .proto-chart { display: flex; gap: 20px; align-items: center; margin-top: 12px; }
    .proto-donut { position: relative; width: 120px; height: 120px; }
    .proto-legend { flex: 1; }

    .legend-item {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
        font-size: 13px;
    }

    .legend-dot {
        width: 10px; height: 10px;
        border-radius: 50%;
        flex-shrink: 0;
    }

    @media (max-width: 768px) {
        .grid-4 { grid-template-columns: repeat(2, 1fr); }
        .grid-2 { grid-template-columns: 1fr; }
        .main { padding: 12px; }
    }
</style>
</head>
<body>

<div class="header">
    <h1>
        <div class="logo">&#x1F6E1;</div>
        DPI Engine Dashboard
    </h1>
    <div>
        <span class="status-badge status-live" id="statusBadge">&#x25CF; LIVE</span>
    </div>
</div>

<div class="nav">
    <button class="nav-btn active" onclick="switchTab('overview')">Overview</button>
    <button class="nav-btn" onclick="switchTab('bandwidth')">Bandwidth</button>
    <button class="nav-btn" onclick="switchTab('threats')">Threats</button>
    <button class="nav-btn" onclick="switchTab('connections')">Connections</button>
    <button class="nav-btn" onclick="switchTab('rules')">Rules</button>
    <button class="nav-btn" onclick="switchTab('export')">Export</button>
</div>

<div class="main">

<!-- ==================== OVERVIEW TAB ==================== -->
<div class="tab-content active" id="tab-overview">
    <div class="grid grid-4">
        <div class="card">
            <div class="card-title">Total Packets</div>
            <div class="stat-value" id="totalPackets">0</div>
            <div class="stat-sub" id="totalBytes">0 bytes</div>
        </div>
        <div class="card">
            <div class="card-title">Forwarded</div>
            <div class="stat-value" style="color:var(--accent-green)" id="forwarded">0</div>
            <div class="stat-sub" id="fwdPct">0%</div>
        </div>
        <div class="card">
            <div class="card-title">Dropped/Blocked</div>
            <div class="stat-value" style="color:var(--accent-red)" id="dropped">0</div>
            <div class="stat-sub" id="dropPct">0%</div>
        </div>
        <div class="card">
            <div class="card-title">Threat Alerts</div>
            <div class="stat-value" style="color:var(--accent-yellow)" id="threatCount">0</div>
            <div class="stat-sub" id="threatBreakdown">-</div>
        </div>
    </div>

    <div class="grid grid-2 section">
        <div class="card">
            <div class="section-title">Application Distribution</div>
            <div class="bar-chart" id="appChart"></div>
        </div>
        <div class="card">
            <div class="section-title">Protocol Distribution</div>
            <div class="proto-chart">
                <canvas id="protoCanvas" width="120" height="120"></canvas>
                <div class="proto-legend" id="protoLegend"></div>
            </div>
        </div>
    </div>

    <div class="grid grid-2 section">
        <div class="card">
            <div class="section-title">Network Overview</div>
            <table>
                <tr><td>Duration</td><td id="duration">-</td></tr>
                <tr><td>Avg Throughput</td><td id="avgBps">-</td></tr>
                <tr><td>Avg Packet Rate</td><td id="avgPps">-</td></tr>
                <tr><td>Avg Packet Size</td><td id="avgPktSize">-</td></tr>
                <tr><td>Unique Source IPs</td><td id="uniqueSrc">-</td></tr>
                <tr><td>Unique Dest IPs</td><td id="uniqueDst">-</td></tr>
            </table>
        </div>
        <div class="card">
            <div class="section-title">Top Talkers</div>
            <table>
                <thead><tr><th>IP Address</th><th>Sent</th><th>Received</th></tr></thead>
                <tbody id="topTalkersTable"></tbody>
            </table>
        </div>
    </div>
</div>

<!-- ==================== BANDWIDTH TAB ==================== -->
<div class="tab-content" id="tab-bandwidth">
    <div class="grid grid-4">
        <div class="card">
            <div class="card-title">Total Data</div>
            <div class="stat-value" id="bwTotal">-</div>
        </div>
        <div class="card">
            <div class="card-title">TCP Data</div>
            <div class="stat-value" style="color:var(--accent-blue)" id="bwTcp">-</div>
        </div>
        <div class="card">
            <div class="card-title">UDP Data</div>
            <div class="stat-value" style="color:var(--accent-green)" id="bwUdp">-</div>
        </div>
        <div class="card">
            <div class="card-title">Avg Speed</div>
            <div class="stat-value" style="color:var(--accent-cyan)" id="bwSpeed">-</div>
        </div>
    </div>

    <div class="section card">
        <div class="section-title">Per-Application Bandwidth</div>
        <table>
            <thead><tr><th>Application</th><th>Data</th><th>Packets</th><th>Connections</th><th>Share</th></tr></thead>
            <tbody id="bwAppTable"></tbody>
        </table>
    </div>

    <div class="section card">
        <div class="section-title">Top Talkers (by total bytes)</div>
        <table>
            <thead><tr><th>IP Address</th><th>Sent</th><th>Received</th><th>Packets Sent</th><th>Packets Recv</th></tr></thead>
            <tbody id="bwTalkersTable"></tbody>
        </table>
    </div>
</div>

<!-- ==================== THREATS TAB ==================== -->
<div class="tab-content" id="tab-threats">
    <div class="grid grid-4">
        <div class="card">
            <div class="card-title">Total Alerts</div>
            <div class="stat-value" style="color:var(--accent-red)" id="tTotalAlerts">0</div>
        </div>
        <div class="card">
            <div class="card-title">Port Scans</div>
            <div class="stat-value" id="tPortScans">0</div>
        </div>
        <div class="card">
            <div class="card-title">DDoS Floods</div>
            <div class="stat-value" id="tDDoS">0</div>
        </div>
        <div class="card">
            <div class="card-title">SYN Floods</div>
            <div class="stat-value" id="tSYN">0</div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Recent Alerts</div>
        <div id="threatAlerts">
            <p style="color: var(--text-secondary)">No threat alerts detected.</p>
        </div>
    </div>
</div>

<!-- ==================== CONNECTIONS TAB ==================== -->
<div class="tab-content" id="tab-connections">
    <div class="card">
        <div class="section-title">Active Connections</div>
        <div style="overflow-x: auto;">
        <table>
            <thead><tr><th>Flow</th><th>State</th><th>Application</th><th>SNI/Domain</th><th>Pkts In</th><th>Pkts Out</th><th>Bytes</th></tr></thead>
            <tbody id="connTable"></tbody>
        </table>
        </div>
    </div>
</div>

<!-- ==================== RULES TAB ==================== -->
<div class="tab-content" id="tab-rules">
    <div class="grid grid-1">
        <div class="card">
            <div class="section-title">Block IP Address</div>
            <div class="form-row">
                <input type="text" id="blockIpInput" placeholder="e.g. 192.168.1.100">
                <button class="btn btn-red" onclick="blockIP()">Block IP</button>
            </div>
            <div id="blockedIPs" style="margin-top:8px;"></div>
        </div>
        <div class="card">
            <div class="section-title">Block Application</div>
            <div class="form-row">
                <select id="blockAppSelect">
                    <option value="YouTube">YouTube</option>
                    <option value="Facebook">Facebook</option>
                    <option value="Netflix">Netflix</option>
                    <option value="Instagram">Instagram</option>
                    <option value="Twitter">Twitter</option>
                    <option value="TikTok">TikTok</option>
                    <option value="WhatsApp">WhatsApp</option>
                    <option value="Telegram">Telegram</option>
                    <option value="Discord">Discord</option>
                    <option value="Spotify">Spotify</option>
                    <option value="Zoom">Zoom</option>
                    <option value="GitHub">GitHub</option>
                </select>
                <button class="btn btn-red" onclick="blockApp()">Block App</button>
            </div>
            <div id="blockedApps" style="margin-top:8px;"></div>
        </div>
        <div class="card">
            <div class="section-title">Block Domain</div>
            <div class="form-row">
                <input type="text" id="blockDomainInput" placeholder="e.g. *.facebook.com">
                <button class="btn btn-red" onclick="blockDomain()">Block Domain</button>
            </div>
            <div id="blockedDomains" style="margin-top:8px;"></div>
        </div>
    </div>
</div>

<!-- ==================== EXPORT TAB ==================== -->
<div class="tab-content" id="tab-export">
    <div class="card">
        <div class="section-title">Export Reports</div>
        <p style="color:var(--text-secondary);margin-bottom:16px;">Download DPI analysis data in various formats.</p>
        <div class="export-btns">
            <button class="btn btn-blue" onclick="window.open('/api/export/json')">Download JSON Report</button>
            <button class="btn btn-green" onclick="window.open('/api/export/csv')">Download CSV (Connections)</button>
        </div>
    </div>
</div>

</div>

<script>
// ==================== State ====================
let currentTab = 'overview';
let refreshInterval = null;

// ==================== Navigation ====================
function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + tab).classList.add('active');
    event.target.classList.add('active');
    refreshData();
}

// ==================== Formatting ====================
function fmtBytes(b) {
    if (b >= 1073741824) return (b/1073741824).toFixed(2) + ' GB';
    if (b >= 1048576) return (b/1048576).toFixed(2) + ' MB';
    if (b >= 1024) return (b/1024).toFixed(2) + ' KB';
    return b + ' B';
}

function fmtNumber(n) {
    return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function fmtBits(bps) {
    if (bps >= 1e9) return (bps/1e9).toFixed(2) + ' Gbps';
    if (bps >= 1e6) return (bps/1e6).toFixed(2) + ' Mbps';
    if (bps >= 1e3) return (bps/1e3).toFixed(2) + ' Kbps';
    return bps.toFixed(0) + ' bps';
}

function stateBadge(s) {
    const map = {
        'ESTABLISHED': 'badge-green', 'CLASSIFIED': 'badge-blue',
        'BLOCKED': 'badge-red', 'NEW': 'badge-yellow', 'CLOSED': 'badge-purple'
    };
    return `<span class="badge ${map[s]||'badge-yellow'}">${s}</span>`;
}

function severityBadge(s) {
    const map = { 'LOW': 'badge-blue', 'MEDIUM': 'badge-yellow', 'HIGH': 'badge-purple', 'CRITICAL': 'badge-red' };
    return `<span class="badge ${map[s]||'badge-yellow'}">${s}</span>`;
}

// ==================== API Calls ====================
async function fetchJSON(url) {
    try {
        const r = await fetch(url);
        return await r.json();
    } catch(e) {
        console.error('Fetch error:', url, e);
        return null;
    }
}

async function postJSON(url, data) {
    try {
        const r = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        return await r.json();
    } catch(e) {
        console.error('Post error:', url, e);
        return null;
    }
}

// ==================== Data Refresh ====================
async function refreshData() {
    if (currentTab === 'overview' || currentTab === 'bandwidth') {
        const stats = await fetchJSON('/api/stats');
        if (stats) updateOverview(stats);
    }
    if (currentTab === 'overview' || currentTab === 'threats') {
        const threats = await fetchJSON('/api/threats');
        if (threats) updateThreats(threats);
    }
    if (currentTab === 'connections') {
        const conns = await fetchJSON('/api/connections');
        if (conns) updateConnections(conns);
    }
    if (currentTab === 'rules') {
        const rules = await fetchJSON('/api/rules');
        if (rules) updateRules(rules);
    }
}

// ==================== Update Functions ====================
function updateOverview(data) {
    const ps = data.packet_stats;
    const bw = data.bandwidth;
    const proto = data.protocols;

    document.getElementById('totalPackets').textContent = fmtNumber(ps.total_packets);
    document.getElementById('totalBytes').textContent = fmtBytes(ps.total_bytes);
    document.getElementById('forwarded').textContent = fmtNumber(ps.forwarded);
    document.getElementById('dropped').textContent = fmtNumber(ps.dropped);

    const total = ps.total_packets || 1;
    document.getElementById('fwdPct').textContent = ((ps.forwarded/total)*100).toFixed(1) + '%';
    document.getElementById('dropPct').textContent = ((ps.dropped/total)*100).toFixed(1) + '%';

    // Network overview
    document.getElementById('duration').textContent = bw.duration_sec > 0 ? bw.duration_sec.toFixed(1) + 's' : '-';
    document.getElementById('avgBps').textContent = fmtBits(bw.avg_bps);
    document.getElementById('avgPps').textContent = bw.avg_pps.toFixed(1) + ' pps';
    document.getElementById('avgPktSize').textContent = bw.avg_packet_size.toFixed(0) + ' bytes';
    document.getElementById('uniqueSrc').textContent = fmtNumber(bw.unique_src_ips);
    document.getElementById('uniqueDst').textContent = fmtNumber(bw.unique_dst_ips);

    // App chart
    const appBw = data.app_bandwidth || [];
    const totalAppBytes = appBw.reduce((s,a) => s + a.bytes, 0) || 1;
    let appHTML = '';
    appBw.slice(0, 8).forEach((app, i) => {
        const pct = (app.bytes / totalAppBytes * 100);
        appHTML += `<div class="bar-row">
            <div class="bar-label">${app.app}</div>
            <div class="bar-track"><div class="bar-fill colors-${i%6}" style="width:${Math.max(pct,2)}%">${pct.toFixed(1)}%</div></div>
            <div class="bar-value">${fmtBytes(app.bytes)}</div>
        </div>`;
    });
    document.getElementById('appChart').innerHTML = appHTML;

    // Protocol donut
    drawProtocolDonut(proto);

    // Top talkers
    const talkers = data.top_talkers || [];
    let tHTML = '';
    talkers.slice(0,5).forEach(t => {
        tHTML += `<tr><td>${t.ip}</td><td>${fmtBytes(t.bytes_sent)}</td><td>${fmtBytes(t.bytes_received)}</td></tr>`;
    });
    document.getElementById('topTalkersTable').innerHTML = tHTML || '<tr><td colspan="3" style="color:var(--text-secondary)">No data</td></tr>';

    // Bandwidth tab
    document.getElementById('bwTotal').textContent = fmtBytes(bw.total_bytes);
    document.getElementById('bwTcp').textContent = fmtBytes(proto.tcp_bytes);
    document.getElementById('bwUdp').textContent = fmtBytes(proto.udp_bytes);
    document.getElementById('bwSpeed').textContent = fmtBits(bw.avg_bps);

    let bwAppHTML = '';
    appBw.forEach((app, i) => {
        const pct = (app.bytes / totalAppBytes * 100).toFixed(1);
        bwAppHTML += `<tr><td>${app.app}</td><td>${fmtBytes(app.bytes)}</td><td>${fmtNumber(app.packets)}</td><td>${app.connections}</td>
            <td><div class="bar-track" style="height:16px;width:120px;display:inline-block"><div class="bar-fill colors-${i%6}" style="width:${Math.max(parseFloat(pct),2)}%"></div></div> ${pct}%</td></tr>`;
    });
    document.getElementById('bwAppTable').innerHTML = bwAppHTML || '<tr><td colspan="5">No data</td></tr>';

    let bwTalkHTML = '';
    talkers.slice(0,10).forEach(t => {
        bwTalkHTML += `<tr><td>${t.ip}</td><td>${fmtBytes(t.bytes_sent)}</td><td>${fmtBytes(t.bytes_received)}</td><td>${fmtNumber(t.packets_sent)}</td><td>${fmtNumber(t.packets_received)}</td></tr>`;
    });
    document.getElementById('bwTalkersTable').innerHTML = bwTalkHTML || '<tr><td colspan="5">No data</td></tr>';
}

function drawProtocolDonut(proto) {
    const canvas = document.getElementById('protoCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const total = (proto.tcp_bytes + proto.udp_bytes + proto.other_bytes) || 1;
    const data = [
        { label: 'TCP', value: proto.tcp_bytes, color: '#3b82f6' },
        { label: 'UDP', value: proto.udp_bytes, color: '#22c55e' },
        { label: 'Other', value: proto.other_bytes, color: '#a855f7' }
    ];

    const cx = 60, cy = 60, r = 50, ir = 30;
    ctx.clearRect(0, 0, 120, 120);

    let startAngle = -Math.PI/2;
    data.forEach(d => {
        const sliceAngle = (d.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, ir, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = d.color;
        ctx.fill();
        startAngle += sliceAngle;
    });

    let legendHTML = '';
    data.forEach(d => {
        const pct = (d.value / total * 100).toFixed(1);
        legendHTML += `<div class="legend-item"><div class="legend-dot" style="background:${d.color}"></div>${d.label}: ${fmtBytes(d.value)} (${pct}%)</div>`;
    });
    document.getElementById('protoLegend').innerHTML = legendHTML;
}

function updateThreats(data) {
    document.getElementById('threatCount').textContent = data.stats.total_alerts;
    document.getElementById('tTotalAlerts').textContent = data.stats.total_alerts;
    document.getElementById('tPortScans').textContent = data.stats.port_scans;
    document.getElementById('tDDoS').textContent = data.stats.ddos_floods;
    document.getElementById('tSYN').textContent = data.stats.syn_floods;

    const breakdown = [];
    if (data.stats.port_scans > 0) breakdown.push(data.stats.port_scans + ' port scans');
    if (data.stats.ddos_floods > 0) breakdown.push(data.stats.ddos_floods + ' floods');
    if (data.stats.syn_floods > 0) breakdown.push(data.stats.syn_floods + ' SYN floods');
    if (data.stats.dns_tunneling > 0) breakdown.push(data.stats.dns_tunneling + ' DNS tunnel');
    document.getElementById('threatBreakdown').textContent = breakdown.length ? breakdown.join(', ') : 'No threats';

    const alerts = data.alerts || [];
    if (alerts.length === 0) {
        document.getElementById('threatAlerts').innerHTML = '<p style="color:var(--text-secondary)">No threat alerts detected. The network looks clean!</p>';
        return;
    }

    let html = '';
    alerts.slice().reverse().forEach(a => {
        html += `<div class="threat-card severity-${a.severity}">
            <div class="threat-header">
                <span class="threat-type">${a.type}</span>
                ${severityBadge(a.severity)}
            </div>
            <div class="threat-desc">${a.description}</div>
            <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">Source: ${a.source_ip} | Count: ${a.related_count}</div>
        </div>`;
    });
    document.getElementById('threatAlerts').innerHTML = html;
}

function updateConnections(conns) {
    let html = '';
    conns.forEach(c => {
        html += `<tr>
            <td style="font-family:monospace;font-size:11px;">${c.five_tuple}</td>
            <td>${stateBadge(c.state)}</td>
            <td>${c.app_type}</td>
            <td>${c.sni || '-'}</td>
            <td>${fmtNumber(c.packets_in)}</td>
            <td>${fmtNumber(c.packets_out)}</td>
            <td>${fmtBytes(c.bytes_in + c.bytes_out)}</td>
        </tr>`;
    });
    document.getElementById('connTable').innerHTML = html || '<tr><td colspan="7" style="color:var(--text-secondary)">No active connections</td></tr>';
}

function updateRules(rules) {
    const renderTags = (arr, type, containerId, unblockFn) => {
        let html = '';
        arr.forEach(item => {
            html += `<span class="rule-tag">${item} <span class="remove" onclick="${unblockFn}('${item}')">&times;</span></span>`;
        });
        document.getElementById(containerId).innerHTML = html || '<span style="color:var(--text-secondary);font-size:13px;">None</span>';
    };

    renderTags(rules.blocked_ips || [], 'ip', 'blockedIPs', 'unblockIP');
    renderTags(rules.blocked_apps || [], 'app', 'blockedApps', 'unblockApp');
    renderTags(rules.blocked_domains || [], 'domain', 'blockedDomains', 'unblockDomain');
}

// ==================== Rule Actions ====================
async function blockIP() {
    const ip = document.getElementById('blockIpInput').value.trim();
    if (!ip) return;
    await postJSON('/api/rules/block-ip', { ip });
    document.getElementById('blockIpInput').value = '';
    refreshData();
}

async function unblockIP(ip) {
    await postJSON('/api/rules/unblock-ip', { ip });
    refreshData();
}

async function blockApp() {
    const app = document.getElementById('blockAppSelect').value;
    await postJSON('/api/rules/block-app', { app });
    refreshData();
}

async function unblockApp(app) {
    await postJSON('/api/rules/unblock-app', { app });
    refreshData();
}

async function blockDomain() {
    const domain = document.getElementById('blockDomainInput').value.trim();
    if (!domain) return;
    await postJSON('/api/rules/block-domain', { domain });
    document.getElementById('blockDomainInput').value = '';
    refreshData();
}

async function unblockDomain(domain) {
    await postJSON('/api/rules/unblock-domain', { domain });
    refreshData();
}

// ==================== Init ====================
refreshData();
refreshInterval = setInterval(refreshData, 3000);
</script>
</body>
</html>
)DASHBOARD";
}

} // namespace DPI
