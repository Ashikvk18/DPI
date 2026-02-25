cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 3.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# Shared library sources (common to all executables)
# ============================================================================
set(COMMON_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# ============================================================================
# Original packet analyzer (basic PCAP reader)
# ============================================================================
add_executable(packet_analyzer
    src/main.cpp
    ${COMMON_SOURCES}
)

# ============================================================================
# DPI Dashboard (v3.0 with Web UI, Threat Detection, Bandwidth Monitor)
# ============================================================================
set(DPI_DASHBOARD_SOURCES
    src/main_dashboard.cpp
    src/threat_detector.cpp
    src/bandwidth_monitor.cpp
    src/report_exporter.cpp
    src/web_server.cpp
    ${COMMON_SOURCES}
)

add_executable(dpi_dashboard ${DPI_DASHBOARD_SOURCES})

# Platform-specific linking
if(WIN32)
    target_link_libraries(dpi_dashboard ws2_32)
endif()

if(APPLE)
    # Add any macOS-specific settings here
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(dpi_dashboard pthread)
endif()
