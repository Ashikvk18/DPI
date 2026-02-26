#!/bin/sh
exec /app/dpi_dashboard test_dpi.pcap output.pcap --port "${PORT:-10000}"
