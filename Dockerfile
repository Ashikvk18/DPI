# ============================================================================
# Stage 1: Build
# ============================================================================
FROM gcc:13-bookworm AS builder

RUN apt-get update && apt-get install -y cmake make && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXE_LINKER_FLAGS="-static -pthread" \
    && cmake --build build --target dpi_dashboard -j$(nproc)

# ============================================================================
# Stage 2: Runtime (minimal — binary is statically linked)
# ============================================================================
FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/build/dpi_dashboard /app/dpi_dashboard
COPY test_dpi.pcap /app/test_dpi.pcap
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 10000

ENTRYPOINT ["/app/entrypoint.sh"]
