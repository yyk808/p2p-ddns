# syntax=docker/dockerfile:1.7
#
# Base Dockerfile for p2p-ddns test nodes

FROM rust:1.90-bookworm AS builder

WORKDIR /app
RUN mkdir -p /app/bin

# Pre-cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Build actual binary
COPY src/ src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/p2p-ddns /app/bin/p2p-ddns

FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    bash \
    ca-certificates \
    iputils-ping \
    net-tools \
    iptables \
    curl \
    procps \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 testuser

# Copy built binary
COPY --from=builder /app/bin/p2p-ddns /usr/local/bin/p2p-ddns

# Set up directories
RUN mkdir -p /app/data /app/logs /app/config /shared && \
    chown -R testuser:testuser /app /shared

# Copy scripts and configurations
COPY tests/integration/scripts/ /app/scripts/

# Make scripts executable
RUN chmod +x /app/scripts/*.sh

# Switch to non-root user
USER testuser

# Expose default port (if any)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/scripts/health-check.sh || exit 1

# Default command
CMD ["/usr/local/bin/p2p-ddns"]
