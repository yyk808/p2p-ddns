# Daemon node Dockerfile for p2p-ddns integration tests
FROM p2p-ddns-test-base:latest

# Label for identification
LABEL p2p-ddns.node.type="daemon"
LABEL p2p-ddns.test.node="true"

# Copy daemon-specific scripts
COPY tests/integration/nodes/daemon/entrypoint.sh /app/entrypoint.sh

# Set environment variables for daemon node
ENV P2P_DDNS_MODE=daemon
ENV P2P_DDNS_PRIMARY=false
ENV P2P_DDNS_LOG_LEVEL=info

# Set default entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command arguments (will be overridden by compose)
CMD ["--daemon"]
