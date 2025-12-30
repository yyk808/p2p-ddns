# Primary node Dockerfile for p2p-ddns integration tests
FROM p2p-ddns-test-base:latest

# Label for identification
LABEL p2p-ddns.node.type="primary"
LABEL p2p-ddns.test.node="true"

# Copy primary-specific scripts
COPY tests/integration/nodes/primary/entrypoint.sh /app/entrypoint.sh

# Set environment variables for primary node
ENV P2P_DDNS_MODE=daemon
ENV P2P_DDNS_PRIMARY=true
ENV P2P_DDNS_LOG_LEVEL=info

# Set default entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
