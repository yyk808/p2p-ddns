# Client node Dockerfile for p2p-ddns integration tests
FROM p2p-ddns-test-base:latest

# Label for identification
LABEL p2p-ddns.node.type="client"
LABEL p2p-ddns.test.node="true"

# Copy client-specific scripts
COPY tests/integration/nodes/client/entrypoint.sh /app/entrypoint.sh

# Set environment variables for client node
ENV P2P_DDNS_MODE=client
ENV P2P_DDNS_PRIMARY=false
ENV P2P_DDNS_LOG_LEVEL=info

# Set default entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command arguments (will be overridden by compose)
CMD []
