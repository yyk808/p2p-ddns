#!/bin/bash

# Build script for p2p-ddns test Docker images

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Image names
BASE_IMAGE="p2p-ddns-test-base"
PRIMARY_IMAGE="p2p-ddns-test-primary"
DAEMON_IMAGE="p2p-ddns-test-daemon"
CLIENT_IMAGE="p2p-ddns-test-client"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] BUILD:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] BUILD WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] BUILD ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] BUILD INFO:${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        exit 1
    fi

    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/Cargo.toml" ]]; then
        error "Could not find Cargo.toml in project root: $PROJECT_ROOT"
        exit 1
    fi

    # Check project edition and Rust version compatibility
    local project_edition
    project_edition=$(grep -E "^edition = " "$PROJECT_ROOT/Cargo.toml" | sed 's/edition = "//; s/"//' | tr -d ' ')

    log "Project edition: $project_edition"

    if [[ "$project_edition" == "2024" ]]; then
        log "Project uses Rust edition 2024, requiring Rust 1.85+"
        export RUST_VERSION="1.85"
    else
        log "Project uses Rust edition $project_edition, using Rust 1.75"
        export RUST_VERSION="1.75"
    fi

    # Check if Docker BuildKit is available
    export DOCKER_BUILDKIT=1

    log "Prerequisites check passed (using Rust $RUST_VERSION)"
}

# Build base image
build_base_image() {
    local tag="${1:-latest}"

    log "Building base image: $BASE_IMAGE:$tag"

    # Create temporary build context
    local build_context
    build_context=$(mktemp -d)
    trap "rm -rf $build_context" RETURN

    # Copy necessary files to build context
    mkdir -p "$build_context/src"
    cp -r "$PROJECT_ROOT/src"/* "$build_context/src/"
    cp "$PROJECT_ROOT/Cargo.toml" "$build_context/"

    # Handle Cargo.lock version compatibility
    if [[ -f "$PROJECT_ROOT/Cargo.lock" ]]; then
        # Check lock file version
        local lock_version
        lock_version=$(grep "^version = " "$PROJECT_ROOT/Cargo.lock" | head -1 | sed 's/version = "//; s/"//' | tr -d ' ')

        log "Found Cargo.lock version: $lock_version"

        if [[ "$lock_version" == "4" && "$RUST_VERSION" == "1.75" ]]; then
            warn "Cargo.lock version 4 is incompatible with Rust 1.75, regenerating lock file..."
            # Don't copy the incompatible lock file, let Cargo generate a new one
            log "Skipping Cargo.lock copy - will regenerate in container"
        else
            cp "$PROJECT_ROOT/Cargo.lock" "$build_context/"
            log "Copied compatible Cargo.lock version: $lock_version"
        fi
    else
        log "No Cargo.lock found, will generate in container"
    fi

    # Create base Dockerfile in build context
    cat > "$build_context/Dockerfile.base" << EOF
FROM rust:${RUST_VERSION}-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy project files
COPY . .

# Handle Cargo.lock compatibility for Rust 1.75
RUN if [ "$RUST_VERSION" = "1.75" ] && [ -f Cargo.lock ]; then \
        if grep -q '^version = 4' Cargo.lock; then \
            echo "Removing incompatible Cargo.lock version 4 for Rust 1.75..."; \
            rm Cargo.lock; \
            echo "Regenerating compatible lock file..."; \
        fi; \
    fi

# Build the project in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iputils-ping \
    net-tools \
    iptables \
    curl \
    jq \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 testuser

# Copy binary from builder
COPY --from=builder /build/target/release/p2p-ddns /usr/local/bin/p2p-ddns

# Set up directories
RUN mkdir -p /app/data /app/logs /app/config /app/scripts && \
    chown -R testuser:testuser /app

# Set working directory
WORKDIR /app

# Switch to non-root user
USER testuser

# Default command
CMD ["/usr/local/bin/p2p-ddns"]
EOF

    # Build base image
    if docker build \
        --file "$build_context/Dockerfile.base" \
        --tag "$BASE_IMAGE:$tag" \
        "$build_context"; then
        log "Base image built successfully: $BASE_IMAGE:$tag"
    else
        error "Failed to build base image"
        exit 1
    fi

    # Clean up build context
    rm -rf "$build_context"
}

# Build node-specific images
build_node_image() {
    local node_type="$1"
    local tag="${2:-latest}"

    log "Building $node_type image: ${node_type}-image:$tag"

    local image_name
    case "$node_type" in
        primary)
            image_name="$PRIMARY_IMAGE"
            ;;
        daemon)
            image_name="$DAEMON_IMAGE"
            ;;
        client)
            image_name="$CLIENT_IMAGE"
            ;;
        *)
            error "Unknown node type: $node_type"
            exit 1
            ;;
    esac

    # Create Dockerfile for node type
    local dockerfile_content
    case "$node_type" in
        primary)
            dockerfile_content="FROM $BASE_IMAGE:$tag

# Copy scripts
COPY scripts/ /app/scripts/
COPY nodes/primary/entrypoint.sh /app/entrypoint.sh

# Make scripts executable
RUN chmod +x /app/entrypoint.sh /app/scripts/*.sh

# Set environment variables
ENV P2P_DDNS_MODE=daemon
ENV P2P_DDNS_PRIMARY=true
ENV P2P_DDNS_LOG_LEVEL=info

# Set entrypoint
ENTRYPOINT [\"/app/entrypoint.sh\"]
CMD [\"--daemon\", \"--primary\", \"--alias\", \"primary-node\"]"
            ;;
        daemon)
            dockerfile_content="FROM $BASE_IMAGE:$tag

# Copy scripts
COPY scripts/ /app/scripts/
COPY nodes/daemon/entrypoint.sh /app/entrypoint.sh

# Make scripts executable
RUN chmod +x /app/entrypoint.sh /app/scripts/*.sh

# Set environment variables
ENV P2P_DDNS_MODE=daemon
ENV P2P_DDNS_PRIMARY=false
ENV P2P_DDNS_LOG_LEVEL=info

# Set entrypoint
ENTRYPOINT [\"/app/entrypoint.sh\"]
CMD [\"--daemon\"]"
            ;;
        client)
            dockerfile_content="FROM $BASE_IMAGE:$tag

# Copy scripts
COPY scripts/ /app/scripts/
COPY nodes/client/entrypoint.sh /app/entrypoint.sh

# Make scripts executable
RUN chmod +x /app/entrypoint.sh /app/scripts/*.sh

# Set environment variables
ENV P2P_DDNS_MODE=client
ENV P2P_DDNS_PRIMARY=false
ENV P2P_DDNS_LOG_LEVEL=info

# Set entrypoint
ENTRYPOINT [\"/app/entrypoint.sh\"]"
            ;;
    esac

    # Create temporary Dockerfile
    local temp_dockerfile
    temp_dockerfile=$(mktemp)
    trap "rm -f $temp_dockerfile" RETURN
    echo "$dockerfile_content" > "$temp_dockerfile"

    # Build image
    if docker build \
        --file "$temp_dockerfile" \
        --tag "$image_name:$tag" \
        "$INTEGRATION_DIR"; then
        log "$node_type image built successfully: $image_name:$tag"
    else
        error "Failed to build $node_type image"
        exit 1
    fi

    # Clean up
    rm -f "$temp_dockerfile"
}

# Build all images
build_all_images() {
    local tag="${1:-latest}"

    log "Building all p2p-ddns test images with tag: $tag"

    check_prerequisites
    build_base_image "$tag"
    build_node_image "primary" "$tag"
    build_node_image "daemon" "$tag"
    build_node_image "client" "$tag"

    log "All images built successfully"
}

# List built images
list_images() {
    log "Listing p2p-ddns test images..."
    echo

    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | \
        grep -E "(REPOSITORY|$BASE_IMAGE|$PRIMARY_IMAGE|$DAEMON_IMAGE|$CLIENT_IMAGE)" || \
        warn "No p2p-ddns test images found"
    echo
}

# Remove images
remove_images() {
    local tag="${1:-latest}"

    log "Removing p2p-ddns test images with tag: $tag"

    docker rmi "$CLIENT_IMAGE:$tag" 2>/dev/null || true
    docker rmi "$DAEMON_IMAGE:$tag" 2>/dev/null || true
    docker rmi "$PRIMARY_IMAGE:$tag" 2>/dev/null || true
    docker rmi "$BASE_IMAGE:$tag" 2>/dev/null || true

    log "Images removed"
}

# Show usage
show_usage() {
    echo "Usage: $0 {build|build-base|build-node|list|remove|help} [options]"
    echo
    echo "Commands:"
    echo "  build           - Build all images"
    echo "  build-base      - Build base image only"
    echo "  build-node      - Build specific node type"
    echo "  list            - List built images"
    echo "  remove          - Remove built images"
    echo "  help            - Show this help"
    echo
    echo "Options:"
    echo "  --tag TAG       - Use specific tag (default: latest)"
    echo "  --node TYPE     - Node type for build-node (primary|daemon|client)"
    echo
    echo "Examples:"
    echo "  $0 build                    # Build all images with 'latest' tag"
    echo "  $0 build --tag v1.0.0      # Build all images with 'v1.0.0' tag"
    echo "  $0 build-node --node primary # Build primary image only"
    echo "  $0 list                     # List all built images"
    echo "  $0 remove --tag v1.0.0     # Remove images with 'v1.0.0' tag"
}

# Main execution
main() {
    local command="${1:-build}"
    local tag="latest"
    local node_type=""

    # Parse arguments
    shift
    while [[ $# -gt 0 ]]; do
        case $1 in
            --tag)
                tag="$2"
                shift 2
                ;;
            --node)
                node_type="$2"
                shift 2
                ;;
            *)
                warn "Unknown argument: $1"
                shift
                ;;
        esac
    done

    case "$command" in
        build)
            build_all_images "$tag"
            ;;
        build-base)
            check_prerequisites
            build_base_image "$tag"
            ;;
        build-node)
            if [[ -z "$node_type" ]]; then
                error "Node type required for build-node command"
                echo "Use: $0 build-node --node (primary|daemon|client)"
                exit 1
            fi
            check_prerequisites
            build_node_image "$node_type" "$tag"
            ;;
        list)
            list_images
            ;;
        remove)
            remove_images "$tag"
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"