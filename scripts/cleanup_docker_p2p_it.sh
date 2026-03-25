#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
cleanup_docker_p2p_it.sh

Removes p2p-ddns docker integration-test resources created by tests/docker_p2p.rs:
- containers named like: p2pddns-it-*
- networks named like:    p2pddns-it-*
- images: p2p-ddns-test-{base,primary,daemon}:*

Usage:
  scripts/cleanup_docker_p2p_it.sh [--containers] [--networks] [--images] [--prune]

If no flags are provided, it removes containers + networks + images (not global prune).
EOF
}

want_containers=0
want_networks=0
want_images=0
want_prune=0

if [[ $# -eq 0 ]]; then
  want_containers=1
  want_networks=1
  want_images=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --containers) want_containers=1 ;;
    --networks) want_networks=1 ;;
    --images) want_images=1 ;;
    --prune) want_prune=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker is not available (docker info failed)" >&2
  exit 1
fi

if [[ $want_containers -eq 1 ]]; then
  echo "Removing containers with name prefix p2pddns-it-..."
  docker ps -a --format '{{.ID}} {{.Names}}' \
    | awk '$2 ~ /^p2pddns-it-/' \
    | awk '{print $1}' \
    | xargs -r docker rm -f >/dev/null
fi

if [[ $want_networks -eq 1 ]]; then
  echo "Removing networks with name prefix p2pddns-it-..."
  docker network ls --format '{{.ID}} {{.Name}}' \
    | awk '$2 ~ /^p2pddns-it-/' \
    | awk '{print $1}' \
    | xargs -r docker network rm >/dev/null
fi

if [[ $want_images -eq 1 ]]; then
  echo "Removing images p2p-ddns-test-{base,primary,daemon}:* ..."
  docker images --format '{{.Repository}}:{{.Tag}}' \
    | awk '$1 ~ /^p2p-ddns-test-(base|primary|daemon):/' \
    | xargs -r docker rmi -f >/dev/null || true
fi

if [[ $want_prune -eq 1 ]]; then
  echo "Pruning dangling images/build cache (global prune)..."
  docker image prune -f >/dev/null || true
  docker builder prune -f >/dev/null || true
fi

echo "Done."

