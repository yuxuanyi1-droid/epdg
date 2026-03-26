#!/usr/bin/env bash
set -euo pipefail

NETNS_NAME="${1:-swu1}"
ip netns del "${NETNS_NAME}" 2>/dev/null || true
ip link del veth-epdg 2>/dev/null || true
echo "Cleaned ${NETNS_NAME}"
