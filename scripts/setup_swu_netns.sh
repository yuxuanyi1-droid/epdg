#!/usr/bin/env bash
set -euo pipefail

NETNS_NAME="${1:-swu1}"
HOST_IF="veth-epdg"
UE_IF="veth-ue"
HOST_IP="172.31.255.1/30"
UE_IP="172.31.255.2/30"
UE_ADDR="${UE_IP%/*}"

ip netns del "${NETNS_NAME}" 2>/dev/null || true
ip link del "${HOST_IF}" 2>/dev/null || true

ip netns add "${NETNS_NAME}"
ip link add "${HOST_IF}" type veth peer name "${UE_IF}"
ip addr add "${HOST_IP}" dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip link set "${UE_IF}" netns "${NETNS_NAME}"

ip netns exec "${NETNS_NAME}" ip addr add "${UE_IP}" dev "${UE_IF}"
ip netns exec "${NETNS_NAME}" ip link set lo up
ip netns exec "${NETNS_NAME}" ip link set "${UE_IF}" up
ip netns exec "${NETNS_NAME}" ip route add default via "${HOST_IP%/*}"
ip netns exec "${NETNS_NAME}" ip route add 10.46.0.2/32 via "${HOST_IP%/*}"

echo "Created netns ${NETNS_NAME} with UE address ${UE_ADDR}"
ip netns exec "${NETNS_NAME}" ip -4 addr show
ip netns exec "${NETNS_NAME}" ip route show
