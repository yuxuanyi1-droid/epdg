#!/usr/bin/env bash
set -euo pipefail

NETNS_NAME="${NETNS_NAME:-swu1}"
SWU_DIR="${SWU_DIR:-/root/epdg_work/SWu-IKEv2}"
SOURCE_IP="${SOURCE_IP:-172.31.255.2}"
EPDG_IP="${EPDG_IP:-10.46.0.2}"
GATEWAY_IP="${GATEWAY_IP:-172.31.255.1}"
APN="${APN:-ims}"
IMSI="${IMSI:-001010000000001}"
MCC="${MCC:-001}"
MNC="${MNC:-001}"
KI="${KI:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${OPC:-E8ED289DEBA9526743BA151B062835CC}"

ip netns exec "${NETNS_NAME}" bash -lc "
  set -euo pipefail
  cd '${SWU_DIR}'
  . .venv/bin/activate
  python3 swu_emulator.py \
    -s '${SOURCE_IP}' \
    -d '${EPDG_IP}' \
    -g '${GATEWAY_IP}' \
    -a '${APN}' \
    -I '${IMSI}' \
    -M '${MCC}' \
    -N '${MNC}' \
    -K '${KI}' \
    -C '${OPC}'
"
