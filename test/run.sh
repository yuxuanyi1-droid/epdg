#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default values for current lab environment; override via env vars if needed.
SUDO_PASSWORD="${SUDO_PASSWORD:-root}"
NETNS="${NETNS:-swu-test}"
EPDG_IP="${EPDG_IP:-10.255.0.1}"
MCC="${MCC:-001}"
MNC="${MNC:-001}"
PCSCF_IP="${PCSCF_IP:-10.46.0.1}"
PCSCF_PORT="${PCSCF_PORT:-5060}"
IMSI="${IMSI:-001010000000001}"
KI="${KI:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${OPC:-2e001f1df0a0bb769940a2c6342cf795}"
APN="${APN:-ims}"
IMPU="${IMPU:-001010000000001@ims.mnc001.mcc001.3gppnetwork.org}"
SIP_DOMAIN="${SIP_DOMAIN:-ims.mnc001.mcc001.3gppnetwork.org}"
SWU_TIMEOUT="${SWU_TIMEOUT:-40}"
SIP_TIMEOUT="${SIP_TIMEOUT:-20}"

exec python3 "${PROJECT_ROOT}/test/vowifi_register_sim.py" \
  --sudo-password "${SUDO_PASSWORD}" \
  --netns "${NETNS}" \
  --epdg "${EPDG_IP}" \
  --mcc "${MCC}" \
  --mnc "${MNC}" \
  --pcscf-ip "${PCSCF_IP}" \
  --pcscf-port "${PCSCF_PORT}" \
  --imsi "${IMSI}" \
  --ki "${KI}" \
  --opc "${OPC}" \
  --apn "${APN}" \
  --impu "${IMPU}" \
  --sip-domain "${SIP_DOMAIN}" \
  --swu-timeout "${SWU_TIMEOUT}" \
  --sip-timeout "${SIP_TIMEOUT}" \
  --cleanup-netns
