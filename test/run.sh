#!/usr/bin/env bash
set -uo pipefail

# Regression entry point for the SWu/VoWiFi lab. The real end to end test now
# lives in test/integration/swu_eap_aka.sh: it starts two strongSwan charon
# instances, a real PyHSS and the Go ePDG, then asserts IKE_SA/CHILD_SA
# establishment and a working inner data path.
#
# SWAN must point at a strongSwan prefix that includes the eap-aka-3gpp plugin,
# which Debian does not package. See test/integration/swu_eap_aka.sh for the
# build flags.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

exec sudo -E SWAN="${SWAN:-/tmp/it/swan}" WORK="${WORK:-/tmp/it/run}" \
  "${PROJECT_ROOT}/test/integration/swu_eap_aka.sh" "$@"
