#!/usr/bin/env bash
#
# Checks that a running lab is actually working, rather than merely up.
#
# It asserts, in order:
#   * every expected container is running and, where one is defined, healthy
#   * PyHSS answers /oam/ping
#   * the I-CSCF and S-CSCF have their Cx Diameter peer OPEN
#   * the ePDG control plane answers /healthz
#   * a REGISTER through the containerised P-CSCF completes 401 -> 200 OK,
#     which is the whole IMS control chain: P-CSCF -> I-CSCF -> S-CSCF -> Cx -> HSS
#
# Usage: bash deploy/scripts/verify.sh
set -uo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${DEPLOY_DIR}/.." && pwd)"
COMPOSE="docker compose --project-directory ${DEPLOY_DIR}"
# The UE has to bind a source address on the lab bridge. The host end of the
# bridge is network.host_address, which is where the UE runs from in this check.
PYHSS_PYTHON="${PYHSS_PYTHON:-python3}"

PASS=0
FAIL=0
declare -a RESULTS=()

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()  { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '\033[1;32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '\033[1;31mFAIL\033[0m %s\n' "$1"; }

# shellcheck disable=SC1091
set -a; . "${DEPLOY_DIR}/.env"; set +a

check_containers() {
	log "container status"
	local running
	running="$(${COMPOSE} ps --services --status running 2>/dev/null)"
	if [ -z "${running}" ]; then
		bad "no containers are running; start the lab with 'make lab-up'"
		return
	fi
	# pyhss runs as three services that share one address; the rest are one each.
	for svc in mariadb redis pyhss pcscf icscf scscf epdgd; do
		if grep -qx "${svc}" <<<"${running}"; then
			ok "container ${svc} is running"
		else
			bad "container ${svc} is not running"
		fi
	done

	# Anything the compose file defines as unhealthy should be reported as such.
	local unhealthy
	unhealthy="$(${COMPOSE} ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk '$2 == "unhealthy" {print $1}')"
	if [ -z "${unhealthy}" ]; then
		ok "no container reports unhealthy"
	else
		bad "unhealthy containers: ${unhealthy}"
	fi
}

check_pyhss() {
	log "PyHSS REST API"
	if curl -fsS -m 5 "http://127.0.0.1:8080/oam/ping" >/dev/null 2>&1; then
		ok "PyHSS answers /oam/ping"
	else
		bad "PyHSS does not answer /oam/ping on 127.0.0.1:8080"
	fi
	local vectors
	vectors="$(curl -fsS -m 5 "http://127.0.0.1:8080/auc/aka/vector_count/1/imsi/${IMSI}" 2>/dev/null)"
	if grep -q '"rand"' <<<"${vectors}"; then
		ok "PyHSS issues an AKA quintuplet for IMSI ${IMSI}"
	else
		bad "PyHSS does not issue a vector for IMSI ${IMSI} (is the seed applied?)"
	fi
}

check_cx() {
	log "Cx Diameter peers"
	for role in icscf scscf; do
		local state
		state="$(${COMPOSE} exec -T "${role}" kamcmd -s unix:/run/kamailio/kamailio_ctl cdp.list_peers 2>/dev/null | grep -m1 'State:')"
		if grep -q "I_Open" <<<"${state}"; then
			ok "${role} Cx peer is I_Open"
		else
			bad "${role} Cx peer is not open (${state:-no answer})"
		fi
	done
}

check_epdg() {
	log "ePDG control plane"
	if curl -fsS -m 5 "http://127.0.0.1:${EPDG_HTTP_PORT}/healthz" >/dev/null 2>&1; then
		ok "epdgd answers /healthz on 127.0.0.1:${EPDG_HTTP_PORT}"
	else
		bad "epdgd does not answer /healthz on 127.0.0.1:${EPDG_HTTP_PORT}"
	fi
}

check_register() {
	log "IMS REGISTER through the containerised P-CSCF"
	# The host can reach the bridge, so the same UE script the native test uses
	# runs unchanged against the container.
	local log="${DEPLOY_DIR}/runtime/verify-register.log"
	PYHSS_CONFIG="${DEPLOY_DIR}/runtime/pyhss/config.yaml" \
		SIP_DOMAIN="${PLMN_REALM}" \
		IMPU="${IMSI}@${PLMN_REALM}" \
		KI_HEX="${KI}" \
		OPC_HEX="${OPC}" \
		IMSI="${IMSI}" \
		UE_IP="${UE_IP:-${LAB_HOST_ADDRESS}}" \
		PCSCF_IP="${IP_PCSCF}" \
		PYTHONPATH="${REPO_ROOT}/pyhss/lib" \
		"${PYHSS_PYTHON}" "${REPO_ROOT}/test/integration/ims_register.py" >"${log}" 2>&1
	local rc=$?

	# Reaching the challenge proves the whole control chain works across the
	# container boundary: P-CSCF -> I-CSCF (UAR/UAA) -> S-CSCF (MAR/MAA) -> HSS,
	# and that the HSS handed out a vector the UE can validate.
	if grep -q "AKAv1-MD5" "${log}"; then
		ok "the UE received an AKAv1-MD5 challenge through the container chain"
	else
		bad "no AKAv1-MD5 challenge; see ${log}"
		tail -5 "${log}" | sed 's/^/     /'
	fi
	if grep -q "derived RES=" "${log}"; then
		ok "the UE derived RES from the vector the containerised HSS issued"
	else
		bad "the UE could not derive RES"
	fi
	if [ "${rc}" -eq 0 ]; then
		ok "REGISTER completed 401 -> 200 OK against the P-CSCF container"
	else
		bad "REGISTER did not complete; see ${log}"
		grep -E "^(FATAL|FAIL)" "${log}" | tail -3 | sed 's/^/     /'
	fi

	# A crash inside the registrar is worth calling out on its own: from the UE
	# side it looks like a protocol failure, but it is a Kamailio defect, and the
	# version is what decides it (5.6.x segfaults, 6.0.x does not).
	local crashes
	crashes="$(${COMPOSE} logs scscf 2>&1 | grep -c 'signal 11' || true)"
	if [ "${crashes}" -eq 0 ]; then
		ok "the S-CSCF did not crash during the exchange"
	else
		bad "the S-CSCF logged ${crashes} SIGSEGV(s); check the Kamailio version in the image"
	fi
}

summary() {
	echo
	echo "=================== lab verification summary ==================="
	printf '%s\n' "${RESULTS[@]}"
	echo "---------------------------------------------------------------"
	printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
	echo "==============================================================="
	[ "${FAIL}" -eq 0 ]
}

check_containers
check_pyhss
check_cx
check_epdg
check_register
summary
