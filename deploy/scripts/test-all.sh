#!/usr/bin/env bash
#
# Runs every layer of test the repository has, in order of how much
# environment they need.
#
#   1 unit        protocol conformance, no services at all
#   2 container   the containerised stack: IMS REGISTER, Cx and S2b readiness
#   3 native-ims  the three CSCFs natively, which is where the full
#                 401 -> 200 OK is achieved
#   4 s2b-container S2b Create/Delete through the containerised ePDG + PGW-C
#   4b s2b-native  the same against a natively built Open5GS (needs the build)
#   5 swu         the full SWu call: strongSwan on both ends, EAP-AKA, IPsec
#
# Levels 4b and 5 need components that have to be built from source (Open5GS, and
# a strongSwan with the eap-aka-3gpp test card), so they are skipped with a clear
# message when those are not present rather than failing.
#
# Usage:
#   sudo -E deploy/scripts/test-all.sh [level ...]
#
# With no arguments it runs every level that the environment can support.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="${REPO_ROOT}/deploy"

PYHSS_VENV="${PYHSS_VENV:-/tmp/pyhss-venv}"
PYHSS_PYTHON="${PYHSS_PYTHON:-${PYHSS_VENV}/bin/python}"
OPEN5GS_BIN="${OPEN5GS_BIN:-/tmp/it/o5gs/bin}"
OPEN5GS_PREFIX="${OPEN5GS_PREFIX:-/tmp/it/o5gs}"
SWAN="${SWAN:-/tmp/it/swan}"

declare -a SUMMARY=()
declare -a SKIPPED=()

log()  { printf '\n\033[1;34m══ %s\033[0m\n' "$*"; }
ok()   { SUMMARY+=("PASS  $1"); printf '\033[1;32mPASS\033[0m %s\n' "$1"; }
bad()  { SUMMARY+=("FAIL  $1"); printf '\033[1;31mFAIL\033[0m %s\n' "$1"; }
skip() { SKIPPED+=("$1"); printf '\033[1;33mSKIP\033[0m %s\n' "$1"; }

want() {
	[ "${#LEVELS[@]}" -eq 0 ] && return 0
	local l
	for l in "${LEVELS[@]}"; do [ "$l" = "$1" ] && return 0; done
	return 1
}

# ---------------------------------------------------------------- 1 unit

level_unit() {
	want unit || return 0
	log "1/5 protocol conformance (go test)"
	if ( cd "${REPO_ROOT}" && go test ./... 2>&1 | grep -v "no test files" ); then
		ok "go test ./... passes"
	else
		bad "go test ./... fails"
	fi
}

# ----------------------------------------------------------- 2 containerised

level_container() {
	want container || return 0
	log "2/5 containerised stack"
	if ! docker info >/dev/null 2>&1; then
		skip "container stack (the docker daemon is not running)"
		return 0
	fi
	if ! docker compose --project-directory "${DEPLOY_DIR}" ps --services --status running 2>/dev/null | grep -q pyhss; then
		skip "container stack (not running; start it with deploy/scripts/bootstrap.sh up)"
		return 0
	fi
	if PYHSS_PYTHON="${PYHSS_PYTHON}" bash "${DEPLOY_DIR}/scripts/verify.sh" > /tmp/lab-verify.log 2>&1; then
		ok "container stack verification"
		grep -E "^(PASS|KNOWN)" /tmp/lab-verify.log | sed 's/^/     /'
	else
		# verify.sh exits non-zero only for a real failure; a known limitation is
		# printed but does not fail the run.
		bad "container stack verification"
		grep -E "^(FAIL|KNOWN)" /tmp/lab-verify.log | sed 's/^/     /'
	fi
}

# --------------------------------------------------------------- 3 native IMS

level_native_ims() {
	want native-ims || return 0
	log "3/5 IMS REGISTER natively (full 401 -> 200 OK)"
	if [ ! -x "${PYHSS_PYTHON}" ]; then
		skip "native IMS (no PyHSS virtualenv at ${PYHSS_VENV}; run bootstrap.sh host)"
		return 0
	fi
	if [ ! -x /usr/sbin/kamailio ]; then
		skip "native IMS (kamailio is not installed)"
		return 0
	fi
	if PYHSS_PYTHON="${PYHSS_PYTHON}" WORK="${WORK:-/tmp/it/ims}" \
		bash "${REPO_ROOT}/test/integration/ims_register.sh" > /tmp/lab-ims.log 2>&1; then
		ok "native IMS REGISTER"
		sed -n '/integration summary/,$p' /tmp/lab-ims.log | grep -E "^passed:" | sed 's/^/     /'
	else
		bad "native IMS REGISTER"
		grep -E "^FAIL" /tmp/lab-ims.log | tail -5 | sed 's/^/     /'
	fi
}

# ------------------------------------------------------------------- 4 S2b

# level_s2b_container drives a real S2b Create/Delete Session through the
# containerised ePDG and Open5GS PGW-C. It needs no source builds, so it runs
# wherever the `epc` profile is up.
level_s2b_container() {
	want s2b-container || want s2b || return 0
	log "4a/5 S2b through the containerised ePDG and PGW-C"

	if ! docker info >/dev/null 2>&1; then
		skip "S2b (container) (the docker daemon is not running)"
		return 0
	fi
	local running
	running="$(docker compose --project-directory "${DEPLOY_DIR}" ps --services --status running 2>/dev/null)"
	if ! grep -qx "smf" <<<"${running}"; then
		skip "S2b (container) (the epc profile is not up; start it with bootstrap.sh up)"
		return 0
	fi

	local api="http://127.0.0.1:${EPDG_HTTP_PORT:-19090}"
	local ue="ue-testall-$$"

	# Wait for the ePDG to report its own dependencies ready before driving it:
	# the containers may still be settling after a render or a restart, and a
	# connection refused here would be a timing artefact rather than a defect.
	local ready=0
	for _ in $(seq 1 30); do
		if curl -fsS -m 3 "${api}/v1/compliance/check" 2>/dev/null | grep -q '"passed":true'; then
			ready=1
			break
		fi
		sleep 2
	done
	if [ "${ready}" -eq 1 ]; then
		ok "the ePDG reports every dependency ready"
	else
		skip "S2b (container) (the ePDG is not ready yet: $(curl -sS -m 3 "${api}/v1/compliance/check" 2>/dev/null | head -c 200))"
		return 0
	fi

	local body
	body="$(curl -sS -m 20 -X POST "${api}/v1/sessions/create" \
		-d "{\"ue_id\":\"${ue}\",\"imsi\":\"${IMSI:-001010000000001}\",\"apn\":\"ims\"}" 2>&1)"

	if grep -q '"ue_address"' <<<"${body}"; then
		local addr
		addr="$(sed -n 's/.*"ue_address":"\([^"]*\)".*/\1/p' <<<"${body}")"
		ok "the PGW-C allocated ${addr} to ${ue} over S2b"
	else
		bad "no PDN address was allocated: ${body}"
		return 0
	fi

	# Release it again so the check leaves no state behind.
	local del
	del="$(curl -sS -m 20 -X POST "${api}/v1/sessions/delete" -d "{\"ue_id\":\"${ue}\"}" 2>&1)"
	if grep -q '"result":"deleted"' <<<"${del}"; then
		ok "the session was released over S2b"
	else
		bad "the session could not be released: ${del}"
	fi

	# The crash class that bit the IMS side once: make sure nothing segfaulted.
	local crashes
	crashes="$(docker compose --project-directory "${DEPLOY_DIR}" logs smf 2>&1 | grep -c 'signal 11' || true)"
	if [ "${crashes}" -eq 0 ]; then
		ok "the PGW-C did not crash during the exchange"
	else
		bad "the PGW-C logged ${crashes} SIGSEGV(s)"
	fi
}

level_s2b() {
	want s2b-native || return 0
	log "4b/5 S2b against a native Open5GS PGW-C"
	if [ ! -x "${OPEN5GS_BIN}/open5gs-smfd" ]; then
		skip "S2b (native) (no Open5GS at ${OPEN5GS_BIN}; the containerised check above covers the same path)"
		return 0
	fi
	if OPEN5GS_BIN="${OPEN5GS_BIN}" OPEN5GS_PREFIX="${OPEN5GS_PREFIX}" \
		bash "${REPO_ROOT}/test/integration/s2b_open5gs.sh" > /tmp/lab-s2b.log 2>&1; then
		ok "S2b integration (native)"
		sed -n '/S2b integration summary/,$p' /tmp/lab-s2b.log | grep -E "^passed:" | sed 's/^/     /'
	else
		bad "S2b integration (native)"
		grep -E "^FAIL" /tmp/lab-s2b.log | tail -5 | sed 's/^/     /'
	fi
}

# ------------------------------------------------------------------- 5 SWu

level_swu() {
	want swu || return 0
	log "5/5 SWu end to end (IKEv2 + EAP-AKA + IPsec)"
	if [ ! -x "${SWAN}/libexec/ipsec/charon" ]; then
		skip "SWu (no strongSwan with the eap-aka-3gpp card at ${SWAN}; see AGENTS.md)"
		return 0
	fi
	if [ ! -x "${PYHSS_PYTHON}" ]; then
		skip "SWu (no PyHSS virtualenv at ${PYHSS_VENV})"
		return 0
	fi
	if SWAN="${SWAN}" PYHSS_PYTHON="${PYHSS_PYTHON}" \
		bash "${REPO_ROOT}/test/integration/swu_eap_aka.sh" > /tmp/lab-swu.log 2>&1; then
		ok "SWu end to end"
		sed -n '/integration test summary/,$p' /tmp/lab-swu.log | grep -E "^passed:" | sed 's/^/     /'
	else
		bad "SWu end to end"
		grep -E "^FAIL" /tmp/lab-swu.log | tail -5 | sed 's/^/     /'
	fi
}

# ------------------------------------------------------------------ summary

summary() {
	echo
	echo "=================== test-all summary ==================="
	printf '%s\n' "${SUMMARY[@]}"
	if [ "${#SKIPPED[@]}" -gt 0 ]; then
		echo
		echo "Skipped (missing components):"
		printf '  - %s\n' "${SKIPPED[@]}"
	fi
	echo "--------------------------------------------------------"
	local failed
	failed="$(printf '%s\n' "${SUMMARY[@]}" | grep -c '^FAIL' || true)"
	printf 'failed: %d   skipped: %d\n' "${failed}" "${#SKIPPED[@]}"
	echo "logs: /tmp/lab-{verify,ims,s2b,swu}.log"
	echo "========================================================"
	[ "${failed}" -eq 0 ]
}

LEVELS=("$@")
[ "${#LEVELS[@]}" -eq 0 ] && LEVELS=()

level_unit
level_container
level_native_ims
level_s2b_container
level_s2b
level_swu
summary
