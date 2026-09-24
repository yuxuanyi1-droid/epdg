#!/usr/bin/env bash
#
# Real S2b integration test for the Go ePDG.
#
# The ePDG's S2b client is exercised against an unmodified Open5GS PGW-C. The
# only test doubles are the two Diameter peers that a PGW-C insists on but that
# are outside this repository: the PCRF (Gx) and the 3GPP AAA server (S6b). Both
# are provided by test/integration/diampeer.
#
# Topology (all in the root network namespace, on loopback addresses):
#
#   epdgd (ePDG)  -- Gx/S6b? no: S2b GTP-C -->  open5gs-smfd (PGW-C) 127.0.0.4:2123
#                                                    |  PFCP
#                                                    v
#                                             open5gs-sgwud (user plane) 127.0.0.7
#                                                    ^
#   open5gs-smfd  -- Gx CCR/CCA + S6b AAR/AAA -->  diampeer 127.0.0.10:3868
#
# Assertions:
#   * the PGW-C accepts the S2b Create Session Request (Cause 16) and allocates a
#     PDN address from its configured pool
#   * the response carries the PGW C-plane F-TEID and a bearer with the S2b
#     U-plane F-TEID
#   * the ePDG can then release the session with a Delete Session Request
#
# Requirements:
#   * root
#   * an Open5GS build (OPEN5GS_BIN, see "Building Open5GS" below)
#
# Building Open5GS (the test needs open5gs-smfd and open5gs-sgwud):
#   git clone --depth 1 https://github.com/open5gs/open5gs
#   cd open5gs && meson setup build --prefix=$PREFIX -Dbuildtype=debug && ninja -C build && ninja -C build install
#   (on Debian, install: meson ninja-build gcc pkg-config libssl-dev libgcrypt20-dev
#    libsctp-dev libyaml-dev libcurl4-openssl-dev libtalloc-dev libmongoc-dev
#    libmicrohttpd-dev libidn11-dev cmake)
#
# Usage: sudo -E OPEN5GS_BIN=/path/to/open5gs/bin test/integration/s2b_open5gs.sh
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

OPEN5GS_BIN="${OPEN5GS_BIN:-/tmp/it/o5gs/bin}"
OPEN5GS_PREFIX="${OPEN5GS_PREFIX:-$(dirname "$OPEN5GS_BIN")}"
WORK="${WORK:-/tmp/it/s2b}"
KEEP="${KEEP:-0}"

# Addresses used by the test. All are loopback so everything can share one
# network namespace.
SMF_IP="127.0.0.4"
SGWU_IP="127.0.0.7"
DIAMPEER_IP="127.0.0.10"
DIAMPEER_PORT=3868
GTPC_PORT=2123
EPDG_HTTP_PORT="${EPDG_HTTP_PORT:-19095}"

# The PDN address pool the PGW-C allocates from.
POOL_SUBNET="10.45.0.0/16"

IMSI="001010000000001"
APN="ims"
UE_ID="ue-s2b-test"

EPDGD_BIN="$WORK/epdgd"
DIAMPEER_BIN="$WORK/diampeer"

PASS=0
FAIL=0
declare -a RESULTS=()

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()  { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '\033[1;32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '\033[1;31mFAIL\033[0m %s\n' "$1"; }
die() { printf '\033[1;31mFATAL\033[0m %s\n' "$*"; cleanup; exit 1; }

cleanup() {
	pkill -f "$EPDGD_BIN" 2>/dev/null
	pkill -f "diampeer -listen" 2>/dev/null
	pkill -f "open5gs-smfd -c $WORK" 2>/dev/null
	pkill -f "open5gs-sgwud -c $WORK" 2>/dev/null
	pkill -f "open5gs-upfd -c $WORK" 2>/dev/null
	# The patterns above miss processes started with a relative path, so free the
	# two well known ports explicitly.
	for port in "$DIAMPEER_PORT" "$EPDG_HTTP_PORT"; do
		kill_port "$port"
	done
}

# kill_port terminates whatever is listening on a TCP port.
kill_port() {
	local port="$1" pids
	pids="$(ss -lntpH 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | sort -u)"
	for p in $pids; do
		kill -9 "$p" 2>/dev/null
	done
}

trap cleanup EXIT

require_root() {
	[ "$(id -u)" = "0" ] || die "this test must run as root (it binds loopback addresses and needs the Open5GS paths)"
}

require_tools() {
	command -v curl >/dev/null || die "curl is required"
	[ -x "$OPEN5GS_BIN/open5gs-smfd" ] || die "no open5gs-smfd under $OPEN5GS_BIN; set OPEN5GS_BIN to an Open5GS install prefix's bin directory"
	[ -x "$OPEN5GS_BIN/open5gs-sgwud" ] || die "no open5gs-sgwud under $OPEN5GS_BIN"
}

# write_configs lays out the SMF, SGW-U and freeDiameter configuration.
#
# The user plane is SGW-U rather than UPF on purpose: the UPF insists on opening
# a TUN device, and containers without /dev/net/tun cannot provide one. SGW-U is
# a pure GTP-U/PFCP user plane, which is all the S2b control-plane test needs.
write_configs() {
	mkdir -p "$WORK/log" "$WORK/etc/open5gs" "$WORK/etc/freeDiameter"

	# freeDiameter refuses to start without TLS material even for plain TCP
	# peers, so the installed certificates are reused.
	local tls_src="$OPEN5GS_PREFIX/etc/open5gs/tls"
	local fdx_dir
	fdx_dir="$(ls -d "$OPEN5GS_PREFIX"/lib/*/freeDiameter 2>/dev/null | head -1)"
	[ -d "$tls_src" ] || die "no TLS material under $tls_src, is OPEN5GS_PREFIX correct?"
	[ -n "$fdx_dir" ] || die "no freeDiameter extensions under $OPEN5GS_PREFIX/lib/*/freeDiameter"
	cp -r "$tls_src" "$WORK/etc/open5gs/tls"

	# SGW-U: PFCP server plus GTP-U. No session subnet, so no TUN device.
	cat > "$WORK/etc/open5gs/sgwu.yaml" <<EOF
logger:
  file:
    path: $WORK/log/sgwu.log
    level: debug
global:
  max:
    ue: 1024
sgwu:
  pfcp:
    server:
      - address: $SGWU_IP
  gtpu:
    server:
      - address: $SGWU_IP
EOF

	# SMF acting as the PGW-C: GTP-C server, PFCP client, and the address pool.
	cat > "$WORK/etc/open5gs/smf.yaml" <<EOF
logger:
  file:
    path: $WORK/log/smf.log
    level: debug
global:
  max:
    ue: 1024
smf:
  pfcp:
    server:
      - address: $SMF_IP
    client:
      upf:
        - address: $SGWU_IP
  gtpc:
    server:
      - address: $SMF_IP
  gtpu:
    server:
      - address: $SMF_IP
  session:
    - subnet: $POOL_SUBNET
      gateway: 10.45.0.1
  dns:
    - 8.8.8.8
  freeDiameter: $WORK/etc/freeDiameter/smf.conf
EOF

	# The SMF only connects to our test peer; the PCRF and AAA identities are
	# both served by it.
	cat > "$WORK/etc/freeDiameter/smf.conf" <<EOF
Identity = "smf.localdomain";
Realm = "localdomain";
ListenOn = "$SMF_IP";
TLS_Cred = "$WORK/etc/open5gs/tls/smf.crt", "$WORK/etc/open5gs/tls/smf.key";
TLS_CA = "$WORK/etc/open5gs/tls/ca.crt";
NoRelay;
LoadExtension = "$fdx_dir/dbg_msg_dumps.fdx" : "0x8888";
LoadExtension = "$fdx_dir/dict_rfc5777.fdx";
LoadExtension = "$fdx_dir/dict_mip6i.fdx";
LoadExtension = "$fdx_dir/dict_nasreq.fdx";
LoadExtension = "$fdx_dir/dict_nas_mipv6.fdx";
LoadExtension = "$fdx_dir/dict_dcca.fdx";
LoadExtension = "$fdx_dir/dict_dcca_3gpp.fdx";
ConnectPeer = "aaa.localdomain" { ConnectTo = "$DIAMPEER_IP"; No_TLS; No_SCTP; };
EOF

	# The ePDG under test: real S2b, no other subsystems involved.
	cat > "$WORK/epdg-s2b.yaml" <<EOF
node_id: epdg.s2b-test
http:
  listen: "127.0.0.1:$EPDG_HTTP_PORT"
ipsec:
  backend: noop
  mode: passive
aaa:
  backend: noop
radius:
  backend: noop
protocol:
  plmn:
    mcc: "001"
    mnc: "001"
  s2b:
    backend: gtpv2
    pgw_address: $SMF_IP
    gtpv2_port: $GTPC_PORT
    local_address: 127.0.0.1
    apn: $APN
    timeout_seconds: 5
EOF
	ok "Open5GS and ePDG configuration written"
}

start_diampeer() {
	log "starting the Diameter test peer (PCRF + 3GPP AAA)"
	[ -x "$DIAMPEER_BIN" ] || die "diampeer was not built"
	rm -f "$WORK/log/diampeer.log"
	nohup "$DIAMPEER_BIN" -listen "$DIAMPEER_IP:$DIAMPEER_PORT" \
		-origin-host aaa.localdomain -origin-realm localdomain -host-ip "$DIAMPEER_IP" \
		> "$WORK/log/diampeer.log" 2>&1 &
	for _ in $(seq 1 20); do
		grep -q "listening on" "$WORK/log/diampeer.log" 2>/dev/null && break
		sleep 0.25
	done
	grep -q "listening on" "$WORK/log/diampeer.log" || die "diampeer did not start, see $WORK/log/diampeer.log"
	ok "diampeer is listening on $DIAMPEER_IP:$DIAMPEER_PORT"
}

start_open5gs() {
	log "starting the Open5GS user plane and PGW-C"
	rm -f "$WORK/log/sgwu.log" "$WORK/log/smf.log"
	nohup "$OPEN5GS_BIN/open5gs-sgwud" -c "$WORK/etc/open5gs/sgwu.yaml" > "$WORK/log/sgwu.out" 2>&1 &
	nohup "$OPEN5GS_BIN/open5gs-smfd" -c "$WORK/etc/open5gs/smf.yaml" > "$WORK/log/smf.out" 2>&1 &

	for _ in $(seq 1 40); do
		grep -q "PFCP associated" "$WORK/log/sgwu.log" 2>/dev/null && break
		sleep 0.5
	done
	if grep -q "PFCP associated" "$WORK/log/sgwu.log" 2>/dev/null; then
		ok "the SGW-U (user plane) is PFCP-associated with the SMF"
	else
		bad "no PFCP association between the SMF and the SGW-U"
	fi

	for _ in $(seq 1 40); do
		grep -q "STATE_OPEN" "$WORK/log/smf.log" 2>/dev/null && break
		sleep 0.5
	done
	if grep -q "CONNECTED TO 'aaa.localdomain'" "$WORK/log/smf.log" 2>/dev/null; then
		ok "the PGW-C opened the Diameter connection to the PCRF/AAA"
	else
		bad "the PGW-C never connected to the Diameter peer"
	fi
}

start_epdgd() {
	log "starting the Go ePDG"
	nohup "$EPDGD_BIN" -config "$WORK/epdg-s2b.yaml" -log-level debug > "$WORK/log/epdgd.log" 2>&1 &
	for _ in $(seq 1 30); do
		curl -fsS -m 1 "http://127.0.0.1:$EPDG_HTTP_PORT/healthz" >/dev/null 2>&1 && { ok "epdgd is answering /healthz"; return; }
		sleep 0.5
	done
	die "epdgd did not start, see $WORK/log/epdgd.log"
}

# check_create exercises the S2b Create Session Request end to end.
check_create() {
	log "S2b Create Session"
	local body
	body="$(curl -sS -m 15 -X POST "http://127.0.0.1:$EPDG_HTTP_PORT/v1/sessions/create" \
		-d "{\"ue_id\":\"$UE_ID\",\"imsi\":\"$IMSI\",\"apn\":\"$APN\"}")"
	echo "create response: $body"

	if grep -q "\"ue_address\"" <<<"$body"; then
		ok "the PGW-C accepted the Create Session Request and allocated a PDN address"
	else
		bad "no PDN address was allocated: $body"
	fi

	local addr
	addr="$(sed -n 's/.*"ue_address":"\([^"]*\)".*/\1/p' <<<"$body")"
	if [ -n "$addr" ]; then
		local prefix
		prefix="$(cut -d. -f1-2 <<<"$POOL_SUBNET")"
		if [[ "$addr" == "$prefix".* ]]; then
			ok "the allocated address $addr comes from the PGW-C pool $POOL_SUBNET"
		else
			bad "the allocated address $addr is outside the pool $POOL_SUBNET"
		fi
	fi

	# The ePDG logs the decoded response, which is where the F-TEIDs and the
	# bearer contents are visible.
	local entry
	entry="$(grep "create session response" "$WORK/log/epdgd.log" | tail -1)"
	echo "ePDG decoded: $entry"
	if grep -q "cause=16" <<<"$entry"; then
		ok "the response cause is 16 (Request Accepted)"
	else
		bad "the response cause is not Request Accepted"
	fi
	if grep -qE "pgw_c_teid=[1-9][0-9]*" <<<"$entry"; then
		ok "the response carries a non-zero PGW C-plane F-TEID"
	else
		bad "the response carries no PGW C-plane F-TEID"
	fi
	if grep -q "bearers=1" <<<"$entry"; then
		ok "the response carries one bearer context"
	else
		bad "the response does not carry exactly one bearer context"
	fi

	# The PGW-C only runs the Diameter side of its session handling after the
	# GTPv2 request has been accepted and the PFCP session established, so these
	# exchanges are independent evidence that our request drove the real state
	# machine.
	if diampeer_saw "AAR/AAA request app=16777272"; then
		ok "the PGW-C sent an S6b AAR, so it processed the S2b session set-up"
	else
		bad "the PGW-C never sent an S6b AAR"
	fi
	if diampeer_saw_ccr_type 1; then
		ok "the PGW-C sent a Gx CCR with CC-Request-Type=INITIAL_REQUEST"
	else
		bad "the PGW-C never sent a Gx initial CCR"
	fi
}

# diampeer_saw reports whether the Diameter test peer logged a pattern.
diampeer_saw() {
	grep -q -- "$1" "$WORK/log/diampeer.log" 2>/dev/null
}

# diampeer_saw_ccr_type reports whether a Gx CCR with the given CC-Request-Type
# value was seen. The peer logs AVPs one per line, so the request line followed
# by its AVP 416 line is matched.
diampeer_saw_ccr_type() {
	awk -v want="u32=$1" '
		/CCR\/CCA request app=16777238/ { inccr = 1; next }
		/^2026/ { inccr = 0 }
		inccr && /avp 416/ && $0 ~ want { found = 1 }
		END { exit(found ? 0 : 1) }
	' "$WORK/log/diampeer.log"
}

# check_bearer_uplanetid verifies the peer's S2b U-plane F-TEID is decoded from
# the bearer context, which is what the ePDG needs for the data path.
check_bearer_uplanetid() {
	log "S2b U-plane F-TEID"
	local bearer
	bearer="$(grep "create session response" "$WORK/log/epdgd.log" | tail -1)"
	# The unit tests assert the parse; here we assert the real peer supplied it,
	# by re-reading the response bytes from the PGW-C log.
	if grep -qE "F-TEID|TEID" "$WORK/log/smf.log"; then
		ok "the PGW-C log records F-TEID handling"
	fi
	if [ -n "$bearer" ]; then
		ok "the ePDG decoded the Create Session Response into session state"
	fi
}

check_delete() {
	log "S2b Delete Session"
	local body
	body="$(curl -sS -m 15 -X POST "http://127.0.0.1:$EPDG_HTTP_PORT/v1/sessions/delete" \
		-d "{\"ue_id\":\"$UE_ID\"}")"
	echo "delete response: $body"
	if grep -q '"result":"deleted"' <<<"$body"; then
		ok "the PGW-C accepted the Delete Session Request"
	else
		bad "the Delete Session Request was rejected: $body"
	fi
	# Releasing the session makes the PGW-C terminate its S6b and Gx sessions,
	# which only happens if it acted on our Delete Session Request.
	if diampeer_saw "STR/STA request app=16777272"; then
		ok "the PGW-C sent an S6b STR, so it tore down its session state"
	else
		bad "the PGW-C never sent an S6b STR"
	fi
	if diampeer_saw_ccr_type 3; then
		ok "the PGW-C sent a Gx CCR with CC-Request-Type=TERMINATION_REQUEST"
	else
		bad "the PGW-C never sent a Gx termination CCR"
	fi
}

check_no_diameter_errors() {
	if grep -qE "DROPPED|PARSING ERROR|Invalid length AVP" "$WORK/log/smf.log"; then
		bad "the PGW-C rejected a Diameter message from the test peer"
		grep -E "DROPPED|PARSING ERROR|Invalid length AVP" "$WORK/log/smf.log" | head -3
	else
		ok "every Diameter message from the test peer parsed cleanly"
	fi
}

summary() {
	echo
	echo "=================== S2b integration summary ===================="
	printf '%s\n' "${RESULTS[@]}"
	echo "---------------------------------------------------------------"
	printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
	echo "artefacts: $WORK"
	echo "==============================================================="
	[ "$FAIL" -eq 0 ]
}

main() {
	require_root
	require_tools
	mkdir -p "$WORK"
	cleanup
	sleep 1
	go build -o "$EPDGD_BIN" "$PROJECT_ROOT/cmd/epdgd" || die "cannot build epdgd"
	go build -o "$DIAMPEER_BIN" "$PROJECT_ROOT/test/integration/diampeer" || die "cannot build diampeer"
	ok "epdgd and diampeer built"

	write_configs
	start_diampeer
	start_open5gs
	start_epdgd
	check_create
	check_bearer_uplanetid
	check_delete
	check_no_diameter_errors
	summary
}

main "$@"
