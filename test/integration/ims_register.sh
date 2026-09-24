#!/usr/bin/env bash
#
# Real IMS REGISTER integration test: 401 challenge -> 200 OK.
#
# There is no mock anywhere in the signalling path:
#   * Kamailio runs the P-CSCF, I-CSCF and S-CSCF from the configs in
#     configs/kamailio/ (unmodified).
#   * PyHSS is the HSS, answering Cx (UAR/UAA, MAR/MAA, SAR/SAA).
#   * The subscriber's K/OPc live in the PyHSS SQLite database, and the "UE" in
#     test/integration/ims_register.py derives RES from the AKA nonce with
#     Milenage and answers the AKAv1-MD5 challenge.
#
# The test asserts each step of the exchange and, at the end, that the
# Authentication-Info/200 OK came back through the strict IMS IPsec return path.
#
# Requirements: root, kamailio + IMS modules, mariadb-server, redis-server,
# python3-venv with the PyHSS dependencies (see pyhss/requirements.txt).
#
# Usage: sudo -E PYHSS_PYTHON=/path/to/venv/bin/python test/integration/ims_register.sh
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PYHSS_PYTHON="${PYHSS_PYTHON:-/tmp/pyhss-venv/bin/python}"
WORK="${WORK:-/tmp/it/ims}"
KEEP="${KEEP:-0}"

# IMS identities. The CSCF configs shipped in the repository already use these.
# Note the two MNC spellings: the IMS domain (and the I-CSCF/S-CSCF configs) use
# the three digit form mnc001, while the IMSI carries the two digit form 01.
IMSI="001010000000001"
MCC="001"
MNC_DOMAIN="001"
SIP_DOMAIN="ims.mnc${MNC_DOMAIN}.mcc${MCC}.3gppnetwork.org"
IMPU="${IMSI}@${SIP_DOMAIN}"
KI_HEX="465B5CE8B199B49FAA5F0A2EE238A6BC"
OPC_HEX="2e001f1df0a0bb769940a2c6342cf795"

# Lab addresses the shipped kamailio_pcscf config listens on. They are provided
# by a dummy interface so the repository configs stay untouched.
PCSCF_LAB_ADDR="10.46.0.1"
PCSCF_TUNNEL_ADDR="10.255.0.1"
UE_IP="10.46.0.100"
LAB_IF="ims-lab0"

HSS_IP="127.0.0.8"
UE_SECURITY_PORT="${UE_SECURITY_PORT:-5060}"

PASS=0
FAIL=0
declare -a RESULTS=()

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()  { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '\033[1;32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '\033[1;31mFAIL\033[0m %s\n' "$1"; }
die() { printf '\033[1;31mFATAL\033[0m %s\n' "$*"; cleanup; exit 1; }

kill_by_cmdline() {
	local pattern="$1" pids
	pids="$(pgrep -f "$pattern" 2>/dev/null)"
	for p in $pids; do kill -9 "$p" 2>/dev/null; done
}

cleanup() {
	kill_by_cmdline "kamailio -DD -E -f /etc/kamailio_"
	kill_by_cmdline "diameterService.py"
	kill_by_cmdline "hssService.py"
	# Give the processes a moment to exit, then clear the pid files: kamailio
	# refuses to start while a pid file points at a live process, and a SIGKILLed
	# instance leaves its pid file behind.
	sleep 1
	rm -f /run/kamailio_pcscf/*.pid /run/kamailio_icscf/*.pid /run/kamailio_scscf/*.pid 2>/dev/null
	if [ "$KEEP" != "1" ]; then
		ip link del "$LAB_IF" 2>/dev/null
	fi
}

trap cleanup EXIT

require_root() {
	[ "$(id -u)" = "0" ] || die "this test must run as root (it creates interfaces and reads /etc/kamailio_*)"
}

require_tools() {
	command -v kamailio >/dev/null || die "kamailio is not installed"
	command -v kamcmd >/dev/null || die "kamcmd is not installed"
	command -v mysql >/dev/null || die "mariadb-client is not installed"
	command -v redis-cli >/dev/null || die "redis-tools are not installed"
	[ -x "$PYHSS_PYTHON" ] || die "python interpreter $PYHSS_PYTHON not found (set PYHSS_PYTHON)"
	for m in ims_icscf ims_auth ims_registrar_scscf ims_ipsec_pcscf cdp db_mysql; do
		[ -f "/usr/lib/x86_64-linux-gnu/kamailio/modules/${m}.so" ] \
			|| die "kamailio module ${m}.so is missing; install kamailio-ims-modules and kamailio-mysql-modules"
	done
}

start_infra() {
	log "starting MariaDB and Redis"
	if ! mysqladmin ping >/dev/null 2>&1; then
		mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld
		nohup /usr/sbin/mariadbd --user=mysql > "$WORK/mariadb.log" 2>&1 &
		for _ in $(seq 1 40); do
			mysqladmin ping >/dev/null 2>&1 && break
			sleep 0.5
		done
	fi
	mysqladmin ping >/dev/null 2>&1 || die "MariaDB did not start, see $WORK/mariadb.log"
	ok "MariaDB is up"

	if ! redis-cli ping >/dev/null 2>&1; then
		nohup /usr/bin/redis-server --protected-mode no --bind 127.0.0.1 > "$WORK/redis.log" 2>&1 &
		for _ in $(seq 1 20); do
			redis-cli ping >/dev/null 2>&1 && break
			sleep 0.5
		done
	fi
	redis-cli ping >/dev/null 2>&1 || die "Redis did not start, see $WORK/redis.log"
	ok "Redis is up"
}

load_ims_database() {
	log "loading the IMS database"
	if ! mysql -e "use pcscf" >/dev/null 2>&1; then
		mysql < "$PROJECT_ROOT/database/kamailio/kamailio_ims.sql" || die "cannot import kamailio_ims.sql"
		ok "the IMS schema was imported from database/kamailio/kamailio_ims.sql"
	else
		ok "the IMS schema is already present"
	fi
	# Each CSCF connects with its own MySQL user, as the shipped configs expect.
	mysql <<'SQL' || die "cannot create the CSCF database users"
CREATE USER IF NOT EXISTS 'pcscf'@'%' IDENTIFIED BY 'heslo';
CREATE USER IF NOT EXISTS 'icscf'@'%' IDENTIFIED BY 'heslo';
CREATE USER IF NOT EXISTS 'scscf'@'%' IDENTIFIED BY 'heslo';
GRANT ALL ON pcscf.* TO 'pcscf'@'%';
GRANT ALL ON icscf.* TO 'icscf'@'%';
GRANT ALL ON scscf.* TO 'scscf'@'%';
FLUSH PRIVILEGES;
SQL
	ok "the CSCF database users exist"
}

setup_hosts_and_interfaces() {
	log "preparing names and the lab addresses"
	# Kamailio's cdp resolves the HSS by name, and the configs reference the CSCF
	# aliases.
	if ! grep -q "hss.localdomain" /etc/hosts; then
		printf '%s hss.localdomain\n127.0.0.1 icscf.localdomain scscf.localdomain pcscf.localdomain ims.localdomain\n' \
			"$HSS_IP" >> /etc/hosts
	fi
	ok "name resolution is in place"

	# pcscf.cfg listens on 10.255.0.1 and 10.46.0.1 from the original lab.
	ip link add "$LAB_IF" type dummy 2>/dev/null
	ip addr add "$PCSCF_LAB_ADDR/24" dev "$LAB_IF" 2>/dev/null
	ip addr add "$PCSCF_TUNNEL_ADDR/24" dev "$LAB_IF" 2>/dev/null
	ip addr add "$UE_IP/24" dev "$LAB_IF" 2>/dev/null
	ip link set "$LAB_IF" up
	for addr in "$PCSCF_LAB_ADDR" "$PCSCF_TUNNEL_ADDR" "$UE_IP"; do
		ip addr show "$LAB_IF" | grep -q "$addr" || die "cannot assign $addr to $LAB_IF"
	done
	ok "lab addresses $PCSCF_LAB_ADDR / $PCSCF_TUNNEL_ADDR / $UE_IP are up on $LAB_IF"
}

install_cscf_configs() {
	log "installing the CSCF configurations"
	for role in pcscf icscf scscf; do
		rm -rf "/etc/kamailio_$role"
		mkdir -p "/etc/kamailio_$role" "/run/kamailio_$role"
		cp -r "$PROJECT_ROOT/configs/kamailio/$role/." "/etc/kamailio_$role/"
	done
	ok "configs/kamailio/{pcscf,icscf,scscf} installed under /etc and /run"
}

start_pyhss() {
	log "starting PyHSS (diameterService + hssService)"
	local cfg="$WORK/pyhss-config.yaml"
	mkdir -p "$WORK" /var/log/pyhss
	[ -f "$WORK/hss.db" ] || cp "$PROJECT_ROOT/database/pyhss/hss.db" "$WORK/hss.db"
	sed -e "s|/var/lib/pyhss/hss.db|$WORK/hss.db|" \
		"$PROJECT_ROOT/configs/pyhss/config.yaml" > "$cfg"

	# hssService.py loads its iFC template through a path relative to the working
	# directory (jinja2.FileSystemLoader(searchpath="../")), and the shipped
	# systemd units run with WorkingDirectory=<pyhss>/services. Starting it
	# anywhere else makes the SAR handler fail with TemplateNotFound and the
	# S-CSCF then times out waiting for a SAA.
	( cd "$PROJECT_ROOT/pyhss/services" && \
		PYHSS_CONFIG="$cfg" nohup "$PYHSS_PYTHON" diameterService.py > "$WORK/pyhss-diameter.log" 2>&1 & )
	( cd "$PROJECT_ROOT/pyhss/services" && \
		PYHSS_CONFIG="$cfg" nohup "$PYHSS_PYTHON" hssService.py > "$WORK/pyhss-hss.log" 2>&1 & )

	for _ in $(seq 1 40); do
		ss -lnt 2>/dev/null | grep -q "$HSS_IP:3868" && break
		sleep 0.5
	done
	ss -lnt 2>/dev/null | grep -q "$HSS_IP:3868" \
		|| die "PyHSS did not bind $HSS_IP:3868, see $WORK/pyhss-diameter.log"
	ok "PyHSS is listening on $HSS_IP:3868"

	# The subscriber's credentials in the database must match the ones the UE uses.
	local db_ki db_opc
	db_ki="$("$PYHSS_PYTHON" - <<PY
import sqlite3
print(sqlite3.connect("$WORK/hss.db").execute("select ki from auc where imsi='$IMSI'").fetchone()[0])
PY
)"
	db_opc="$("$PYHSS_PYTHON" - <<PY
import sqlite3
print(sqlite3.connect("$WORK/hss.db").execute("select opc from auc where imsi='$IMSI'").fetchone()[0])
PY
)"
	if [ "$db_ki" = "$KI_HEX" ] && [ "$db_opc" = "$OPC_HEX" ]; then
		ok "the HSS holds the expected K/OPc for IMSI $IMSI"
	else
		bad "the HSS K/OPc for $IMSI differ from the values the UE uses"
	fi
}

start_cscf() {
	local role="$1"
	nohup kamailio -DD -E -f "/etc/kamailio_$role/kamailio.cfg" \
		-P "/run/kamailio_$role/kamailio.pid" > "$WORK/$role.log" 2>&1 &
	for _ in $(seq 1 30); do
		[ -S "/run/kamailio_$role/kamailio_ctl" ] && return 0
		sleep 0.5
	done
	return 1
}

# wait_pcscf_ready sends a throwaway REGISTER until the P-CSCF answers something.
# The P-CSCF logs rtpengine connection failures while starting and only begins
# serving SIP once that settles, so probing is more reliable than a fixed sleep.
wait_pcscf_ready() {
	local attempt
	for attempt in $(seq 1 20); do
		if PCSCF_IP="$PCSCF_LAB_ADDR" UE_IP="$UE_IP" IMPU="$IMPU" SIP_DOMAIN="$SIP_DOMAIN" \
			TIMEOUT=3 python3 "$PROJECT_ROOT/test/integration/ims_register_probe.py" \
			> "$WORK/pcscf_ready.log" 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_cx_open() {
	local role="$1"
	# The CSCF configs use Tc=30, so cdp may take up to that long to retry a peer
	# that was not reachable at start up.
	for _ in $(seq 1 100); do
		if kamcmd -s "unix:/run/kamailio_$role/kamailio_ctl" cdp.list_peers 2>/dev/null | grep -q "I_Open"; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

start_cscfs() {
	log "starting the CSCF chain"
	for role in icscf scscf; do
		start_cscf "$role" || die "$role did not start, see $WORK/$role.log"
	done
	ok "I-CSCF and S-CSCF started"

	for role in icscf scscf; do
		if wait_cx_open "$role"; then
			ok "$role has its Cx Diameter peer to the HSS OPEN"
		else
			bad "$role never reached Cx I_Open, see $WORK/$role.log"
		fi
	done

	start_cscf pcscf || die "pcscf did not start, see $WORK/pcscf.log"
	ok "P-CSCF started (strict IMS IPsec is enabled in the config)"

	if wait_pcscf_ready; then
		ok "the P-CSCF answers REGISTER on $PCSCF_LAB_ADDR:5060"
	else
		die "the P-CSCF never answered a probe REGISTER, see $WORK/pcscf_ready.log"
	fi
}

run_registration() {
	log "running the REGISTER exchange"
	PYHSS_CONFIG="$WORK/pyhss-config.yaml" \
	PYHSS_PYTHON="$PYHSS_PYTHON" \
	IMSI="$IMSI" \
	SIP_DOMAIN="$SIP_DOMAIN" \
	IMPU="$IMPU" \
	KI_HEX="$KI_HEX" \
	OPC_HEX="$OPC_HEX" \
	UE_IP="$UE_IP" \
	UE_SECURITY_PORT="$UE_SECURITY_PORT" \
	PCSCF_IP="$PCSCF_LAB_ADDR" \
		"$PYHSS_PYTHON" "$PROJECT_ROOT/test/integration/ims_register.py" 2>&1 | tee "$WORK/ims_register.log"
	local rc="${PIPESTATUS[0]}"

	if [ "$rc" -eq 0 ]; then
		ok "the UE completed REGISTER 401 -> 200 OK"
	else
		bad "the REGISTER exchange did not complete"
	fi

	# Independent evidence from the server side.
	if grep -q "UE said: .* and we expect" "$WORK/scscf.log"; then
		ok "the S-CSCF verified the AKAv1-MD5 response derived from the AKA vector"
	else
		bad "the S-CSCF log shows no verified AKA response"
	fi
	if grep -q "generated response" "$WORK/pyhss-hss.log" && grep -q "\[SAA\]" "$WORK/pyhss-hss.log"; then
		ok "PyHSS generated a Server-Assignment-Answer over Cx"
	else
		bad "PyHSS produced no SAA"
	fi
	if grep -q "rs=200" "$WORK/pcscf.log"; then
		ok "the P-CSCF logged a 200 OK for the REGISTER"
	else
		bad "the P-CSCF logged no 200 OK"
	fi
	if grep -q "ipsec_forward" "$WORK/pcscf.log"; then
		ok "the 200 OK was returned through the strict IMS IPsec path"
	else
		bad "no ipsec_forward in the P-CSCF log"
	fi
}

summary() {
	echo
	echo "=================== IMS REGISTER integration summary ==================="
	printf '%s\n' "${RESULTS[@]}"
	echo "----------------------------------------------------------------------"
	printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
	echo "artefacts: $WORK"
	echo "======================================================================"
	[ "$FAIL" -eq 0 ]
}

main() {
	require_root
	require_tools
	mkdir -p "$WORK"
	cleanup
	sleep 1



	start_infra
	load_ims_database
	setup_hosts_and_interfaces
	install_cscf_configs
	start_pyhss
	start_cscfs
	run_registration
	summary
}

main "$@"
