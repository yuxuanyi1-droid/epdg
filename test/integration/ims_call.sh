#!/usr/bin/env bash
#
# Real IMS call integration test: two UEs register with AKA, then A calls B and
# the dialog completes (INVITE -> 180/200 -> ACK -> BYE -> 200).
#
# It reuses the P/I/S-CSCF chain of ims_register.sh but drives a full dialog
# instead of a single REGISTER. A UE-side IMS IPsec stack is out of scope for
# this repository, so the installed CSCF configs (under /etc, never the ones in
# configs/) are relaxed for this test:
#   * the P-CSCF advertises its IP in the Path header, so the S-CSCF can route
#     the terminating request back to it without DNS;
#   * the S-CSCF treats the IMS domain as local and terminates local users;
#   * the subscribers use a minimal iFC (no Application Server diversion).
# The signalling itself is the real Kamailio chain and the real PyHSS.
#
# Requirements: root, kamailio + IMS modules, mariadb-server, redis-server,
# python3-venv with the PyHSS dependencies.
#
# Usage: sudo -E PYHSS_PYTHON=/path/to/venv/bin/python test/integration/ims_call.sh
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PYHSS_PYTHON="${PYHSS_PYTHON:-/tmp/pyhss-venv/bin/python}"
WORK="${WORK:-/tmp/it/imscall}"
KEEP="${KEEP:-0}"

IMSI_A="001010000000001"
IMSI_B="001010000000002"
MCC="001"
MNC_DOMAIN="001"
SIP_DOMAIN="ims.mnc${MNC_DOMAIN}.mcc${MCC}.3gppnetwork.org"
KI_HEX="465B5CE8B199B49FAA5F0A2EE238A6BC"
OPC_HEX="2e001f1df0a0bb769940a2c6342cf795"

PCSCF_LAB_ADDR="10.46.0.1"
PCSCF_TUNNEL_ADDR="10.255.0.1"
UE_IP="10.46.0.100"
LAB_IF="ims-lab0"
HSS_IP="127.0.0.8"

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
	sleep 1
	rm -f /run/kamailio_pcscf/*.pid /run/kamailio_icscf/*.pid /run/kamailio_scscf/*.pid 2>/dev/null
	rm -f "$PROJECT_ROOT/pyhss/_ims_call_ifc.xml"
	if [ "$KEEP" != "1" ]; then
		ip link del "$LAB_IF" 2>/dev/null
	fi
}
trap cleanup EXIT

require_root() {
	[ "$(id -u)" = "0" ] || die "this test must run as root (it creates interfaces and reads /etc/kamailio_*)"
}

require_tools() {
	for t in kamailio kamcmd mysql redis-cli python3; do
		command -v "$t" >/dev/null || die "$t is required"
	done
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
		for _ in $(seq 1 40); do mysqladmin ping >/dev/null 2>&1 && break; sleep 0.5; done
	fi
	mysqladmin ping >/dev/null 2>&1 || die "MariaDB did not start"
	ok "MariaDB is up"

	if ! redis-cli ping >/dev/null 2>&1; then
		nohup /usr/bin/redis-server --protected-mode no --bind 127.0.0.1 > "$WORK/redis.log" 2>&1 &
		for _ in $(seq 1 20); do redis-cli ping >/dev/null 2>&1 && break; sleep 0.5; done
	fi
	redis-cli ping >/dev/null 2>&1 || die "Redis did not start"
	ok "Redis is up"
}

load_ims_database() {
	log "loading the IMS database"
	if ! mysql -e "use pcscf" >/dev/null 2>&1; then
		mysql < "$PROJECT_ROOT/database/kamailio/kamailio_ims.sql" || die "cannot import kamailio_ims.sql"
		ok "the IMS schema was imported"
	else
		ok "the IMS schema is already present"
	fi
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
	if ! grep -q "hss.localdomain" /etc/hosts; then
		printf '%s hss.localdomain\n127.0.0.1 icscf.localdomain scscf.localdomain pcscf.localdomain ims.localdomain\n' \
			"$HSS_IP" >> /etc/hosts
	fi
	ip link add "$LAB_IF" type dummy 2>/dev/null
	ip addr add "$PCSCF_LAB_ADDR/24" dev "$LAB_IF" 2>/dev/null
	ip addr add "$PCSCF_TUNNEL_ADDR/24" dev "$LAB_IF" 2>/dev/null
	ip addr add "$UE_IP/24" dev "$LAB_IF" 2>/dev/null
	ip link set "$LAB_IF" up
	ok "lab addresses are up on $LAB_IF"
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

# patch_cscf_configs relaxes the installed configs so a plain-UDP UE can drive a
# call without a UE-side IMS IPsec stack. Only /etc is touched; the repository
# configs stay exactly as shipped.
patch_cscf_configs() {
	log "relaxing the installed CSCF configs for the call test"
	"$PYHSS_PYTHON" - "$PCSCF_LAB_ADDR" "$SIP_DOMAIN" <<'PY'
import sys
pcscf_ip, domain = sys.argv[1], sys.argv[2]

p = "/etc/kamailio_pcscf/pcscf.cfg"
s = open(p).read()
s = s.replace('#!subst "/HOSTNAME/pcscf.localdomain/"', f'#!subst "/HOSTNAME/{pcscf_ip}/"')
s = s.replace("#!define WITH_IPSEC", "# #!define WITH_IPSEC")
s = s.replace("#!define STRICT_IMS_IPSEC", "# #!define STRICT_IMS_IPSEC")
open(p, "w").write(s)

k = "/etc/kamailio_pcscf/kamailio.cfg"
t = open(k).read()
if "ignore_reg_state" not in t:
    t += ('\nmodparam("ims_registrar_pcscf", "ignore_reg_state", 1)\n'
          'modparam("ims_registrar_pcscf", "ignore_contact_rxport_check", 1)\n'
          'modparam("ims_registrar_pcscf", "is_registered_fallback2ip", 1)\n')
open(k, "w").write(t)

q = "/etc/kamailio_scscf/kamailio.cfg"
u = open(q).read()
if f"alias={domain}" not in u:
    u = u.replace("alias=HOSTNAME", f"alias=HOSTNAME\nalias={domain}", 1)
old = '''route[FINAL_ORIG]
{
        # Check for PSTN destinations:
        if (is_method("INVITE")) {
                route(PSTN_handling);
        }

        t_on_reply("orig_reply");

        t_relay();
}'''
new = '''route[FINAL_ORIG]
{
        # Check for PSTN destinations:
        if (is_method("INVITE")) {
                route(PSTN_handling);
        }

        # A local terminating user is routed to the terminating side instead of
        # being relayed to a domain that does not resolve.
        if (uri == myself) {
                route(term);
                exit;
        }

        t_on_reply("orig_reply");

        t_relay();
}'''
if new not in u:
    assert old in u, "FINAL_ORIG block not found in the shipped S-CSCF config"
    u = u.replace(old, new)
open(q, "w").write(u)
print("patched")
PY
	ok "installed CSCFs relaxed (no strict IMS IPsec, local terminating route)"
}

start_pyhss() {
	log "starting PyHSS (diameterService + hssService)"
	local cfg="$WORK/pyhss-config.yaml"
	mkdir -p "$WORK" /var/log/pyhss
	[ -f "$WORK/hss.db" ] || cp "$PROJECT_ROOT/database/pyhss/hss.db" "$WORK/hss.db"
	sed -e "s|/var/lib/pyhss/hss.db|$WORK/hss.db|" \
		"$PROJECT_ROOT/configs/pyhss/config.yaml" > "$cfg"

	# The call needs a subscriber profile without the Application Server iFC.
	cp "$PROJECT_ROOT/test/integration/ims_call_ifc.xml" "$PROJECT_ROOT/pyhss/_ims_call_ifc.xml"

	( cd "$PROJECT_ROOT/pyhss/services" && \
		PYHSS_CONFIG="$cfg" nohup "$PYHSS_PYTHON" diameterService.py > "$WORK/pyhss-diameter.log" 2>&1 & )
	( cd "$PROJECT_ROOT/pyhss/services" && \
		PYHSS_CONFIG="$cfg" nohup "$PYHSS_PYTHON" hssService.py > "$WORK/pyhss-hss.log" 2>&1 & )

	for _ in $(seq 1 40); do
		ss -lnt 2>/dev/null | grep -q "$HSS_IP:3868" && break
		sleep 0.5
	done
	ss -lnt 2>/dev/null | grep -q "$HSS_IP:3868" || die "PyHSS did not bind $HSS_IP:3868"
	ok "PyHSS is listening on $HSS_IP:3868"
}

# add_callee provisions the second subscriber and points both at the minimal iFC.
add_callee() {
	log "provisioning the callee subscriber"
	"$PYHSS_PYTHON" - "$WORK/hss.db" "$IMSI_A" "$IMSI_B" <<'PY'
import sqlite3, sys
db_path, imsi_a, imsi_b = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)
c = db.cursor()
c.execute("DELETE FROM auc WHERE imsi=?", (imsi_b,))
c.execute("DELETE FROM subscriber WHERE imsi=?", (imsi_b,))
c.execute("DELETE FROM ims_subscriber WHERE imsi=?", (imsi_b,))
c.execute("""INSERT INTO auc (ki,opc,amf,sqn,imsi,algo,last_modified)
             SELECT ki,opc,amf,0,?,algo,last_modified FROM auc WHERE imsi=?""", (imsi_b, imsi_a))
c.execute("""INSERT INTO subscriber (imsi,enabled,auc_id,default_apn,apn_list,msisdn,
                  ue_ambr_dl,ue_ambr_ul,nam,roaming_enabled,subscribed_rau_tau_timer,last_modified)
             VALUES (?,1,(SELECT auc_id FROM auc WHERE imsi=?),1,'1','123456790',
                     9999999,9999999,0,1,600,'2026-01-01T00:00:00Z')""", (imsi_b, imsi_b))
c.execute("""INSERT INTO ims_subscriber (msisdn,msisdn_list,imsi,ifc_path,xcap_profile,last_modified)
             SELECT '123456790','123456790',?,ifc_path,xcap_profile,'2026-01-01T00:00:00Z'
             FROM ims_subscriber WHERE imsi=?""", (imsi_b, imsi_a))
c.execute("UPDATE ims_subscriber SET ifc_path='_ims_call_ifc.xml' WHERE imsi LIKE '001010%'")
db.commit()
print("callee provisioned")
PY
	ok "the callee subscriber $IMSI_B was provisioned"
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

wait_cx_open() {
	local role="$1"
	for _ in $(seq 1 100); do
		if kamcmd -s "unix:/run/kamailio_$role/kamailio_ctl" cdp.list_peers 2>/dev/null | grep -q "I_Open"; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

wait_pcscf_ready() {
	local attempt
	for attempt in $(seq 1 20); do
		if PCSCF_IP="$PCSCF_LAB_ADDR" UE_IP="$UE_IP" IMPU="$IMSI_A@$SIP_DOMAIN" SIP_DOMAIN="$SIP_DOMAIN" \
			TIMEOUT=3 python3 "$PROJECT_ROOT/test/integration/ims_register_probe.py" \
			> "$WORK/pcscf_ready.log" 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

start_cscfs() {
	log "starting the CSCF chain"
	mysql -e "delete from scscf.impu_contact; delete from scscf.contact; delete from scscf.impu; delete from scscf.impu_subscriber;" 2>/dev/null
	for role in icscf scscf; do
		start_cscf "$role" || die "$role did not start, see $WORK/$role.log"
	done
	ok "I-CSCF and S-CSCF started"
	for role in icscf scscf; do
		wait_cx_open "$role" || bad "$role never reached Cx I_Open"
	done
	start_cscf pcscf || die "pcscf did not start, see $WORK/pcscf.log"
	wait_pcscf_ready || die "the P-CSCF never answered a probe REGISTER"
	ok "the CSCF chain is serving"
}

run_call() {
	log "running the two-UE call"
	PCSCF_IP="$PCSCF_LAB_ADDR" \
	PCSCF_PORT=5060 \
	UE_IP="$UE_IP" \
	SIP_DOMAIN="$SIP_DOMAIN" \
	IMSI_A="$IMSI_A" \
	IMSI_B="$IMSI_B" \
	KI_HEX="$KI_HEX" \
	OPC_HEX="$OPC_HEX" \
	PYHSS_LIB="$PROJECT_ROOT/pyhss/lib" \
		"$PYHSS_PYTHON" "$PROJECT_ROOT/test/integration/ims_call.py" 2>&1 | tee "$WORK/ims_call.log"
	local rc="${PIPESTATUS[0]}"
	if [ "$rc" -eq 0 ]; then
		ok "the two UEs completed INVITE -> 200 OK -> ACK -> BYE -> 200 OK"
	else
		bad "the IMS call did not complete"
	fi
	grep -q "call established" "$WORK/ims_call.log" && ok "the call was established"
	grep -q "call released" "$WORK/ims_call.log" && ok "the call was released"
}

summary() {
	echo
	echo "=================== IMS CALL integration summary ==================="
	printf '%s\n' "${RESULTS[@]}"
	echo "--------------------------------------------------------------------"
	printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
	echo "artefacts: $WORK"
	echo "===================================================================="
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
	patch_cscf_configs
	start_pyhss
	add_callee
	start_cscfs
	run_call
	summary
}

main "$@"
