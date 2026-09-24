#!/usr/bin/env bash
#
# Real SWu integration test for the Go ePDG.
#
# Nothing here is simulated:
#   * strongSwan charon terminates IKEv2/IPsec on both ends. The ePDG acts as the
#     responder with the eap-radius plugin, the UE acts as the initiator with the
#     eap-aka-3gpp test card (K and OPc configured exactly like a USIM).
#   * PyHSS generates the AKA quintuplets with its own Milenage implementation,
#     read from a real SQLite subscriber database.
#   * The Go ePDG implements the RADIUS EAP-AKA server in between.
#
# The test asserts that the IKE_SA and CHILD_SA reach the established/installed
# state on both peers, which can only happen if the ePDG derived the same MSK as
# the UE, and that the negotiated tunnel actually carries traffic.
#
# Requirements: root, a strongSwan build with the eap-aka-3gpp plugin
# (SWAN=/path/to/prefix), python3 venv with PyHSS dependencies, and pki.
#
# Usage: sudo -E test/integration/swu_eap_aka.sh
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

SWAN="${SWAN:-/tmp/it/swan}"
WORK="${WORK:-/tmp/it/run}"
KEEP="${KEEP:-0}"

NS_EPDG="${NS_EPDG:-epdg-it}"
NS_UE="${NS_UE:-ue-it}"

HOST_IP="10.99.0.254"
# Separate management subnet for the host link, so the namespace does not end up
# with two routes for the underlay prefix.
MGMT_HOST_IP="10.98.0.254"
MGMT_GW_IP="10.98.0.253"
EPDG_IP="10.99.0.1"
UE_IP="10.99.0.2"
INNER_EPDG="10.46.0.1"
INNER_UE="10.46.0.100"

IMSI="001010000000001"
NAI="0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"
KI="465B5CE8B199B49FAA5F0A2EE238A6BC"
OPC="2e001f1df0a0bb769940a2c6342cf795"

PYHSS_PYTHON="${PYHSS_PYTHON:-/tmp/pyhss-venv/bin/python}"
PYHSS_PORT="${PYHSS_PORT:-8080}"
RADIUS_PORT="${RADIUS_PORT:-18120}"
RADIUS_SECRET="pyhss-radius-secret"
EPDG_HTTP_PORT="${EPDG_HTTP_PORT:-19090}"

EPDGD_BIN="$WORK/epdgd"
PYHSS_DB="$WORK/hss.db"

PASS=0
FAIL=0
declare -a RESULTS=()

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '\033[1;32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '\033[1;31mFAIL\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31mFATAL\033[0m %s\n' "$*"; cleanup; exit 1; }

cleanup() {
	pkill -f "$EPDGD_BIN" 2>/dev/null
	pkill -f "$SWAN/libexec/ipsec/charon" 2>/dev/null
	for pidfile in "$WORK/epdg/charon.pid" "$WORK/ue/charon.pid"; do
		[ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null
	done
	pkill -f "apiService.py" 2>/dev/null
	ip netns del "$NS_EPDG" 2>/dev/null
	ip netns del "$NS_UE" 2>/dev/null
	ip link del v-eph 2>/dev/null
	ip link del v-host 2>/dev/null
	rm -f /run/charon.pid
}

trap cleanup EXIT

require_root() {
	[ "$(id -u)" = "0" ] || die "this test must run as root (it creates network namespaces)"
}

require_tools() {
	command -v ip >/dev/null || die "iproute2 is required"
	command -v pki >/dev/null || die "the strongSwan pki tool is required"
	command -v curl >/dev/null || die "curl is required"
	[ -x "$SWAN/libexec/ipsec/charon" ] || die "no charon under $SWAN, set SWAN to a strongSwan prefix built with --enable-eap-aka-3gpp"
	[ -x "$SWAN/sbin/swanctl" ] || die "no swanctl under $SWAN"
	[ -f "$SWAN/lib/ipsec/plugins/libstrongswan-eap-aka-3gpp.so" ] \
		|| die "$SWAN lacks the eap-aka-3gpp plugin, the UE cannot compute AKA vectors"
	[ -x "$PYHSS_PYTHON" ] || die "python interpreter $PYHSS_PYTHON not found (set PYHSS_PYTHON)"
}

setup_namespaces() {
	log "creating network namespaces $NS_EPDG and $NS_UE"
	ip netns add "$NS_EPDG" || die "cannot create $NS_EPDG"
	ip netns add "$NS_UE" || die "cannot create $NS_UE"

	# UE <-> ePDG underlay.
	ip link add v-eph type veth peer name v-ue || die "cannot create veth pair"
	ip link set v-eph netns "$NS_EPDG"
	ip link set v-ue netns "$NS_UE"
	ip -n "$NS_EPDG" addr add "$EPDG_IP/24" dev v-eph
	ip -n "$NS_UE" addr add "$UE_IP/24" dev v-ue
	ip -n "$NS_EPDG" link set v-eph up
	ip -n "$NS_UE" link set v-ue up
	ip -n "$NS_EPDG" link set lo up
	ip -n "$NS_UE" link set lo up

	# A second pair, on its own subnet, so the ePDG namespace can reach PyHSS on
	# the host.
	ip link add v-host type veth peer name v-gw || die "cannot create host veth pair"
	ip link set v-gw netns "$NS_EPDG"
	ip addr add "$MGMT_HOST_IP/24" dev v-host
	ip -n "$NS_EPDG" addr add "$MGMT_GW_IP/24" dev v-gw
	ip link set v-host up
	ip -n "$NS_EPDG" link set v-gw up

	# Inner addresses used to verify the data path through the tunnel. The UE
	# address is assigned by the ePDG from the swanctl pool, so only the ePDG
	# side is configured statically here.
	ip -n "$NS_EPDG" link add inner0 type dummy
	ip -n "$NS_EPDG" addr add "$INNER_EPDG/24" dev inner0
	ip -n "$NS_EPDG" link set inner0 up

	# The neighbour entry on the host side may need a moment to appear.
	local reachable=""
	for _ in $(seq 1 10); do
		if ip netns exec "$NS_EPDG" ping -c 1 -W 2 "$MGMT_HOST_IP" >/dev/null 2>&1; then
			reachable=yes
			break
		fi
		sleep 0.5
	done
	[ -n "$reachable" ] || die "the ePDG namespace cannot reach the host at $MGMT_HOST_IP"
	ok "network namespaces and inner addressing ready"
}

start_pyhss() {
	log "starting PyHSS"
	cp "$PROJECT_ROOT/database/pyhss/hss.db" "$PYHSS_DB" || die "cannot seed the PyHSS database"
	sed -e "s|/var/lib/pyhss/hss.db|$PYHSS_DB|" \
		"$PROJECT_ROOT/configs/pyhss/config.yaml" > "$WORK/pyhss.yaml"
	PYHSS_CONFIG="$WORK/pyhss.yaml" nohup "$PYHSS_PYTHON" \
		"$PROJECT_ROOT/pyhss/services/apiService.py" > "$WORK/pyhss.log" 2>&1 &
	echo $! > "$WORK/pyhss.pid"

	for _ in $(seq 1 60); do
		if curl -fsS -m 1 "http://127.0.0.1:$PYHSS_PORT/oam/ping" >/dev/null 2>&1; then
			ok "PyHSS is answering /oam/ping"
			return
		fi
		sleep 0.5
	done
	die "PyHSS did not start, see $WORK/pyhss.log"
}

make_certificates() {
	log "generating the ePDG certificate"
	mkdir -p "$WORK/ca"
	pki --gen --type rsa --size 2048 --outform pem > "$WORK/ca/ca.key" || die "pki --gen (CA) failed"
	pki --self --ca --lifetime 3650 --in "$WORK/ca/ca.key" \
		--dn "C=IT, O=ePDG Integration, CN=ePDG Test CA" --outform pem > "$WORK/ca/ca.crt" \
		|| die "pki --self failed"
	pki --gen --type rsa --size 2048 --outform pem > "$WORK/ca/epdg.key" || die "pki --gen (ePDG) failed"
	pki --pub --in "$WORK/ca/epdg.key" --outform pem \
		| pki --issue --lifetime 3650 --cacert "$WORK/ca/ca.crt" --cakey "$WORK/ca/ca.key" \
			--dn "C=IT, O=ePDG Integration, CN=epdg.local" \
			--san epdg.local --san "$EPDG_IP" --outform pem > "$WORK/ca/epdg.crt" \
		|| die "pki --issue failed"
	ok "certificates generated"
}

write_charon_configs() {
	log "writing charon and swanctl configuration"

	mkdir -p "$WORK/epdg/run" "$WORK/ue/run"
	mkdir -p "$WORK/epdg/swanctl/conf.d" "$WORK/epdg/swanctl/x509" "$WORK/epdg/swanctl/x509ca" "$WORK/epdg/swanctl/private"
	mkdir -p "$WORK/ue/swanctl/conf.d" "$WORK/ue/swanctl/x509ca"

	cp "$WORK/ca/epdg.crt" "$WORK/epdg/swanctl/x509/"
	cp "$WORK/ca/ca.crt"   "$WORK/epdg/swanctl/x509ca/"
	cp "$WORK/ca/epdg.key" "$WORK/epdg/swanctl/private/"
	cp "$WORK/ca/ca.crt"   "$WORK/ue/swanctl/x509ca/"

	# swanctl only loads swanctl.conf; conf.d snippets are pulled in by the
	# include directive, exactly like the packaged /etc/swanctl/swanctl.conf.
	printf 'include conf.d/*.conf\n' > "$WORK/epdg/swanctl/swanctl.conf"
	printf 'include conf.d/*.conf\n' > "$WORK/ue/swanctl/swanctl.conf"

	cat > "$WORK/epdg/strongswan.conf" <<EOF
charon {
  pid_file = $WORK/epdg/charon.pid
  install_routes = yes
  filelog {
    $WORK/epdg/charonlog {
      default = 2
      cfg = 2
      knl = 2
      enc = 1
      net = 1
    }
  }
  plugins {
    vici {
      socket = unix://$WORK/epdg/charon.vici
    }
    eap-radius {
      nas_identifier = epdg.local
      servers {
        go-epdg {
          address = 127.0.0.1
          port = $RADIUS_PORT
          secret = $RADIUS_SECRET
        }
      }
    }
  }
}
EOF

	cat > "$WORK/ue/strongswan.conf" <<EOF
charon {
  pid_file = $WORK/ue/charon.pid
  install_routes = yes
  filelog {
    $WORK/ue/charonlog {
      default = 2
      cfg = 2
      knl = 2
      enc = 1
      net = 1
    }
  }
  plugins {
    vici {
      socket = unix://$WORK/ue/charon.vici
    }
    eap-aka-3gpp {
      seq_check = no
    }
  }
}
EOF

	cat > "$WORK/epdg/swanctl/conf.d/epdg.conf" <<EOF
connections {
  epdg-ike {
    version = 2
    local_addrs = $EPDG_IP
    remote_addrs = %any
    proposals = aes128-sha1-modp2048,aes128-sha256-modp2048
    rekey_time = 0
    pools = ue_pool
    local {
      auth = pubkey
      certs = epdg.crt
      id = epdg.local
    }
    remote {
      auth = eap-radius
    }
    children {
      ue-default {
        local_ts = $INNER_EPDG/24
        remote_ts = dynamic
        esp_proposals = aes128-sha1,aes128-sha256
        start_action = trap
      }
    }
  }
}
pools {
  ue_pool {
    addrs = $INNER_UE-$INNER_UE
    dns = 8.8.8.8
  }
}
EOF

	cat > "$WORK/ue/swanctl/conf.d/ue.conf" <<EOF
connections {
  swu {
    version = 2
    local_addrs = $UE_IP
    remote_addrs = $EPDG_IP
    proposals = aes128-sha1-modp2048
    rekey_time = 0
    # Request an inner address from the ePDG pool over IKEv2 configuration
    # payloads, which is what a UE does across SWu.
    vips = 0.0.0.0
    local {
      auth = eap
      id = $NAI
      eap_id = $NAI
    }
    remote {
      auth = pubkey
      id = epdg.local
      cacerts = ca.crt
    }
    children {
      home {
        # dynamic asks the ePDG for an address from its pool, which is what a
        # real UE does across SWu.
        local_ts = dynamic
        remote_ts = $INNER_EPDG/24
        esp_proposals = aes128-sha1
        start_action = trap
      }
    }
  }
}
secrets {
  eap-ue {
    id = $NAI
    secret = 0x$KI$OPC
  }
}
EOF
	ok "charon configuration written"
}

start_charon() {
	local side="$1" ns="$2"
	log "starting charon ($side) in $ns"
	# The classic charon daemon uses a hard coded /run/charon.pid and refuses to
	# start when it points at a live process, so clear it before each instance.
	rm -f /run/charon.pid /var/run/charon.pid
	ip netns exec "$ns" env STRONGSWAN_CONF="$WORK/$side/strongswan.conf" \
		"$SWAN/libexec/ipsec/charon" --use-syslog > "$WORK/$side/charon.out" 2>&1 &
	echo $! > "$WORK/$side/charon.pid"
	sleep 1
	for _ in $(seq 1 20); do
		[ -S "$WORK/$side/charon.vici" ] && { ok "charon ($side) created its VICI socket"; return; }
		sleep 0.5
	done
	die "charon ($side) did not start, see $WORK/$side/charonlog"
}

load_conns() {
	local side="$1" ns="$2" conn="$3"
	if ! SWANCTL_DIR="$WORK/$side/swanctl" ip netns exec "$ns" \
		"$SWAN/sbin/swanctl" --load-all -u "unix://$WORK/$side/charon.vici" \
		> "$WORK/$side/load.log" 2>&1; then
		sed -n '1,25p' "$WORK/$side/load.log"
		die "swanctl --load-all failed for $side"
	fi
	# --load-all exits zero even when nothing matched, so assert that charon
	# actually knows the connection before continuing.
	local conns
	conns="$(SWANCTL_DIR="$WORK/$side/swanctl" ip netns exec "$ns" \
		"$SWAN/sbin/swanctl" --list-conns -u "unix://$WORK/$side/charon.vici" 2>&1)"
	printf '%s\n' "$conns" > "$WORK/$side/list-conns.log"
	if grep -q "$conn" <<<"$conns"; then
		ok "connection $conn is loaded on the $side"
	else
		die "connection $conn was not loaded on the $side, see $WORK/$side/list-conns.log"
	fi
}

start_epdgd() {
	log "starting the Go ePDG control plane"
	cat > "$WORK/epdg/epdg-it.yaml" <<EOF
node_id: epdg.it
http:
  listen: "127.0.0.1:$EPDG_HTTP_PORT"
ipsec:
  backend: vici
  mode: passive
  socket: $WORK/epdg/charon.vici
  connection_name: epdg-ike
  child_name: ue-default
  timeout_seconds: 5
aaa:
  backend: pyhss_api
  origin_host: epdg.local
  origin_realm: localdomain
  eap_max_rounds: 4
  pyhss_api:
    base_url: http://$MGMT_HOST_IP:$PYHSS_PORT
    vector_path_template: /auc/aka/vector_count/1/imsi/{imsi}
    oam_ping_path: /oam/ping
    timeout_seconds: 5
radius:
  backend: eap_aka
  listen: 127.0.0.1:$RADIUS_PORT
  secret: $RADIUS_SECRET
  realm: localdomain
  require_message_authenticator: true
protocol:
  plmn:
    mcc: "001"
    mnc: "001"
  swu:
    local_address: $EPDG_IP
    ike_port: 500
    natt_port: 4500
  s2b:
    backend: noop
EOF
	ip netns exec "$NS_EPDG" nohup "$EPDGD_BIN" -config "$WORK/epdg/epdg-it.yaml" -log-level debug \
		> "$WORK/epdg/epdgd.log" 2>&1 &
	echo $! > "$WORK/epdg/epdgd.pid"

	for _ in $(seq 1 30); do
		if ip netns exec "$NS_EPDG" curl -fsS -m 1 "http://127.0.0.1:$EPDG_HTTP_PORT/healthz" >/dev/null 2>&1; then
			ok "epdgd is answering /healthz"
			return
		fi
		sleep 0.5
	done
	die "epdgd did not start, see $WORK/epdg/epdgd.log"
}

swanctl_cmd() {
	# swanctl expects the command as the first argument: after locating the
	# command it resets optind to 2 and parses everything else, including -u.
	local side="$1" ns="$2"; shift 2
	SWANCTL_DIR="$WORK/$side/swanctl" ip netns exec "$ns" \
		"$SWAN/sbin/swanctl" "$@" -u "unix://$WORK/$side/charon.vici"
}

initiate_from_ue() {
	log "initiating the IKEv2/EAP-AKA exchange from the UE"
	swanctl_cmd ue "$NS_UE" --initiate --child home > "$WORK/ue/initiate.log" 2>&1
	echo "--- swanctl --initiate output ---"
	cat "$WORK/ue/initiate.log"
	echo "---------------------------------"
	if grep -qiE "established|installed" "$WORK/ue/initiate.log"; then
		ok "the UE reports the CHILD_SA as installed"
	else
		bad "the UE did not report an installed CHILD_SA"
	fi
}

check_epdg_sa() {
	local sas
	sas="$(swanctl_cmd epdg "$NS_EPDG" --list-sas 2>&1)"
	printf '%s\n' "$sas" > "$WORK/epdg/list-sas.log"
	if grep -q "ESTABLISHED" <<<"$sas"; then
		ok "the ePDG reports an ESTABLISHED IKE_SA"
	else
		bad "the ePDG has no ESTABLISHED IKE_SA"
	fi
	if grep -q "INSTALLED" <<<"$sas"; then
		ok "the ePDG reports an INSTALLED CHILD_SA"
	else
		bad "the ePDG has no INSTALLED CHILD_SA"
	fi
	if grep -q "eap-radius" <<<"$sas"; then
		ok "the ePDG IKE_SA was authenticated over EAP (RADIUS)"
	fi
}

check_ue_sa() {
	local sas
	sas="$(swanctl_cmd ue "$NS_UE" --list-sas 2>&1)"
	printf '%s\n' "$sas" > "$WORK/ue/list-sas.log"
	if grep -q "ESTABLISHED" <<<"$sas"; then
		ok "the UE reports an ESTABLISHED IKE_SA"
	else
		bad "the UE has no ESTABLISHED IKE_SA"
	fi
	if grep -q "INSTALLED" <<<"$sas"; then
		ok "the UE reports an INSTALLED CHILD_SA"
	else
		bad "the UE has no INSTALLED CHILD_SA"
	fi
}

check_radius_exchange() {
	local log="$WORK/epdg/epdgd.log"
	if grep -q "AKA challenge" "$log"; then
		ok "the ePDG sent an EAP-Request/AKA-Challenge over RADIUS"
	else
		bad "no AKA challenge in the ePDG log"
	fi
	if grep -q "AKA success" "$log"; then
		ok "the ePDG verified the AKA response and returned the MSK"
	else
		bad "the ePDG never accepted an AKA response"
	fi
	echo "--- ePDG AAA log ---"
	grep -E "radius:|session" "$log" | tail -15
	echo "--------------------"
}

check_data_path() {
	log "verifying the data path through the tunnel"
	local vip
	vip="$(grep -oE "$INNER_UE/32" "$WORK/ue/list-sas.log" | head -1 | cut -d/ -f1)"
	if [ -z "$vip" ]; then
		bad "the ePDG did not assign an inner address to the UE"
		return
	fi
	ok "the ePDG assigned $vip to the UE from its pool"

	if ip netns exec "$NS_UE" ip addr show | grep -q "$vip"; then
		ok "the UE installed the assigned address on its tunnel interface"
	else
		bad "the UE did not install the assigned address"
	fi

	if ip netns exec "$NS_UE" ping -c 3 -W 3 -I "$vip" "$INNER_EPDG" > "$WORK/ue/ping.log" 2>&1; then
		ok "ICMP through the SWu tunnel succeeded"
	else
		bad "ICMP through the SWu tunnel failed"
		cat "$WORK/ue/ping.log"
	fi
	if ip netns exec "$NS_EPDG" ip xfrm state | grep -q "proto esp"; then
		ok "the ePDG installed an ESP state in the kernel"
	else
		bad "no ESP state installed on the ePDG"
	fi
	if ip netns exec "$NS_UE" ip xfrm state | grep -q "proto esp"; then
		ok "the UE installed an ESP state in the kernel"
	else
		bad "no ESP state installed on the UE"
	fi
}

check_compliance() {
	local body
	body="$(ip netns exec "$NS_EPDG" curl -sS -m 5 "http://127.0.0.1:$EPDG_HTTP_PORT/v1/compliance/check")"
	echo "compliance: $body"
	# Parse the document so a passing sub-item cannot masquerade as an overall
	# pass.
	if python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.stdin.read()).get("passed") is True else 1)' <<<"$body"; then
		ok "the ePDG readiness report is green"
	else
		bad "the ePDG readiness report is not green"
	fi
}

summary() {
	echo
	echo "=================== integration test summary ==================="
	printf '%s\n' "${RESULTS[@]}"
	echo "----------------------------------------------------------------"
	printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
	echo "artefacts: $WORK"
	echo "================================================================"
	[ "$FAIL" -eq 0 ]
}

main() {
	require_root
	require_tools
	mkdir -p "$WORK"
	cleanup
	go build -o "$EPDGD_BIN" "$PROJECT_ROOT/cmd/epdgd" || die "cannot build epdgd"
	ok "epdgd built"

	setup_namespaces
	start_pyhss
	make_certificates
	write_charon_configs
	start_charon epdg "$NS_EPDG"
	start_charon ue "$NS_UE"
	load_conns epdg "$NS_EPDG" epdg-ike
	load_conns ue "$NS_UE" swu
	start_epdgd
	initiate_from_ue
	check_ue_sa
	check_epdg_sa
	check_radius_exchange
	check_data_path
	check_compliance
	summary
}

main "$@"
