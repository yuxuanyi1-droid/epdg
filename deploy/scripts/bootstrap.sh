#!/usr/bin/env bash
#
# Takes a bare Debian host to a working ePDG lab, and is safe to re-run.
#
# The sandbox this was developed in is reset periodically, which wipes installed
# packages, container images and volumes. Every step below is therefore
# idempotent and checks what is already present before doing work, so the script
# can be re-run after a reset without rebuilding what survived.
#
# Layers (each can be requested on its own):
#
#   host     host packages the other layers need (docker, golang, python,
#            strongSwan, the PyHSS virtualenv, ...)
#   images   build the container images
#   up       start the stack
#   verify   assert the stack works
#   all      host + images + up + verify (the default)
#
# Usage:
#   sudo -E deploy/scripts/bootstrap.sh [layer]
#
# Environment:
#   PROFILES      compose profiles to start (default: whatever labctl renders)
#   SKIP_EPC=1    do not build the Open5GS image (its source build dominates the
#                 build time); the S2b tests then cannot run
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="${REPO_ROOT}/deploy"
LAYER="${1:-all}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
	[ "$(id -u)" = "0" ] || die "run this as root (it installs packages and starts docker)"
}

# ---------------------------------------------------------------- host layer

install_host_packages() {
	log "host packages"
	local missing=()
	for pkg in ca-certificates curl mariadb-server redis-server python3-venv \
		python3-dev gcc libsctp-dev sqlite3 golang-go; do
		dpkg -s "${pkg}" >/dev/null 2>&1 || missing+=("${pkg}")
	done
	if [ "${#missing[@]}" -eq 0 ]; then
		log "  all present"
	else
		log "  installing: ${missing[*]}"
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y -qq "${missing[@]}" || die "cannot install host packages"
	fi

	# Docker is the one package that may need the upstream repository.
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		log "  docker and the compose plugin are present"
	else
		die "docker with the compose plugin is required; install it, then re-run"
	fi

	# Kamailio is run natively by test/integration/ims_register.sh, so its IMS
	# modules are needed on the host as well as in the image.
	local kam_missing=()
	for pkg in kamailio kamailio-ims-modules kamailio-mysql-modules \
		kamailio-extra-modules kamailio-json-modules kamailio-presence-modules \
		kamailio-tls-modules kamailio-sctp-modules kamailio-utils-modules \
		kamailio-websocket-modules kamailio-xml-modules; do
		dpkg -s "${pkg}" >/dev/null 2>&1 || kam_missing+=("${pkg}")
	done
	if [ "${#kam_missing[@]}" -eq 0 ]; then
		log "  kamailio and its IMS modules are present"
	else
		log "  installing: ${kam_missing[*]}"
		export DEBIAN_FRONTEND=noninteractive
		apt-get install -y -qq "${kam_missing[@]}" || die "cannot install kamailio"
	fi
	# Kamailio refuses to start when a pid file points at a live process, and a
	# killed instance leaves one behind.
	rm -rf /run/kamailio_pcscf /run/kamailio_icscf /run/kamailio_scscf
	mkdir -p /run/kamailio_pcscf /run/kamailio_icscf /run/kamailio_scscf
}

# pick_python returns an interpreter that can actually create a virtualenv and
# load a C extension.
#
# This is not paranoia: on the sandbox image /usr/local/bin/python3 is a 14 KB
# shim whose pip dies with SIGSEGV, and it shadows the real /usr/bin/python3 on
# PATH. Building the venv from the shim produces an interpreter that segfaults
# on `from Crypto.Cipher import AES`, which looks like a Milenage bug but is not.
pick_python() {
	local candidate probe
	for candidate in "${PYTHON_BIN:-}" /usr/bin/python3 python3; do
		[ -z "${candidate}" ] && continue
		command -v "${candidate}" >/dev/null 2>&1 || continue
		probe="$(mktemp -d)"
		if "${candidate}" -m venv "${probe}/v" >/dev/null 2>&1 \
			&& "${probe}/v/bin/python" -c "import ctypes, ssl, hashlib" >/dev/null 2>&1; then
			rm -rf "${probe}"
			echo "${candidate}"
			return 0
		fi
		rm -rf "${probe}"
	done
	return 1
}

# The PyHSS services run from a virtual environment in the native tests, and the
# UE scripts import Milenage from it, so the dependencies are needed on the host.
setup_pyhss_venv() {
	local venv="${PYHSS_VENV:-/tmp/pyhss-venv}"
	# The check has to cover PyHSS's own imports, not just the third party ones: a
	# venv with an incompatible SQLAlchemy_Utils still imports flask and redis,
	# but hssService.py then fails at start up and Cx goes unanswered.
	# pyhss_config.py exits when it cannot find a config file, so the import probe
	# has to point at one; configs/pyhss/config.yaml only has to exist and parse.
	if [ -x "${venv}/bin/python" ] \
		&& "${venv}/bin/python" -c "import flask, redis, comp128" 2>/dev/null \
		&& "${venv}/bin/python" -c "from Crypto.Cipher import AES" 2>/dev/null \
		&& ( cd "${REPO_ROOT}/pyhss/lib" && PYHSS_CONFIG="${REPO_ROOT}/configs/pyhss/config.yaml" \
			"${venv}/bin/python" -c "import database" ) 2>/dev/null; then
		log "  PyHSS virtualenv is present at ${venv}"
		return
	fi

	local py
	py="$(pick_python)" || die "no working python3 interpreter found (tried \$PYTHON_BIN, /usr/bin/python3, python3)"
	log "  creating the PyHSS virtualenv at ${venv} with ${py}"

	rm -rf "${venv}"
	"${py}" -m venv "${venv}" || die "cannot create ${venv}"
	"${venv}/bin/pip" install -q --upgrade pip

	# Only what the api/diameter/hss services and the UE scripts import. The full
	# pyhss/requirements.txt pulls mysqlclient and pysnmp, neither of which the
	# SQLite setup uses.
	#
	# SQLAlchemy and SQLAlchemy_Utils stay pinned to the versions PyHSS works
	# with: newer sqlalchemy_utils dereferences
	# sqlalchemy.orm.attributes.ScalarAttributeImpl, which SQLAlchemy 2.x no
	# longer exports, and hssService.py then dies on import with an
	# AttributeError that surfaces as an unanswered Cx request.
	#
	# pycryptodome is the one floor that matters: 3.17 predates Python 3.13 and
	# has no cp313 wheel, so a pinned install builds something that segfaults on
	# the first AES call, which looks like a Milenage bug but is not.
	"${venv}/bin/pip" install -q \
		"flask==2.2.3" "flask-restx==1.1.0" "werkzeug==2.2.3" \
		requests "sqlalchemy==2.0.44" "SQLAlchemy_Utils==0.41.1" alembic \
		pyyaml "redis==5.0.0" "pydantic==2.8.2" "prometheus_client==0.16.0" \
		"pycryptodome>=3.20" "comp128==1.0.0" "pysctp==0.7.2" "tzlocal==4.3" \
		|| die "cannot install the PyHSS dependencies"

	# Prove the imports the UE and HSS paths depend on actually work.
	( cd "${REPO_ROOT}/pyhss/lib" && PYHSS_CONFIG="${REPO_ROOT}/configs/pyhss/config.yaml" \
		"${venv}/bin/python" -c "import database" ) 2>/dev/null \
		|| die "the virtualenv cannot import PyHSS's database module; check the SQLAlchemy pins"
	if ! "${venv}/bin/python" -c "from Crypto.Cipher import AES" 2>/dev/null; then
		die "the virtualenv cannot load pycryptodome; the UE cannot derive RES"
	fi
	log "  virtualenv ready"
}

# strongSwan runs on the host, not in a container: it needs the host network
# namespace and the kernel XFRM to terminate IPsec. The ePDG container reaches it
# through the VICI socket, and charon reaches the container's RADIUS server over
# the bridge.
setup_host_strongswan() {
	local missing=()
	# strongswan-charon provides the standalone /usr/lib/ipsec/charon. The
	# charon-systemd package is not enough here: it expects the systemd notify
	# socket and exits silently without it, leaving no VICI socket behind.
	for pkg in strongswan strongswan-charon strongswan-swanctl \
		libcharon-extra-plugins libstrongswan-standard-plugins \
		libstrongswan-extra-plugins; do
		dpkg -s "${pkg}" >/dev/null 2>&1 || missing+=("${pkg}")
	done
	if [ "${#missing[@]}" -ne 0 ]; then
		log "  installing strongSwan: ${missing[*]}"
		export DEBIAN_FRONTEND=noninteractive
		apt-get install -y -qq "${missing[@]}" || die "cannot install strongSwan"
	fi

	# fips-prf is what gives eap-aka its PRF; without it EAP-AKA is silently
	# disabled rather than reported, so check for the plugin file.
	if [ ! -f /usr/lib/ipsec/plugins/libstrongswan-fips-prf.so ]; then
		warn "libstrongswan-fips-prf.so is missing; EAP-AKA will not be offered"
	fi

	# Install the rendered configuration. deploy/runtime/strongswan mirrors the
	# layout of /etc/strongswan.d and /etc/swanctl, and the RADIUS server in it
	# already points at the ePDG container.
	if [ -f "${DEPLOY_DIR}/runtime/strongswan/strongswan.conf" ]; then
		cp -a "${DEPLOY_DIR}/runtime/strongswan/strongswan.conf" /etc/strongswan.conf
	fi
	if [ -d "${DEPLOY_DIR}/runtime/strongswan/strongswan.d" ]; then
		cp -a "${DEPLOY_DIR}/runtime/strongswan/strongswan.d/." /etc/strongswan.d/
	fi
	if [ -d "${DEPLOY_DIR}/runtime/strongswan/swanctl" ]; then
		mkdir -p /etc/swanctl
		cp -a "${DEPLOY_DIR}/runtime/strongswan/swanctl/." /etc/swanctl/
	fi
	# The VICI socket directory is shared with the ePDG container.
	mkdir -p /run/epdg-lab

	# charon needs to be started by hand in this sandbox, and it refuses to start
	# when a stale pid file points at a live process.
	#
	# The check is on the VICI socket, not on a process name: a killed or
	# systemd-less charon leaves a zombie that still matches pgrep, which would
	# make a re-run skip starting a daemon that is not actually there.
	if [ -S '/run/epdg-lab/charon.vici' ]; then
		log "  charon is already running (VICI socket present)"
		return
	fi
	rm -f /run/charon.pid /var/run/charon.pid

	# The daemon's path depends on the packaging: the classic charon lives in
	# libexec, while charon-systemd is in sbin. Either works for VICI and
	# eap-radius.
	local daemon=""
	for candidate in /usr/lib/ipsec/charon /usr/local/libexec/ipsec/charon \
		/usr/sbin/charon-systemd /usr/local/sbin/charon-systemd; do
		if [ -x "${candidate}" ]; then
			daemon="${candidate}"
			break
		fi
	done
	[ -n "${daemon}" ] || die "no charon daemon found; is strongswan installed?"

	log "  starting ${daemon}"
	nohup "${daemon}" > /tmp/charon.log 2>&1 &
	for _ in $(seq 1 30); do
		[ -S /run/epdg-lab/charon.vici ] && break
		sleep 1
	done
	if [ -S '/run/epdg-lab/charon.vici' ]; then
		log "  charon is up, VICI socket at /run/epdg-lab/charon.vici"
	else
		warn "charon did not create its VICI socket; see /tmp/charon.log"
	fi
}

ensure_docker() {
	if ! docker info >/dev/null 2>&1; then
		log "starting the docker daemon"
		# The sandbox has no init system, so the daemon is started by hand. It is
		# lost on a reset, which is why this is part of bootstrap rather than a
		# documented prerequisite.
		nohup dockerd > /tmp/dockerd.log 2>&1 &
		for _ in $(seq 1 40); do
			docker info >/dev/null 2>&1 && break
			sleep 1
		done
	fi
	docker info >/dev/null 2>&1 || die "the docker daemon is not available; see /tmp/dockerd.log"
	log "  docker daemon is up"
}

render_lab() {
	log "rendering deploy/lab.yaml"
	( cd "${REPO_ROOT}" && go build -o bin/labctl ./cmd/labctl ) || die "cannot build labctl"
	( cd "${REPO_ROOT}" && bin/labctl render -lab deploy/lab.yaml -deploy deploy -quiet ) \
		|| die "labctl render failed"
	# Bootstrap runs as root, so the generated tree and the binary would otherwise
	# be unwritable by the invoking user, and a later `labctl render` (or the
	# console's render button) would fail with permission denied.
	if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
		local owner
		owner="$(id -u "${SUDO_USER}"):$(id -g "${SUDO_USER}")"
		chown -R "${owner}" "${DEPLOY_DIR}/runtime" "${DEPLOY_DIR}/.env" \
			"${REPO_ROOT}/bin" 2>/dev/null || true
	fi
	log "  deploy/.env and deploy/runtime are up to date"
}

# --------------------------------------------------------------- image layer

build_images() {
	log "container images"
	local services=(mariadb redis pyhss pcscf icscf scscf epdgd)
	if [ "${SKIP_EPC:-0}" != "1" ]; then
		services+=(mme sgwc sgwu smf upf)
	fi
	# Build only what will be started; `--build` on a profile-excluded service
	# would drag in the Open5GS source build.
	COMPOSE_PROFILES="${PROFILES:-core,epc}" docker compose \
		--project-directory "${DEPLOY_DIR}" build "${services[@]}" \
		|| die "image build failed"
	log "  images built"
}

# ------------------------------------------------------------------ up layer

start_stack() {
	log "starting the stack"
	COMPOSE_PROFILES="${PROFILES:-core,epc}" docker compose \
		--project-directory "${DEPLOY_DIR}" up -d --remove-orphans \
		|| die "cannot start the stack"

	# mariadb reports healthy only after its init scripts have run, and the CSCFs
	# exit if they cannot reach it, so wait before declaring the stack up.
	log "  waiting for mariadb and pyhss to report healthy"
	for _ in $(seq 1 60); do
		local unhealthy
		unhealthy="$(docker compose --project-directory "${DEPLOY_DIR}" ps --format '{{.Service}} {{.Health}}' 2>/dev/null \
			| awk '$1 == "mariadb" || $1 == "pyhss" { if ($2 != "healthy") print $1 }')"
		[ -z "${unhealthy}" ] && break
		sleep 2
	done
	docker compose --project-directory "${DEPLOY_DIR}" ps --format '{{.Service}}\t{{.State}}\t{{.Status}}'
}

# -------------------------------------------------------------- verify layer

verify_stack() {
	log "verifying"
	PYHSS_PYTHON="${PYHSS_VENV:-/tmp/pyhss-venv}/bin/python" \
		bash "${DEPLOY_DIR}/scripts/verify.sh"
}

case "${LAYER}" in
	host)
		require_root
		install_host_packages
		setup_pyhss_venv
		ensure_docker
		render_lab
		setup_host_strongswan
		;;
	images)
		require_root
		ensure_docker
		render_lab
		build_images
		;;
	up)
		require_root
		ensure_docker
		render_lab
		start_stack
		;;
	verify)
		require_root
		verify_stack
		;;
	all)
		require_root
		install_host_packages
		setup_pyhss_venv
		ensure_docker
		render_lab
		setup_host_strongswan
		build_images
		start_stack
		verify_stack
		;;
	*)
		die "unknown layer '${LAYER}' (want host, images, up, verify or all)"
		;;
esac
