#!/usr/bin/env bash
# Starts a Kamailio CSCF.
#
# The role comes from KAM_ROLE and the configuration from /etc/kamailio, which
# deploy/runtime/kamailio/<role> is mounted onto. labctl rewrote the addresses
# in that config, so nothing here has to know the lab topology.
set -euo pipefail

ROLE="${KAM_ROLE:?KAM_ROLE must be pcscf, icscf or scscf}"

if [ ! -f /etc/kamailio/kamailio.cfg ]; then
	echo "entrypoint-kamailio: /etc/kamailio/kamailio.cfg is missing; run 'labctl render' first" >&2
	exit 1
fi

# The ctl module binds a binrpc socket under /run/kamailio.
mkdir -p /run/kamailio /var/log/kamailio

# Wait for the database: every CSCF opens it at start up and exits if it cannot.
DB_HOST="${KAM_DB_HOST:-}"
if [ -n "${DB_HOST}" ]; then
	for _ in $(seq 1 60); do
		if mysqladmin --protocol=tcp -h "${DB_HOST}" -u root ping >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done
fi

# Kamailio refuses to start when a pid file points at a live process, and a
# killed instance leaves one behind.
rm -f /run/kamailio/*.pid

echo "entrypoint-kamailio: starting ${ROLE}"
exec kamailio -DD -E -f /etc/kamailio/kamailio.cfg -P /run/kamailio/kamailio.pid
