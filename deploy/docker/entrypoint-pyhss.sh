#!/usr/bin/env bash
# Runs the PyHSS node.
#
# PyHSS is three cooperating processes on one address, so they share a
# container:
#
#   api       REST API on :8080, used by the ePDG to fetch AKA vectors
#   diameter  the Cx socket relay: raw bytes to/from Redis
#   hss       the Diameter logic: answers CER, UAR, MAR and SAR
#
# `diameter` and `hss` must both run. Starting only `diameter` leaves the CSCF's
# CER unanswered forever, which looks like a protocol bug but is not.
#
# Running a single component is still possible for debugging:
#   docker compose run --rm pyhss api
set -euo pipefail

CONFIG="${PYHSS_CONFIG:-/config/config.yaml}"
DB_DIR="/var/lib/pyhss"
DB="${DB_DIR}/hss.db"

# Seed the database on first start. The image ships the repository's populated
# hss.db, and deploy/runtime/pyhss/seed.sql applies the subscriber from
# deploy/lab.yaml, so changing credentials there is enough.
if [ ! -f "${DB}" ]; then
	echo "entrypoint-pyhss: seeding ${DB}"
	cp /seed/hss.db "${DB}"
	sqlite3 "${DB}" < /seed.sql
fi

if [ ! -f "${CONFIG}" ]; then
	echo "entrypoint-pyhss: ${CONFIG} is missing; run 'labctl render' first" >&2
	exit 1
fi

pids=()

shutdown() {
	trap - TERM INT
	if [ "${#pids[@]}" -gt 0 ]; then
		kill "${pids[@]}" 2>/dev/null || true
		wait 2>/dev/null || true
	fi
	exit 0
}
trap shutdown TERM INT

start() {
	echo "entrypoint-pyhss: starting $1"
	python3 "$1Service.py" &
	pids+=("$!")
}

case "${1:-all}" in
	api)      exec python3 apiService.py ;;
	diameter) exec python3 diameterService.py ;;
	hss)      exec python3 hssService.py ;;
	all)
		start api
		start diameter
		start hss
		;;
	*)
		echo "entrypoint-pyhss: unknown component '$1' (want all, api, diameter or hss)" >&2
		exit 2
		;;
esac

# If any component exits, take the container down so the restart policy applies.
wait -n "${pids[@]}"
status=$?
echo "entrypoint-pyhss: a component exited with status ${status}; stopping the rest"
shutdown
