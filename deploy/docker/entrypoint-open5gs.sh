#!/usr/bin/env bash
# Starts one Open5GS network function.
#
# Open5GS picks its configuration up from /etc/open5gs/default/<component>.yaml,
# which deploy/runtime/open5gs/<component>.yaml is mounted onto. labctl already
# rewrote the addresses, so nothing here needs the lab topology.
set -euo pipefail

component="${1:-}"
if [ -z "${component}" ]; then
	echo "entrypoint-open5gs: usage: <mmed|sgwcd|sgwud|smfd|upfd|hssd|pcrfd>" >&2
	exit 2
fi

binary="open5gs-${component}"
if ! command -v "${binary}" >/dev/null 2>&1; then
	echo "entrypoint-open5gs: ${binary} is not installed in this image" >&2
	exit 2
fi

name="${OPEN5GS_COMPONENT:-${component}}"
config="/etc/open5gs/default/${name}.yaml"
if [ ! -f "${config}" ]; then
	echo "entrypoint-open5gs: ${config} is missing; run 'labctl render' first" >&2
	exit 1
fi

mkdir -p /var/log/open5gs

# The UPF opens a TUN device for the UE pool, which needs NET_ADMIN and
# /dev/net/tun. It creates the interface itself, so only the directory has to
# exist.
if [ "${component}" = "upfd" ]; then
	mkdir -p /dev/net
fi

echo "entrypoint-open5gs: starting ${binary} with ${config}"
exec "${binary}" -c "${config}"
