#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date +%Y%m%d_%H%M%S)"
ROOT="/root/epdg_work"
OUTDIR="${ROOT}/backups/native_migration_${STAMP}"
ARCHIVE="${OUTDIR}.tar.gz"

mkdir -p "${OUTDIR}"/{workspace,etc,systemd}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [ -e "${src}" ]; then
    mkdir -p "$(dirname "${dst}")"
    cp -a "${src}" "${dst}"
  fi
}

# workspace artifacts
copy_if_exists "${ROOT}/epdg-go" "${OUTDIR}/workspace/epdg-go"
copy_if_exists "${ROOT}/SWu-IKEv2" "${OUTDIR}/workspace/SWu-IKEv2"
copy_if_exists "${ROOT}/docs" "${OUTDIR}/workspace/docs"
copy_if_exists "${ROOT}/pyhss/config.yaml" "${OUTDIR}/workspace/pyhss-config.yaml"

# runtime configs
copy_if_exists "/etc/swanctl/conf.d/epdg-ike.conf" "${OUTDIR}/etc/swanctl/conf.d/epdg-ike.conf"
copy_if_exists "/etc/swanctl/private/epdg.key" "${OUTDIR}/etc/swanctl/private/epdg.key"
copy_if_exists "/etc/swanctl/x509/epdg.crt" "${OUTDIR}/etc/swanctl/x509/epdg.crt"
copy_if_exists "/etc/freeDiameter/aaa_swm.conf" "${OUTDIR}/etc/freeDiameter/aaa_swm.conf"
copy_if_exists "/etc/epdg-go/swm-aaad.yaml" "${OUTDIR}/etc/epdg-go/swm-aaad.yaml"
copy_if_exists "/etc/kamailio_pcscf" "${OUTDIR}/etc/kamailio_pcscf"
copy_if_exists "/etc/kamailio_icscf" "${OUTDIR}/etc/kamailio_icscf"
copy_if_exists "/etc/kamailio_scscf" "${OUTDIR}/etc/kamailio_scscf"
copy_if_exists "/etc/open5gs" "${OUTDIR}/etc/open5gs"

# systemd units
copy_if_exists "/etc/systemd/system/swm-aaad.service" "${OUTDIR}/systemd/swm-aaad.service"
copy_if_exists "/etc/systemd/system/aaa-freediameter.service" "${OUTDIR}/systemd/aaa-freediameter.service"

cat > "${OUTDIR}/manifest.txt" <<'EOF'
Target platform:
- Native Ubuntu 22.04 or a full Linux VM

Primary components:
- Open5GS EPC
- Kamailio IMS (P/I/S-CSCF)
- PyHSS
- strongSwan/swanctl
- freeDiameter
- epdg-go
- SWu-IKEv2 test client

Restore order:
1. Install packages
2. Restore workspace under /root/epdg_work
3. Restore /etc configs
4. Restore systemd units
5. daemon-reload + enable/start services
6. Run SWu-IKEv2 netns test
EOF

tar -C "$(dirname "${OUTDIR}")" -czf "${ARCHIVE}" "$(basename "${OUTDIR}")"
sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"

echo "Bundle directory: ${OUTDIR}"
echo "Bundle archive: ${ARCHIVE}"
echo "Bundle sha256: $(cut -d' ' -f1 "${ARCHIVE}.sha256")"
