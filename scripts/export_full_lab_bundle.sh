#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date +%Y%m%d_%H%M%S)"
ROOT="/root/epdg_work"
OUTDIR="${ROOT}/backups/full_lab_${STAMP}"
ARCHIVE="${OUTDIR}.tar.gz"

mkdir -p "${OUTDIR}"/{workspace,etc,usr_local,systemd,data}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [ -e "${src}" ]; then
    mkdir -p "$(dirname "${dst}")"
    cp -a "${src}" "${dst}"
  fi
}

# workspace
copy_if_exists "${ROOT}/epdg-go" "${OUTDIR}/workspace/epdg-go"
copy_if_exists "${ROOT}/SWu-IKEv2" "${OUTDIR}/workspace/SWu-IKEv2"
copy_if_exists "${ROOT}/pyhss" "${OUTDIR}/workspace/pyhss"
copy_if_exists "${ROOT}/kamailio" "${OUTDIR}/workspace/kamailio"
copy_if_exists "${ROOT}/docs" "${OUTDIR}/workspace/docs"

# runtime configs
copy_if_exists "/etc/open5gs" "${OUTDIR}/etc/open5gs"
copy_if_exists "/etc/pyhss" "${OUTDIR}/etc/pyhss"
copy_if_exists "/etc/freeDiameter" "${OUTDIR}/etc/freeDiameter"
copy_if_exists "/etc/epdg-go" "${OUTDIR}/etc/epdg-go"
copy_if_exists "/etc/swanctl" "${OUTDIR}/etc/swanctl"
copy_if_exists "/etc/kamailio_pcscf" "${OUTDIR}/etc/kamailio_pcscf"
copy_if_exists "/etc/kamailio_icscf" "${OUTDIR}/etc/kamailio_icscf"
copy_if_exists "/etc/kamailio_scscf" "${OUTDIR}/etc/kamailio_scscf"

# /usr/local custom installs
copy_if_exists "/usr/local/sbin/kamailio" "${OUTDIR}/usr_local/sbin/kamailio"
copy_if_exists "/usr/local/sbin/open5gs_ims_net.sh" "${OUTDIR}/usr_local/sbin/open5gs_ims_net.sh"
copy_if_exists "/usr/local/lib64/kamailio" "${OUTDIR}/usr_local/lib64/kamailio"
copy_if_exists "/usr/local/lib/kamailio" "${OUTDIR}/usr_local/lib/kamailio"
copy_if_exists "/usr/local/etc/kamailio" "${OUTDIR}/usr_local/etc/kamailio"
copy_if_exists "/usr/local/share/kamailio" "${OUTDIR}/usr_local/share/kamailio"

# data snapshots
copy_if_exists "${ROOT}/pyhss/hss.db" "${OUTDIR}/data/hss.db"
copy_if_exists "${ROOT}/backups/icscf_$(date +%Y%m%d).sql.gz" "${OUTDIR}/data/icscf.sql.gz"
copy_if_exists "${ROOT}/backups/pcscf_$(date +%Y%m%d).sql.gz" "${OUTDIR}/data/pcscf.sql.gz"
copy_if_exists "${ROOT}/backups/scscf_$(date +%Y%m%d).sql.gz" "${OUTDIR}/data/scscf.sql.gz"

# systemd units
for unit in /etc/systemd/system/pyhss_*.service \
            /etc/systemd/system/open5gs-ims-net.service \
            /etc/systemd/system/swm-aaad.service \
            /etc/systemd/system/aaa-freediameter.service \
            /etc/systemd/system/epdgd.service; do
  [ -e "${unit}" ] && copy_if_exists "${unit}" "${OUTDIR}/systemd/$(basename "${unit}")"
done

cat > "${OUTDIR}/manifest.txt" <<'EOF'
Full lab bundle contents:
- epdg-go / SWu-IKEv2 / PyHSS / Kamailio source trees
- Open5GS, PyHSS, Kamailio, swanctl, freeDiameter configs
- custom /usr/local Kamailio install tree
- PyHSS sqlite database snapshot
- Kamailio MySQL dumps (icscf/pcscf/scscf)
- relevant systemd units
EOF

tar -C "$(dirname "${OUTDIR}")" -czf "${ARCHIVE}" "$(basename "${OUTDIR}")"
sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"

echo "Full bundle directory: ${OUTDIR}"
echo "Full bundle archive: ${ARCHIVE}"
echo "Full bundle sha256: $(cut -d' ' -f1 "${ARCHIVE}.sha256")"
