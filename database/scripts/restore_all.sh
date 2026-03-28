#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DB_DIR="${ROOT_DIR}/database"

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
PYHSS_DB_DST="${PYHSS_DB_DST:-/var/lib/pyhss/hss.db}"
PYHSS_DB_OWNER="${PYHSS_DB_OWNER:-pyhss:pyhss}"

if [[ -f "${DB_DIR}/kamailio/kamailio_ims.sql" ]]; then
  if [[ -n "${MYSQL_PASSWORD}" ]]; then
    mysql -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" < "${DB_DIR}/kamailio/kamailio_ims.sql"
  else
    mysql -u "${MYSQL_USER}" < "${DB_DIR}/kamailio/kamailio_ims.sql"
  fi
fi

if [[ -f "${DB_DIR}/pyhss/hss.db" ]]; then
  sudo cp "${DB_DIR}/pyhss/hss.db" "${PYHSS_DB_DST}"
  sudo chown "${PYHSS_DB_OWNER}" "${PYHSS_DB_DST}"
fi

echo "restore done"
