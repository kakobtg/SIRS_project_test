#!/usr/bin/env bash
# Configure static IP for VM2 (DB). Defaults match README (10.0.1.10/24).
set -euo pipefail

IP_CIDR="${IP_CIDR:-10.0.1.10/24}"
GATEWAY="${GATEWAY:-}"
DNS="${DNS:-}"
CONNECTION="${CONNECTION:-}"

if ! command -v nmcli >/dev/null 2>&1; then
  echo "nmcli not found; install NetworkManager tools." >&2
  exit 1
fi

if [[ -z "${CONNECTION}" ]]; then
  CONNECTION="$(nmcli -t -f NAME,TYPE connection show --active | awk -F: '$2=="ethernet"{print $1; exit}')"
fi

if [[ -z "${CONNECTION}" ]]; then
  echo "No active ethernet connection detected; set CONNECTION explicitly." >&2
  exit 1
fi

echo "[vm2] Using connection: ${CONNECTION}"
echo "[vm2] Setting static IP: ${IP_CIDR}"
nmcli con mod "${CONNECTION}" ipv4.addresses "${IP_CIDR}" ipv4.method manual

if [[ -n "${GATEWAY}" ]]; then
  echo "[vm2] Setting gateway: ${GATEWAY}"
  nmcli con mod "${CONNECTION}" ipv4.gateway "${GATEWAY}"
else
  nmcli con mod "${CONNECTION}" ipv4.gateway ""
fi

if [[ -n "${DNS}" ]]; then
  echo "[vm2] Setting DNS: ${DNS}"
  nmcli con mod "${CONNECTION}" ipv4.dns "${DNS}"
else
  nmcli con mod "${CONNECTION}" ipv4.dns ""
fi

echo "[vm2] Applying connection..."
nmcli con down "${CONNECTION}" || true
nmcli con up "${CONNECTION}"
nmcli -p device show | grep -E "IP4.ADDRESS\[|IP4.GATEWAY|IP4.DNS" -n
