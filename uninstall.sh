#!/usr/bin/env bash
# Poistaa Sihdin. Asetukset ja loki jäävät, ellei anneta --purge.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Aja root-oikeuksin." >&2; exit 1; }
systemctl disable --now sihti 2>/dev/null || true
rm -f /etc/systemd/system/sihti.service
systemctl daemon-reload
rm -rf /opt/sihti
rm -f /etc/systemd/resolved.conf.d/sihti.conf
if [[ -f /usr/local/share/ca-certificates/sihti-varmentaja.crt ]]; then
  rm -f /usr/local/share/ca-certificates/sihti-varmentaja.crt
  update-ca-certificates --fresh >/dev/null 2>&1 || true
fi
systemctl restart systemd-resolved 2>/dev/null || true
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /etc/sihti /var/lib/sihti
  userdel sihti 2>/dev/null || true
fi
echo "Sihti poistettu. Muista palauttaa reitittimen DNS-asetus ja poistaa varmentaja muilta laitteilta."
