#!/usr/bin/env bash
# Sihti – asennus Raspberry Pi OS:lle (ja muille systemd-pohjaisille Debian-jakeluille).
# Käyttö: sudo ./install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Aja root-oikeuksin: sudo ./install.sh" >&2
  exit 1
fi

SRC="$(cd "$(dirname "$0")" && pwd)"

MISSING=()
command -v python3 >/dev/null || MISSING+=(python3)
command -v openssl >/dev/null || MISSING+=(openssl)
command -v update-ca-certificates >/dev/null || MISSING+=(ca-certificates)
if (( ${#MISSING[@]} )); then
  apt-get update && apt-get install -y "${MISSING[@]}"
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || { echo "Tarvitaan Python 3.9 tai uudempi." >&2; exit 1; }

echo "» Luodaan käyttäjä ja hakemistot"
id sihti >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sihti
install -d -o sihti -g sihti -m 750 /var/lib/sihti /etc/sihti
install -d -m 755 /opt/sihti

echo "» Kopioidaan ohjelma"
rm -rf /opt/sihti/sihti
cp -r "$SRC/sihti" /opt/sihti/
find /opt/sihti -name '__pycache__' -prune -exec rm -rf {} +

if [[ ! -f /etc/sihti/sihti.json ]]; then
  install -o sihti -g sihti -m 640 "$SRC/sihti.example.json" /etc/sihti/sihti.json
  echo "» Asetukset: /etc/sihti/sihti.json"
fi

# systemd-resolved varaa portin 53 joissain jakeluissa
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  echo "» systemd-resolved varaa portin 53 – poistetaan sen kuuntelija käytöstä"
  install -d /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/sihti.conf
  systemctl restart systemd-resolved
fi
if ss -lunp 2>/dev/null | grep -q ':53 ' && ! ss -lunp | grep ':53 ' | grep -q python3; then
  echo "! Portti 53 on jo käytössä (esim. dnsmasq). Pysäytä se ennen käynnistystä:" >&2
  ss -lunp | grep ':53 ' >&2
fi

WEB_PORT="$(python3 -c 'import json;print(json.load(open("/etc/sihti/sihti.json")).get("web_port",4000))')"
if ss -ltnp 2>/dev/null | grep -q ":${WEB_PORT} " && ! ss -ltnp | grep ":${WEB_PORT} " | grep -q python3; then
  echo "! Portti ${WEB_PORT} on jo käytössä. Vaihda web_port tiedostossa /etc/sihti/sihti.json." >&2
fi

echo "» Asennetaan palvelu"
install -m 644 "$SRC/sihti.service" /etc/systemd/system/sihti.service
systemctl daemon-reload
systemctl enable --now sihti

# Paikallinen varmentaja Pi:n omaan luottosäilöön, jolloin Pi itse luottaa käyttöliittymän varmenteeseen
CA_SRC=/var/lib/sihti/tls/ca.crt
CA_DST=/usr/local/share/ca-certificates/sihti-varmentaja.crt
for _ in $(seq 1 30); do [[ -f "$CA_SRC" ]] && break; sleep 1; done
if [[ -f "$CA_SRC" ]]; then
  if ! cmp -s "$CA_SRC" "$CA_DST" 2>/dev/null; then
    install -m 644 "$CA_SRC" "$CA_DST"
    update-ca-certificates >/dev/null
  fi
  echo "» Varmentaja asennettu Pi:n luotettuihin varmenteisiin"
  CA_FP="$(openssl x509 -in "$CA_SRC" -noout -fingerprint -sha256 | cut -d= -f2)"
else
  echo "! Varmennetta ei syntynyt – katso: journalctl -u sihti" >&2
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

Valmis! Sihti on käynnissä.

  Käyttöliittymä:  https://${IP:-<pi:n osoite>}:${WEB_PORT}/
                   (myös http:// toimii – se ohjataan suojattuun osoitteeseen)
  DNS-palvelin:    ${IP:-<pi:n osoite>}  (portti 53)

Seuraavaksi:
  1. Aseta salasana Asetukset-välilehdeltä, tai komentoriviltä:
       cd /opt/sihti && sudo -u sihti python3 -m sihti --config /etc/sihti/sihti.json --set-password
  2. Aseta reitittimen DHCP-asetuksiin DNS-palvelimeksi ${IP:-tämän laitteen osoite}.
  3. Anna Pi:lle kiinteä IP-osoite (reitittimen varaus tai /etc/dhcpcd.conf / NetworkManager).
  4. Asenna varmentaja muille laitteille: Asetukset → Suojattu yhteys → Lataa varmentaja.
     Varmentajan sormenjälki (vertaa laitteella näkyvään): ${CA_FP:-–}

Loki:  journalctl -u sihti -f
EOF
