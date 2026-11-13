#!/usr/bin/env bash
# Sihti – päivitys uusimpaan konttiin (Docker Compose).
#
# Käyttö: pidä tämä tiedosto samassa hakemistossa kuin docker-compose.yml ja aja
#   ./update.sh            (tai sudo ./update.sh, jos käyttäjä ei ole docker-ryhmässä)
#
# Hakee uusimman kontin. Jos uutta versiota ei ole, mitään ei käynnistetä uudelleen
# (salasana ei vaihdu). Muuten kontti luodaan uudelleen, odotetaan terveystarkistusta,
# tulostetaan versio ja uusi salasana ja poistetaan vanha kontti levyltä.
set -euo pipefail

SERVICE=sihti
HEALTH_WAIT=90   # s; Docker 25+ tarkistaa käynnistyksen aikana 5 s välein (--start-interval)

cd "$(dirname "$0")"
if [[ ! -f docker-compose.yml && ! -f compose.yml && ! -f compose.yaml && ! -f docker-compose.yaml ]]; then
  echo "Tämän hakemiston ($PWD) vieressä ei ole compose-tiedostoa." >&2
  echo "Siirrä update.sh samaan hakemistoon kuin docker-compose.yml." >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "Docker Compose puuttuu." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Dockeriin ei saada yhteyttä. Aja: sudo $0" >&2
  exit 1
fi

container() { "${DC[@]}" ps -q "$SERVICE" 2>/dev/null | head -n1; }
image_of() { [[ -n "$1" ]] && docker inspect -f '{{.Image}}' "$1" 2>/dev/null || true; }

old_cid=$(container)
old_image=$(image_of "$old_cid")

echo "» Haetaan uusin versio"
"${DC[@]}" pull "$SERVICE"

echo "» Käynnistetään"
"${DC[@]}" up -d "$SERVICE"   # luo kontin uudelleen vain, jos kontti tai asetukset muuttuivat

cid=$(container)
if [[ -z "$cid" ]]; then
  echo "Kontti ei käynnistynyt. Katso: ${DC[*]} logs $SERVICE" >&2
  exit 1
fi
new_image=$(image_of "$cid")

if [[ "$cid" == "$old_cid" ]]; then
  echo "Sihti on jo ajan tasalla, eikä sitä käynnistetty uudelleen."
  exit 0
fi

echo "» Odotetaan, että Sihti vastaa (enintään $HEALTH_WAIT s)"
status=""
for (( i = 0; i < HEALTH_WAIT; i += 3 )); do
  status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo puuttuu)
  [[ "$status" == healthy || "$status" == unhealthy || "$status" == none ]] && break
  sleep 3
done

version=$(docker exec "$cid" python3 -c 'import sihti; print(sihti.__version__)' 2>/dev/null || echo "?")
password=$(docker logs "$cid" 2>/dev/null | grep "random password" | tail -n1 | awk '{print $NF}')

if [[ -n "$old_image" && "$old_image" != "$new_image" ]]; then
  # Vain edellinen Sihti-kontti poistetaan; muihin kontteihin ja kuviin ei kosketa
  docker image rm "$old_image" >/dev/null 2>&1 && echo "» Vanha versio poistettu levyltä" || true
fi

echo
echo "Sihti $version päivitetty."
echo "Tila:     $status"
echo "Salasana: ${password:-(ei vielä lokissa – katso: docker logs $cid | grep 'random password' | tail -n1)}"
case "$status" in
  healthy) ;;
  unhealthy) echo "VAROITUS: terveystarkistus epäonnistui. Katso: ${DC[*]} logs $SERVICE" >&2; exit 1 ;;
  *) echo "Terveystarkistus ei vielä valmistunut (vanha Docker tarkistaa ensimmäisen kerran 5 min kohdalla)." \
          "Tarkista myöhemmin: ${DC[*]} ps" ;;
esac
