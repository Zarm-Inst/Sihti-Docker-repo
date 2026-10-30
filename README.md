<p><img src="docs/logo-full.svg" alt="Sihti – Zarm Instruments" width="300"></p>

Kevyt DNS-suodatin kotiverkkoon ja pientoimistoon. Sihti toimii verkon DNS-palvelimena ja jättää mainos- ja seurantapalvelimien nimet vastaamatta, jolloin ne eivät lataudu millekään verkon laitteelle – ilman laitekohtaisia asennuksia.

Kirjoitettu pelkällä Pythonin standardikirjastolla: ei riippuvuuksia, ei tietokantapalvelinta. Toimii Raspberry Pi Zero 2 W:stä ylöspäin.

## Ominaisuudet

- DNS-palvelin UDP:llä ja TCP:llä (IPv4 ja IPv6), välitys valitsemillesi ylävirtapalvelimille
- Estolistat hosts-muodossa, pelkkinä nimilistoina tai `||nimi^` -muodossa; automaattinen päivitys
- Omat sallitut ja estetyt verkkotunnukset (koskevat myös aliverkkotunnuksia) sekä säännölliset lausekkeet
- Välimuisti, joka noudattaa vastausten TTL-arvoja
- Kyselyloki SQLiteen, haku ja suodatus, estä/salli yhdellä napilla; jokaisen eston syy näkyy lokissa (mikä estolista, oma sääntö tai lauseke)
- Yleiskuva: tilastoruudut läpäisseistä ja estetyistä kyselyistä (määrä, osuus ja eri verkkotunnukset), estolistojen nimien kokonaismäärä, vuorokauden kaavio, estetyimmät nimet ja aktiivisimmat laitteet
- Suodatuksen tauotus (5 min / 30 min / 1 h) ja kytkin
- Salasanasuojattu web-käyttöliittymä suomeksi, vaalea ja tumma teema
- HTTPS omalla, automaattisesti uusiutuvalla varmenteella (http-osoitteet ohjataan https:ään)

## Asennus Dockerilla (suositus)

Valmis kontti on GitHubin konttirekisterissä Raspberry Pi:lle (64- ja 32-bittinen ARM) sekä tavallisille PC:ille.

**Docker Compose:** repossa on valmis [`docker-compose.yml`](docker-compose.yml). Sama tiedosto sopii jokaiselle Raspberry Pi:lle sellaisenaan, eikä siihen tarvitse kirjoittaa koneen osoitetta. Sen voi ajaa sellaisenaan tai kopioida `sihti:`-palvelun omaan compose-tiedostoon:

```yaml
services:
  sihti:
    image: ghcr.io/zarm-inst/sihti-docker-repo:latest
    container_name: sihti
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "4000:4000/tcp"
    volumes:
      - sihti-data:/data
      - /etc/hostname:/etc/host-hostname:ro
    environment:
      TZ: Europe/Helsinki
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  sihti-data:
```

```bash
docker compose up -d                                      # käynnistys
docker compose pull sihti && docker compose up -d sihti   # päivitys uuteen versioon
docker compose logs -f sihti                              # loki
```

**Salasana:** kontti luo jokaisella käynnistyksellä uuden satunnaisen 10 merkin salasanan (A–Z, a–z, 0–9) ja tulostaa sen kontin lokiin (stdout):

```
Sihti random password: Xq7rTb2mKa
```

Uusin salasana skriptissä:

```bash
webpass=$(docker logs "$CONTAINER" 2>/dev/null | grep "random password" | tail -n1 | awk '{print $NF}')
```

Käytä `tail -n1` eikä `grep -m1`: Docker säilyttää kontin lokin `docker restart`in ja Pi:n uudelleenkäynnistyksen yli, joten lokissa on silloin useita salasanarivejä ja vain viimeinen on voimassa. (`grep -m1` toimii vain, jos kontti luodaan aina uudelleen, esim. `docker compose up -d --force-recreate`.) Toiminnon saa pois asetuksella `SIHTI_RANDOM_PASSWORD: "false"`, jolloin salasana asetetaan käyttöliittymästä.

**Miten HTTPS-varmenne saa koneen nimen ja osoitteen ilman asetuksia:**

- *Nimi:* `/etc/hostname`-liitos kertoo kontille koneen nimen, joten varmenne kattaa heti esim. `pi-olohuone.local`. Myös muut paikalliset nimet (`.local`, `.lan`, `.home`, `.internal`, `.koti` tai pisteetön nimi) lisätään automaattisesti jo ensimmäisellä yhteydellä.
- *IP-osoite:* kontti ei näe koneen lähiverkko-osoitetta, joten Sihti oppii sen siitä, millä osoitteella käyttöliittymä avataan. Avaa uusi Pi ensimmäisellä kerralla osoitteella **`http://<pi:n IP>:4000`**: Sihti lisää osoitteen varmenteeseen ennen kuin ohjaa selaimen https:ään, eikä varoitusta tule. (Jos avaat suoraan `https://<IP>`, selain varoittaa yhden kerran; kun ohitat varoituksen, osoite lisätään ja seuraavalla kerralla yhteys on kunnossa.)
- Opitut osoitteet säilyvät uudelleenkäynnistyksissä. Vain lähiverkon osoitteet ja paikalliset nimet hyväksytään (enintään 32), joten julkisia nimiä ei voi lisätä varmenteeseen. Toiminnon voi poistaa asetuksella `SIHTI_TLS_LEARN_NAMES: "false"` ja antaa nimet itse: `SIHTI_TLS_EXTRA_NAMES: "192.168.1.10,sihti.koti"`.

### Useampi Raspberry Pi: yksi yhteinen varmentaja

Oletuksena jokainen Pi luo oman varmentajansa, jolloin jokaisen Pi:n varmentaja pitäisi asentaa erikseen jokaiselle puhelimelle ja koneelle. Kun Pi:tä on useampi, tee kerran yhteinen varmentaja ja jaa se kaikille. Laitteille asennetaan silloin vain yksi varmentaja, ja se kelpaa kaikkiin Sihteihin.

1. Luo varmentaja kerran (millä tahansa koneella, jossa on Docker):
   ```bash
   docker run --rm --user 0 -v "$PWD/sihti-ca:/out" ghcr.io/zarm-inst/sihti-docker-repo:latest python3 -m sihti --make-ca /out
   ```
   Komento tulostaa sormenjäljen. Hakemistoon syntyvät `ca.crt` ja `ca.key`, jotka kuuluvat valmiiksi kontin käyttäjälle (uid 10053).
2. Kopioi `sihti-ca`-hakemisto jokaiselle Pi:lle compose-tiedoston viereen, esim. `scp -rp sihti-ca pi@pi-olohuone.local:~/sihti/`. Säilytä oikeudet (`-p`); tarvittaessa Pi:llä `sudo chown -R 10053:10053 sihti-ca`.
3. Ota compose-tiedostossa käyttöön kommentoidut rivit `./sihti-ca:/ca:ro`, `SIHTI_TLS_CA_CERT` ja `SIHTI_TLS_CA_KEY`, ja käynnistä `docker compose up -d`.
4. Asenna `sihti-ca/ca.crt` kerran puhelimille ja koneille (ohjeet käyttöliittymässä: *Asetukset → Suojattu yhteys*).

`ca.key`:llä voi allekirjoittaa varmenteita, joihin laitteesi luottavat, joten säilytä se vain Pi:illä ja turvallisessa varmuuskopiossa.

- Portit 53 (udp ja tcp) ja 4000 eivät saa olla koneella muun ohjelman käytössä (esim. systemd-resolved tai dnsmasq). Jos käyttöliittymän portti on varattu, vaihda vain vasen numero, esim. `"4100:4000/tcp"`.
- Kaikki tiedot (asetukset, listat, loki, varmenteet) ovat volyymissa `sihti-data`. Kontin voi päivittää menettämättä mitään.
- Kontti ajetaan tavallisena käyttäjänä (uid 10053), ei rootina. Älä lisää asetusta `security_opt: no-new-privileges`, koska se estää pääsyn porttiin 53.
- Varmentajan saa ulos kontista komennolla `docker cp sihti:/data/tls/ca.crt sihti-varmentaja.crt` tai käyttöliittymästä.
- Kontilla on terveystarkistus: `docker compose ps` näyttää tilan `healthy`.

Asetuksia voi antaa ympäristömuuttujina `SIHTI_<AVAIN>` (esim. `SIHTI_UPSTREAMS: "1.1.1.1,9.9.9.9"`, `SIHTI_LOG_RETENTION_DAYS: "14"`). Ympäristömuuttuja voittaa käyttöliittymässä tehdyn muutoksen kontin seuraavalla käynnistyksellä. Estolistat ja salasana hallitaan käyttöliittymästä.

**Oma rakennus:** `docker build -t sihti .` GitHub Actions rakentaa ja julkaisee kontin automaattisesti jokaisesta `main`-haaran muutoksesta (`:latest`) ja versiotagista `v1.2.3` (`:1.2.3`). Testit ajetaan ennen rakennusta.

## Asennus Raspberry Pi:lle ilman Dockeria

```bash
# kopioi repo Pi:lle, esim. git clone tai, esim. scp -r sihti pi@raspberrypi.local:
cd sihti
sudo ./install.sh
```

Asennus luo `sihti`-järjestelmäkäyttäjän, kopioi ohjelman hakemistoon `/opt/sihti`, asetukset tiedostoon `/etc/sihti/sihti.json` ja tiedot hakemistoon `/var/lib/sihti`, ja käynnistää systemd-palvelun. Palvelu ei aja root-oikeuksin; DNS-porttiin 53 se pääsee `CAP_NET_BIND_SERVICE`-oikeudella.

Asennuksen jälkeen:

1. Avaa `https://<pi:n osoite>:4000/` ja aseta salasana Asetukset-välilehdeltä. Selain varoittaa ensimmäisellä kerralla, kunnes asennat varmentajan (ks. alla).
2. Anna Pi:lle kiinteä IP-osoite (helpoimmin reitittimen DHCP-varauksella).
3. Aseta reitittimen DHCP-asetuksissa DNS-palvelimeksi Pi:n osoite. Laitteet ottavat uuden asetuksen käyttöön, kun ne uusivat osoitteensa (tai yhdistävät verkkoon uudelleen).

Testaa toiselta koneelta: `nslookup doubleclick.net <pi:n osoite>` – vastauksen pitäisi olla `0.0.0.0`.

## HTTPS ja varmenteet

Käyttöliittymä toimii HTTPS:llä samassa portissa 4000. Jos osoitteeseen mennään `http://`-alkuisena, Sihti ohjaa automaattisesti suojattuun osoitteeseen.

Sihti luo varmenteet itse:

- **Paikallinen varmentaja** (voimassa 10 vuotta) luodaan ensimmäisellä käynnistyksellä. `install.sh` asentaa sen valmiiksi Pi:n omiin luotettuihin varmenteisiin.
- **Palvelinvarmenne** (voimassa vuoden) on varmentajan allekirjoittama. Sihti uusii sen automaattisesti 30 päivää ennen vanhenemista, aina kun Pi:n nimi tai IP-osoite muuttuu sekä jos tiedosto vioittuu. Uusi varmenne otetaan käyttöön ilman uudelleenkäynnistystä.

Varmenne kattaa nimet `localhost`, `<nimi>`, `<nimi>.local`, `<nimi>.lan`, `<nimi>.home` sekä Pi:n IP-osoitteet. Lisäksi varmenteeseen lisätään automaattisesti lähiverkko-osoite tai paikallinen nimi, jolla käyttöliittymä avataan. Muita nimiä voi lisätä asetuksella `tls_extra_names`.

**Muut laitteet:** asenna varmentaja kerran jokaiselle laitteelle, jolla käytät käyttöliittymää: *Asetukset → Suojattu yhteys → Lataa varmentaja*. Samassa kohdassa on ohjeet Windowsille, macOS:lle, iPhonelle, Androidille, Linuxille ja Firefoxille. Tarkista, että varmentajan sormenjälki vastaa sivulla (ja `install.sh`:n lopussa) näkyvää. Ilman asennusta sivu toimii, mutta selain varoittaa.

Varmentajan yksityinen avain on vain Pi:llä (`/var/lib/sihti/tls/ca.key`, oikeudet 600). Sitä ei voi ladata käyttöliittymästä.

**Oma varmenne:** jos haluat käyttää esim. omaa verkkotunnustasi varten hankittua varmennetta, aseta `tls_cert` (PEM-ketju) ja `tls_key`. Sihti lataa tiedoston uudelleen automaattisesti, kun se vaihtuu.

## Asetukset

`/etc/sihti/sihti.json` – useimmat voi muuttaa myös käyttöliittymästä. Käynnistä palvelu uudelleen (`sudo systemctl restart sihti`), jos muutat kuunteluosoitteita tai portteja.

| Avain | Oletus | Merkitys |
|---|---|---|
| `dns_listen`, `dns_port` | `0.0.0.0`, `53` | DNS-kuuntelija (IPv6: `"::"`) |
| `web_listen`, `web_port` | `0.0.0.0`, `4000` | Käyttöliittymä (vaihda, jos portti on varattu) |
| `upstreams` | Cloudflare, Quad9 | Ylävirran palvelimet, kokeillaan järjestyksessä |
| `block_mode` | `null` | `null` = 0.0.0.0 / ::, `nxdomain` = nimeä ei ole |
| `cache_size` | `10000` | Välimuistin nimien määrä (0 = pois) |
| `log_retention_days` | `7` | Kyselylokin säilytysaika |
| `log_queries` | `true` | Kyselylokin tallennus (pois = parempi yksityisyys) |
| `lists` | yksi lista | Estolistojen osoitteet |
| `update_interval_hours` | `24` | Listojen päivitysväli |
| `https` | `true` | HTTPS käyttöliittymään (`false` = pelkkä HTTP) |
| `random_password` | `false` (Dockerissa `true`) | Uusi satunnainen salasana jokaisella käynnistyksellä, tulostuu lokiin |
| `tls_extra_names` | `[]` | Lisänimet ja -osoitteet varmenteeseen |
| `tls_learn_names` | `true` | Lisää käyttöliittymän avaamiseen käytetty lähiverkko-osoite tai paikallinen nimi varmenteeseen |
| `tls_ca_cert`, `tls_ca_key` | tyhjä | Yhteinen varmentaja usealle laitteelle; tyhjä = laite luo oman |
| `tls_cert`, `tls_key` | tyhjä | Oma varmenne; tyhjä = luodaan automaattisesti |

## Komentorivi

```bash
cd /opt/sihti
sudo -u sihti python3 -m sihti --config /etc/sihti/sihti.json --set-password   # salasana
sudo -u sihti python3 -m sihti --config /etc/sihti/sihti.json --update-lists   # päivitä listat
sudo -u sihti python3 -m sihti --config /etc/sihti/sihti.json --renew-cert     # uusi varmenne heti
journalctl -u sihti -f                                                          # loki
```

## Kehitys omalla koneella

```bash
cat > dev.json <<'EOF'
{"dns_listen":"127.0.0.1","dns_port":5353,"web_listen":"127.0.0.1","web_port":4000,"data_dir":"./data"}
EOF
python3 -m sihti --config dev.json -v
dig @127.0.0.1 -p 5353 doubleclick.net

python3 -m unittest discover -s tests -v   # testit
```

## Huomioita

- Estolistojen nimet estetään täsmällisinä (lista sisältää yleensä jokaisen aliverkkotunnuksen erikseen). Omat estot ja sallinnat koskevat myös aliverkkotunnuksia.
- Sallittu-lista voittaa aina eston.
- Suuretkin estolistat toimivat Pi:llä: viisi miljoonaa nimeä vie noin 120 Mt muistia, koska nimistä tallennetaan vain 8 tavun tiiviste. Listat jäsennetään erillisessä prosessissa taustalla, joten DNS vastaa heti käynnistyksessä ja listojen päivityksen aikana (vanha lista on käytössä, kunnes uusi on valmis). Mittaus 5 miljoonalla nimellä: hitain DNS-vastaus latauksen aikana 22 ms.
- Jos portti 53 on varattu, `install.sh` poistaa systemd-resolvedin kuuntelijan käytöstä. Muut DNS-palvelut (esim. dnsmasq) pitää pysäyttää itse.
- Komentorivitoiminnot ajetaan `sihti`-käyttäjänä (`sudo -u sihti …`), jotta tiedostojen omistajuus säilyy.
- Poisto: `sudo ./uninstall.sh` (asetukset ja loki jäävät) tai `sudo ./uninstall.sh --purge`.

## Rakenne

```
sihti/
  __main__.py    käynnistys ja komentorivi
  dnswire.py     DNS-viestien jäsennys ja rakentaminen
  resolver.py    DNS-palvelin, välitys, välimuisti
  filtering.py   estolistat ja omat säännöt
  querylog.py    kyselyloki ja tilastot (SQLite)
  web.py         käyttöliittymän palvelin (HTTPS + ohjaus) ja JSON-rajapinta
  tls.py         varmentaja ja palvelinvarmenteen automaattinen uusiminen
  config.py      asetukset (tiedosto + SIHTI_*-ympäristömuuttujat)
  healthcheck.py kontin terveystarkistus
  static/        käyttöliittymä (HTML, CSS, JS, logo)
tests/           testit (python -m unittest)
docs/            logot
Dockerfile, docker-compose.yml, .github/workflows/docker.yml
install.sh, uninstall.sh, sihti.service   asennus ilman Dockeria
```

## Logo

Merkki kuvaa DNS-suodatusta: **Z** ohjaa kyselyt suodattimelle, **I** on portti, jossa on yksi aukko. Sallittu kysely (vihreä) pääsee läpi, estetyt (punaiset) pysähtyvät porttiin. Kirjaimet ZI viittaavat Zarm Instrumentsiin. Tiedostot: `docs/logo.svg` (merkki), `docs/logo-full.svg` (merkki ja nimi), `docs/logo-512.png`.
