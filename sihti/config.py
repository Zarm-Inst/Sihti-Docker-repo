"""Asetusten lataus ja tallennus (JSON)."""
import copy
import json
import os
import threading

from .fileutil import atomic_write_json

DEFAULTS = {
    "dns_listen": "0.0.0.0",
    "dns_port": 53,
    "web_listen": "0.0.0.0",
    "web_port": 4000,
    "upstreams": ["1.1.1.1", "9.9.9.9"],
    "upstream_timeout": 2.0,
    "block_mode": "null",          # "null" = 0.0.0.0 / ::, "nxdomain" = ei olemassa
    "blocking_enabled": True,
    "cache_size": 10000,
    "log_retention_days": 7,
    "log_queries": True,
    "lists": [
        {"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "enabled": True},
    ],
    "update_interval_hours": 24,
    "skip_redundant_lists": True,  # ohita listat, joiden kaikki nimet ovat muilla listoilla (tarkistus viikoittain)
    "local_clients_only": True,    # vastaa vain lähiverkon laitteille (ei avointa DNS-palvelinta internetiin)
    "allowed_networks": [],        # lisäksi sallitut verkot, esim. ["203.0.113.0/24", "2001:db8::/48"]
    "block_dns_bypass": True,      # Firefoxin oma DNS ja iCloud Private Relay pois (niiden testinimet -> NXDOMAIN)
    "block_cname": True,           # estä myös nimet, jotka osoittavat (CNAME) estettyyn nimeen
    "local_dns": "",               # reititin paikallisille nimille, esim. "192.168.1.1" (tyhjä = ei käytössä)
    "local_domains": ["lan", "home", "home.arpa", "internal", "localdomain"],
    "dns_listen_ipv6": True,       # kuuntele myös IPv6:ta, kun dns_listen on 0.0.0.0 (jos verkko tukee)
    "https": True,                # käyttöliittymä HTTPS:llä (http-osoitteet ohjataan https:ään)
    "tls_extra_names": [],         # lisänimet/IP:t varmenteeseen, esim. ["sihti.koti", "10.0.0.5"]
    "tls_cert": "",                # oma varmenne (PEM, ketju); tyhjä = luodaan automaattisesti
    "tls_key": "",                 # oman varmenteen avain
    "tls_learn_names": True,       # lisää käyttöliittymän avaamiseen käytetty lähiverkko-osoite varmenteeseen
    "tls_ca_cert": "",             # yhteinen varmentaja usealle laitteelle (tyhjä = oma varmentaja)
    "tls_ca_key": "",
    "data_dir": "/var/lib/sihti",
}


# Ympäristömuuttujat (esim. Docker): SIHTI_<AVAIN>, esim. SIHTI_WEB_PORT=4000,
# SIHTI_UPSTREAMS="1.1.1.1,9.9.9.9", SIHTI_TLS_EXTRA_NAMES="sihti.koti,192.168.1.10".
# Ympäristömuuttuja voittaa asetustiedoston arvon jokaisella käynnistyksellä.
ENV_PREFIX = "SIHTI_"
_ENV_SKIP = {"lists"}  # hallitaan käyttöliittymästä
# Poistuneet avaimet: salasana on aina satunnainen ja vain muistissa, joten vanhan asennuksen
# tiedostossa olevat arvot jätetään huomiotta (ja poistuvat tiedostosta seuraavalla tallennuksella).
_OBSOLETE = ("password_hash", "random_password")


def _parse_env(key, raw):
    default = DEFAULTS[key]
    if isinstance(default, bool):
        if raw.strip().lower() in ("1", "true", "yes", "on", "kyllä"):
            return True
        if raw.strip().lower() in ("0", "false", "no", "off", "ei"):
            return False
        raise ValueError(f"{ENV_PREFIX}{key.upper()}: odotettiin true/false")
    if isinstance(default, int):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    if isinstance(default, list):
        return [x.strip() for x in raw.replace(";", ",").split(",") if x.strip()]
    return raw.strip()


def env_overrides(environ=None):
    environ = os.environ if environ is None else environ
    out = {}
    for key in DEFAULTS:
        if key in _ENV_SKIP:
            continue
        raw = environ.get(ENV_PREFIX + key.upper())
        if raw is not None and raw != "":
            out[key] = _parse_env(key, raw)
    return out


def deviations(values):
    """Vain oletuksista poikkeavat arvot. Tiedostoon ei tallenneta oletusarvoja, jotta uuden version
    muuttamat oletukset tulevat voimaan myös vanhoissa asennuksissa. Tuntemattomat avaimet säilyvät."""
    return {k: v for k, v in values.items() if k not in DEFAULTS or v != DEFAULTS[k]}


class Config:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._file = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._file = json.load(f)
        for key in _OBSOLETE:
            self._file.pop(key, None)
        # Vanhat versiot tallensivat kaikki oletusarvot: oletuksen kanssa yhtä suuret arvot eivät ole
        # ylläpitäjän valintoja, joten ne jätetään huomiotta (ja poistuvat seuraavalla tallennuksella)
        self._file = deviations(self._file)
        self.env = env_overrides()
        # Oletuksista kopio: muuten listan tai sanakirjan muokkaus paikallaan (esim. oletuslistan
        # päälle/pois-valinta) muuttaisi myös DEFAULTS-arvoa, eikä muutosta tunnistettaisi poikkeamaksi
        self.data = {**copy.deepcopy(DEFAULTS), **self._file, **self.env}

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def update(self, **changes):
        with self._lock:
            self.data.update(changes)
            self._file = deviations({**self._file, **changes})   # takaisin oletukseen = pois tiedostosta
            self.save()

    def save(self):
        # Tiedostoon tallennetaan vain oletuksista poikkeavat omat arvot, ei ympäristömuuttujista tulleita
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        atomic_write_json(self.path, deviations(self._file), indent=2, ensure_ascii=False)
