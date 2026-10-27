"""Asetusten lataus ja tallennus (JSON)."""
import json
import os
import threading

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
    "password_hash": "",           # tyhjä = ei salasanaa
    "https": True,                 # käyttöliittymä HTTPS:llä (http-osoitteet ohjataan https:ään)
    "tls_extra_names": [],         # lisänimet/IP:t varmenteeseen, esim. ["sihti.koti", "10.0.0.5"]
    "tls_cert": "",                # oma varmenne (PEM, ketju); tyhjä = luodaan automaattisesti
    "tls_key": "",                 # oman varmenteen avain
    "data_dir": "/var/lib/sihti",
}


# Ympäristömuuttujat (esim. Docker): SIHTI_<AVAIN>, esim. SIHTI_WEB_PORT=4000,
# SIHTI_UPSTREAMS="1.1.1.1,9.9.9.9", SIHTI_TLS_EXTRA_NAMES="sihti.koti,192.168.1.10".
# Ympäristömuuttuja voittaa asetustiedoston arvon jokaisella käynnistyksellä.
ENV_PREFIX = "SIHTI_"
_ENV_SKIP = {"lists", "password_hash"}  # nämä hallitaan käyttöliittymästä


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


class Config:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._file = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._file = json.load(f)
        self.env = env_overrides()
        self.data = {**DEFAULTS, **self._file, **self.env}

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def update(self, **changes):
        with self._lock:
            self.data.update(changes)
            self._file.update(changes)
            self.save()

    def save(self):
        # Tiedostoon tallennetaan vain tiedoston omat arvot, ei ympäristömuuttujista tulleita
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({**DEFAULTS, **self._file}, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)
