"""Estolistojen lataus, jäsennys ja verkkotunnusten tarkistus."""
import hashlib
import json
import shutil
from array import array
from bisect import bisect_left
import logging
import os
import re
import threading
import time
import urllib.request

log = logging.getLogger("sihti.suodatin")

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_CHARS_RE = re.compile(r"[a-z0-9._-]+")


def _valid_list_domain(c):
    """Nopea tarkistus listojen riveille (miljoonia rivejä): sama tulos kuin _DOMAIN_RE
    tavallisille nimille, mutta ilman raskasta säännöllistä lauseketta."""
    if len(c) > 253 or not _CHARS_RE.fullmatch(c) or "." not in c or ".." in c:
        return False
    if c[0] in ".-" or c[-1] in ".-" or ".-" in c or "-." in c:
        return False
    tld = c.rsplit(".", 1)[1]
    if len(tld) < 2 or "_" in tld:
        return False
    if len(c) > 63 and any(len(label) > 63 for label in c.split(".")):
        return False
    return True


_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
         "ip6-loopback", "0.0.0.0", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
         "ip6-allrouters", "ip6-allhosts"}


def iter_domains(lines):
    """Käy listan rivit läpi yksi kerrallaan (ei koko tiedostoa muistiin).
    Tukee hosts-muotoa, pelkkiä verkkotunnuksia ja ||domain^ -muotoa."""
    valid = _valid_list_domain
    for raw in lines:
        line = raw.split("#", 1)[0].strip().lower()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if line.startswith("||"):
            line = line[2:].split("^", 1)[0]
            if "/" in line or "*" in line:
                continue
            candidate = line
        else:
            parts = line.split()
            candidate = parts[1] if len(parts) >= 2 else parts[0]
        candidate = candidate.rstrip(".")
        if candidate in _SKIP or not valid(candidate):
            continue
        yield candidate


def parse_list(text):
    return set(iter_domains(text.splitlines()))


class DomainSet:
    """Tiivis joukko estettäviä nimiä: jokaisesta nimestä tallennetaan vain 64-bittinen
    avaimellinen tiiviste (8 tavua) yhteen lajiteltuun taulukkoon, jonka hakemisto jakaa
    sen 65 536 lohkoon. Viisi miljoonaa nimeä vie noin 45 Mt, kun tavallisena Python-
    joukkona ne veisivät lähes gigatavun. Väärän osuman todennäköisyys on käytännössä nolla."""
    SHIFT = 48

    def __init__(self, key=b"", data=None, index=None, count=0):
        self.key = key
        self._data = data
        self._index = index
        self._count = count

    def __contains__(self, name):
        if not self._count:
            return False
        h = fingerprint(name, self.key)
        b = h >> self.SHIFT
        lo, hi = self._index[b], self._index[b + 1]
        i = bisect_left(self._data, h, lo, hi)
        return i < hi and self._data[i] == h

    def __len__(self):
        return self._count

    def __bool__(self):
        return self._count > 0


def fingerprint(name, key):
    return int.from_bytes(hashlib.blake2b(name.encode(), digest_size=8, key=key).digest(), "big")


def build_domain_set(paths, key):
    """Lukee listatiedostot ja rakentaa DomainSetin raakadatan. Ajetaan omassa prosessissaan,
    jotta raskas jäsennys ei hidasta DNS-vastauksia (Pythonin GIL). Palauttaa
    (data_bytes, index_bytes, nimiä_yhteensä, [rivejä_per_tiedosto])."""
    buckets = [array("Q") for _ in range(1 << (64 - DomainSet.SHIFT))]
    shift = DomainSet.SHIFT
    per_file = []
    for path in paths:
        n = 0
        with open(path, encoding="utf-8", errors="replace") as f:
            for name in iter_domains(f):
                h = fingerprint(name, key)
                buckets[h >> shift].append(h)
                n += 1
        per_file.append(n)
    data = array("Q")
    index = array("Q", [0])
    for i, a in enumerate(buckets):
        if a:
            data.extend(sorted(set(a)))   # päällekkäiset pois, lajittelu hakua varten
            buckets[i] = None
        index.append(len(data))
    return data.tobytes(), index.tobytes(), len(data), per_file


def _build_isolated(paths, key):
    """Rakentaa erillisessä prosessissa; jos se ei onnistu, tässä prosessissa."""
    try:
        import multiprocessing
        ctx = multiprocessing.get_context("spawn")
        with ctx.Pool(1) as pool:
            return pool.apply(build_domain_set, (paths, key))
    except Exception as e:  # noqa: BLE001
        log.warning("erillistä prosessia ei voitu käyttää (%s), rakennetaan pääprosessissa", e)
        return build_domain_set(paths, key)


def normalize_domain(raw):
    """Siistii käyttäjän syötteen verkkotunnukseksi. Palauttaa None, jos tulos ei kelpaa.
    Hyväksyy esim. 'Example.com.', '*.example.com', '.example.com', '||example.com^',
    'https://www.example.com:8443/polku?x=1' ja 'käyttäjä@example.com'."""
    s = raw.strip().strip("\"'").lower()
    if s.startswith("||"):
        s = s[2:]
    s = s.split("^", 1)[0]
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.count(":") == 1:  # portti pois (IPv6-osoitteet eivät ole verkkotunnuksia)
        s = s.split(":", 1)[0]
    while s.startswith(("*.", ".")):
        s = s[2:] if s.startswith("*.") else s[1:]
    s = s.rstrip(".")
    try:
        s = s.encode("idna").decode("ascii")  # ääkköstunnukset, esim. äö.fi -> xn--...
    except UnicodeError:
        return None
    return s if _DOMAIN_RE.match(s) else None


def _parents(name):
    """example.sub.domain.com -> itse ja kaikki yläverkkotunnukset."""
    parts = name.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


class Filter:
    def __init__(self, config):
        self.config = config
        self.data_dir = config["data_dir"]
        self.lists_dir = os.path.join(self.data_dir, "lists")
        self.custom_path = os.path.join(self.data_dir, "custom.json")
        os.makedirs(self.lists_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._rebuild_lock = threading.Lock()
        self.rebuilding = False
        self.blocked = DomainSet()
        self.allow = set()        # sallitaan + kaikki aliverkkotunnukset
        self.deny = set()         # estetään + kaikki aliverkkotunnukset
        self.deny_regex = []      # [(pattern_str, compiled)]
        self.list_status = {}     # url -> {"count", "updated", "error"}
        self.last_update = None
        self.pause_until = None
        self._load_custom()
        # Listat ladataan taustalla (updater_loop), jotta DNS vastaa heti käynnistyksessä

    # ---------- omat listat ----------
    def _load_custom(self):
        if os.path.exists(self.custom_path):
            with open(self.custom_path, encoding="utf-8") as f:
                d = json.load(f)
            self.allow = set(d.get("allow", []))
            self.deny = set(d.get("deny", []))
            self.deny_regex = []
            for p in d.get("deny_regex", []):
                try:
                    self.deny_regex.append((p, re.compile(p)))
                except re.error:
                    log.warning("virheellinen säännöllinen lauseke ohitettiin: %s", p)

    def _save_custom(self):
        d = {"allow": sorted(self.allow), "deny": sorted(self.deny),
             "deny_regex": [p for p, _ in self.deny_regex]}
        tmp = self.custom_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, self.custom_path)

    def add_custom(self, kind, text):
        """Lisää yhden tai useamman säännön. Verkkotunnuksia voi erottaa rivinvaihdoilla,
        välilyönneillä tai pilkuilla; lausekkeita rivinvaihdoilla.
        Palauttaa {"added": [...], "existing": [...], "invalid": [...]}."""
        result = {"added": [], "existing": [], "invalid": []}
        with self._lock:
            if kind == "deny_regex":
                for line in text.splitlines():
                    p = line.strip()
                    if not p:
                        continue
                    try:
                        compiled = re.compile(p)
                    except re.error:
                        result["invalid"].append(p)
                        continue
                    if p in (q for q, _ in self.deny_regex):
                        result["existing"].append(p)
                    else:
                        self.deny_regex.append((p, compiled))
                        result["added"].append(p)
            elif kind in ("allow", "deny"):
                target = getattr(self, kind)
                for line in text.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    # hosts-rivi "0.0.0.0 nimi" -> nimi; muuten jokainen sana omana arvonaan
                    parts = line.split()
                    if len(parts) == 2 and re.fullmatch(r"[\d.:a-fA-F]+", parts[0]) and "." in parts[1]:
                        parts = parts[1:]
                    for raw in (x for p in parts for x in p.split(",")):
                        if not raw:
                            continue
                        name = normalize_domain(raw)
                        if not name:
                            result["invalid"].append(raw)
                        elif name in target:
                            result["existing"].append(name)
                        else:
                            target.add(name)
                            result["added"].append(name)
            else:
                raise ValueError("tuntematon lista")
            if result["added"]:
                self._save_custom()
        if not (result["added"] or result["existing"]) and result["invalid"]:
            raise ValueError("ei kelvollisia arvoja: " + ", ".join(result["invalid"][:5]))
        return result

    def remove_custom(self, kind, value):
        with self._lock:
            if kind == "deny_regex":
                self.deny_regex = [(p, c) for p, c in self.deny_regex if p != value]
            elif kind in ("allow", "deny"):
                getattr(self, kind).discard(value)
            self._save_custom()

    # ---------- tila ----------
    @property
    def active(self):
        if not self.config["blocking_enabled"]:
            return False
        if self.pause_until and time.time() < self.pause_until:
            return False
        return True

    def pause(self, seconds):
        self.pause_until = time.time() + seconds if seconds else None

    # ---------- tarkistus ----------
    def check(self, name):
        """Palauttaa (estetty: bool, syy: str|None)."""
        if not self.active:
            return False, None
        for p in _parents(name):
            if p in self.allow:
                return False, None
        if name in self.blocked:
            return True, "lista"
        for p in _parents(name):
            if p in self.deny:
                return True, "oma"
        for _, rx in self.deny_regex:
            if rx.search(name):
                return True, "lauseke"
        return False, None

    # ---------- listojen päivitys ----------
    def _list_file(self, url):
        return os.path.join(self.lists_dir, hashlib.sha1(url.encode()).hexdigest()[:16] + ".txt")

    def update_lists(self):
        for entry in self.config["lists"]:
            if not entry.get("enabled", True):
                continue
            url = entry["url"]
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "sihti/1.0"})
                dest = self._list_file(url)
                # Suoraan levylle paloina: suurikaan lista ei vie muistia
                with urllib.request.urlopen(req, timeout=60) as r, open(dest + ".tmp", "wb") as f:
                    shutil.copyfileobj(r, f, 1 << 16)
                os.replace(dest + ".tmp", dest)
                self.list_status[url] = {"updated": time.time(), "error": None}
                log.info("ladattu %s", url)
            except Exception as e:  # noqa: BLE001 — verkkovirheet kirjataan, vanha kopio jää käyttöön
                self.list_status.setdefault(url, {})["error"] = str(e)
                log.warning("lataus epäonnistui %s: %s", url, e)
        self.rebuild()
        self.last_update = time.time()

    def rebuild(self):
        """Rakentaa estojoukon listatiedostoista. Vanha joukko on käytössä, kunnes uusi on valmis."""
        with self._rebuild_lock:
            self.rebuilding = True
            try:
                t0 = time.monotonic()
                entries, paths = [], []
                for entry in list(self.config["lists"]):
                    url = entry["url"]
                    path = self._list_file(url)
                    st = self.list_status.setdefault(url, {"updated": None, "error": None})
                    if not entry.get("enabled", True) or not os.path.exists(path):
                        st["count"] = 0
                        continue
                    entries.append(st)
                    paths.append(path)
                    if st.get("updated") is None:
                        st["updated"] = os.path.getmtime(path)
                    # Uudelleenkäynnistyksen jälkeen päivitysaika luetaan tallennetuista tiedostoista
                    if self.last_update is None or st["updated"] > self.last_update:
                        self.last_update = st["updated"]
                key = os.urandom(16)   # uusi avain joka rakennukselle: tiivisteitä ei voi ennustaa
                if paths:
                    data_b, index_b, count, per_file = _build_isolated(paths, key)
                    data, index = array("Q"), array("Q")
                    data.frombytes(data_b)
                    index.frombytes(index_b)
                    del data_b, index_b
                    for st, n in zip(entries, per_file):
                        st["count"] = n
                    blocked = DomainSet(key, data, index, count)
                else:
                    blocked = DomainSet()
                with self._lock:
                    self.blocked = blocked
                log.info("estettäviä verkkotunnuksia: %d (%.1f s)", len(blocked), time.monotonic() - t0)
            finally:
                self.rebuilding = False

    def rebuild_async(self):
        threading.Thread(target=self.rebuild, daemon=True, name="listat-rakennus").start()

    def updater_loop(self, stop_event):
        self.rebuild()                 # tallennetut listat ensin
        if not self.blocked:
            self.update_lists()        # ensimmäinen käynnistys: ladataan
        while not stop_event.wait(max(1, self.config["update_interval_hours"]) * 3600):
            self.update_lists()
