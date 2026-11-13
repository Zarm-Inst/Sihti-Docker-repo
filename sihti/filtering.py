"""Estolistojen lataus, jäsennys ja verkkotunnusten tarkistus."""
import hashlib
import json
import multiprocessing
from array import array
from collections import Counter
from bisect import bisect_left
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from concurrent.futures.process import BrokenProcessPool
import logging
import os
import re
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

from . import __version__
from .fileutil import atomic_write, atomic_write_json, commit

log = logging.getLogger("sihti.suodatin")

USER_AGENT = f"sihti/{__version__}"   # FLT-030; versio yhdestä paikasta (H-15)

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
    sen 65 536 lohkoon. Viisi miljoonaa nimeä vie taulukkoina noin 43 Mt (koko prosessin muisti
    on suurempi, ks. README ja tools/measure_memory.py), kun tavallisena Python-
    joukkona ne veisivät lähes gigatavun. Väärän osuman todennäköisyys on käytännössä nolla.
    Rinnakkainen bittimaski kertoo, millä listoilla nimi on (1 tavu per nimi, kun listoja
    on enintään 8), jotta kyselylokiin saadaan eston syy."""
    SHIFT = 48

    def __init__(self, key=b"", data=None, index=None, count=0, masks=None, sources=()):
        self.key = key
        self._data = data
        self._index = index
        self._count = count
        self._masks = masks       # bitti n = nimi on listalla sources[n]
        self.sources = sources    # listojen osoitteet bittien järjestyksessä

    def _find(self, name):
        if not self._count:
            return -1
        h = fingerprint(name, self.key)
        b = h >> self.SHIFT
        lo, hi = self._index[b], self._index[b + 1]
        i = bisect_left(self._data, h, lo, hi)
        return i if i < hi and self._data[i] == h else -1

    def __contains__(self, name):
        return self._find(name) >= 0

    def lookup(self, name):
        """None, jos nimeä ei ole; muuten niiden listojen osoitteet, joilla nimi on."""
        i = self._find(name)
        if i < 0:
            return None
        if self._masks is None:
            return []
        m = self._masks[i]
        return [url for n, url in enumerate(self.sources) if m >> n & 1]

    def __len__(self):
        return self._count

    def __bool__(self):
        return self._count > 0


def fingerprint(name, key):
    return int.from_bytes(hashlib.blake2b(name.encode(), digest_size=8, key=key).digest(), "big")


_BUCKETS = 1 << (64 - DomainSet.SHIFT)


def _fingerprint_file(f, key):
    """Yhden listan nimet tiivisteiksi: lajiteltu taulukko ilman päällekkäisiä sekä sen
    lohkohakemisto. Palauttaa (data, index, nimiä)."""
    shift = DomainSet.SHIFT
    buckets = [array("Q") for _ in range(_BUCKETS)]
    copy = hashlib.blake2b(digest_size=8, key=key).copy   # avain alustetaan kerran, ei joka nimelle
    to_int = int.from_bytes
    n = 0
    for name in iter_domains(f):
        h = copy()
        h.update(name.encode())
        v = to_int(h.digest(), "big")   # sama arvo kuin fingerprint(name, key)
        buckets[v >> shift].append(v)
        n += 1
    data, index = array("Q"), array("Q", [0])
    for i, a in enumerate(buckets):
        if a:
            data.extend(sorted(set(a)))   # päällekkäiset pois, lajittelu hakua varten
            buckets[i] = None
        index.append(len(data))
    return data, index, n


_CACHE_HEAD = struct.Struct("<8s8sqqqq")   # tunniste, avaimen tunniste, koko, muokattu, nimiä, tiivisteitä
_CACHE_MAGIC = b"SIHTI-1\n"


def _list_fingerprints(path, key, load=True):
    """Kuten _fingerprint_file, mutta tulos tallennetaan listan viereen (.fp). Kun lista ei ole
    muuttunut, tiivisteet luetaan sieltä eikä listaa tarvitse jäsentää uudelleen.
    load=False: varmistetaan vain, että välimuisti on ajan tasalla (palauttaa None)."""
    cache = os.path.splitext(path)[0] + ".fp"
    key_id = hashlib.blake2b(key, digest_size=8).digest()
    with open(path, encoding="utf-8", errors="replace") as f:
        st = os.fstat(f.fileno())
        try:
            with open(cache, "rb") as c:
                magic, kid, size, mtime, n, count = _CACHE_HEAD.unpack(c.read(_CACHE_HEAD.size))
                if (magic, kid, size, mtime) == (_CACHE_MAGIC, key_id, st.st_size, st.st_mtime_ns):
                    if not load:
                        return None
                    index, data = array("Q"), array("Q")
                    index.fromfile(c, _BUCKETS + 1)
                    data.fromfile(c, count)
                    return data, index, n
        except (OSError, EOFError, ValueError, struct.error):   # puuttuva tai vioittunut välimuisti
            pass
        data, index, n = _fingerprint_file(f, key)
    try:
        with open(cache + ".tmp", "wb") as c:
            c.write(_CACHE_HEAD.pack(_CACHE_MAGIC, key_id, st.st_size, st.st_mtime_ns, n, len(data)))
            index.tofile(c)
            data.tofile(c)
        commit(cache + ".tmp", cache)
    except OSError as e:
        log.warning("välimuistia ei voitu tallentaa %s: %s", cache, e)
    return (data, index, n) if load else None


def _merge(parts, mask_type):
    """Yhdistää listojen taulukot [(data, index)]: jokainen nimi kerran, ja bittimaski kertoo,
    millä listoilla se on. Päällekkäisyydet etsitään joukko-operaatioilla lohkoittain."""
    if len(parts) == 1:
        data, index = parts[0]
        return data, index, array(mask_type, [1]) * len(data)
    data, index, masks = array("Q"), array("Q", [0]), array(mask_type)
    bits = [1 << k if k < 64 else 0 for k in range(len(parts))]   # yli 64 listaa: syy ilman listan nimeä
    for b in range(_BUCKETS):
        slices = [(bit, d[ix[b]:ix[b + 1]]) for bit, (d, ix) in zip(bits, parts) if ix[b] != ix[b + 1]]
        if len(slices) == 1:
            bit, sl = slices[0]
            data.extend(sl)
            masks.extend(array(mask_type, [bit]) * len(sl))
        elif slices:
            merged = {}
            for bit, sl in slices:
                both = {h: merged[h] for h in merged.keys() & sl}   # jo aiemmilla listoilla
                merged.update(dict.fromkeys(sl, bit))
                for h, m in both.items():
                    merged[h] = m | bit
            keys = sorted(merged)
            data.extend(keys)
            masks.extend(map(merged.__getitem__, keys))
        index.append(len(data))
    return data, index, masks


def redundant_lists(mask_counts, n_lists, sizes, protected=()):
    """Valitsee listat, jotka voi ohittaa menettämättä yhtään nimeä: jokainen ohitetun listan
    nimi on jollain käyttöön jäävällä listalla. mask_counts = {bittimaski: nimiä}. Ohitetaan
    yksi kerrallaan, pienin ensin, ja lasketaan tilanne uudelleen, joten kahdesta samanlaisesta
    listasta vain toinen ohitetaan. protected: listat, joita ei ohiteta koskaan.
    Palauttaa (ohitettavat indeksit, [vain tällä listalla olevia nimiä per lista])."""
    n = min(n_lists, 64)   # yli 64 listaa ei voi analysoida (ei bittiä maskissa)
    active = (1 << n) - 1
    skipped = []
    while True:
        unique = [0] * n_lists
        for m, c in mask_counts.items():
            a = m & active
            if a and not a & (a - 1):   # nimi on täsmälleen yhdellä käytössä olevalla listalla
                unique[a.bit_length() - 1] += c
        candidates = [k for k in range(n) if active >> k & 1 and not unique[k] and k not in protected]
        if not candidates:
            return skipped, unique
        k = min(candidates, key=lambda k: (sizes[k], -k))   # pienin ensin; tasan: myöhemmin lisätty
        active &= ~(1 << k)
        skipped.append(k)


def _build_arrays(paths, key, protected=()):
    """Lukee listatiedostot (välimuistista, jos mahdollista), yhdistää ne ja analysoi
    päällekkäisyyden. Palauttaa (data, index, masks, [rivejä_per_tiedosto], maskin_tyyppi,
    {"skippable": [päällekkäiset listat], "unique": [vain tällä listalla per lista]})."""
    parts, per_file = [], []
    for path in paths:
        data, index, n = _list_fingerprints(path, key)
        parts.append((data, index))
        per_file.append(n)
    mask_type = _mask_type(len(paths))
    if not parts:
        return (array("Q"), array("Q", [0] * (_BUCKETS + 1)), array(mask_type), [], mask_type,
                {"skippable": [], "unique": []})
    data, index, masks = _merge(parts, mask_type)
    sizes = [len(d) for d, _ in parts]
    del parts
    skippable, unique = redundant_lists(Counter(masks), len(paths), sizes, set(protected))
    return data, index, masks, per_file, mask_type, {"skippable": skippable, "unique": unique}


def build_domain_set(paths, key, protected=()):
    """Kuten _build_arrays, mutta taulukot tavuina: (data_bytes, index_bytes, nimiä_yhteensä,
    [rivejä_per_tiedosto], maskin_tyyppi, maskit_bytes, analyysi)."""
    data, index, masks, per_file, mask_type, stats = _build_arrays(paths, key, protected)
    return data.tobytes(), index.tobytes(), len(data), per_file, mask_type, masks.tobytes(), stats


def _build_to_file(paths, key, protected, out):
    """Ajetaan erillisessä prosessissa: tulos kirjoitetaan tiedostoon, josta pääprosessi lukee
    taulukot suoraan. Prosessien välinen siirto (pickle) tekisi koko joukosta kaksi ylimääräistä
    kopiota, mikä nostaisi muistin huippua pienimuistisella laitteella."""
    data, index, masks, per_file, mask_type, stats = _build_arrays(paths, key, protected)
    with open(out + ".tmp", "wb") as f:
        index.tofile(f)
        data.tofile(f)
        masks.tofile(f)
    os.replace(out + ".tmp", out)
    return len(data), per_file, mask_type, stats


def _mask_type(n_lists):
    for code in ("B", "H", "I", "Q"):
        if n_lists <= array(code).itemsize * 8:
            return code
    return "Q"


BUILD_WORKERS = 2        # muuttuneet listat jäsennetään rinnakkain; maltillinen määrä muistin takia
BUILD_TIMEOUT = 3600    # s; jumiutunut käsittely keskeytetään, jotta päivitys ei jää päälle
DOWNLOAD_TIMEOUT = 900  # s; yhden listan lataus kokonaisuudessaan
REDUNDANT_RECHECK = 7 * 86400   # s; päällekkäisenä ohitettu lista tarkistetaan uudelleen viikon päästä
UPDATE_RETRY = 3600     # s; epäonnistunut päivitys yritetään uudelleen tunnin päästä


def _build_workers(n_lists):
    """Rinnakkaisten prosessien määrä. Pienimuistisilla laitteilla (esim. Pi Zero 2 W, 512 Mt)
    vain yksi, jotta muisti ei lopu eikä laite ala käyttää sivutustilaa."""
    try:
        with open("/proc/meminfo") as f:
            total_kb = int(next(line for line in f if line.startswith("MemTotal")).split()[1])
    except (OSError, StopIteration, ValueError, IndexError):
        total_kb = 0
    limit = 1 if 0 < total_kb < 1_200_000 else BUILD_WORKERS
    return max(1, min(n_lists, os.cpu_count() or 1, limit))


def _build_isolated(paths, key, protected=(), out=None):
    """Rakentaa erillisissä prosesseissa: ensin muuttuneet listat jäsennetään välimuistiin,
    sitten yhdistetään. Jos prosessi kaatuu (esim. muisti loppuu) tai käsittely kestää yli
    BUILD_TIMEOUT, nostetaan virhe eikä jäädä odottamaan. Jos erillistä prosessia ei voi
    käynnistää lainkaan, rakennetaan tässä prosessissa. Palauttaa kuten _build_arrays.
    out: välitiedosto tulokselle (oletus: ensimmäisen listan hakemisto)."""
    out = out or os.path.join(os.path.dirname(paths[0]), "joukko.tmp")
    try:
        ex = ProcessPoolExecutor(max_workers=_build_workers(len(paths)),
                                 mp_context=multiprocessing.get_context("spawn"))
        cached = [ex.submit(_list_fingerprints, p, key, False) for p in paths]
    except Exception as e:  # noqa: BLE001
        log.warning("erillistä prosessia ei voitu käyttää (%s), rakennetaan pääprosessissa", e)
        return _build_arrays(paths, key, protected)
    deadline = time.monotonic() + BUILD_TIMEOUT
    left = lambda: max(1.0, deadline - time.monotonic())  # noqa: E731
    try:
        for c in cached:
            c.result(timeout=left())
        count, per_file, mask_type, stats = ex.submit(_build_to_file, paths, key, protected, out).result(timeout=left())
    except BrokenProcessPool:
        ex.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError("listojen käsittely keskeytyi, koska erillinen prosessi pysähtyi "
                           "(loppuiko muisti?)") from None
    except FutureTimeout:
        for proc in list(getattr(ex, "_processes", {}).values()):   # jumiutuneet prosessit pois
            proc.kill()
        ex.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError(f"listojen käsittely kesti yli {BUILD_TIMEOUT // 60} min ja keskeytettiin") from None
    ex.shutdown(wait=True)
    index, data, masks = array("Q"), array("Q"), array(mask_type)
    try:
        with open(out, "rb") as f:
            index.fromfile(f, _BUCKETS + 1)
            data.fromfile(f, count)
            masks.fromfile(f, count)
    finally:
        os.remove(out)
    return data, index, masks, per_file, mask_type, stats


_malloc_trim = None


def release_memory():
    """Palauttaa vapautuneen muistin käyttöjärjestelmälle (NFR-003, havainto H-16). glibc pitää
    vanhan joukon ja väliaikaisten taulukoiden vapauttaman muistin prosessilla; malloc_trim(0)
    palauttaa sen. Muualla (Alpine-kontin musl, macOS, Windows) funktiota ei ole: ei tehdä mitään.
    Palauttaa True, jos kutsu tehtiin."""
    global _malloc_trim
    if _malloc_trim is None:
        _malloc_trim = False
        if sys.platform.startswith("linux"):
            try:
                import ctypes
                fn = ctypes.CDLL(None).malloc_trim
                fn.argtypes, fn.restype = [ctypes.c_size_t], ctypes.c_int
                _malloc_trim = fn
            except (OSError, AttributeError):
                pass
    if not _malloc_trim:
        return False
    _malloc_trim(0)
    return True


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
        self._update_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active = 0          # käynnissä tai jonossa olevat päivitykset
        self.rebuilding = False
        self.build_error = None
        self._progress = None     # {"phase": "lataus"|"käsittely", "done", "total", "since"}
        self._built_sig = None    # listat, joista nykyinen joukko rakennettiin
        self.blocked = DomainSet()
        self.allow = set()        # sallitaan + kaikki aliverkkotunnukset
        self.deny = set()         # estetään + kaikki aliverkkotunnukset
        self.deny_regex = []      # [(pattern_str, compiled)]
        self.list_status = {}     # url -> {"count", "updated", "error"}
        self._schedule_path = os.path.join(self.lists_dir, "ajastus.json")
        self.last_update = self._load_last_update()   # viimeisin täysi päivitys (säilyy uudelleenkäynnistyksessä)
        self._retry_at = None
        self.pause_until = None
        self._key = self._load_key()
        self._meta_path = os.path.join(self.lists_dir, "tila.json")
        self._meta_lock = threading.Lock()
        self._meta = self._load_meta()   # url -> {"etag", "modified", "sha256"}
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
        atomic_write_json(self.custom_path, d, indent=2)

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

    def replace_custom(self, allow, deny, deny_regex):
        """Korvaa kaikki omat säännöt (varmuuskopion palautus). Palauttaa ohitetut virheelliset arvot."""
        skipped = []

        def names(values):
            out = set()
            for v in values:
                n = normalize_domain(str(v))
                if n:
                    out.add(n)
                else:
                    skipped.append(str(v))
            return out
        regex = []
        for p in deny_regex:
            try:
                regex.append((str(p), re.compile(str(p))))
            except re.error:
                skipped.append(str(p))
        with self._lock:
            self.allow, self.deny, self.deny_regex = names(allow), names(deny), regex
            self._save_custom()
        return skipped

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
    def allow_rule(self, name):
        """Oma sallittu-sääntö, joka koskee nimeä tai sen yläverkkotunnusta, tai None.
        Ei riipu suodatuksen tilasta (käytetään myös ohitusten estossa, DNS-012)."""
        for p in _parents(name):
            if p in self.allow:
                return p
        return None

    def check(self, name):
        """Palauttaa (estetty: bool, syy: str|None, tarkenne: str|None).
        Syy: lista | oma | lauseke, tai sallinta (oma sallittu-sääntö ohitti suodatuksen).
        Tarkenne: listojen osoitteet välilyönnein, osunut oma sääntö tai lauseke."""
        if not self.active:
            return False, None, None
        rule = self.allow_rule(name)
        if rule:
            return False, "sallinta", rule
        sources = self.blocked.lookup(name)
        if sources is not None:
            return True, "lista", " ".join(sources) or None
        for p in _parents(name):
            if p in self.deny:
                return True, "oma", p
        for pattern, rx in self.deny_regex:
            if rx.search(name):
                return True, "lauseke", pattern
        return False, None, None

    # ---------- listojen päivitys ----------
    def _list_file(self, url):
        return os.path.join(self.lists_dir, hashlib.sha1(url.encode()).hexdigest()[:16] + ".txt")

    def _load_key(self):
        """Tiivisteiden salainen avain. Luodaan kerran ja säilytetään, jotta listojen tiivisteet
        voidaan tallentaa välimuistiin; ulkopuolinen ei silti voi ennustaa niitä."""
        path = os.path.join(self.lists_dir, "avain")
        try:
            with open(path, "rb") as f:
                key = f.read()
            if len(key) == 16:
                return key
        except OSError:
            pass
        key = os.urandom(16)
        atomic_write(path, key, mode=0o600)
        return key

    def _load_meta(self):
        try:
            with open(self._meta_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save_meta(self):
        atomic_write_json(self._meta_path, self._meta, indent=2)

    @property
    def updating(self):
        """Listoja ladataan tai estojoukkoa rakennetaan (tai päivitys odottaa vuoroaan)."""
        return self._active > 0 or self.rebuilding

    def progress(self):
        """Päivityksen vaihe käyttöliittymälle, esim. {"phase": "lataus", "done": 1, "total": 3,
        "elapsed": 12.5}, tai None."""
        p = self._progress
        if not p or not self.updating:
            return None
        return {k: v for k, v in p.items() if k != "since"} | {"elapsed": round(time.time() - p["since"], 1)}

    def _download(self, url):
        """Lataa listan suoraan levylle. Jos palvelin kertoo, ettei lista ole muuttunut (ETag /
        Last-Modified), tai sisältö on täsmälleen sama kuin ennen, vanha tiedosto jää paikalleen
        eikä estojoukkoa tarvitse rakentaa uudelleen. Palauttaa True, jos tiedosto vaihtui."""
        dest = self._list_file(url)
        tmp = dest + ".tmp"
        st = self.list_status.setdefault(url, {"updated": None, "error": None})
        meta = self._meta.get(url, {}) if os.path.exists(dest) else {}
        headers = {"User-Agent": USER_AGENT}
        if meta.get("etag"):
            headers["If-None-Match"] = meta["etag"]
        if meta.get("modified"):
            headers["If-Modified-Since"] = meta["modified"]
        try:
            digest = hashlib.sha256()
            try:
                req = urllib.request.Request(url, headers=headers)
                deadline = time.monotonic() + DOWNLOAD_TIMEOUT
                with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
                    while True:   # paloina: suurikaan lista ei vie muistia
                        chunk = r.read(1 << 16)
                        if not chunk:
                            break
                        digest.update(chunk)
                        f.write(chunk)
                        if time.monotonic() > deadline:
                            raise TimeoutError(f"lataus kesti yli {DOWNLOAD_TIMEOUT // 60} min")
                    new = {"etag": r.headers.get("ETag"), "modified": r.headers.get("Last-Modified"),
                           "sha256": digest.hexdigest()}
            except urllib.error.HTTPError as e:
                if e.code != 304:
                    raise
                e.close()
                changed = False
            else:
                changed = new["sha256"] != meta.get("sha256")
                if changed:
                    commit(tmp, dest)
                with self._meta_lock:
                    m = self._meta.setdefault(url, {})
                    for k, v in new.items():
                        if v:
                            m[k] = v
                        else:
                            m.pop(k, None)
                    self._save_meta()
            st.update(updated=time.time(), error=None)
            log.info("%s %s", "ladattu" if changed else "ei muutoksia", url)
            return changed
        except Exception as e:  # noqa: BLE001 — verkkovirheet kirjataan, vanha kopio jää käyttöön
            st["error"] = str(e)
            log.warning("lataus epäonnistui %s: %s", url, e)
            return False
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def update_lists(self, missing_only=False):
        """Lataa käytössä olevat listat rinnakkain ja rakentaa estojoukon, jos jokin muuttui.
        missing_only: vain listat, joita ei vielä ole levyllä (juuri lisätty tai käyttöön otettu)."""
        with self._active_lock:
            self._active += 1
        try:
            with self._update_lock:
                all_urls = [e["url"] for e in self.config["lists"]
                            if e.get("enabled", True) and not self.skipped_until(e)]
                urls = [u for u in all_urls if not os.path.exists(self._list_file(u))] if missing_only else all_urls
                # Ensimmäisellä käynnistyksellä kaikki listat puuttuvat: lataus on täysi päivitys
                full = not missing_only or (bool(urls) and len(urls) == len(all_urls))
                try:
                    if urls:
                        self._progress = {"phase": "lataus", "done": 0, "total": len(urls), "since": time.time()}
                        with ThreadPoolExecutor(max_workers=min(4, len(urls)), thread_name_prefix="lataus") as ex:
                            for _ in ex.map(self._download, urls):
                                self._progress["done"] += 1
                    self.rebuild()
                    if full:
                        failed = [u for u in urls if self.list_status.get(u, {}).get("error")]
                        self._retry_at = time.time() + UPDATE_RETRY if failed else None
                        self.last_update = time.time()
                        self._save_last_update()
                finally:
                    self._progress = None
        finally:
            with self._active_lock:
                self._active -= 1

    def update_async(self, missing_only=False):
        with self._active_lock:
            self._active += 1   # näkyy käyttöliittymälle heti, vaikka edellinen päivitys olisi kesken

        def run():
            try:
                self.update_lists(missing_only)
            finally:
                with self._active_lock:
                    self._active -= 1
        threading.Thread(target=run, daemon=True, name="listat-päivitys").start()

    def rebuild(self):
        """Rakentaa estojoukon listatiedostoista, jos käytössä olevat listat tai niiden sisältö
        ovat muuttuneet. Muuttumattomien listojen tiivisteet luetaan välimuistista. Vanha joukko
        on käytössä, kunnes uusi on valmis. Palauttaa True, jos joukko rakennettiin."""
        with self._rebuild_lock:
            entries, paths, urls, sig, protected = [], [], [], [], []
            for entry in list(self.config["lists"]):
                url = entry["url"]
                path = self._list_file(url)
                st = self.list_status.setdefault(url, {"updated": None, "error": None})
                if self.skipped_until(entry):
                    continue   # päällekkäinen: nimet ovat muilla listoilla (lukumäärä jää näkyviin)
                if not entry.get("enabled", True) or not os.path.exists(path):
                    st["count"] = 0
                    continue
                fs = os.stat(path)
                if entry.get("keep"):
                    protected.append(len(paths))
                entries.append(st)
                paths.append(path)
                urls.append(url)
                sig.append((url, fs.st_size, fs.st_mtime_ns))
                if st.get("updated") is None:
                    st["updated"] = fs.st_mtime
                # Vanhasta versiosta päivitettäessä aikaa ei ole tallessa: arvioidaan tiedostoista
                if self.last_update is None or (not os.path.exists(self._schedule_path) and st["updated"] > self.last_update):
                    self.last_update = st["updated"]
            sig = tuple(sig)
            if sig == self._built_sig:
                return False
            self.rebuilding = True
            self._progress = {"phase": "käsittely", "since": time.time()}
            t0 = time.monotonic()
            try:
                stats = None
                if paths:
                    data, index, masks, per_file, mask_type, stats = _build_isolated(
                        paths, self._key, protected, os.path.join(self.lists_dir, "joukko.tmp"))
                    for st, n in zip(entries, per_file):
                        st["count"] = n
                    blocked = DomainSet(self._key, data, index, len(data), masks, tuple(urls))
                else:
                    blocked = DomainSet()
            except Exception as e:  # noqa: BLE001 — vanha joukko jää käyttöön
                self.build_error = str(e)
                log.error("estolistojen käsittely epäonnistui: %s", e)
                return False
            finally:
                self.rebuilding = False
            with self._lock:
                self.blocked = blocked   # vanha joukko vapautuu tässä
            release_memory()
            self._built_sig = sig
            self.build_error = None
            if stats:
                skip = self._apply_redundancy(urls, stats)
                # Joukko on sama ilman ohitettuja listoja, joten seuraava päivitys ei rakenna turhaan
                self._built_sig = tuple(x for x in sig if x[0] not in skip)
            self._remove_stale_files()
            log.info("estettäviä verkkotunnuksia: %d (%.1f s)", len(blocked), time.monotonic() - t0)
            return True

    def skipped_until(self, entry):
        """Jos lista ohitetaan päällekkäisenä (kaikki sen nimet ovat muilla listoilla), aika
        jolloin se ladataan ja tarkistetaan uudelleen; muuten None."""
        if not self.config["skip_redundant_lists"] or entry.get("keep") or not entry.get("enabled", True):
            return None
        since = self._meta.get(entry["url"], {}).get("redundant_since")
        if since and time.time() < since + REDUNDANT_RECHECK:
            return since + REDUNDANT_RECHECK
        return None

    def list_counts(self):
        """(käytössä olevat listat, päällekkäisinä ohitetut listat)."""
        skipped = {e["url"] for e in self.config["lists"] if self.skipped_until(e)}
        return len([u for u in self.blocked.sources if u not in skipped]), len(skipped)

    def _apply_redundancy(self, urls, stats):
        """Merkitsee listat, joiden kaikki nimet ovat muilla listoilla, ohitettaviksi viikoksi, ja
        palauttaa käyttöön listat, joilla on taas omia nimiä. Palauttaa ohitettavat osoitteet."""
        skip = {urls[k] for k in stats["skippable"]} if self.config["skip_redundant_lists"] else set()
        now = time.time()
        with self._meta_lock:
            for k, url in enumerate(urls):
                self.list_status.setdefault(url, {})["unique"] = stats["unique"][k] if k < 64 else None
                m = self._meta.setdefault(url, {})
                if url in skip:
                    m["redundant_since"] = now
                elif m.pop("redundant_since", None):
                    log.info("lista otettu taas käyttöön, siinä on omia nimiä: %s", url)
            self._save_meta()
        if skip:
            log.info("ohitetaan %d listaa, joiden kaikki nimet ovat muilla listoilla: %s",
                     len(skip), ", ".join(sorted(skip)))
        return skip

    def reanalyze(self):
        """Ohitusasetus muuttui: listat ladataan ja analysoidaan uudelleen."""
        self._built_sig = None
        self.update_async()

    def _remove_stale_files(self):
        """Poistaa poistettujen listojen tiedostot, niiden välimuistit ja keskeytyneiden latausten
        väliaikaistiedostot sekä listojen tiedot (etag, tiiviste), jotta mikään ei kasva vuosien
        mittaan, kun listoja lisätään ja poistetaan."""
        urls = {e["url"] for e in self.config["lists"]}
        keep = {os.path.splitext(os.path.basename(self._list_file(u)))[0] for u in urls}
        for fn in os.listdir(self.lists_dir):
            name = fn[:-4] if fn.endswith(".tmp") else fn   # <tunniste>.txt.tmp: keskeytynyt lataus
            base, ext = os.path.splitext(name)
            if ext in (".txt", ".fp") and re.fullmatch(r"[0-9a-f]{16}", base) and base not in keep:
                try:
                    os.remove(os.path.join(self.lists_dir, fn))
                except OSError:
                    pass
        with self._meta_lock:
            stale = [u for u in self._meta if u not in urls]
            for u in stale:
                del self._meta[u]
            for u in [u for u in list(self.list_status) if u not in urls]:
                del self.list_status[u]
            if stale:
                self._save_meta()

    def _load_last_update(self):
        try:
            with open(self._schedule_path, encoding="utf-8") as f:
                return float(json.load(f)["last_update"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _save_last_update(self):
        atomic_write_json(self._schedule_path, {"last_update": self.last_update})

    def next_update(self):
        """Seuraavan automaattisen päivityksen aika: viimeisimmästä täydestä päivityksestä
        asetuksen välein, epäonnistuneen jälkeen tunnin päästä, ja heti, jos aikaa ei tiedetä."""
        if self._retry_at:
            return self._retry_at
        if self.last_update is None:
            return time.time()
        return self.last_update + max(1, self.config["update_interval_hours"]) * 3600

    def _scheduled_update(self, missing_only):
        try:
            self.update_lists(missing_only)
        except Exception:  # noqa: BLE001 — yritetään uudelleen tunnin päästä
            self._retry_at = time.time() + UPDATE_RETRY
            log.exception("listojen päivitys epäonnistui")

    def updater_loop(self, stop_event):
        """Käynnistyksessä tallennetut listat otetaan käyttöön välimuistista ja puuttuvat ladataan.
        Sen jälkeen tarkistetaan minuutin välein, onko päivitys ajankohtainen. Aika lasketaan
        levylle tallennetusta viimeisimmästä päivityksestä, joten uudelleenkäynnistys ei siirrä
        päivitystä ja päivitysvälin muutos tulee voimaan heti."""
        self._scheduled_update(missing_only=True)
        while True:
            if time.time() >= self.next_update():
                self._scheduled_update(missing_only=False)
            if stop_event.wait(60):
                return
