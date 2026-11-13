"""Sihdin testit. Ajo: python -m unittest discover -s tests -v   (ei ulkoisia riippuvuuksia)"""
import json
import os
import random
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sihti import dnswire as w                          # noqa: E402
from sihti.config import DEFAULTS, Config, env_overrides  # noqa: E402
from sihti.filtering import Filter, normalize_domain, parse_list  # noqa: E402
from sihti.querylog import QueryLog                     # noqa: E402
from sihti.resolver import Resolver, start_servers     # noqa: E402
from sihti.web import App, start_web                    # noqa: E402
from sihti import resolver as _resolver                 # noqa: E402

# Testeissä kuuntelijat suljetaan usein; tuotannon 5 s pysäytystarkistus hidastaisi ajoa turhaan.
PROD_SERVE_POLL = _resolver.SERVE_POLL
_resolver.SERVE_POLL = 0.2


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_query(name, qtype=1):
    qid = random.randint(0, 0xFFFF)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def udp_ask(port, name, qtype=1):
    msg = make_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(msg, ("127.0.0.1", port))
        r = s.recv(4096)
    assert r[:2] == msg[:2]
    return r


def tcp_ask(port, name):
    msg = make_query(name)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(struct.pack("!H", len(msg)) + msg)
        ln = struct.unpack("!H", s.recv(2))[0]
        buf = b""
        while len(buf) < ln:
            buf += s.recv(ln - len(buf))
    return buf


def answer_ip(resp):
    return ".".join(map(str, resp[-4:])) if struct.unpack("!H", resp[6:8])[0] else None


class FakeUpstream(threading.Thread):
    """Vastaa jokaiseen A-kyselyyn osoitteella 1.2.3.4."""
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.count = 0

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            self.count += 1
            _qid, _f, name, qtype, qend = w.parse_query(data)
            if name.startswith("piilo."):   # sivuston oma nimi, joka osoittaa seurantapalvelimeen
                target = b"".join(bytes([len(p)]) + p.encode() for p in "tracker.example.net".split(".")) + b"\0"
                resp = w.build_response(data, qend)
                resp = resp[:6] + struct.pack("!H", 2) + resp[8:]
                resp += struct.pack("!HHHIH", 0xC00C, 5, 1, 300, len(target)) + target
                resp += target + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([5, 6, 7, 8])
            elif qtype == 1:
                resp = w.build_response(data, qend, answer_rdata=bytes([1, 2, 3, 4]), qtype=1, ttl=300)
            else:
                resp = w.build_response(data, qend)
            self.sock.sendto(resp, addr)


# ---------------------------------------------------------------- yksikkötestit

class TestNormalize(unittest.TestCase):
    def test_accepts_common_forms(self):
        cases = {
            "Example.COM.": "example.com",
            "*.ads.example.com": "ads.example.com",
            ".track.example.net": "track.example.net",
            "||banner.example.org^": "banner.example.org",
            "https://www.esimerkki.fi:8443/polku?x=1#a": "www.esimerkki.fi",
            "user@mail.example.com": "mail.example.com",
            "äö.fi": "xn--4ca0b.fi",
        }
        for raw, want in cases.items():
            self.assertEqual(normalize_domain(raw), want, raw)

    def test_rejects_invalid(self):
        for raw in ("localhost", "ei verkkotunnus", "1.2.3.4", "http://", ""):
            self.assertIsNone(normalize_domain(raw), raw)


class TestParseList(unittest.TestCase):
    def test_formats(self):
        text = ("# kommentti\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n"
                "tracker.example.net # loppukommentti\n||banner.example.org^\n||x.example.org/polku^\n! adblock\n")
        self.assertEqual(parse_list(text), {"ads.example.com", "tracker.example.net", "banner.example.org"})


def build_with_other_key(path):
    """Eri avaimella rakennettu joukko ei saa käyttää toisen avaimen välimuistia."""
    from sihti.filtering import DomainSet, build_domain_set
    from array import array
    key = os.urandom(16)
    data_b, index_b, count, _, _, _, _ = build_domain_set([path], key)
    data, index = array("Q"), array("Q")
    data.frombytes(data_b)
    index.frombytes(index_b)
    ds = DomainSet(key, data, index, count)
    assert "uusi.example.com" in ds and "vanha.example.com" in ds
    return ds


class TestDomainSet(unittest.TestCase):
    def test_release_memory(self):
        # NFR-003, H-16: glibc-Linuxissa muisti palautetaan, muualla funktio ei tee mitään
        import platform
        from sihti.filtering import release_memory
        expected = sys.platform.startswith("linux") and platform.libc_ver()[0] == "glibc"
        self.assertEqual(release_memory(), expected)

    def test_build_and_lookup(self):
        from sihti.filtering import DomainSet, build_domain_set, _build_isolated
        from array import array
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        names = [f"n{i}.esimerkki{i % 97}.fi" for i in range(20000)]
        p1, p2 = os.path.join(d, "a.txt"), os.path.join(d, "b.txt")
        with open(p1, "w") as f:
            f.write("# lista\n" + "".join(f"0.0.0.0 {n}\n" for n in names[:12000]))
        with open(p2, "w") as f:   # osin päällekkäinen, eri muoto
            f.write("".join(f"||{n}^\n" for n in names[10000:]))
        key = os.urandom(16)
        def in_process(paths, key):
            data_b, index_b, count, per_file, mask_type, masks_b, stats = build_domain_set(paths, key)
            data, index, masks = array("Q"), array("Q"), array(mask_type)
            data.frombytes(data_b)
            index.frombytes(index_b)
            masks.frombytes(masks_b)
            return data, index, masks, per_file, mask_type, stats
        for builder in (in_process, _build_isolated):   # sama tulos omassa prosessissa (välitiedoston kautta)
            data, index, masks, per_file, mask_type, stats = builder([p1, p2], key)
            count = len(data)
            ds = DomainSet(key, data, index, count, masks, ("a", "b"))
            self.assertEqual((count, per_file, mask_type, len(masks)), (20000, [12000, 10000], "B", 20000))
            self.assertTrue(all(n in ds for n in names))
            self.assertFalse(any(f"x{i}.esimerkki.fi" in ds for i in range(20000)))
            # millä listalla nimi on: vain a, molemmilla, vain b
            self.assertTrue(all(ds.lookup(n) == ["a"] for n in names[:10000]))
            self.assertTrue(all(ds.lookup(n) == ["a", "b"] for n in names[10000:12000]))
            self.assertTrue(all(ds.lookup(n) == ["b"] for n in names[12000:]))
            self.assertIsNone(ds.lookup("x1.esimerkki.fi"))
            self.assertEqual(stats, {"skippable": [], "unique": [10000, 8000]})
        self.assertNotIn("a.fi", DomainSet())
        self.assertIsNone(DomainSet().lookup("a.fi"))
        self.assertFalse(os.path.exists(os.path.join(d, "joukko.tmp")), "välitiedosto poistetaan")

    def test_cache_reused_and_invalidated(self):
        from sihti.filtering import DomainSet, build_domain_set
        from array import array
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "a.txt")
        with open(p, "w") as f:
            f.write("0.0.0.0 vanha.example.com\n")
        key = os.urandom(16)

        def build():
            data_b, index_b, count, _, mask_type, masks_b, _ = build_domain_set([p], key)
            data, index, masks = array("Q"), array("Q"), array(mask_type)
            data.frombytes(data_b)
            index.frombytes(index_b)
            masks.frombytes(masks_b)
            return DomainSet(key, data, index, count, masks, ("a",))
        self.assertIn("vanha.example.com", build())
        cache = os.path.join(d, "a.fp")
        self.assertTrue(os.path.exists(cache))
        with open(p, "a") as f:   # lista muuttuu: välimuisti ei kelpaa
            f.write("0.0.0.0 uusi.example.com\n")
        ds = build()
        self.assertEqual(len(ds), 2)
        self.assertEqual(ds.lookup("uusi.example.com"), ["a"])
        with open(cache, "r+b") as f:   # vioittunut välimuisti: lista jäsennetään uudelleen
            f.truncate(100)
        self.assertEqual(len(build()), 2)
        self.assertNotIn("x.example.com", build_with_other_key(p))

    def test_redundant_lists_never_lose_names(self):
        from sihti.filtering import redundant_lists
        rnd = random.Random(5)
        for _ in range(300):
            n = rnd.randint(1, 7)
            lists = [set(rnd.sample(range(40), rnd.randint(0, 15))) for _ in range(n)]
            if rnd.random() < 0.3 and n > 1:
                lists[-1] = set(lists[0])                       # sama lista kahdesti
            if rnd.random() < 0.3 and n > 1:
                lists[1] = set(list(lists[0])[:3])              # osajoukko
            names = set().union(*lists)
            counts = {}
            for x in names:
                m = sum(1 << k for k, l in enumerate(lists) if x in l)
                counts[m] = counts.get(m, 0) + 1
            protected = {k for k in range(n) if rnd.random() < 0.2}
            skip, unique = redundant_lists(counts, n, [len(l) for l in lists], protected)
            kept = [l for k, l in enumerate(lists) if k not in skip]
            self.assertEqual(set().union(*kept) if kept else set(), names, "yksikään nimi ei saa kadota")
            self.assertFalse(protected & set(skip))
            for k, l in enumerate(lists):   # jäljelle jääneistä ei voi ohittaa enempää
                if k not in skip and k not in protected:
                    others = set().union(*[o for j, o in enumerate(lists) if j != k and j not in skip])
                    self.assertTrue(l - others, "ohitettavissa oleva lista jäi käyttöön")
                    self.assertEqual(unique[k], len(l - others))

    def test_subset_and_duplicate_lists_skipped(self):
        from sihti.filtering import redundant_lists
        # a = {1,2,3}, b = {1,2} (a:n osajoukko), c = {4}, d = {4} (sama kuin c)
        counts = {0b0011: 2, 0b0001: 1, 0b1100: 1}
        skip, unique = redundant_lists(counts, 4, [3, 2, 1, 1])
        self.assertEqual(sorted(skip), [1, 3])     # b ja myöhemmin lisätty d
        self.assertEqual(unique, [3, 0, 1, 0])

    def test_mask_width(self):
        from sihti.filtering import _mask_type
        self.assertEqual([_mask_type(n) for n in (1, 8, 9, 16, 17, 32, 33, 64, 100)],
                         ["B", "B", "H", "H", "I", "I", "Q", "Q", "Q"])

    def test_fast_validation_matches_regex_on_real_names(self):
        from sihti.filtering import _DOMAIN_RE, _valid_list_domain
        for n in ("ads.example.com", "a-b.c_d.example.co.uk", "xn--4ca0b.fi", "1.2.3.example.net"):
            self.assertTrue(_valid_list_domain(n) and _DOMAIN_RE.match(n), n)
        for n in ("-a.com", "a-.com", "a..com", ".a.com", "a.c", "a" * 64 + ".com", "a.co-", "a b.com", "a.c_m"):
            self.assertFalse(_valid_list_domain(n), n)


class TestEnv(unittest.TestCase):
    def test_types(self):
        got = env_overrides({"SIHTI_WEB_PORT": "4400", "SIHTI_HTTPS": "false",
                             "SIHTI_UPSTREAMS": "1.1.1.1, 9.9.9.9", "SIHTI_TLS_EXTRA_NAMES": "a.koti;10.0.0.5",
                             "SIHTI_UPSTREAM_TIMEOUT": "1.5", "SIHTI_LISTS": "ohitetaan"})
        self.assertEqual(got, {"web_port": 4400, "https": False, "upstreams": ["1.1.1.1", "9.9.9.9"],
                               "tls_extra_names": ["a.koti", "10.0.0.5"], "upstream_timeout": 1.5})

    def test_env_not_written_to_file(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "c.json")
        os.environ["SIHTI_DNS_PORT"] = "5300"
        try:
            c = Config(path)
            self.assertEqual(c["dns_port"], 5300)
            c.update(cache_size=5)
        finally:
            del os.environ["SIHTI_DNS_PORT"]
        with open(path) as f:
            saved = json.load(f)
        self.assertNotIn("dns_port", saved)
        self.assertEqual(saved, {"cache_size": 5})

    def test_only_deviations_saved(self):
        # CFG-004: tiedostoon vain oletuksista poikkeavat arvot; vanhan version jäätyneet oletukset pois
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "c.json")
        with open(path, "w") as f:
            json.dump({**DEFAULTS, "cache_size": 500, "oma_avain": 1}, f)   # kuten vanha versio tallensi
        c = Config(path)
        self.assertEqual(c["upstreams"], DEFAULTS["upstreams"])
        c.update(block_cname=False)
        with open(path) as f:
            self.assertEqual(json.load(f), {"cache_size": 500, "oma_avain": 1, "block_cname": False})
        c.update(cache_size=DEFAULTS["cache_size"], block_cname=True)   # takaisin oletukseen
        with open(path) as f:
            self.assertEqual(json.load(f), {"oma_avain": 1})

    def test_default_list_change_saved_and_defaults_untouched(self):
        # Oletuslistan muokkaus paikallaan (kuten PATCH /api/lists) tallentuu eikä muuta DEFAULTS-arvoa
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "c.json")
        c = Config(path)
        lists = list(c["lists"])
        lists[0]["enabled"] = False
        c.update(lists=lists)
        self.assertTrue(DEFAULTS["lists"][0]["enabled"])
        self.assertFalse(Config(path)["lists"][0]["enabled"])

    def test_example_config_matches_defaults(self):
        # sihti.example.json dokumentoi kaikki avaimet oletusarvoineen
        with open(os.path.join(os.path.dirname(__file__), "..", "sihti.example.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f), DEFAULTS)

    def test_obsolete_password_keys_dropped(self):
        # CFG-005: vanhan version salasana-avaimet jätetään huomiotta ja poistuvat tallennuksessa
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "c.json")
        with open(path, "w") as f:
            json.dump({"password_hash": "pbkdf2$00$00", "random_password": False, "cache_size": 7}, f)
        c = Config(path)
        self.assertNotIn("password_hash", c.data)
        self.assertNotIn("random_password", c.data)
        c.update(cache_size=8)
        with open(path) as f:
            saved = json.load(f)
        self.assertNotIn("password_hash", saved)
        self.assertNotIn("random_password", saved)
        self.assertEqual(saved["cache_size"], 8)


class TestDnsWire(unittest.TestCase):
    def test_roundtrip(self):
        q = make_query("Www.Example.com", 28)
        qid, _f, name, qtype, qend = w.parse_query(q)
        self.assertEqual((name, qtype, qend), ("www.example.com", 28, len(q)))
        r = w.build_response(q, qend, answer_rdata=b"\0" * 16, qtype=28)
        self.assertEqual(r[:2], q[:2])
        self.assertEqual(struct.unpack("!H", r[6:8])[0], 1)
        self.assertEqual(w.min_ttl(r), 2)

    def test_edns_ttl_aging_truncation_and_case(self):
        opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)   # EDNS, DO-bitti
        q = make_query("WWW.Example.com")
        q_edns = q[:10] + struct.pack("!H", 1) + q[12:] + opt
        qend = w.parse_query(q)[4]
        self.assertEqual(w.query_edns(q_edns, qend), (1232, True))
        self.assertEqual(w.query_edns(q, qend), (None, False))
        r = w.build_response(make_query("www.example.com"), qend, answer_rdata=b"\1\2\3\4", qtype=1, ttl=300)
        self.assertEqual(w.min_ttl(w.aged(r, w.ttl_offsets(r), 100)), 200)
        self.assertEqual(w.min_ttl(w.aged(r, w.ttl_offsets(r), 999)), 0)
        same = w.with_question(r, q, qend)   # kysyjän kirjoitusasu ja tunniste
        self.assertEqual((same[:2], same[12:qend]), (q[:2], q[12:qend]))
        tc = w.truncated(q_edns, qend, r)
        self.assertTrue(tc[2] & 0x02)
        self.assertEqual(struct.unpack("!HHHH", tc[4:12]), (1, 0, 0, 1))
        self.assertEqual(w.query_edns(tc, qend), (1232, True), "DO-bitti kopioidaan")

    def test_own_responses_have_opt_for_edns_query(self):
        # DNS-037: Sihdin omiin vastauksiin OPT, kun kyselyssä on EDNS (H-10)
        q = make_query("ads.example.com")
        qend = w.parse_query(q)[4]
        for size, flags, do in ((4096, 0x8000, True), (512, 0, False), (0, 0, False)):
            q_edns = q[:10] + struct.pack("!H", 1) + q[12:] + b"\x00" + struct.pack("!HHIH", 41, size, flags, 0)
            for kw in ({"rc": w.RCODE_NXDOMAIN}, {"rc": w.RCODE_REFUSED}, {"rc": w.RCODE_SERVFAIL},
                       {"answer_rdata": b"\0\0\0\0", "qtype": 1}, {}):
                r = w.build_response(q_edns, qend, **kw)
                self.assertEqual(struct.unpack("!H", r[10:12])[0], 1, kw)
                self.assertEqual(w.query_edns(r, qend), (1232, do), kw)
                self.assertEqual(r[-11:-8], b"\x00\x00\x29", "juurinimi ja tyyppi OPT")
                self.assertEqual(r[-6:-4], b"\x00\x00", "laajennettu koodi 0, versio 0")
                self.assertEqual(r[-2:], b"\x00\x00", "ei EDNS-asetuksia")
                self.assertEqual(w.rcode(r), kw.get("rc", 0))
            r = w.build_response(q_edns, qend, answer_rdata=b"\0\0\0\0", qtype=1, ttl=2)
            self.assertEqual(w.min_ttl(r), 2, "OPT ei vaikuta TTL:ään")
        r = w.build_response(q, qend, rc=w.RCODE_NXDOMAIN)
        self.assertEqual(struct.unpack("!H", r[10:12])[0], 0, "ilman EDNS:ää ei OPT-tietuetta")
        self.assertEqual(len(r), len(q))

    def test_cname_targets(self):
        q = make_query("www.example.com")
        qend = w.parse_query(q)[4]
        target = b"\x03cdn\x07example\x03net\x00"
        r = w.build_response(q, qend)
        r = r[:6] + struct.pack("!H", 1) + r[8:] + struct.pack("!HHHIH", 0xC00C, 5, 1, 60, len(target)) + target
        self.assertEqual(w.cname_targets(r), ["cdn.example.net"])
        self.assertEqual(w.cname_targets(w.build_response(q, qend, answer_rdata=b"\1\2\3\4", qtype=1)), [])
        self.assertEqual(w.cname_targets(b"\0" * 5), [])

    def test_udp_reply_fits_client_size(self):
        from sihti.resolver import _fit_udp
        big = w.build_response(make_query("a.example.com"), w.parse_query(make_query("a.example.com"))[4]) + b"\0" * 3000
        for size, fits in ((None, False), (1232, False), (4096, True)):
            q = make_query("a.example.com")
            if size:
                q = q[:10] + struct.pack("!H", 1) + q[12:] + b"\x00" + struct.pack("!HHIH", 41, size, 0, 0)
            out = _fit_udp(q, big)
            self.assertEqual(out == big, fits, size)
            if not fits:
                self.assertTrue(out[2] & 0x02)

    def test_garbage(self):
        for junk in (b"", b"\x00" * 5, b"\x00" * 12, make_query("a.b")[:-3]):
            with self.assertRaises(w.ParseError):
                w.parse_query(junk)


class TestLearnable(unittest.TestCase):
    def test_rules(self):
        from sihti.tls import learnable
        ok = {"192.168.1.10:4000": "192.168.1.10", "10.0.0.5": "10.0.0.5", "[fd00::5]:4000": "fd00::5",
              "Pi-Toimisto.local:4000": "pi-toimisto.local", "raspberrypi": "raspberrypi", "sihti.lan": "sihti.lan"}
        for raw, want in ok.items():
            self.assertEqual(learnable(raw), want, raw)
        for raw in ("8.8.8.8", "127.0.0.1", "0.0.0.0", "example.com", "pankki.fi:4000", "a b", "", "x" * 300 + ".local"):
            self.assertIsNone(learnable(raw), raw)


class TestListUpdates(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.src = os.path.join(self.dir, "lahde.txt")
        with open(self.src, "w") as f:
            f.write("0.0.0.0 eka.example.com\n")
        cfg_path = os.path.join(self.dir, "sihti.json")
        with open(cfg_path, "w") as f:
            json.dump({"data_dir": self.dir, "lists": [{"url": "file://" + self.src, "enabled": True}]}, f)
        self.cfg = Config(cfg_path)

    def test_unchanged_list_skips_rebuild(self):
        filt = Filter(self.cfg)
        filt.update_lists()
        first = filt.blocked
        self.assertIn("eka.example.com", first)
        filt.update_lists()   # sama sisältö: ei uutta rakennusta
        self.assertIs(filt.blocked, first)
        with open(self.src, "a") as f:
            f.write("0.0.0.0 toka.example.com\n")
        filt.update_lists()
        self.assertIsNot(filt.blocked, first)
        self.assertIn("toka.example.com", filt.blocked)
        self.assertFalse(filt.updating)

    def test_restart_uses_saved_key_and_cache(self):
        Filter(self.cfg).update_lists()
        filt = Filter(self.cfg)   # uudelleenkäynnistys: listaa ei ladata, tiivisteet välimuistista
        filt.update_lists(missing_only=True)
        self.assertIn("eka.example.com", filt.blocked)
        self.assertEqual(filt.blocked.lookup("eka.example.com"), ["file://" + self.src])

    def test_new_list_downloaded_and_removed_files_cleaned(self):
        filt = Filter(self.cfg)
        filt.update_lists()
        other = os.path.join(self.dir, "toinen.txt")
        with open(other, "w") as f:
            f.write("||uusi.example.org^\n")
        self.cfg.update(lists=self.cfg["lists"] + [{"url": "file://" + other, "enabled": True}])
        filt.update_lists(missing_only=True)
        self.assertEqual(len(filt.blocked), 2)
        old_files = {f for f in os.listdir(filt.lists_dir) if f.endswith((".txt", ".fp"))}
        removed = self.cfg["lists"][0]["url"]
        tmp = filt._list_file(removed) + ".tmp"   # keskeytynyt lataus (esim. sähkökatko)
        open(tmp, "w").close()
        self.assertIn(removed, filt._meta)
        self.cfg.update(lists=self.cfg["lists"][1:])
        filt.update_lists(missing_only=True)
        self.assertEqual(len(filt.blocked), 1)
        files = {f for f in os.listdir(filt.lists_dir) if f.endswith((".txt", ".fp"))}
        self.assertEqual(len(old_files - files), 2, "poistetun listan tiedosto ja välimuisti pois")
        self.assertFalse(os.path.exists(tmp), "keskeytyneen latauksen väliaikaistiedosto pois")
        self.assertNotIn(removed, filt._meta)
        self.assertNotIn(removed, filt.list_status)
        with open(os.path.join(filt.lists_dir, "tila.json")) as f:
            self.assertNotIn(removed, json.load(f), "poistetun listan tiedot pois levyltä")

    def _lists(self, **files):
        urls = []
        for name, text in files.items():
            path = os.path.join(self.dir, name + ".txt")
            with open(path, "w") as f:
                f.write(text)
            urls.append({"url": "file://" + path, "enabled": True})
        self.cfg.update(lists=urls)
        return [u["url"] for u in urls]

    def test_redundant_list_skipped_and_rechecked(self):
        from unittest import mock
        import sihti.filtering as F
        big, small, other = self._lists(iso="a.example.com\nb.example.com\nc.example.com\n",
                                        pieni="a.example.com\nb.example.com\n", muu="x.example.org\n")
        filt = Filter(self.cfg)
        filt.update_lists()
        self.assertEqual(len(filt.blocked), 4)
        self.assertIsNotNone(filt.skipped_until({"url": small, "enabled": True}))
        self.assertEqual(filt.list_counts(), (2, 1))
        self.assertEqual((filt.list_status[big]["unique"], filt.list_status[other]["unique"]), (3, 1))
        with open(os.path.join(filt.lists_dir, "tila.json")) as f:
            self.assertIn("redundant_since", json.load(f)[small])

        # Päivittäinen päivitys ei lataa ohitettua listaa, eikä joukkoa rakenneta turhaan
        first = filt.blocked
        with mock.patch.object(filt, "_download", wraps=filt._download) as dl:
            filt.update_lists()
        self.assertEqual(sorted(c.args[0] for c in dl.call_args_list), sorted([big, other]))
        self.assertIs(filt.blocked, first)

        # Viikon päästä lista tarkistetaan: yhä päällekkäinen -> ohitus jatkuu
        filt._meta[small]["redundant_since"] -= F.REDUNDANT_RECHECK + 1
        with mock.patch.object(filt, "_download", wraps=filt._download) as dl:
            filt.update_lists()
        self.assertIn(small, [c.args[0] for c in dl.call_args_list])
        self.assertIsNotNone(filt.skipped_until({"url": small, "enabled": True}))

        # Listaan tulee oma nimi: seuraavassa tarkistuksessa se otetaan takaisin käyttöön
        with open(small[len("file://"):], "a") as f:
            f.write("uusi.example.net\n")
        filt._meta[small]["redundant_since"] -= F.REDUNDANT_RECHECK + 1
        filt.update_lists()
        self.assertIsNone(filt.skipped_until({"url": small, "enabled": True}))
        self.assertIn("uusi.example.net", filt.blocked)
        self.assertEqual(filt.list_counts(), (3, 0))

    def test_keep_and_setting_disable_skipping(self):
        big, small = self._lists(iso="a.example.com\nb.example.com\n", pieni="a.example.com\n")
        filt = Filter(self.cfg)
        filt.update_lists()
        self.assertEqual(filt.list_counts(), (1, 1))
        self.cfg.update(lists=[self.cfg["lists"][0], {**self.cfg["lists"][1], "keep": True}])
        filt.update_lists()
        self.assertEqual(filt.list_counts(), (2, 0))
        self.assertEqual(filt.list_status[small]["unique"], 0)
        self.cfg.update(lists=[self.cfg["lists"][0], {**self.cfg["lists"][1], "keep": False}],
                        skip_redundant_lists=False)
        filt._built_sig = None
        filt.update_lists()
        self.assertEqual(filt.list_counts(), (2, 0))

    def test_crashed_build_keeps_old_set(self):
        from unittest import mock
        from concurrent.futures.process import BrokenProcessPool
        import sihti.filtering as F
        filt = Filter(self.cfg)
        filt.update_lists()
        first = filt.blocked
        with open(self.src, "a") as f:
            f.write("0.0.0.0 toka.example.com\n")
        broken = mock.MagicMock()
        broken.submit.return_value.result.side_effect = BrokenProcessPool()
        with mock.patch.object(F, "ProcessPoolExecutor", return_value=broken), \
                self.assertLogs("sihti.suodatin", "ERROR"):
            filt.update_lists()
        self.assertIs(filt.blocked, first)
        self.assertIn("muisti", filt.build_error)
        self.assertFalse(filt.updating, "kaatunut rakennus ei saa jäädä roikkumaan")
        filt.update_lists()   # seuraava yritys onnistuu
        self.assertIn("toka.example.com", filt.blocked)
        self.assertIsNone(filt.build_error)

    def test_stuck_build_times_out(self):
        from unittest import mock
        import sihti.filtering as F
        filt = Filter(self.cfg)
        stuck = mock.MagicMock()
        stuck.submit.return_value.result.side_effect = F.FutureTimeout()
        with mock.patch.object(F, "ProcessPoolExecutor", return_value=stuck), \
                self.assertLogs("sihti.suodatin", "ERROR"):
            filt.update_lists()
        self.assertIn("keskeytettiin", filt.build_error)
        self.assertFalse(filt.updating)
        self.assertIsNone(filt.progress())

    def test_progress_reported_during_download(self):
        import functools
        from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

        class Slow(SimpleHTTPRequestHandler):
            def do_GET(self):
                time.sleep(1)
                super().do_GET()

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Slow, directory=self.dir))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.cfg.update(lists=[{"url": f"http://127.0.0.1:{srv.server_address[1]}/lahde.txt", "enabled": True}])
        filt = Filter(self.cfg)
        filt.update_async()
        time.sleep(0.5)
        self.assertTrue(filt.updating)
        self.assertEqual({k: v for k, v in filt.progress().items() if k != "elapsed"},
                         {"phase": "lataus", "done": 0, "total": 1})
        for _ in range(100):
            if not filt.updating:
                break
            time.sleep(0.1)
        self.assertFalse(filt.updating)
        self.assertIsNone(filt.progress())
        self.assertIn("eka.example.com", filt.blocked)

    def test_updater_loop_survives_errors(self):
        from unittest import mock
        filt = Filter(self.cfg)
        stop = threading.Event()
        stop.set()
        with mock.patch.object(filt, "update_lists", side_effect=OSError("levy täynnä")) as upd, \
                self.assertLogs("sihti.suodatin", "ERROR"):
            filt.updater_loop(stop)   # ei saa kaatua; palaa, koska stop on asetettu
        upd.assert_called_once_with(True)


class TestUpdateSchedule(unittest.TestCase):
    """Automaattinen päivitys asetuksen välein: aika lasketaan levylle tallennetusta viimeisimmästä
    päivityksestä, joten uudelleenkäynnistys ei siirrä sitä."""
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.src = os.path.join(self.dir, "lahde.txt")
        with open(self.src, "w") as f:
            f.write("0.0.0.0 eka.example.com\n")
        path = os.path.join(self.dir, "sihti.json")
        with open(path, "w") as f:
            json.dump({"data_dir": self.dir, "lists": [{"url": "file://" + self.src, "enabled": True}]}, f)
        self.cfg = Config(path)

    def run_loop(self, filt):
        """Ajaa updater_loopin yhden kierroksen ja palauttaa tehdyt päivitykset."""
        from unittest import mock
        calls = []
        real = filt.update_lists

        def record(missing_only=False):
            calls.append("puuttuvat" if missing_only else "täysi")
            real(missing_only)
        stop = mock.Mock()
        stop.wait.return_value = True
        with mock.patch.object(filt, "update_lists", side_effect=record):
            filt.updater_loop(stop)
        return calls

    def test_first_install_counts_as_full_update(self):
        filt = Filter(self.cfg)
        self.assertEqual(self.run_loop(filt), ["puuttuvat"])   # kaikki listat ladattiin: ei toista kierrosta
        self.assertAlmostEqual(filt.last_update, time.time(), delta=5)
        self.assertAlmostEqual(Filter(self.cfg).last_update, filt.last_update, delta=0.01, msg="tallessa levyllä")

    def test_restart_keeps_schedule(self):
        filt = Filter(self.cfg)
        filt.update_lists()
        filt.last_update = time.time() - 20 * 3600
        filt._save_last_update()
        restarted = Filter(self.cfg)
        self.assertAlmostEqual(restarted.next_update(), time.time() + 4 * 3600, delta=5)
        self.assertEqual(self.run_loop(restarted), ["puuttuvat"], "ei vielä täyttä päivitystä")
        restarted.last_update = time.time() - 25 * 3600
        restarted._save_last_update()
        self.assertEqual(self.run_loop(Filter(self.cfg)), ["puuttuvat", "täysi"], "myöhässä: päivitetään heti")

    def test_interval_change_applies_immediately(self):
        filt = Filter(self.cfg)
        filt.update_lists()
        filt.last_update = time.time() - 7 * 3600
        self.assertGreater(filt.next_update(), time.time())
        self.cfg.update(update_interval_hours=6)
        self.assertLess(filt.next_update(), time.time())

    def test_failed_update_retried_in_an_hour(self):
        filt = Filter(self.cfg)
        filt.update_lists()
        self.cfg.update(lists=self.cfg["lists"] + [{"url": "http://127.0.0.1:9/ei-vastaa.txt", "enabled": True}])
        with self.assertLogs("sihti.suodatin", "WARNING"):
            filt.update_lists()
        self.assertAlmostEqual(filt.next_update(), time.time() + 3600, delta=5)
        self.cfg.update(lists=self.cfg["lists"][:1])
        filt.update_lists()
        self.assertAlmostEqual(filt.next_update(), time.time() + 24 * 3600, delta=5)

    def test_adding_list_does_not_postpone_update(self):
        filt = Filter(self.cfg)
        filt.update_lists()
        filt.last_update = before = time.time() - 10 * 3600
        filt._save_last_update()
        other = os.path.join(self.dir, "uusi.txt")
        with open(other, "w") as f:
            f.write("0.0.0.0 toka.example.com\n")
        self.cfg.update(lists=self.cfg["lists"] + [{"url": "file://" + other, "enabled": True}])
        filt.update_lists(missing_only=True)
        self.assertIn("toka.example.com", filt.blocked)
        self.assertEqual(filt.last_update, before)


class TestBackup(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        path = os.path.join(self.dir, "sihti.json")
        with open(path, "w") as f:
            json.dump({"data_dir": self.dir, "lists": [{"url": "https://lista.example/a.txt", "enabled": True}]}, f)
        self.cfg = Config(path)
        self.filt = Filter(self.cfg)
        patcher = mock.patch.object(self.filt, "reanalyze")   # ei latauksia taustalla
        patcher.start()
        self.addCleanup(patcher.stop)
        qlog = QueryLog(self.cfg)
        self.app = App(self.cfg, self.filt, qlog, Resolver(self.cfg, self.filt, qlog))

    def test_roundtrip(self):
        self.filt.add_custom("deny", "oma.example.com")
        self.filt.add_custom("deny_regex", "^seuranta")
        self.app.apply_settings({"local_dns": "192.168.1.1", "block_cname": False})
        backup = json.loads(json.dumps(self.app.api("GET", "/api/backup", {}, {})))
        self.assertNotIn("password_hash", backup["settings"])

        # Toinen laite / uusi asennus: kaikki toisin
        self.cfg.update(lists=[], local_dns="", block_cname=True)
        self.filt.replace_custom([], [], [])
        r = self.app.api("POST", "/api/backup", {}, backup)
        self.assertEqual((r["lists"], r["rules"], r["skipped"]), (1, 2, []))
        self.assertEqual(self.cfg["lists"][0]["url"], "https://lista.example/a.txt")
        self.assertEqual((self.cfg["local_dns"], self.cfg["block_cname"]), ("192.168.1.1", False))
        self.assertEqual(self.filt.deny, {"oma.example.com"})
        self.assertTrue(self.filt.check("seuranta.example.org")[0])
        self.filt.reanalyze.assert_called()

    def test_invalid_backup_changes_nothing(self):
        for bad in ({"jotain": 1}, {"sihti_backup": 1, "lists": [{"url": "ftp://x"}]},
                    {"sihti_backup": 1, "settings": {"allowed_networks": ["ei verkko"]}},
                    {"sihti_backup": 1, "settings": {"local_dns": "reititin.lan"}},
                    {"sihti_backup": 1, "settings": {"cache_size": "paljon"}, "lists": []},
                    {"sihti_backup": 1, "settings": {"log_retention_days": -1}, "lists": []}):
            with self.assertRaises(ValueError):
                self.app.restore_backup(bad)
        self.assertEqual(len(self.cfg["lists"]), 1)
        self.assertEqual(self.cfg["allowed_networks"], [])
        self.assertEqual(self.cfg["cache_size"], DEFAULTS["cache_size"])

    def test_numeric_settings_validated(self):
        # CFG-022: kokonaisluku sallitulta väliltä, myös merkkijonona; muu hylätään eikä mitään tallenneta
        self.app.apply_settings({"cache_size": "5000", "log_retention_days": 14.0, "update_interval_hours": 12})
        self.assertEqual((self.cfg["cache_size"], self.cfg["log_retention_days"], self.cfg["update_interval_hours"]),
                         (5000, 14, 12))
        self.assertEqual(self.app.resolver.cache.size, 5000)
        for key, bad in (("cache_size", "abc"), ("cache_size", -1), ("cache_size", 1_000_001),
                         ("log_retention_days", 0), ("log_retention_days", 7.5), ("log_retention_days", True),
                         ("update_interval_hours", 721), ("update_interval_hours", None),
                         ("update_interval_hours", [24])):
            with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                self.app.apply_settings({key: bad, "local_dns": "10.0.0.1"})
        self.assertEqual(self.cfg["cache_size"], 5000)
        self.assertEqual(self.cfg["local_dns"], "")


class TestLogin(unittest.TestCase):
    """WEB-012, WEB-013, WEB-017: istuntojen siivous ja yläraja, arvailun rajoitus, lokitus."""
    def setUp(self):
        from sihti import web
        self.web = web
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        path = os.path.join(self.dir, "sihti.json")
        with open(path, "w") as f:
            json.dump({"data_dir": self.dir, "lists": []}, f)
        self.cfg = Config(path)
        filt = Filter(self.cfg)
        qlog = QueryLog(self.cfg)
        self.app = App(self.cfg, filt, qlog, Resolver(self.cfg, filt, qlog), password_hash=web.hash_password("oikea"))

    def test_sessions_pruned_and_capped(self):
        old = self.app.new_session()
        self.app.sessions[old] = time.time() - 1   # vanhentunut
        tokens = [self.app.new_session() for _ in range(self.web.SESSION_MAX + 5)]
        self.assertNotIn(old, self.app.sessions)
        self.assertEqual(len(self.app.sessions), self.web.SESSION_MAX)
        self.assertFalse(self.app.valid_session(tokens[0]), "vanhin poistuu, kun yläraja täyttyy")
        self.assertTrue(self.app.valid_session(tokens[-1]))

    def test_wrong_passwords_checked_one_at_a_time(self):
        from unittest import mock
        with mock.patch.object(self.web, "LOGIN_FAIL_DELAY", 0.3):
            t0 = time.monotonic()
            threads = [threading.Thread(target=self.app.login, args=("väärä", "192.168.1.9")) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertGreaterEqual(time.monotonic() - t0, 0.9, "rinnakkaiset yritykset odottavat vuoroaan")
        self.assertIsNotNone(self.app.login("oikea", "192.168.1.9"))

    def test_failed_logins_logged_at_most_once_a_minute(self):
        from unittest import mock
        with mock.patch.object(self.web, "LOGIN_FAIL_DELAY", 0), \
                self.assertLogs("sihti.web", "WARNING") as logs:
            self.assertIsNone(self.app.login("väärä", "192.168.1.9"))
            self.assertIsNone(self.app.login("väärä", "192.168.1.10"))
        self.assertEqual(len(logs.records), 1)
        self.assertIn("192.168.1.9", logs.output[0])
        self.app._fail_warned -= self.web.LOGIN_WARN_INTERVAL   # minuutti kulunut
        with mock.patch.object(self.web, "LOGIN_FAIL_DELAY", 0), \
                self.assertLogs("sihti.web", "WARNING") as logs:
            self.app.login("väärä", "192.168.1.11")
        self.assertIn("jälkeen: 2)", logs.output[0])


def _ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


class TestIPv6(unittest.TestCase):
    @unittest.skipUnless(_ipv6_available(), "ei IPv6:ta tässä ympäristössä")
    def test_dual_stack(self):
        class Echo:
            def handle(self, data, client, tcp=False):
                qend = w.parse_query(data)[4]
                return w.build_response(data, qend, answer_rdata=bytes([9, 9, 9, 9]), qtype=1)
        port = free_port(socket.SOCK_DGRAM)
        servers = start_servers(Echo(), "0.0.0.0", port, ipv6=True)
        self.addCleanup(lambda: [(s.shutdown(), s.server_close()) for s in servers])
        self.assertEqual(len(servers), 4)
        for host, fam in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
            msg = make_query("a.example.org")
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(msg, (host, port))
                self.assertEqual(answer_ip(s.recv(512)), "9.9.9.9", host)

    def test_falls_back_to_ipv4(self):
        from unittest import mock
        import sihti.resolver as R
        real = R._bind

        def no_ipv6(resolver, host, port, v6only=False):
            if host == "::":
                raise OSError(97, "Address family not supported by protocol")
            return real(resolver, host, port, v6only)
        with mock.patch.object(R, "_bind", side_effect=no_ipv6):
            servers = start_servers(object(), "0.0.0.0", free_port(socket.SOCK_DGRAM), ipv6=True)
        self.addCleanup(lambda: [(s.shutdown(), s.server_close()) for s in servers])
        self.assertEqual(len(servers), 2)


class TestQueryLogMigration(unittest.TestCase):
    def test_old_database_gets_detail_column(self):
        import sqlite3
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        db = sqlite3.connect(os.path.join(d, "kyselyt.db"))
        db.executescript("CREATE TABLE kyselyt (ts REAL NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL, "
                         "qtype TEXT NOT NULL, status TEXT NOT NULL, reason TEXT, ms REAL);")
        db.execute("INSERT INTO kyselyt VALUES (?,?,?,?,?,?,?)", (time.time(), "10.0.0.2", "vanha.fi", "A", "estetty", "lista", 0.1))
        db.commit()
        db.close()
        qlog = QueryLog({"data_dir": d, "log_queries": True, "log_retention_days": 7})
        qlog.flush_interval = 0
        qlog.add("10.0.0.3", "uusi.fi", "A", "estetty", "oma", 0.2, "uusi.fi")
        stop = threading.Event()
        t = threading.Thread(target=qlog.writer_loop, args=(stop,))
        t.start()
        self.addCleanup(t.join)
        self.addCleanup(qlog.wake)
        self.addCleanup(stop.set)
        time.sleep(1.5)
        rows = {r["domain"]: r for r in qlog.recent()}
        self.assertIsNone(rows["vanha.fi"]["detail"])
        self.assertEqual(rows["uusi.fi"]["detail"], "uusi.fi")
        self.assertEqual(qlog.summary()["blocked_domains"], 2)
        qlog.add("10.0.0.4", "kolmas.fi", "A", "estetty", "oma", 0.2, "kolmas.fi")
        time.sleep(1.5)
        self.assertEqual(qlog.summary()["blocked_domains"], 2, "tulos välimuistista")
        qlog.summary_ttl = 0
        self.assertEqual(qlog.summary()["blocked_domains"], 3)
        qlog._rdb.close()


class TestIdleWakeups(unittest.TestCase):
    """GEN-008: tyhjäkäynnillä säikeet eivät herää turhaan."""
    def test_intervals(self):
        from sihti import querylog
        self.assertEqual(PROD_SERVE_POLL, 5)
        self.assertEqual(querylog.FLUSH_INTERVAL, 10)
        self.assertEqual(querylog.IDLE_WAIT, 60)


class TestQueryLogWriter(unittest.TestCase):
    """LOG-009: tietokantavirhe ei pysäytä kirjoitussäiettä (H-14)."""
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.qlog = QueryLog({"data_dir": self.dir, "log_queries": True, "log_retention_days": 7})
        self.qlog.summary_ttl = 0
        self.qlog.flush_interval = 0

    def wait(self, cond, timeout=10):
        deadline = time.time() + timeout
        while not cond() and time.time() < deadline:
            time.sleep(0.05)
        return cond()

    def start_writer(self):
        stop = threading.Event()
        t = threading.Thread(target=self.qlog.writer_loop, args=(stop,))
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(self.qlog.wake)
        self.addCleanup(stop.set)
        return stop, t

    def test_rows_saved_together_after_flush_interval(self):
        """LOG-004: rivit kerätään ja tallennetaan yhdellä kertaa, ei jokaista erikseen."""
        self.qlog.flush_interval = 1
        self.qlog.add("10.0.0.2", "eka.fi", "A", "sallittu")
        self.start_writer()
        time.sleep(0.3)
        self.qlog.add("10.0.0.2", "toka.fi", "A", "sallittu")
        self.assertEqual(self.qlog.recent(), [], "ei tallenneta ennen keräysajan loppua")
        self.assertTrue(self.wait(lambda: len(self.qlog.recent()) == 2))
        self.qlog._rdb.close()

    def test_stop_saves_collected_rows(self):
        """GEN-007: pysäytys keskeyttää keräyksen, ja kerätyt rivit tallennetaan heti."""
        self.qlog.flush_interval = 60
        self.qlog.add("10.0.0.2", "eka.fi", "A", "sallittu")
        stop, t = self.start_writer()
        time.sleep(0.3)
        stop.set()
        t.join(3)
        self.assertFalse(t.is_alive())
        self.assertEqual([r["domain"] for r in self.qlog.recent()], ["eka.fi"])
        self.qlog._rdb.close()

    def test_wake_stops_idle_writer(self):
        """Tyhjää jonoa odottava säie pysähtyy heti wake()-kutsusta, ei vasta IDLE_WAIT-ajan jälkeen."""
        stop, t = self.start_writer()
        time.sleep(0.3)
        stop.set()
        self.qlog.wake()
        t.join(3)
        self.assertFalse(t.is_alive())

    def test_write_error_retried_and_reported(self):
        import sqlite3
        from sihti import querylog
        self.addCleanup(setattr, querylog, "RETRY_DELAY", querylog.RETRY_DELAY)
        querylog.RETRY_DELAY = 0.1
        real, calls = self.qlog._connect, []

        def flaky():   # levy täynnä kahdesti, sitten toimii
            calls.append(1)
            if len(calls) <= 2:
                raise sqlite3.OperationalError("database or disk is full")
            return real()
        self.qlog._connect = flaky
        self.qlog.add("10.0.0.2", "eka.fi", "A", "sallittu")
        stop = threading.Event()
        t = threading.Thread(target=self.qlog.writer_loop, args=(stop,))
        with self.assertLogs("sihti.loki", "INFO") as logs:
            t.start()
            self.addCleanup(t.join)
            self.addCleanup(self.qlog.wake)
            self.addCleanup(stop.set)
            self.assertTrue(self.wait(lambda: self.qlog.write_error is not None))
            self.assertIn("disk is full", self.qlog.write_error)
            self.assertTrue(self.wait(lambda: self.qlog.write_error is None), "toipuu virheestä")
        self.assertTrue(t.is_alive(), "säie jatkaa virheen jälkeen")
        errors = [r for r in logs.records if r.levelname == "ERROR"]
        self.assertEqual(len(errors), 1, "toistuva virhe kirjataan enintään kerran minuutissa")
        self.assertIn("toimii taas", logs.output[-1])
        self.qlog.add("10.0.0.2", "toka.fi", "A", "sallittu")
        self.assertTrue(self.wait(lambda: len(self.qlog.recent()) == 2), "epäonnistunut erä kirjoitettiin uudelleen")
        self.assertEqual({r["domain"] for r in self.qlog.recent()}, {"eka.fi", "toka.fi"})
        self.qlog._rdb.close()

    def test_full_queue_counts_dropped(self):
        import queue as q
        self.qlog._q = q.Queue(maxsize=2)
        for i in range(5):
            self.qlog.add("10.0.0.2", f"n{i}.fi", "A", "sallittu")
        self.assertEqual(self.qlog.dropped, 3)

    def test_read_error_does_not_break_status(self):
        import sqlite3

        def broken(*_a):
            raise sqlite3.DatabaseError("database disk image is malformed")
        self.qlog._rows = broken
        with self.assertLogs("sihti.loki", "ERROR"):
            s = self.qlog.summary()
        self.assertEqual((s["total"], s["blocked"]), (0, 0))
        self.assertIn("malformed", self.qlog.read_error)


# ------------------------------------------------------------- integraatiotesti

class TestService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        lst = os.path.join(cls.dir, "lista.txt")
        with open(lst, "w") as f:
            f.write("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n")
        cls.up = FakeUpstream()
        cls.up.start()
        cls.dns_port = free_port(socket.SOCK_DGRAM)
        cls.web_port = free_port()
        cfg_path = os.path.join(cls.dir, "sihti.json")
        with open(cfg_path, "w") as f:
            json.dump({"dns_listen": "127.0.0.1", "dns_port": cls.dns_port,
                       "web_listen": "127.0.0.1", "web_port": cls.web_port,
                       "upstreams": [f"127.0.0.1:{cls.up.port}"], "data_dir": cls.dir,
                       "lists": [{"url": "file://" + lst, "enabled": True}]}, f)
        cls.cfg = Config(cfg_path)
        cls.filt = Filter(cls.cfg)
        cls.filt.update_lists()
        cls.qlog = QueryLog(cls.cfg)
        cls.qlog.summary_ttl = 0   # testit tarkistavat luvut heti kyselyjen jälkeen
        cls.qlog.flush_interval = 0
        cls.stop = threading.Event()
        threading.Thread(target=cls.qlog.writer_loop, args=(cls.stop,), daemon=True).start()
        cls.resolver = Resolver(cls.cfg, cls.filt, cls.qlog)
        cls.servers = start_servers(cls.resolver, "127.0.0.1", cls.dns_port)

        cls.certs, ctx = None, None
        if shutil.which("openssl"):
            from sihti.tls import CertManager
            cls.certs = CertManager(cls.cfg)
            ctx = cls.certs.build_context()
        cls.servers.append(start_web(App(cls.cfg, cls.filt, cls.qlog, cls.resolver, cls.certs),
                                     "127.0.0.1", cls.web_port, ctx))
        cls.base = f"{'https' if ctx else 'http'}://localhost:{cls.web_port}"
        cls.ssl = ssl.create_default_context(cafile=cls.certs.ca_crt) if ctx else None

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()
        for s in cls.servers:
            s.shutdown()
            s.server_close()
        cls.up.sock.close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def api(self, path, method="GET", body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-Sihti": "1", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=self.ssl, timeout=5) as r:
            return json.load(r)

    def test_allowed_and_cached(self):
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "hyva.example.org")), "1.2.3.4")
        before = self.up.count
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "hyva.example.org")), "1.2.3.4")
        self.assertEqual(self.up.count, before, "toisen vastauksen pitäisi tulla välimuistista")

    def test_cached_ttl_counts_down(self):
        first = udp_ask(self.dns_port, "ttl.example.org")
        time.sleep(1.2)
        second = udp_ask(self.dns_port, "ttl.example.org")
        self.assertEqual(w.min_ttl(first), 300)
        self.assertLess(w.min_ttl(second), 300)

    def test_silent_upstream_moved_last(self):
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # ottaa vastaan, ei vastaa
        silent.bind(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        cfg = {**DEFAULTS, "upstreams": [f"127.0.0.1:{silent.getsockname()[1]}", f"127.0.0.1:{self.up.port}"],
               "upstream_timeout": 0.5, "cache_size": 0}
        res = Resolver(cfg, self.filt, self.qlog)
        times = []
        for i in range(3):
            t = time.monotonic()
            self.assertEqual(answer_ip(res.handle(make_query(f"uusi{i}.example.org"), "127.0.0.1")), "1.2.3.4")
            times.append(time.monotonic() - t)
        self.assertGreaterEqual(times[0], 0.5)
        self.assertLess(max(times[1:]), 0.2, "vastaamaton ylävirta pitää kokeilla viimeisenä")

    def _resolver(self, **cfg):
        return Resolver({**DEFAULTS, "upstreams": [f"127.0.0.1:{self.up.port}"], "cache_size": 100, **cfg},
                        self.filt, self.qlog)

    def test_bypass_test_names_answered_nxdomain(self):
        before = self.up.count
        for name in ("use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"):
            self.assertEqual(udp_ask(self.dns_port, name)[3] & 0x0F, w.RCODE_NXDOMAIN, name)
        self.assertEqual(self.up.count, before, "testinimiä ei kysytä internetistä")
        res = self._resolver(block_dns_bypass=False)
        self.assertEqual(answer_ip(res.handle(make_query("mask.icloud.com"), "127.0.0.1")), "1.2.3.4")
        self.api("/api/custom", "POST", {"kind": "allow", "value": "mask-h2.icloud.com"})   # oma sallinta voittaa
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "mask-h2.icloud.com")), "1.2.3.4")

    def test_bypass_blocked_when_paused_or_disabled_unless_allowed(self):
        # DNS-012: ohitusten esto ei riipu tauosta eikä suodatuksen kytkimestä (H-07)
        res = self._resolver(cache_size=0)
        name = "use-application-dns.net"
        rc = lambda: w.rcode(res.handle(make_query(name), "127.0.0.1"))   # noqa: E731
        self.filt.pause(60)
        self.addCleanup(self.filt.pause, 0)
        self.assertFalse(self.filt.active)
        self.assertEqual(rc(), w.RCODE_NXDOMAIN, "tauko ei salli ohitusta")
        self.assertEqual(answer_ip(res.handle(make_query("ads.example.com"), "127.0.0.1")), "1.2.3.4",
                         "tauolla listan nimi välitetään")
        self.filt.pause(0)
        self.cfg.data["blocking_enabled"] = False
        self.addCleanup(self.cfg.data.__setitem__, "blocking_enabled", True)
        self.assertEqual(rc(), w.RCODE_NXDOMAIN, "pois päältä oleva suodatus ei salli ohitusta")
        self.filt.pause(60)
        self.filt.add_custom("allow", name)   # oma sallinta voittaa myös tauolla / pois-tilassa
        self.addCleanup(self.filt.remove_custom, "allow", name)
        self.assertEqual(answer_ip(res.handle(make_query(name), "127.0.0.1")), "1.2.3.4")

    def test_only_local_clients_answered(self):
        from unittest import mock
        import sihti.resolver as R
        res = self._resolver(allowed_networks=["8.8.4.0/24"])
        q = make_query("a.example.org")
        for client in ("192.168.1.20", "10.0.0.3", "172.20.1.1", "127.0.0.1", "fd00::20", "fe80::1%eth0",
                       "100.64.1.2", "::ffff:192.168.1.20", "8.8.4.4"):
            self.assertEqual(answer_ip(res.handle(q, client)), "1.2.3.4", client)
        with self.assertLogs("sihti.dns", "WARNING"):
            for client in ("8.8.8.8", "2a00:1450:4001::1", "::ffff:8.8.8.8"):
                self.assertEqual(res.handle(q, client)[3] & 0x0F, w.RCODE_REFUSED, client)
        # Kotiverkon julkinen IPv6-osoite kelpaa, kun se on koneen omassa verkossa
        with mock.patch.object(R, "_own_ipv6_networks",
                               return_value=[__import__("ipaddress").ip_network("2a00:1450:4001::/48")]):
            res2 = self._resolver()
            self.assertEqual(answer_ip(res2.handle(q, "2a00:1450:4001::1")), "1.2.3.4")
        self.assertEqual(answer_ip(self._resolver(local_clients_only=False).handle(q, "8.8.8.8")), "1.2.3.4")
        # Heti laitteen käynnistyksen jälkeen (monotoninen kello pieni) omat verkot pitää silti tunnistaa
        with mock.patch.object(R.time, "monotonic", return_value=5.0), \
                mock.patch.object(R, "_own_ipv6_networks",
                                  return_value=[__import__("ipaddress").ip_network("2a00:1450:4001::/48")]):
            self.assertEqual(answer_ip(self._resolver().handle(q, "2a00:1450:4001::1")), "1.2.3.4")
            with self.assertLogs("sihti.dns", "WARNING"):
                self._resolver().handle(q, "8.8.8.8")

    def test_cname_to_blocked_name_is_blocked(self):
        for _ in range(2):   # myös välimuistista
            self.assertEqual(answer_ip(udp_ask(self.dns_port, "piilo.uutiset.example.org")), "0.0.0.0")
        time.sleep(1.5)
        row = self.api("/api/log?search=piilo.uutiset.example.org")[0]
        self.assertEqual((row["status"], row["reason"], row["detail"]), ("estetty", "cname", "tracker.example.net"))
        res = self._resolver(block_cname=False)
        self.assertEqual(answer_ip(res.handle(make_query("piilo.toinen.example.org"), "127.0.0.1")), "5.6.7.8")

    def test_local_names_go_to_router(self):
        router = FakeUpstream()
        router.start()
        self.addCleanup(router.sock.close)
        res = self._resolver(local_dns=f"127.0.0.1:{router.port}", cache_size=0)
        before = self.up.count
        for name, qtype in (("nas.lan", 1), ("nas", 1), ("tulostin.home.arpa", 1), ("20.1.168.192.in-addr.arpa", 12),
                            ("5.0.0.10.in-addr.arpa", 12), ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", 12)):
            res.handle(make_query(name, qtype), "127.0.0.1")
        self.assertEqual((router.count, self.up.count - before), (6, 0))
        res.handle(make_query("www.example.org"), "127.0.0.1")
        res.handle(make_query("8.8.8.8.in-addr.arpa", 12), "127.0.0.1")
        self.assertEqual((router.count, self.up.count - before), (6, 2))

    def test_blocked_udp_tcp_ipv6(self):
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "ads.example.com")), "0.0.0.0")
        self.assertEqual(answer_ip(tcp_ask(self.dns_port, "tracker.example.net")), "0.0.0.0")
        r = udp_ask(self.dns_port, "ads.example.com", 28)
        self.assertEqual(r[-16:], b"\0" * 16)

    def test_invalid_tld_answered_locally(self):
        before = self.up.count
        self.assertEqual(udp_ask(self.dns_port, "jotain.invalid")[3] & 0x0F, w.RCODE_NXDOMAIN)
        self.assertEqual(self.up.count, before)

    def test_custom_rules_via_api(self):
        r = self.api("/api/custom", "POST", {"kind": "deny", "value": "https://oma.example.com/x\n*.toinen.example.com\nroskaa!"})
        self.assertEqual(r["added"], ["oma.example.com", "toinen.example.com"])
        self.assertEqual(r["invalid"], ["roskaa!"])
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "ali.oma.example.com")), "0.0.0.0")
        self.api("/api/custom", "POST", {"kind": "allow", "value": "ali.oma.example.com"})
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "ali.oma.example.com")), "1.2.3.4")

    def test_settings_limits_and_invalid_number(self):
        # CFG-022: rajat tulevat rajapinnasta, ja virheellinen arvo saa 400 eikä kaada DNS:ää
        self.assertEqual(self.api("/api/settings")["limits"]["log_retention_days"], [1, 365])
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.api("/api/settings", "POST", {"cache_size": "abc"})
        self.assertEqual(e.exception.code, 400)
        self.assertIn("välimuistin koon", json.load(e.exception)["error"])
        self.assertEqual(answer_ip(udp_ask(self.dns_port, "h01.example.org")), "1.2.3.4")

    def test_pause_validated_and_not_saved(self):
        # API-020, FLT-060: tauko 0–86 400 s kokonaislukuna, vain muistissa (H-08)
        self.addCleanup(self.filt.pause, 0)
        for bad in (-1, 86401, 1.5, "abc", None, True, [60]):
            with self.assertRaises(urllib.error.HTTPError, msg=repr(bad)) as e:
                self.api("/api/blocking", "POST", {"pause_seconds": bad, "enabled": False})
            self.assertEqual(e.exception.code, 400)
            self.assertIn("tauon pitää olla kokonaisluku 0–86 400 sekuntia", json.load(e.exception)["error"])
            self.assertTrue(self.cfg["blocking_enabled"], "hylätty pyyntö ei saa muuttaa mitään")
            self.assertIsNone(self.filt.pause_until)
        r = self.api("/api/blocking", "POST", {"pause_seconds": "86400"})
        self.assertFalse(r["blocking"])
        self.assertAlmostEqual(r["pause_until"], time.time() + 86400, delta=5)
        with open(self.cfg.path, encoding="utf-8") as f:
            self.assertNotIn("pause", f.read(), "tauko ei säily uudelleenkäynnistyksen yli")
        self.assertTrue(self.api("/api/blocking", "POST", {"pause_seconds": 0})["blocking"])

    def test_stats_hours_and_log_limit_validated(self):
        # API-016, API-013: aikaväli 1 h – säilytysaika, lokirivit 1–2000 (H-13)
        self.assertIn(len(self.api("/api/timeline?hours=168")), (168 * 6 + 1, 168 * 6 + 2))
        self.assertIn("blocked", self.api("/api/top?hours=1"))
        for path in ("/api/timeline?hours=169", "/api/timeline?hours=0", "/api/timeline?hours=10000000",
                     "/api/top?hours=-5", "/api/top?hours=abc", "/api/timeline?hours=1.5"):
            with self.assertRaises(urllib.error.HTTPError, msg=path) as e:
                self.api(path)
            self.assertEqual(e.exception.code, 400)
            self.assertIn("aikavälin pitää olla kokonaisluku 1–168 tuntia", json.load(e.exception)["error"])
        for i in range(3):
            udp_ask(self.dns_port, f"raja{i}.example.org")
        deadline = time.time() + 5
        while len(self.api("/api/log?limit=2000")) < 3 and time.time() < deadline:
            time.sleep(0.1)
        self.assertEqual(len(self.api("/api/log?limit=1")), 1)
        for bad in ("-1", "0", "2001", "x"):
            with self.assertRaises(urllib.error.HTTPError, msg=bad) as e:
                self.api("/api/log?limit=" + bad)
            self.assertEqual(e.exception.code, 400)
            self.assertIn("rivimäärän pitää olla kokonaisluku 1–2 000 riviä", json.load(e.exception)["error"])

    def test_ui_version_reported(self):
        s = self.api("/api/status")
        self.assertEqual((s["log_error"], s["log_dropped"]), (None, 0), "LOG-009: lokin tila")
        v = s["ui_version"]
        self.assertRegex(v, r"^[0-9a-f]{12}$")
        self.assertEqual(self.api("/api/session")["ui_version"], v)

    def test_csrf_header_required(self):
        req = urllib.request.Request(self.base + "/api/cache/clear", method="POST", data=b"{}")
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, context=self.ssl, timeout=5)
        self.assertEqual(e.exception.code, 403)

    def test_status_and_log(self):
        udp_ask(self.dns_port, "ads.example.com")
        udp_ask(self.dns_port, "lapi.example.org")
        time.sleep(1.5)  # loki kirjoitetaan erissä
        s = self.api("/api/status")
        self.assertGreater(s["total"], 0)
        self.assertGreater(s["blocked"], 0)
        self.assertGreater(s["passed"], 0)
        self.assertEqual(s["total"], s["passed"] + s["blocked"] + s["errors"])
        self.assertGreaterEqual(s["blocked_domains"], 1)
        self.assertGreaterEqual(s["passed_domains"], 1)
        self.assertEqual((s["domains_on_lists"], s["lists_enabled"]), (2, 1))
        rows = [r for r in self.api("/api/log?status=estetty") if r["domain"] == "ads.example.com"]
        self.assertTrue(rows)
        self.assertEqual((rows[0]["reason"], rows[0]["detail"]), ("lista", self.cfg["lists"][0]["url"]))
        passed = self.api("/api/log?status=lapaisi")
        self.assertTrue(any(r["domain"] == "lapi.example.org" for r in passed))
        self.assertTrue(all(r["status"] in ("sallittu", "valimuisti") for r in passed))

    def test_added_list_counted_right_away(self):
        import functools
        from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
        www = os.path.join(self.dir, "www")
        os.makedirs(www)
        with open(os.path.join(www, "lisa.txt"), "w") as f:
            f.write("0.0.0.0 lisa1.example.com\n0.0.0.0 lisa2.example.com\n")
        agents = []

        class Quiet(SimpleHTTPRequestHandler):
            def do_GET(self):
                agents.append(self.headers.get("User-Agent"))
                super().do_GET()

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=www))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        extra = f"http://127.0.0.1:{srv.server_address[1]}/lisa.txt"
        before = self.api("/api/status")["domains_on_lists"]
        self.api("/api/lists", "POST", {"url": extra})
        for _ in range(100):
            s = self.api("/api/status")
            if not s["lists_updating"]:
                break
            time.sleep(0.1)
        self.assertEqual(s["domains_on_lists"], before + 2)
        import sihti
        self.assertEqual(agents, [f"sihti/{sihti.__version__}"], "FLT-030: User-Agent koodin versiosta (H-15)")
        self.assertEqual(s["version"], sihti.__version__)
        lst = next(l for l in self.api("/api/lists") if l["url"] == extra)
        self.assertEqual((lst["count"], lst["error"], lst["in_use"]), (2, None, True))
        self.api("/api/lists", "DELETE", {"url": extra})
        for _ in range(100):
            if not self.api("/api/status")["lists_updating"]:
                break
            time.sleep(0.1)
        self.assertEqual(self.api("/api/status")["domains_on_lists"], before)

    def test_reason_for_custom_rules(self):
        self.api("/api/custom", "POST", {"kind": "deny", "value": "syy.example.com"})
        self.api("/api/custom", "POST", {"kind": "deny_regex", "value": "^mainos\\d"})
        self.api("/api/custom", "POST", {"kind": "allow", "value": "ok.syy.example.com"})
        c = self.api("/api/check?domain=ali.syy.example.com")
        self.assertEqual((c["blocked"], c["reason"], c["detail"]), (True, "oma", "syy.example.com"))
        c = self.api("/api/check?domain=mainos7.example.org")
        self.assertEqual((c["blocked"], c["reason"], c["detail"]), (True, "lauseke", "^mainos\\d"))
        c = self.api("/api/check?domain=x.ok.syy.example.com")
        self.assertEqual((c["blocked"], c["reason"], c["detail"]), (False, "sallinta", "ok.syy.example.com"))
        udp_ask(self.dns_port, "ali.syy.example.com")
        time.sleep(1.5)
        row = self.api("/api/log?search=ali.syy.example.com")[0]
        self.assertEqual((row["status"], row["reason"], row["detail"]), ("estetty", "oma", "syy.example.com"))

    @unittest.skipUnless(shutil.which("openssl"), "openssl puuttuu")
    def test_https_redirect_and_renew(self):
        conn = socket.create_connection(("127.0.0.1", self.web_port), timeout=3)
        conn.sendall(b"GET /api/status HTTP/1.1\r\nHost: localhost:%d\r\n\r\n" % self.web_port)
        head = conn.recv(1024).decode()
        conn.close()
        self.assertIn("301", head.split("\r\n")[0])
        self.assertIn(f"Location: https://localhost:{self.web_port}/api/status", head)
        old = self.api("/api/tls")["fingerprint"]
        new = self.api("/api/tls/renew", "POST")["fingerprint"]
        self.assertNotEqual(old, new)
        self.assertTrue(self.api("/api/session") is not None)  # uusi varmenne kelpaa samalle varmentajalle


@unittest.skipUnless(shutil.which("openssl"), "openssl puuttuu")
class TestLearnAddress(unittest.TestCase):
    """Kontti ilman isäntäverkkoa: varmenteeseen tulee osoite, jolla käyttöliittymä avataan."""
    def setUp(self):
        from sihti.tls import CertManager
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.port = free_port()
        cfg_path = os.path.join(self.dir, "c.json")
        with open(cfg_path, "w") as f:
            json.dump({"data_dir": self.dir, "lists": []}, f)
        self.cfg = Config(cfg_path)
        filt = Filter(self.cfg)
        qlog = QueryLog(self.cfg)
        self.certs = CertManager(self.cfg)
        ctx = self.certs.build_context()
        self.srv = start_web(App(self.cfg, filt, qlog, Resolver(self.cfg, filt, qlog), self.certs), "127.0.0.1", self.port, ctx)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def names(self):
        info = self.certs.info()
        return set(info["names"]) | set(info["ips"])

    def test_http_host_learned_before_redirect(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as c:
            c.sendall(b"GET / HTTP/1.1\r\nHost: 192.168.77.10:4000\r\n\r\n")
            head = c.recv(1024).decode()
        self.assertIn("Location: https://192.168.77.10:4000/", head)
        self.assertIn("192.168.77.10", self.names())

    def test_sni_name_trusted_on_first_connection(self):
        ctx = ssl.create_default_context(cafile=self.certs.ca_crt)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="pi-olohuone.local") as tls:  # varmennetaan nimi
                tls.sendall(b"GET /api/session HTTP/1.1\r\nHost: pi-olohuone.local:4000\r\nConnection: close\r\n\r\n")
                self.assertIn(b"200", tls.recv(64))
        self.assertIn("pi-olohuone.local", self.names())
        self.assertEqual(self.certs.learned(), ["pi-olohuone.local"])

    def test_public_name_not_learned(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as c:
            c.sendall(b"GET / HTTP/1.1\r\nHost: pankki.example.com\r\n\r\n")
            c.recv(1024)
        self.assertNotIn("pankki.example.com", self.names())
        self.assertEqual(self.certs.learned(), [])

    def test_learned_survive_restart(self):
        self.certs.learn("10.1.2.3")
        from sihti.tls import CertManager
        again = CertManager(self.cfg)
        self.assertFalse(again.ensure(), "uudelleenkäynnistys ei saa uusia varmennetta turhaan")
        self.assertIn("10.1.2.3", set(again.info()["ips"]))

    def _replace_key(self, path):
        from sihti.tls import _openssl
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path)

    def test_mismatched_server_key_renewed(self):
        # TLS-026: avain ja varmenne jäivät eri pareiksi (katko siirtojen välissä, H-12)
        from sihti.tls import _pair_ok
        names, ips = self.certs._wanted()
        self.assertIsNone(self.certs.renewal_reason(names, ips))
        self._replace_key(self.certs.key)
        self.assertEqual(self.certs.renewal_reason(names, ips), "avain ei vastaa varmennetta")
        self.assertTrue(self.certs.ensure())
        self.assertTrue(_pair_ok(self.certs.cert, self.certs.key))
        with open(self.certs.meta_path, encoding="utf-8") as f:
            self.assertIn("issued", json.load(f))
        self.assertEqual([n for n in os.listdir(self.certs.dir) if n.endswith(".tmp")], [])

    def test_mismatched_local_ca_recreated(self):
        from sihti.tls import CertManager, _pair_ok
        before = CertManager._fingerprint(self.certs.ca_crt)
        self._replace_key(self.certs.ca_key)
        self.assertTrue(self.certs.ensure())
        self.assertTrue(_pair_ok(self.certs.ca_crt, self.certs.ca_key))
        self.assertNotEqual(CertManager._fingerprint(self.certs.ca_crt), before)
        self.assertIsNone(self.certs.renewal_reason(*self.certs._wanted()), "uusi varmenne uudelta varmentajalta")


class TestFileUtil(unittest.TestCase):
    """GEN-008: atominen kirjoitus fsyncillä."""
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "tila.json")

    def test_write_replace_and_mode(self):
        from sihti.fileutil import atomic_write, atomic_write_json
        atomic_write_json(self.path, {"a": "ä"}, ensure_ascii=False)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"a": "ä"})
        atomic_write(self.path, b"\x01" * 16, mode=0o600)
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), b"\x01" * 16)
        if os.name == "posix":
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(self.dir), ["tila.json"])

    def test_failed_write_keeps_old_file(self):
        from sihti.fileutil import atomic_write, atomic_write_json
        atomic_write_json(self.path, {"vanha": 1})
        with self.assertRaises(TypeError):
            atomic_write(self.path, 12345)   # ei tekstiä eikä tavuja: kirjoitus epäonnistuu
        with self.assertRaises(TypeError):
            atomic_write_json(self.path, {"x": object()})
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"vanha": 1})
        self.assertEqual(os.listdir(self.dir), ["tila.json"], "väliaikaistiedosto poistetaan")


@unittest.skipUnless(shutil.which("openssl"), "openssl puuttuu")
class TestSharedCA(unittest.TestCase):
    def test_two_devices_one_ca(self):
        from sihti.tls import CertManager, make_ca
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        crt, key, _fp = make_ca(os.path.join(base, "ca"))
        fps = set()
        for dev in ("pi1", "pi2"):
            path = os.path.join(base, dev + ".json")
            with open(path, "w") as f:
                json.dump({"data_dir": os.path.join(base, dev), "tls_ca_cert": crt, "tls_ca_key": key}, f)
            m = CertManager(Config(path))
            m.ensure()
            self.assertEqual(m.info()["ca_fingerprint"], CertManager._fingerprint(crt))
            fps.add(m.info()["fingerprint"])
            self.assertFalse(os.path.exists(os.path.join(base, dev, "tls", "ca.key")), "oma varmentaja ei saa syntyä")
        self.assertEqual(len(fps), 2, "laitteilla omat palvelinvarmenteet, yhteinen varmentaja")


class TestRandomPassword(unittest.TestCase):
    """OPS-020: salasana on aina satunnainen ja vaihtuu jokaisella käynnistyksellä, rivi stdoutiin.
    Salasanaa ei voi vaihtaa ohjelman kautta."""
    def test_format(self):
        from sihti.web import random_password
        import re
        for _ in range(200):
            self.assertRegex(random_password(), r"^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9]{10}$")
        self.assertIsNone(re.search(r"\s", random_password()))

    def test_new_password_each_start_and_login(self):
        import subprocess
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        root = os.path.join(os.path.dirname(__file__), "..")
        web_port = free_port()
        env = dict(os.environ, SIHTI_RANDOM_PASSWORD="false", SIHTI_HTTPS="false",
                   SIHTI_DATA_DIR=d, SIHTI_DNS_LISTEN="127.0.0.1", SIHTI_DNS_PORT=str(free_port(socket.SOCK_DGRAM)),
                   SIHTI_WEB_LISTEN="127.0.0.1", SIHTI_WEB_PORT=str(web_port), SIHTI_UPDATE_INTERVAL_HOURS="720")
        cfg = os.path.join(d, "sihti.json")
        with open(cfg, "w") as f:
            # Vanhan asennuksen tiedosto: salasana tyhjä ja satunnainen pois. Ne jätetään huomiotta.
            json.dump({"lists": [], "password_hash": "", "random_password": False}, f)
        passwords = []
        for _ in range(2):
            p = subprocess.Popen([sys.executable, "-m", "sihti", "--config", cfg], cwd=root, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                line = p.stdout.readline().strip()
                # Täsmälleen käyttäjän skriptin poiminta: grep "random password" | awk '{print $NF}'
                self.assertIn("random password", line)
                self.assertIn("Sihti", line)
                pw = line.split()[-1]
                passwords.append(pw)
                time.sleep(0.5)
                base = f"http://127.0.0.1:{web_port}"
                bad = urllib.request.Request(base + "/api/login", method="POST", data=b'{"password":"vaara"}',
                                             headers={"Content-Type": "application/json"})
                with self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(bad, timeout=5)
                ok = urllib.request.Request(base + "/api/login", method="POST",
                                            data=json.dumps({"password": pw}).encode(),
                                            headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(ok, timeout=5) as r:
                    self.assertEqual(json.load(r), {"ok": True})
                    cookie = r.headers["Set-Cookie"].split(";")[0]
                # Salasanaa ei voi vaihtaa rajapinnan kautta, vaikka olisi kirjautunut
                change = urllib.request.Request(base + "/api/password", method="POST", data=b'{"password":""}',
                                                headers={"Content-Type": "application/json", "X-Sihti": "1",
                                                         "Cookie": cookie})
                with self.assertRaises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(change, timeout=5)
                self.assertEqual(e.exception.code, 404)
            finally:
                p.terminate()
                p.wait(10)
                p.stdout.close()
        self.assertNotEqual(passwords[0], passwords[1], "jokaisella käynnistyksellä uusi salasana")
        with open(cfg) as f:
            self.assertNotIn(passwords[1], f.read())
        r = subprocess.run([sys.executable, "-m", "sihti", "--config", cfg, "--set-password"], cwd=root, env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2, "komentorivillä ei ole salasanan asetusta")


class TestRelease(unittest.TestCase):
    """OPS-050, OPS-051: kontin tagit ja versiotagin tarkistus CI:ssä."""

    def test_version_is_taggable(self):
        import sihti
        self.assertRegex(sihti.__version__, r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$",
                         "versiotagi v<__version__> pitää olla semver-muotoinen")

    def test_workflow_latest_only_from_main_and_version_checked(self):
        path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "docker.yml")
        with open(path, encoding="utf-8") as f:
            wf = f.read()
        self.assertIn("latest=false", wf, "versiotagi ei saa siirtää latest-tagia (OPS-050)")
        self.assertIn("type=raw,value=latest,enable={{is_default_branch}}", wf)
        self.assertIn("sihti.__version__", wf, "CI vertaa tagia koodin versioon (OPS-051)")
        self.assertIn("${GITHUB_REF_NAME#v}", wf)


if __name__ == "__main__":
    unittest.main()
