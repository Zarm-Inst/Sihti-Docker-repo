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
from sihti.config import Config, env_overrides          # noqa: E402
from sihti.filtering import Filter, normalize_domain, parse_list  # noqa: E402
from sihti.querylog import QueryLog                     # noqa: E402
from sihti.resolver import Resolver, start_servers     # noqa: E402
from sihti.web import App, start_web                    # noqa: E402


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
            _qid, _f, _name, qtype, qend = w.parse_query(data)
            if qtype == 1:
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
    data_b, index_b, count, _, _, _ = build_domain_set([path], key)
    data, index = array("Q"), array("Q")
    data.frombytes(data_b)
    index.frombytes(index_b)
    ds = DomainSet(key, data, index, count)
    assert "uusi.example.com" in ds and "vanha.example.com" in ds
    return ds


class TestDomainSet(unittest.TestCase):
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
        for builder in (build_domain_set, _build_isolated):   # sama tulos omassa prosessissa
            data_b, index_b, count, per_file, mask_type, masks_b = builder([p1, p2], key)
            data, index, masks = array("Q"), array("Q"), array(mask_type)
            data.frombytes(data_b)
            index.frombytes(index_b)
            masks.frombytes(masks_b)
            ds = DomainSet(key, data, index, count, masks, ("a", "b"))
            self.assertEqual((count, per_file, mask_type, len(masks)), (20000, [12000, 10000], "B", 20000))
            self.assertTrue(all(n in ds for n in names))
            self.assertFalse(any(f"x{i}.esimerkki.fi" in ds for i in range(20000)))
            # millä listalla nimi on: vain a, molemmilla, vain b
            self.assertTrue(all(ds.lookup(n) == ["a"] for n in names[:10000]))
            self.assertTrue(all(ds.lookup(n) == ["a", "b"] for n in names[10000:12000]))
            self.assertTrue(all(ds.lookup(n) == ["b"] for n in names[12000:]))
            self.assertIsNone(ds.lookup("x1.esimerkki.fi"))
        self.assertNotIn("a.fi", DomainSet())
        self.assertIsNone(DomainSet().lookup("a.fi"))

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
            data_b, index_b, count, _, mask_type, masks_b = build_domain_set([p], key)
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
        self.assertEqual(saved["dns_port"], 53)
        self.assertEqual(saved["cache_size"], 5)


class TestDnsWire(unittest.TestCase):
    def test_roundtrip(self):
        q = make_query("Www.Example.com", 28)
        qid, _f, name, qtype, qend = w.parse_query(q)
        self.assertEqual((name, qtype, qend), ("www.example.com", 28, len(q)))
        r = w.build_response(q, qend, answer_rdata=b"\0" * 16, qtype=28)
        self.assertEqual(r[:2], q[:2])
        self.assertEqual(struct.unpack("!H", r[6:8])[0], 1)
        self.assertEqual(w.min_ttl(r), 2)

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
        self.cfg.update(lists=self.cfg["lists"][1:])
        filt.update_lists(missing_only=True)
        self.assertEqual(len(filt.blocked), 1)
        files = {f for f in os.listdir(filt.lists_dir) if f.endswith((".txt", ".fp"))}
        self.assertEqual(len(old_files - files), 2, "poistetun listan tiedosto ja välimuisti pois")

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
        with mock.patch.object(F, "ProcessPoolExecutor", return_value=broken):
            filt.update_lists()
        self.assertIs(filt.blocked, first)
        self.assertIn("muisti", filt.build_error)
        self.assertFalse(filt.updating, "kaatunut rakennus ei saa jäädä roikkumaan")
        filt.update_lists()   # seuraava yritys onnistuu
        self.assertIn("toka.example.com", filt.blocked)
        self.assertIsNone(filt.build_error)


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
        qlog.add("10.0.0.3", "uusi.fi", "A", "estetty", "oma", 0.2, "uusi.fi")
        stop = threading.Event()
        t = threading.Thread(target=qlog.writer_loop, args=(stop,))
        t.start()
        time.sleep(1.5)
        stop.set()
        t.join()
        rows = {r["domain"]: r for r in qlog.recent()}
        self.assertIsNone(rows["vanha.fi"]["detail"])
        self.assertEqual(rows["uusi.fi"]["detail"], "uusi.fi")
        self.assertEqual(qlog.summary()["blocked_domains"], 2)
        qlog._rdb.close()


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
        handler = functools.partial(SimpleHTTPRequestHandler, directory=www)
        handler.log_message = lambda *a: None
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
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
        lst = next(l for l in self.api("/api/lists") if l["url"] == extra)
        self.assertEqual((lst["count"], lst["error"]), (2, None))
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
    """Docker-tila: uusi satunnainen salasana jokaisella käynnistyksellä, rivi stdoutiin."""
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
        env = dict(os.environ, SIHTI_RANDOM_PASSWORD="true", SIHTI_HTTPS="false",
                   SIHTI_DATA_DIR=d, SIHTI_DNS_LISTEN="127.0.0.1", SIHTI_DNS_PORT=str(free_port(socket.SOCK_DGRAM)),
                   SIHTI_WEB_LISTEN="127.0.0.1", SIHTI_WEB_PORT=str(web_port), SIHTI_UPDATE_INTERVAL_HOURS="720")
        cfg = os.path.join(d, "sihti.json")
        with open(cfg, "w") as f:
            json.dump({"lists": []}, f)
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
            finally:
                p.terminate()
                p.wait(10)
                p.stdout.close()
        self.assertNotEqual(passwords[0], passwords[1], "jokaisella käynnistyksellä uusi salasana")


if __name__ == "__main__":
    unittest.main()
