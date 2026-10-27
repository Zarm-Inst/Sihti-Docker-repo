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
        time.sleep(1.5)  # loki kirjoitetaan erissä
        s = self.api("/api/status")
        self.assertGreater(s["total"], 0)
        self.assertGreater(s["blocked"], 0)
        self.assertTrue(any(r["domain"] == "ads.example.com" for r in self.api("/api/log?status=estetty")))

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
