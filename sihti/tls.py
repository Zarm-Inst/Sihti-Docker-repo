"""HTTPS-varmenteet: oma paikallinen varmentaja ja sen allekirjoittama palvelinvarmenne.

Varmentaja (10 v) luodaan kerran. Palvelinvarmenne (365 pv) uusitaan automaattisesti, kun
voimassaoloa on jäljellä alle 30 päivää tai kun laitteen nimi tai IP-osoitteet muuttuvat.
Kun varmentaja on asennettu luotetuksi laitteille, uusiminen ei näy selaimessa mitenkään.

Varmenteet luodaan openssl-komentorivityökalulla, joka kuuluu Raspberry Pi OS:ään.
"""
import ipaddress
import json
import re
import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

log = logging.getLogger("sihti.tls")

CA_DAYS = 3650
CERT_DAYS = 365
RENEW_BEFORE_DAYS = 30
LEARN_MAX = 32              # opittujen nimien/osoitteiden enimmäismäärä
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain", ".koti")
HOST_HOSTNAME_FILE = "/etc/host-hostname"   # Dockerissa: isäntäkoneen /etc/hostname (vain luku)
CHECK_INTERVAL = 6 * 3600   # voimassaolon tarkistus
FILE_POLL = 60              # varmennetiedoston muutoksen tarkistus


class TLSError(Exception):
    pass


def _openssl(*args, input_text=None):
    try:
        r = subprocess.run(["openssl", *args], input=input_text, capture_output=True, text=True, timeout=60)
    except FileNotFoundError as e:
        raise TLSError("openssl-ohjelmaa ei löydy (asenna: sudo apt install openssl)") from e
    if r.returncode != 0:
        raise TLSError(f"openssl {args[0]} epäonnistui: {r.stderr.strip()[:300]}")
    return r.stdout


_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_NAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")


def host_from_header(value):
    """'192.168.1.10:4000' / '[fd00::1]:4000' / 'pi.local' -> pelkkä nimi tai osoite."""
    v = (value or "").strip().lower()
    if v.startswith("["):
        return v[1:].split("]", 1)[0]
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v.rstrip(".")


def learnable(value):
    """Palauttaa siistityn arvon, jos sen saa lisätä varmenteeseen automaattisesti.
    Vain lähiverkon osoitteet ja paikalliset nimet: julkisia nimiä ei opita."""
    v = host_from_header(value)
    if not v:
        return None
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        if a.is_private and not (a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast):
            return str(a)
        return None
    if len(v) > 253 or not _NAME_RE.match(v):
        return None
    if "." not in v or v.endswith(LOCAL_SUFFIXES):
        return v
    return None


def _host_names():
    """Koneen nimi. Dockerissa luetaan isäntäkoneen nimi, jos se on liitetty konttiin."""
    hosts = set()
    try:
        with open(HOST_HOSTNAME_FILE, encoding="utf-8") as f:
            h = f.read().strip().split(".")[0].lower()
        if h:
            hosts.add(h)
    except OSError:
        pass
    h = socket.gethostname().split(".")[0].lower()
    if h:
        hosts.add(h)
    return hosts


def local_names(extra=()):
    """Nimet ja osoitteet, joilla käyttöliittymään todennäköisesti otetaan yhteyttä."""
    names = {"localhost"}
    for host in _host_names():
        names |= {host, f"{host}.local", f"{host}.lan", f"{host}.home"}
    fqdn = socket.getfqdn().lower()
    if "." in fqdn and not fqdn.endswith(".arpa"):
        names.add(fqdn)
    ips = {"127.0.0.1", "::1"}
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout
        ips |= set(out.split())
    except (OSError, subprocess.SubprocessError):
        pass
    for target in ("192.0.2.1", "2001:db8::1"):  # dokumentaatio-osoitteet: mitään ei lähetetä
        try:
            fam = socket.AF_INET6 if ":" in target else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((target, 9))
                ips.add(s.getsockname()[0])
        except OSError:
            pass
    for e in extra:
        e = e.strip().lower()
        if not e:
            continue
        try:
            ips.add(str(ipaddress.ip_address(e)))
        except ValueError:
            names.add(e)
    clean_ips = set()
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        if not a.is_link_local:
            clean_ips.add(str(a))
    return sorted(names), sorted(clean_ips, key=lambda x: (":" in x, x))


class CertManager:
    def __init__(self, config):
        self.config = config
        self.dir = os.path.join(config["data_dir"], "tls")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        # Yhteinen varmentaja usealle laitteelle: tls_ca_cert + tls_ca_key (esim. kontissa
        # vain luku -liitos). Muuten varmentaja luodaan tälle laitteelle.
        shared_crt, shared_key = config.get("tls_ca_cert"), config.get("tls_ca_key")
        self.shared_ca = bool(shared_crt and shared_key)
        self.ca_key = shared_key or os.path.join(self.dir, "ca.key")
        self.ca_crt = shared_crt or os.path.join(self.dir, "ca.crt")
        self.learned_path = os.path.join(self.dir, "opitut.json")
        self._learn_lock = threading.Lock()
        custom_cert, custom_key = config.get("tls_cert"), config.get("tls_key")
        self.custom = bool(custom_cert and custom_key)
        self.cert = custom_cert or os.path.join(self.dir, "server.crt")
        self.key = custom_key or os.path.join(self.dir, "server.key")
        self.meta_path = os.path.join(self.dir, "server.json")
        self.context = None
        self._loaded_mtime = None
        self._lock = threading.Lock()

    # ---------- tiedot ----------
    def _meta(self):
        try:
            with open(self.meta_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _fingerprint(path):
        out = _openssl("x509", "-in", path, "-noout", "-fingerprint", "-sha256")
        return out.strip().split("=", 1)[-1]

    @staticmethod
    def _not_after(path):
        out = _openssl("x509", "-in", path, "-noout", "-enddate").strip().split("=", 1)[-1]
        return ssl.cert_time_to_seconds(out)

    def learned(self):
        try:
            with open(self.learned_path, encoding="utf-8") as f:
                return [x for x in json.load(f) if isinstance(x, str)]
        except (OSError, ValueError):
            return []

    def _wanted(self):
        extra = list(self.config.get("tls_extra_names", [])) + self.learned()
        return local_names(extra)

    def info(self):
        if not os.path.exists(self.cert):
            return {"enabled": False}
        d = {
            "enabled": True,
            "custom": self.custom,
            "shared_ca": self.shared_ca,
            "learned": self.learned(),
            "not_after": self._not_after(self.cert),
            "fingerprint": self._fingerprint(self.cert),
            "names": self._meta().get("names", []),
            "ips": self._meta().get("ips", []),
        }
        if not self.custom and os.path.exists(self.ca_crt):
            d["ca_fingerprint"] = self._fingerprint(self.ca_crt)
            d["ca_not_after"] = self._not_after(self.ca_crt)
        return d

    # ---------- luonti ----------
    def _ensure_ca(self):
        if self.shared_ca:
            if not (os.path.exists(self.ca_crt) and os.path.exists(self.ca_key)):
                raise TLSError(f"yhteistä varmentajaa ei löydy: {self.ca_crt}, {self.ca_key}")
            if not os.access(self.ca_key, os.R_OK):
                raise TLSError(f"yhteisen varmentajan avainta ei voi lukea: {self.ca_key} "
                               "(kontissa: sudo chown 10053 <avain>)")
            if self._not_after(self.ca_crt) - time.time() < (CERT_DAYS + 30) * 86400:
                log.warning("yhteinen varmentaja vanhenee pian – luo uusi ja jaa se laitteille")
            return False
        if os.path.exists(self.ca_crt) and os.path.exists(self.ca_key):
            # Uusi varmentaja vasta, kun vanha on vanhenemassa (silloin laitteille asennetaan uusi)
            if self._not_after(self.ca_crt) - time.time() > (CERT_DAYS + 30) * 86400:
                return False
            log.warning("paikallinen varmentaja vanhenee pian – luodaan uusi")
        host = socket.gethostname().split(".")[0]
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.ca_key + ".tmp")
        os.chmod(self.ca_key + ".tmp", 0o600)
        _openssl("req", "-x509", "-new", "-key", self.ca_key + ".tmp", "-sha256", "-days", str(CA_DAYS),
                 "-subj", f"/O=Sihti/CN=Sihti paikallinen varmentaja ({host})",
                 "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash",
                 "-out", self.ca_crt + ".tmp")
        os.replace(self.ca_key + ".tmp", self.ca_key)
        os.replace(self.ca_crt + ".tmp", self.ca_crt)
        log.info("luotiin paikallinen varmentaja")
        return True

    def _issue(self, names, ips):
        san = ",".join([f"DNS:{n}" for n in names] + [f"IP:{i}" for i in ips])
        with tempfile.TemporaryDirectory(dir=self.dir) as tmp:
            key, csr, crt, ext = (os.path.join(tmp, n) for n in ("k", "csr", "crt", "ext"))
            with open(ext, "w", encoding="utf-8") as f:
                f.write("basicConstraints=critical,CA:FALSE\n"
                        "keyUsage=critical,digitalSignature\n"
                        "extendedKeyUsage=serverAuth\n"
                        "authorityKeyIdentifier=keyid\n"
                        f"subjectAltName={san}\n")
            _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
            _openssl("req", "-new", "-key", key, "-subj", f"/O=Sihti/CN={names[0] if names else 'sihti'}", "-out", csr)
            _openssl("x509", "-req", "-in", csr, "-CA", self.ca_crt, "-CAkey", self.ca_key,
                     "-set_serial", "0x" + os.urandom(12).hex(), "-days", str(CERT_DAYS), "-sha256",
                     "-extfile", ext, "-out", crt)
            # Ketju: palvelinvarmenne + varmentaja, jolloin selain saa koko polun
            with open(crt, encoding="utf-8") as a, open(self.ca_crt, encoding="utf-8") as b:
                chain = a.read() + b.read()
            with open(crt, "w", encoding="utf-8") as f:
                f.write(chain)
            os.chmod(key, 0o600)
            os.replace(key, self.key)
            os.replace(crt, self.cert)
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump({"names": names, "ips": ips, "issued": time.time()}, f, indent=2)
        log.info("uusi palvelinvarmenne: %s", ", ".join(names + ips))

    def renewal_reason(self, names, ips):
        if not (os.path.exists(self.cert) and os.path.exists(self.key)):
            return "varmennetta ei ole"
        try:
            left = self._not_after(self.cert) - time.time()
            _openssl("verify", "-CAfile", self.ca_crt, self.cert)
        except TLSError:
            return "varmenne on vioittunut tai eri varmentajan"
        if left < RENEW_BEFORE_DAYS * 86400:
            return f"voimassa enää {max(0, int(left // 86400))} päivää"
        m = self._meta()
        if not set(names) <= set(m.get("names", [])) or not set(ips) <= set(m.get("ips", [])):
            return "laitteen nimi tai osoite muuttui"
        return None

    def ensure(self, force=False):
        """Varmistaa voimassa olevan varmenteen. Palauttaa True, jos varmenne vaihtui."""
        if self.custom:
            return False
        with self._lock:
            ca_new = self._ensure_ca()
            names, ips = self._wanted()
            reason = "pyydetty" if force else ("varmentaja vaihtui" if ca_new else self.renewal_reason(names, ips))
            if not reason:
                return False
            log.info("uusitaan palvelinvarmenne: %s", reason)
            self._issue(names, ips)
            return True

    # ---------- automaattinen oppiminen ----------
    def covers(self, value):
        m = self._meta()
        return value in m.get("names", []) or value in m.get("ips", [])

    def learn(self, value):
        """Lisää osoitteen tai nimen, jolla selain otti yhteyttä, varmenteeseen.
        Palauttaa True, jos varmenne uusittiin. Kontissa ilman isäntäverkkoa tämä on
        ainoa tapa saada koneen lähiverkko-osoite varmenteeseen ilman asetuksia."""
        if self.custom or not self.config.get("tls_learn_names", True):
            return False
        v = learnable(value)
        if not v or self.covers(v):
            return False
        with self._learn_lock:
            if self.covers(v):
                return False
            learned = self.learned()
            if v in learned:
                return False
            if len(learned) >= LEARN_MAX:
                log.warning("opittujen nimien enimmäismäärä täynnä, ohitetaan %s", v)
                return False
            learned.append(v)
            tmp = self.learned_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(learned, f, indent=2)
            os.replace(tmp, self.learned_path)
            log.info("uusi osoite käyttöliittymälle: %s – lisätään varmenteeseen", v)
            try:
                changed = self.ensure()
                if changed:
                    self.reload()
                return changed
            except (TLSError, OSError, ssl.SSLError) as e:
                log.error("varmenteen uusiminen epäonnistui: %s", e)
                return False

    def _new_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert, self.key)
        return ctx

    def _sni(self, sslsock, server_name, _ctx):
        # Nimellä (esim. pi-olohuone.local) avattaessa selain kertoo nimen jo ennen
        # varmenteen valintaa: uusi varmenne ehditään antaa tälle samalle yhteydelle.
        if server_name and self.learn(server_name):
            sslsock.context = self._new_context()

    # ---------- SSL-konteksti ----------
    def build_context(self):
        self.ensure()
        ctx = self._new_context()
        ctx.sni_callback = self._sni
        self._loaded_mtime = os.path.getmtime(self.cert)
        self.context = ctx
        return ctx

    def reload(self):
        """Lataa uuden varmenteen samaan kontekstiin: uudet yhteydet käyttävät sitä heti."""
        if self.context:
            self.context.load_cert_chain(self.cert, self.key)
            self._loaded_mtime = os.path.getmtime(self.cert)
            log.info("uusi varmenne otettu käyttöön")

    def renew_now(self):
        changed = self.ensure(force=True)
        self.reload()
        return changed

    def renewer_loop(self, stop_event):
        last_check = time.time()
        while not stop_event.wait(FILE_POLL):
            try:
                if time.time() - last_check >= CHECK_INTERVAL:
                    last_check = time.time()
                    self.ensure()
                # Lataa uudelleen myös, jos varmenne vaihdettiin komentoriviltä tai omalla tiedostolla
                if os.path.getmtime(self.cert) != self._loaded_mtime:
                    self.reload()
            except (TLSError, OSError, ssl.SSLError) as e:
                log.error("varmenteen uusiminen epäonnistui: %s", e)


def make_ca(out_dir, owner_uid=10053):
    """Luo yhteisen varmentajan usealle laitteelle (python -m sihti --make-ca HAKEMISTO)."""
    os.makedirs(out_dir, exist_ok=True)
    crt, key = os.path.join(out_dir, "ca.crt"), os.path.join(out_dir, "ca.key")
    if os.path.exists(crt) or os.path.exists(key):
        raise TLSError(f"{out_dir} sisältää jo varmentajan – ei korvata")
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    os.chmod(key, 0o600)
    _openssl("req", "-x509", "-new", "-key", key, "-sha256", "-days", str(CA_DAYS),
             "-subj", "/O=Sihti/CN=Sihti yhteinen varmentaja",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash",
             "-out", crt)
    os.chmod(crt, 0o644)
    if os.geteuid() == 0 and owner_uid is not None:
        for p in (out_dir, crt, key):
            os.chown(p, owner_uid, owner_uid)
    return crt, key, _openssl("x509", "-in", crt, "-noout", "-fingerprint", "-sha256").strip().split("=", 1)[-1]


def openssl_available():
    return shutil.which("openssl") is not None
