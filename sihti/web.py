"""Web-käyttöliittymä ja JSON-rajapinta (http.server, ei ulkoisia riippuvuuksia)."""
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import secrets
import socket
import ssl
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .filtering import normalize_domain

log = logging.getLogger("sihti.web")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
SESSION_TTL = 7 * 86400


def hash_password(password):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"pbkdf2${salt}${dk.hex()}"


def verify_password(password, stored):
    try:
        _, salt, digest = stored.split("$")
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return hmac.compare_digest(dk.hex(), digest)


class App:
    def __init__(self, config, filt, qlog, resolver, certs=None):
        self.config = config
        self.certs = certs          # CertManager tai None (HTTPS pois)
        self.filter = filt
        self.qlog = qlog
        self.resolver = resolver
        self.sessions = {}
        self._updating = threading.Lock()

    # ---------- istunnot ----------
    def auth_required(self):
        return bool(self.config["password_hash"])

    def new_session(self):
        token = secrets.token_urlsafe(32)
        self.sessions[token] = time.time() + SESSION_TTL
        return token

    def valid_session(self, token):
        exp = self.sessions.get(token or "")
        return bool(exp and exp > time.time())

    # ---------- rajapinta ----------
    def api(self, method, path, query, body):
        q = lambda k, d=None: query.get(k, [d])[0]  # noqa: E731
        f = self.filter

        if path == "/api/status" and method == "GET":
            s = self.qlog.summary(24)
            return {
                **s,
                "blocking": f.active,
                "blocking_enabled": self.config["blocking_enabled"],
                "pause_until": f.pause_until,
                "domains_on_lists": len(f.blocked),
                "cache_entries": len(self.resolver.cache),
                "last_update": f.last_update,
                "uptime": time.time() - self.qlog.started,
            }
        if path == "/api/timeline" and method == "GET":
            return self.qlog.timeline(int(q("hours", 24)))
        if path == "/api/top" and method == "GET":
            hours = int(q("hours", 24))
            return {
                "domains": self.qlog.top("domain", "sallittu", hours),
                "blocked": self.qlog.top("domain", "estetty", hours),
                "clients": self.qlog.top("client", None, hours),
            }
        if path == "/api/log" and method == "GET":
            return self.qlog.recent(q("limit", 200), q("search"), q("status"))
        if path == "/api/log/clear" and method == "POST":
            self.qlog.clear()
            return {"ok": True}
        if path == "/api/cache/clear" and method == "POST":
            self.resolver.cache.clear()
            return {"ok": True}

        if path == "/api/blocking" and method == "POST":
            if "pause_seconds" in body:
                f.pause(int(body["pause_seconds"]))
            if "enabled" in body:
                self.config.update(blocking_enabled=bool(body["enabled"]))
                f.pause(0)
            self.resolver.cache.clear()
            return {"blocking": f.active, "pause_until": f.pause_until}

        if path == "/api/custom":
            if method == "GET":
                return {"allow": sorted(f.allow), "deny": sorted(f.deny),
                        "deny_regex": [p for p, _ in f.deny_regex]}
            if method == "POST":
                result = f.add_custom(body["kind"], str(body["value"]))
                self.resolver.cache.clear()
                return result
            if method == "DELETE":
                f.remove_custom(body["kind"], body["value"])
            self.resolver.cache.clear()
            return {"ok": True}

        if path == "/api/check" and method == "GET":
            raw = q("domain") or ""
            name = normalize_domain(raw)
            if not name:
                raise ValueError("virheellinen verkkotunnus")
            blocked, reason = f.check(name)
            return {"domain": name, "blocked": blocked, "reason": reason}

        if path == "/api/lists":
            lists = list(self.config["lists"])
            if method == "POST":
                url = body["url"].strip()
                if not url.startswith(("http://", "https://")):
                    raise ValueError("osoitteen pitää alkaa http:// tai https://")
                if not any(l["url"] == url for l in lists):
                    lists.append({"url": url, "enabled": True})
            elif method == "PATCH":
                for l in lists:
                    if l["url"] == body["url"]:
                        l["enabled"] = bool(body["enabled"])
            elif method == "DELETE":
                lists = [l for l in lists if l["url"] != body["url"]]
            if method != "GET":
                self.config.update(lists=lists)
                f.rebuild()
            return [{**l, **f.list_status.get(l["url"], {})} for l in self.config["lists"]]

        if path == "/api/lists/update" and method == "POST":
            if self._updating.locked():
                return {"ok": True, "running": True}

            def run():
                with self._updating:
                    f.update_lists()
                    self.resolver.cache.clear()
            threading.Thread(target=run, daemon=True).start()
            return {"ok": True, "running": True}

        if path == "/api/settings":
            keys = ("upstreams", "block_mode", "log_retention_days", "log_queries",
                    "cache_size", "update_interval_hours")
            if method == "POST":
                changes = {k: body[k] for k in keys if k in body}
                if "upstreams" in changes:
                    ups = [u.strip() for u in changes["upstreams"] if u.strip()]
                    if not ups:
                        raise ValueError("vähintään yksi ylävirtapalvelin tarvitaan")
                    changes["upstreams"] = ups
                if changes.get("block_mode", "null") not in ("null", "nxdomain"):
                    raise ValueError("tuntematon estotapa")
                self.config.update(**changes)
                self.resolver.cache.size = self.config["cache_size"]
                self.resolver.cache.clear()
            return {k: self.config[k] for k in keys} | {"has_password": self.auth_required()}

        if path == "/api/tls" and method == "GET":
            if not self.certs:
                return {"enabled": False}
            return self.certs.info()
        if path == "/api/tls/renew" and method == "POST":
            if not self.certs or self.certs.custom:
                raise ValueError("automaattiset varmenteet eivät ole käytössä")
            self.certs.renew_now()
            return self.certs.info()

        if path == "/api/password" and method == "POST":
            pw = body.get("password", "")
            self.config.update(password_hash=hash_password(pw) if pw else "")
            self.sessions.clear()
            return {"ok": True, "has_password": bool(pw)}

        return None


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "sihti"
        sys_version = ""
        timeout = 60

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        def _token(self):
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return c["sihti_sid"].value if "sihti_sid" in c else None

        def _send(self, code, payload, ctype="application/json; charset=utf-8", extra=None):
            data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _static(self, path):
            if path in ("/", ""):
                path = "/index.html"
            rel = os.path.normpath(path.lstrip("/"))
            full = os.path.join(STATIC_DIR, rel)
            if rel.startswith("..") or not os.path.isfile(full):
                return self._send(404, {"error": "ei löydy"})
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                ctype += "; charset=utf-8"
            with open(full, "rb") as fh:
                self._send(200, fh.read(), ctype)

        def _dispatch(self, method):
            url = urlparse(self.path)
            path = url.path
            if path == "/sihti-varmentaja.crt" and method == "GET":
                # Julkinen tieto: varmentajan varmenne laitteille asennettavaksi (ei avainta)
                if not app.certs or app.certs.custom or not os.path.exists(app.certs.ca_crt):
                    return self._send(404, {"error": "ei paikallista varmentajaa"})
                with open(app.certs.ca_crt, "rb") as fh:
                    return self._send(200, fh.read(), "application/x-x509-ca-cert", extra={
                        "Content-Disposition": 'attachment; filename="sihti-varmentaja.crt"'})
            if not path.startswith("/api/"):
                if method != "GET":
                    return self._send(405, {"error": "ei sallittu"})
                return self._static(path)

            length = int(self.headers.get("Content-Length") or 0)
            body = {}
            if length:
                try:
                    body = json.loads(self.rfile.read(min(length, 1_000_000)) or b"{}")
                except json.JSONDecodeError:
                    return self._send(400, {"error": "virheellinen JSON"})

            if path == "/api/session":
                return self._send(200, {"auth_required": app.auth_required(),
                                        "logged_in": app.valid_session(self._token())})
            if path == "/api/login" and method == "POST":
                if not app.auth_required() or verify_password(body.get("password", ""), app.config["password_hash"]):
                    token = app.new_session()
                    return self._send(200, {"ok": True}, extra={
                        "Set-Cookie": f"sihti_sid={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
                                      + ("; Secure" if app.certs else "")})
                time.sleep(1)  # hidastaa arvailua
                return self._send(401, {"error": "väärä salasana"})
            if path == "/api/logout" and method == "POST":
                app.sessions.pop(self._token() or "", None)
                return self._send(200, {"ok": True})

            if app.auth_required() and not app.valid_session(self._token()):
                return self._send(401, {"error": "kirjaudu sisään"})
            # CSRF-suoja: muuttavat pyynnöt vain omalta sivulta (JSON + oma otsake)
            if method != "GET" and self.headers.get("X-Sihti") != "1":
                return self._send(403, {"error": "puuttuva otsake"})
            try:
                result = app.api(method, path, parse_qs(url.query), body)
            except (ValueError, KeyError) as e:
                return self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001
                log.exception("rajapintavirhe")
                return self._send(500, {"error": "sisäinen virhe"})
            if result is None:
                return self._send(404, {"error": "tuntematon polku"})
            self._send(200, result)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_DELETE(self):
            self._dispatch("DELETE")

        def do_PATCH(self):
            self._dispatch("PATCH")

    return Handler


class WebServer(ThreadingHTTPServer):
    """Palvelee HTTPS:ää ja HTTP:tä samassa portissa: TLS-kättely tunnistetaan ensimmäisestä
    tavusta (0x16), tavallinen HTTP-pyyntö ohjataan https-osoitteeseen."""
    daemon_threads = True
    tls_context = None

    def finish_request(self, request, client_address):
        if self.tls_context is None:
            return super().finish_request(request, client_address)
        request.settimeout(10)
        try:
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if not first:
            return
        if first != b"\x16":
            return self._redirect(request)
        try:
            tls_sock = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return  # tavallista: selain hylkää tuntemattoman varmenteen ennen kuin käyttäjä hyväksyy sen
        try:
            self.RequestHandlerClass(tls_sock, client_address, self)
        finally:
            try:
                tls_sock.close()
            except OSError:
                pass

    def _redirect(self, sock):
        try:
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                head += chunk
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            path = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else "/"
            host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
            if not host or any(c in host for c in "\r\n /\\@"):
                host = f"{self.server_address[0]}:{self.server_address[1]}"
            location = f"https://{host}{path}"
            body = f'<a href="{location}">Siirry suojattuun osoitteeseen</a>'.encode()
            sock.sendall(
                b"HTTP/1.1 301 Moved Permanently\r\n"
                + f"Location: {location}\r\n".encode("latin-1", "replace")
                + b"Content-Type: text/html; charset=utf-8\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        except OSError:
            pass


def start_web(app, host, port, tls_context=None):
    WebServer.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
    srv = WebServer((host, port), make_handler(app))
    srv.tls_context = tls_context
    threading.Thread(target=srv.serve_forever, daemon=True, name="web").start()
    log.info("käyttöliittymä: %s://%s:%d/", "https" if tls_context else "http", host, port)
    return srv
