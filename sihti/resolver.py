"""DNS-palvelin: vastaanottaa kyselyt, suodattaa, välittää ylävirtaan ja välimuistittaa."""
import collections
import logging
import socket
import socketserver
import struct
import threading
import time

from . import dnswire as w

log = logging.getLogger("sihti.dns")


class Cache:
    def __init__(self, size):
        self.size = size
        self._d = collections.OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            expires, data = item
            if expires < time.time():
                del self._d[key]
                return None
            self._d.move_to_end(key)
            return data

    def put(self, key, data, ttl):
        if self.size <= 0 or ttl <= 0:
            return
        with self._lock:
            self._d[key] = (time.time() + min(ttl, 86400), data)
            self._d.move_to_end(key)
            while len(self._d) > self.size:
                self._d.popitem(last=False)

    def clear(self):
        with self._lock:
            self._d.clear()

    def __len__(self):
        return len(self._d)


class Resolver:
    def __init__(self, config, filt, qlog):
        self.config = config
        self.filter = filt
        self.qlog = qlog
        self.cache = Cache(config["cache_size"])

    # ---------- ylävirta ----------
    def _upstream_udp(self, server, data):
        host, port = self._split(server)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(self.config["upstream_timeout"])
            s.sendto(data, (host, port))
            while True:
                resp, _ = s.recvfrom(65535)
                if resp[:2] == data[:2]:
                    return resp

    def _upstream_tcp(self, server, data):
        host, port = self._split(server)
        with socket.create_connection((host, port), timeout=self.config["upstream_timeout"]) as s:
            s.sendall(struct.pack("!H", len(data)) + data)
            ln = struct.unpack("!H", _recv_exact(s, 2))[0]
            return _recv_exact(s, ln)

    @staticmethod
    def _split(server):
        if server.startswith("[") and "]:" in server:
            host, port = server[1:].split("]:")
            return host, int(port)
        if server.count(":") == 1:
            host, port = server.split(":")
            return host, int(port)
        return server, 53

    def forward(self, data, tcp=False):
        last_err = None
        for server in self.config["upstreams"]:
            try:
                resp = self._upstream_udp(server, data)
                truncated = len(resp) > 2 and resp[2] & 0x02
                if truncated and tcp:
                    resp = self._upstream_tcp(server, data)
                return resp
            except OSError as e:
                last_err = e
                continue
        raise OSError(f"kaikki ylävirtapalvelimet epäonnistuivat: {last_err}")

    # ---------- pääkäsittely ----------
    def handle(self, data, client, tcp=False):
        t0 = time.monotonic()
        try:
            qid, _flags, name, qtype, qend = w.parse_query(data)
        except w.ParseError:
            return None
        tname = w.qtype_name(qtype)

        # RFC 6761: .invalid ei ole koskaan olemassa – vastataan itse, ei välitetä eteenpäin
        if name == "invalid" or name.endswith(".invalid"):
            return w.build_response(data, qend, rc=w.RCODE_NXDOMAIN)

        blocked, reason = self.filter.check(name)
        if blocked:
            resp = self._blocked_response(data, qend, qtype)
            self.qlog.add(client, name, tname, "estetty", reason, _ms(t0))
            return resp

        key = (name, qtype, data[2] & 0x01)  # RD-bitti mukaan avaimeen
        cached = self.cache.get(key)
        if cached:
            self.qlog.add(client, name, tname, "valimuisti", None, _ms(t0))
            return w.with_id(cached, qid)

        try:
            resp = self.forward(data, tcp)
        except OSError as e:
            log.debug("välitys epäonnistui: %s", e)
            self.qlog.add(client, name, tname, "virhe", "ylävirta", _ms(t0))
            return w.build_response(data, qend, rc=w.RCODE_SERVFAIL)

        rc = w.rcode(resp)
        if not (resp[2] & 0x02):  # ei välimuistiteta katkaistuja vastauksia
            ttl = w.min_ttl(resp)
            if ttl is None:
                ttl = 60 if rc in (w.RCODE_NOERROR, w.RCODE_NXDOMAIN) else 0
            if rc in (w.RCODE_NOERROR, w.RCODE_NXDOMAIN):
                self.cache.put(key, resp, ttl)
        self.qlog.add(client, name, tname, "sallittu", None, _ms(t0))
        return resp

    def _blocked_response(self, data, qend, qtype):
        if self.config["block_mode"] == "nxdomain":
            return w.build_response(data, qend, rc=w.RCODE_NXDOMAIN)
        if qtype == 1:
            return w.build_response(data, qend, answer_rdata=b"\x00\x00\x00\x00", qtype=1)
        if qtype == 28:
            return w.build_response(data, qend, answer_rdata=b"\x00" * 16, qtype=28)
        return w.build_response(data, qend)  # NODATA


def _ms(t0):
    return round((time.monotonic() - t0) * 1000, 2)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("yhteys katkesi")
        buf += chunk
    return buf


# ---------- kuuntelijat ----------
class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = self.server.resolver.handle(data, self.client_address[0], tcp=False)
        if resp:
            if len(resp) > 512 and not _has_edns(data):
                # Ilman EDNS:ää asiakas hyväksyy vain 512 tavua: lähetetään TC-bitillä
                # merkitty otsake + kysymys, jolloin asiakas kysyy uudelleen TCP:llä.
                resp = (resp[:2] + bytes([resp[2] | 0x02, resp[3]])
                        + b"\x00\x01\x00\x00\x00\x00\x00\x00" + data[12:])
            sock.sendto(resp, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                ln = struct.unpack("!H", _recv_exact(self.request, 2))[0]
                data = _recv_exact(self.request, ln)
                resp = self.server.resolver.handle(data, self.client_address[0], tcp=True)
                if not resp:
                    return
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except (OSError, struct.error):
            return


def _has_edns(data):
    try:
        return struct.unpack("!H", data[10:12])[0] > 0
    except struct.error:
        return False


class _UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def start_servers(resolver, host, port):
    servers = []
    for cls, handler in ((_UDPServer, _UDPHandler), (_TCPServer, _TCPHandler)):
        cls.address_family = _family(host)
        srv = cls((host, port), handler)
        srv.resolver = resolver
        threading.Thread(target=srv.serve_forever, daemon=True, name=cls.__name__).start()
        servers.append(srv)
    log.info("DNS kuuntelee %s:%d (UDP+TCP)", host, port)
    return servers
