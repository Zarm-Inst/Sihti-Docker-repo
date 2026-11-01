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
    """Vastaukset TTL:n ajaksi. Palautettavan vastauksen TTL:istä vähennetään välimuistissa
    vietetty aika, kuten oikeat palvelimet tekevät. Aika on monotoninen, joten kellon siirto
    (esim. Pi hakee ajan verkosta käynnistyksen jälkeen) ei sotke vanhenemista."""
    def __init__(self, size):
        self.size = size
        self._d = collections.OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        now = time.monotonic()
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            expires, stored, data, offsets = item
            if expires < now:
                del self._d[key]
                return None
            self._d.move_to_end(key)
        return w.aged(data, offsets, int(now - stored))

    def put(self, key, data, ttl):
        if self.size <= 0 or ttl <= 0:
            return
        try:
            offsets = w.ttl_offsets(data)
        except (w.ParseError, struct.error):
            return   # jäsentymätöntä vastausta ei välimuistiteta
        now = time.monotonic()
        with self._lock:
            self._d[key] = (now + min(ttl, 86400), now, data, offsets)
            self._d.move_to_end(key)
            while len(self._d) > self.size:
                self._d.popitem(last=False)

    def clear(self):
        with self._lock:
            self._d.clear()

    def __len__(self):
        return len(self._d)


FAIL_HOLD = 300   # s; vastaamatta jättänyt ylävirta kokeillaan viimeisenä tämän ajan


class Resolver:
    def __init__(self, config, filt, qlog):
        self.config = config
        self.filter = filt
        self.qlog = qlog
        self.cache = Cache(config["cache_size"])
        self._failed = {}   # ylävirta -> viimeisimmän epäonnistumisen aika

    # ---------- ylävirta ----------
    def _servers(self):
        """Ylävirrat asetusten järjestyksessä, mutta äskettäin vastaamatta jättäneet viimeisenä,
        jottei jokainen uusi nimi odota niiden aikakatkaisua."""
        now = time.monotonic()
        return sorted(self.config["upstreams"], key=lambda s: now - self._failed.get(s, -FAIL_HOLD) < FAIL_HOLD)

    def _upstream_udp(self, server, data, question_end):
        host, port = self._split(server)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        timeout = self.config["upstream_timeout"]
        deadline = time.monotonic() + timeout
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))   # vain tältä palvelimelta tulevat paketit otetaan vastaan
            s.send(data)
            while True:
                resp = s.recv(65535)
                # Sama tunniste ja sama kysymys: väärennettyä vastausta on vaikeampi syöttää
                if resp[:2] == data[:2] and resp[12:question_end].lower() == data[12:question_end].lower():
                    return resp
                s.settimeout(max(0.01, deadline - time.monotonic()))

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

    def forward(self, data, question_end, tcp=False):
        last_err = None
        for server in self._servers():
            try:
                resp = self._upstream_udp(server, data, question_end)
                truncated = len(resp) > 2 and resp[2] & 0x02
                if truncated and tcp:
                    resp = self._upstream_tcp(server, data)
                self._failed.pop(server, None)
                return resp
            except OSError as e:
                self._failed[server] = time.monotonic()
                last_err = e
                continue
        raise OSError(f"kaikki ylävirtapalvelimet epäonnistuivat: {last_err}")

    # ---------- pääkäsittely ----------
    def handle(self, data, client, tcp=False):
        t0 = time.monotonic()
        try:
            _qid, _flags, name, qtype, qend = w.parse_query(data)
        except w.ParseError:
            return None
        tname = w.qtype_name(qtype)

        # RFC 6761: .invalid ei ole koskaan olemassa – vastataan itse, ei välitetä eteenpäin
        if name == "invalid" or name.endswith(".invalid"):
            return w.build_response(data, qend, rc=w.RCODE_NXDOMAIN)

        blocked, reason, detail = self.filter.check(name)
        if blocked:
            resp = self._blocked_response(data, qend, qtype)
            self.qlog.add(client, name, tname, "estetty", reason, _ms(t0), detail)
            return resp

        # Avaimeen myös luokka, RD- ja CD-bitti sekä DO-bitti: DNSSEC:iä pyytävä laite saa
        # allekirjoitukset, vaikka sama nimi olisi välimuistissa ilman niitä
        _size, do = w.query_edns(data, qend)
        key = (name, qtype, data[qend - 2:qend], _flags & 0x0110, do)
        cached = self.cache.get(key)
        if cached:
            self.qlog.add(client, name, tname, "valimuisti", reason, _ms(t0), detail)
            return w.with_question(cached, data, qend)

        try:
            resp = self.forward(data, qend, tcp)
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
        self.qlog.add(client, name, tname, "sallittu", reason, _ms(t0), detail)
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
            sock.sendto(_fit_udp(data, resp), self.client_address)


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


def _fit_udp(query, resp):
    """Vastaus mahtuu asiakkaan ilmoittamaan UDP-kokoon (ilman EDNS:ää 512 tavua). Muuten
    lähetetään TC-bitillä merkitty otsake, jolloin asiakas kysyy uudelleen TCP:llä. Koskee
    erityisesti välimuistista tulevaa vastausta, joka on voitu hakea TCP:llä."""
    if len(resp) <= 512:
        return resp
    try:
        qend = w.parse_query(query)[4]
    except w.ParseError:
        return resp
    size, _ = w.query_edns(query, qend)
    limit = max(512, min(size, 4096)) if size else 512
    return resp if len(resp) <= limit else w.truncated(query, qend, resp, size)


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
