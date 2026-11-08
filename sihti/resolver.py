"""DNS-palvelin: vastaanottaa kyselyt, suodattaa, välittää ylävirtaan ja välimuistittaa."""
import collections
import ipaddress
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
        """(vastaus TTL:t päivitettyinä, CNAME-kohteet) tai None."""
        now = time.monotonic()
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            expires, stored, data, offsets, targets = item
            if expires < now:
                del self._d[key]
                return None
            self._d.move_to_end(key)
        return w.aged(data, offsets, int(now - stored)), targets

    def put(self, key, data, ttl, targets=()):
        if self.size <= 0 or ttl <= 0:
            return
        try:
            offsets = w.ttl_offsets(data)
        except (w.ParseError, struct.error):
            return   # jäsentymätöntä vastausta ei välimuistiteta
        now = time.monotonic()
        with self._lock:
            self._d[key] = (now + min(ttl, 86400), now, data, offsets, targets)
            self._d.move_to_end(key)
            while len(self._d) > self.size:
                self._d.popitem(last=False)

    def clear(self):
        with self._lock:
            self._d.clear()

    def __len__(self):
        return len(self._d)


FAIL_HOLD = 300   # s; vastaamatta jättänyt ylävirta kokeillaan viimeisenä tämän ajan

# Testinimet, joilla laitteet tarkistavat, saako ne ohittaa verkon DNS:n. Kun nimeä "ei ole",
# Firefox jättää oman salatun DNS:nsä (DoH) pois päältä ja Apple-laitteet iCloud Private Relayn.
BYPASS_NAMES = {
    "use-application-dns.net": "Firefoxin oma DNS (DoH)",
    "mask.icloud.com": "iCloud Private Relay",
    "mask-h2.icloud.com": "iCloud Private Relay",
}

# Lähiverkon osoitteiden käänteishaut (PTR): kuuluvat reitittimelle, eivät internetiin
_PRIVATE_REVERSE = ("10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
                    *(f"{n}.172.in-addr.arpa" for n in range(16, 32)),
                    "c.f.ip6.arpa", "d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa",
                    "a.e.f.ip6.arpa", "b.e.f.ip6.arpa")


def _private_reverse(name):
    return any(name == z or name.endswith("." + z) for z in _PRIVATE_REVERSE)


def _own_ipv6_networks():
    """Koneen omat IPv6-verkot (Linux). Kotiverkon laitteilla on usein julkinen IPv6-osoite,
    joten "paikallinen" IPv6-kysyjä tunnistetaan siitä, että se on samassa verkossa."""
    nets = []
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "00":   # vain globaalit osoitteet
                    nets.append(ipaddress.IPv6Network((int(parts[0], 16), int(parts[2], 16)), strict=False))
    except (OSError, ValueError):
        pass
    return nets


class LocalClients:
    """Saako osoitteesta kysyä: lähiverkon osoitteet (yksityiset IPv4-verkot, IPv6:n paikalliset
    osoitteet, koneen omat IPv6-verkot) ja asetuksissa erikseen sallitut verkot. Muuten Pi olisi
    avoin DNS-palvelin, jota voi käyttää hyökkäyksiin, jos portti 53 aukeaa internetiin."""
    def __init__(self, config):
        self.config = config
        self._own = (float("-inf"), [])   # monotoninen aika alkaa käynnistyksestä: ladataan heti
        self._extra = (None, [])
        self._cache = {}
        self._warned = float("-inf")

    def allowed(self, addr):
        if not self.config["local_clients_only"]:
            return True
        now = time.monotonic()
        hit = self._cache.get(addr)
        if hit and hit[0] > now:
            return hit[1]
        ok = self._check(addr, now)
        if not ok and now - self._warned > 60:   # enintään kerran minuutissa, ettei hyökkäys täytä lokia
            self._warned = now
            log.warning("kysely torjuttu osoitteesta %s (ei lähiverkosta). Jos laite on omasi, lisää sen "
                        "verkko asetukseen 'Lisäksi sallitut verkot' (allowed_networks).", addr)
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[addr] = (now + 60, ok)
        return ok

    def _check(self, addr, now):
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            return False
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:   # yksityinen, loopback, link-local, ULA, operaattorin NAT
            return True
        if now - self._own[0] > 300:
            self._own = (now, _own_ipv6_networks())
        return any(ip in net for net in self._own[1] + self._extra_networks())

    def _extra_networks(self):
        value = tuple(self.config["allowed_networks"])
        if self._extra[0] != value:
            nets = []
            for v in value:
                try:
                    nets.append(ipaddress.ip_network(v.strip(), strict=False))
                except ValueError:
                    log.warning("virheellinen sallittu verkko ohitettiin: %s", v)
            self._extra = (value, nets)
        return self._extra[1]


class Resolver:
    def __init__(self, config, filt, qlog):
        self.config = config
        self.filter = filt
        self.qlog = qlog
        self.cache = Cache(config["cache_size"])
        self.clients = LocalClients(config)
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

    def _local_server(self, name):
        """Reititin, jolle paikallinen nimi välitetään: pisteetön nimi (esim. nas), paikallinen
        verkkotunnus (nas.lan) tai lähiverkon osoitteen käänteishaku. None, jos ei paikallinen."""
        server = self.config["local_dns"]
        if not server or not name:
            return None
        if "." not in name or _private_reverse(name):
            return server
        for d in self.config["local_domains"]:
            d = d.strip().strip(".").lower()
            if d and (name == d or name.endswith("." + d)):
                return server
        return None

    def forward(self, data, question_end, tcp=False, servers=None):
        last_err = None
        for server in servers or self._servers():
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
        if not self.clients.allowed(client):
            return w.build_response(data, qend, rc=w.RCODE_REFUSED)
        tname = w.qtype_name(qtype)

        # RFC 6761: .invalid ei ole koskaan olemassa – vastataan itse, ei välitetä eteenpäin
        if name == "invalid" or name.endswith(".invalid"):
            return w.build_response(data, qend, rc=w.RCODE_NXDOMAIN)

        blocked, reason, detail = self.filter.check(name)
        if blocked:
            resp = self._blocked_response(data, qend, qtype)
            self.qlog.add(client, name, tname, "estetty", reason, _ms(t0), detail)
            return resp
        # Ohitusten testinimet (DNS-012). Esto on voimassa myös tauolla ja kun suodatus on pois
        # päältä: muuten esim. Firefox voisi ottaa oman DoH:nsa käyttöön tauon aikana ja ohittaa
        # Sihdin vielä tauon jälkeenkin. Oma sallinta voittaa aina.
        if (self.config["block_dns_bypass"] and name in BYPASS_NAMES and reason != "sallinta"
                and not self.filter.allow_rule(name)):
            self.qlog.add(client, name, tname, "estetty", "ohitus", _ms(t0), BYPASS_NAMES[name])
            return w.build_response(data, qend, rc=w.RCODE_NXDOMAIN)
        local = self._local_server(name)
        if local and not reason:
            reason, detail = "paikallinen", local

        # Avaimeen myös luokka, RD- ja CD-bitti sekä DO-bitti: DNSSEC:iä pyytävä laite saa
        # allekirjoitukset, vaikka sama nimi olisi välimuistissa ilman niitä
        _size, do = w.query_edns(data, qend)
        key = (name, qtype, data[qend - 2:qend], _flags & 0x0110, do)
        hit = self.cache.get(key)
        if hit:
            resp, targets = hit
            resp, status = w.with_question(resp, data, qend), "valimuisti"
        else:
            try:
                resp = self.forward(data, qend, tcp, [local] if local else None)
            except OSError as e:
                log.debug("välitys epäonnistui: %s", e)
                self.qlog.add(client, name, tname, "virhe", "ylävirta", _ms(t0))
                return w.build_response(data, qend, rc=w.RCODE_SERVFAIL)
            targets, status = w.cname_targets(resp), "sallittu"
            rc = w.rcode(resp)
            if not (resp[2] & 0x02):  # ei välimuistiteta katkaistuja vastauksia
                ttl = w.min_ttl(resp)
                if ttl is None:
                    ttl = 60 if rc in (w.RCODE_NOERROR, w.RCODE_NXDOMAIN) else 0
                if rc in (w.RCODE_NOERROR, w.RCODE_NXDOMAIN):
                    self.cache.put(key, resp, ttl, targets)

        # Piilotettu seurain: sallittu nimi osoittaa (CNAME) estettyyn nimeen. Oma sallinta
        # ohittaa tarkistuksen. Tarkistetaan joka kerta, joten listojen muutos näkyy heti.
        if targets and reason != "sallinta" and self.config["block_cname"]:
            for target in targets:
                if self.filter.check(target)[0]:
                    self.qlog.add(client, name, tname, "estetty", "cname", _ms(t0), target)
                    return self._blocked_response(data, qend, qtype)
        self.qlog.add(client, name, tname, status, reason, _ms(t0), detail)
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
    return resp if len(resp) <= limit else w.truncated(query, qend, resp)


class _UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _bind(resolver, host, port, v6only=False):
    """UDP- ja TCP-kuuntelija yhteen osoitteeseen. v6only: IPv6-pistoke ei varaa IPv4:ää, joten
    se voi toimia rinnakkain 0.0.0.0-kuuntelijan kanssa samassa portissa."""
    servers = []
    try:
        for base, handler in ((_UDPServer, _UDPHandler), (_TCPServer, _TCPHandler)):
            family = _family(host)

            class Server(base):
                address_family = family

                def server_bind(self):
                    if v6only:
                        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    super().server_bind()
            srv = Server((host, port), handler)
            srv.resolver = resolver
            servers.append(srv)
    except OSError:
        for srv in servers:
            srv.server_close()
        raise
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True, name=f"dns-{host}").start()
    return servers


def start_servers(resolver, host, port, ipv6=False):
    """Kuuntelee osoitteessa host. ipv6: kun host on 0.0.0.0, kuunnellaan myös IPv6:ta (::),
    jotta IPv6:ta käyttävät laitteet eivät ohita suodatusta. Jos laite tai kontti ei tue
    IPv6:ta, jatketaan pelkällä IPv4:llä."""
    servers = _bind(resolver, host, port)
    log.info("DNS kuuntelee %s:%d (UDP+TCP)", host, port)
    if ipv6 and host in ("0.0.0.0", ""):
        try:
            servers += _bind(resolver, "::", port, v6only=True)
            log.info("DNS kuuntelee myös [::]:%d (IPv6)", port)
        except OSError as e:
            log.info("IPv6-kuuntelu ei käytössä: %s", e)
    return servers
