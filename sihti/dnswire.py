"""DNS-viestien jäsennys ja rakentaminen (RFC 1035) pelkällä standardikirjastolla."""
import struct

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5


class ParseError(Exception):
    pass


def _read_name(data, offset):
    """Lukee (mahdollisesti pakatun) nimen. Palauttaa (nimi, offset kentän jälkeen)."""
    labels = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise ParseError("nimi katkeaa")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ParseError("osoitin katkeaa")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = ptr
            hops += 1
            if hops > 30:
                raise ParseError("osoitinsilmukka")
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).lower(), end


def parse_query(data):
    """Palauttaa (id, flags, qname, qtype, question_end) tai nostaa ParseError."""
    if len(data) < 12:
        raise ParseError("liian lyhyt")
    qid, flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount < 1:
        raise ParseError("ei kysymystä")
    name, off = _read_name(data, 12)
    if off + 4 > len(data):
        raise ParseError("kysymys katkeaa")
    qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
    return qid, flags, name, qtype, off + 4


def min_ttl(data):
    """Pienin TTL vastauksen tietueista (välimuistia varten). None jos ei tietueita."""
    try:
        _qid, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        off = 12
        for _ in range(qd):
            _, off = _read_name(data, off)
            off += 4
        ttls = []
        for _ in range(an + ns):
            _, off = _read_name(data, off)
            rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10 + rdlen
            if rtype != 41:  # OPT ei ole oikea tietue
                ttls.append(ttl)
        return min(ttls) if ttls else None
    except (ParseError, struct.error, IndexError):
        return None


def rcode(data):
    return data[3] & 0x0F if len(data) >= 4 else RCODE_SERVFAIL


def with_id(data, qid):
    return struct.pack("!H", qid) + data[2:]


def build_response(query, question_end, rc=RCODE_NOERROR, answer_rdata=None, qtype=None, ttl=2):
    """Rakentaa vastauksen kyselyn pohjalta. answer_rdata = raw-bytes A/AAAA-vastaukselle."""
    qid, flags = struct.unpack("!HH", query[:4])
    rd = flags & 0x0100
    resp_flags = 0x8000 | 0x0400 | rd | 0x0080 | (rc & 0x0F)  # QR, AA, RD kopio, RA
    ancount = 1 if answer_rdata is not None else 0
    header = struct.pack("!HHHHHH", qid, resp_flags, 1, ancount, 0, 0)
    question = query[12:question_end]
    body = header + question
    if answer_rdata is not None:
        body += struct.pack("!HHHIH", 0xC00C, qtype, 1, ttl, len(answer_rdata)) + answer_rdata
    return body


def qtype_name(qtype):
    return QTYPES.get(qtype, f"TYPE{qtype}")
