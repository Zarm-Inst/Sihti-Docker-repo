"""Terveystarkistus kontille: DNS vastaa ja käyttöliittymän portti on auki.
Käyttö: python -m sihti.healthcheck  (paluuarvo 0 = kunnossa)"""
import os
import random
import socket
import struct
import sys

from .config import Config


def main():
    cfg = Config(os.environ.get("SIHTI_CONFIG", "/etc/sihti/sihti.json"))
    host = cfg["dns_listen"]
    host = "127.0.0.1" if host in ("0.0.0.0", "") else ("::1" if host == "::" else host)
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    qid = random.randint(0, 0xFFFF)
    # .invalid-nimiin Sihti vastaa itse (RFC 6761), joten tarkistus ei riipu ylävirrasta
    name = b"".join(bytes([len(p)]) + p for p in (b"sihti-terveys", b"invalid")) + b"\0"
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    try:
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(msg, (host, cfg["dns_port"]))
            if s.recv(512)[:2] != msg[:2]:
                return 1
        with socket.create_connection((host, cfg["web_port"]), timeout=3):
            pass
    except OSError as e:
        print(f"epäkunnossa: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
