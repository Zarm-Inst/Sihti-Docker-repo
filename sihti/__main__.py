"""Käynnistys: python3 -m sihti [--config /etc/sihti/sihti.json]"""
import argparse
import logging
import os
import signal
import sys
import threading

from .config import Config
from .filtering import Filter
from .querylog import QueryLog
from .resolver import Resolver, start_servers
from .tls import CertManager, TLSError, openssl_available
from .web import App, hash_password, random_password, start_web


def main():
    ap = argparse.ArgumentParser(prog="sihti", description="Sihti – DNS-suodatin")
    ap.add_argument("--config", default=os.environ.get("SIHTI_CONFIG", "/etc/sihti/sihti.json"))
    ap.add_argument("--update-lists", action="store_true", help="päivitä estolistat ja lopeta")
    ap.add_argument("--renew-cert", action="store_true", help="luo uusi HTTPS-varmenne ja lopeta")
    ap.add_argument("--ca-path", action="store_true", help="tulosta paikallisen varmentajan polku ja lopeta")
    ap.add_argument("--make-ca", metavar="HAKEMISTO",
                    help="luo yhteinen varmentaja usealle laitteelle hakemistoon ja lopeta")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    config = Config(args.config)

    if args.make_ca:
        from .tls import make_ca
        crt, key, fp = make_ca(args.make_ca)
        print(f"Yhteinen varmentaja luotu:\n  {crt}\n  {key}\nSormenjälki: {fp}")
        print("Kopioi hakemisto jokaiselle laitteelle. Pidä ca.key tallessa: sillä voi allekirjoittaa varmenteita.")
        return

    if args.renew_cert or args.ca_path:
        certs = CertManager(config)
        if args.renew_cert:
            certs.ensure(force=True)
            print("Uusi varmenne luotu. Käynnissä oleva palvelu ottaa sen käyttöön minuutin kuluessa.")
        else:
            certs.ensure()
            print(certs.ca_crt)
        return

    filt = Filter(config)
    if args.update_lists:
        filt.update_lists()
        print(f"Estettäviä verkkotunnuksia: {len(filt.blocked)}")
        return

    # Salasana on aina satunnainen ja vaihtuu jokaisella käynnistyksellä. Tämä on tarkoituksellista:
    # salasanaa ei voi vaihtaa eikä käyttäjiä luoda ohjelman kautta. Tiiviste on vain muistissa.
    # Rivi tulostetaan vakiotulosteeseen (stdout), jotta "docker logs" ja "journalctl -u sihti"
    # näkevät sen; muu loki menee stderr:iin. Viimeinen sana on salasana:
    #   ... | grep "random password" | tail -n1 | awk '{print $NF}'
    pw = random_password(10)
    password_hash = hash_password(pw)
    print(f"Sihti random password: {pw}", file=sys.stdout, flush=True)
    del pw

    stop = threading.Event()
    qlog = QueryLog(config)
    resolver = Resolver(config, filt, qlog)

    writer = threading.Thread(target=qlog.writer_loop, args=(stop,), daemon=True, name="loki")
    writer.start()
    threading.Thread(target=filt.updater_loop, args=(stop,), daemon=True, name="listat").start()
    servers = start_servers(resolver, config["dns_listen"], config["dns_port"], ipv6=config["dns_listen_ipv6"])
    certs, tls_ctx = None, None
    if config["https"]:
        try:
            if not (config.get("tls_cert") or openssl_available()):
                raise TLSError("openssl-ohjelmaa ei löydy")
            certs = CertManager(config)
            tls_ctx = certs.build_context()
            threading.Thread(target=certs.renewer_loop, args=(stop,), daemon=True, name="varmenteet").start()
        except (TLSError, OSError) as e:
            certs, tls_ctx = None, None
            logging.getLogger("sihti").error("HTTPS ei käytössä: %s – käyttöliittymä toimii HTTP:llä", e)
    servers.append(start_web(App(config, filt, qlog, resolver, certs, password_hash=password_hash),
                             config["web_listen"], config["web_port"], tls_ctx))

    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    qlog.wake()   # kerätyt lokirivit tallennetaan, kun kuuntelijat sulkeutuvat
    # Rinnakkain: jokainen kuuntelija huomaa pysäytyksen enintään SERVE_POLL sekunnissa, joten koko
    # pysäytys mahtuu Dockerin 10 s odotusaikaan.
    closers = [threading.Thread(target=s.shutdown) for s in servers]
    for t in closers:
        t.start()
    for t in closers:
        t.join()
    writer.join(timeout=3)
    logging.getLogger("sihti").info("pysäytetty")


if __name__ == "__main__":
    main()
