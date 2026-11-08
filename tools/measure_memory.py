"""Estojoukon muistimittaus (Linux). Ei kuulu konttiin eikä asennukseen.

Käyttö (repon juuresta):  python3 tools/measure_memory.py [nimiä=5000000] [listoja=1] [päivityksiä=5] [ei-trim]

Valinta ei-trim kytkee pois muistin palautuksen käyttöjärjestelmälle (malloc_trim, H-16), jotta
vaikutuksen voi verrata.

Luo väliaikaiset hosts-muotoiset listat, joilla on yhteensä <nimiä> eri nimeä. Jos listoja on useita,
jokaisella on lisäksi 10 % päällekkäisiä nimiä naapurilistan kanssa. Sitten ajaa Sihdin oikean
päivityksen useita kertoja (lataus file://-osoitteesta, käsittely erillisessä prosessissa) ja tulostaa:
  - estojoukon taulukoiden koon (tiivisteet + hakemisto + listamaskit)
  - pääprosessin muistin (VmRSS) ennen listoja ja jokaisen päivityksen jälkeen
  - pääprosessin huipun ja käsittelyprosessin huipun (ru_maxrss)
Mt = 2^20 tavua.

Tulkinta: Linuxissa aliprosessin ru_maxrss sisältää myös pääprosessin muistin sillä hetkellä, kun
aliprosessi käynnistetään. Luotettava käsittelyprosessin luku on siksi ensimmäisen päivityksen arvo,
jolloin pääprosessi on vielä pieni. Pääprosessin huippu syntyy, kun uusi joukko luetaan käsittelyn
jälkeen ja vanha on vielä käytössä. Käsittelyprosessi on silloin jo päättynyt, joten huiput eivät
osu samaan aikaan. Muistia on yhteensä käytössä enimmillään noin pääprosessi + käsittelyprosessi.
"""
import gc
import json
import os
import resource
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from sihti import filtering          # noqa: E402
from sihti.config import Config      # noqa: E402
from sihti.filtering import Filter   # noqa: E402

MB = 1 << 20


def vmrss():
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return 0


def peaks():
    """(pääprosessin huippu, suurin käsittelyprosessin huippu) tavuina."""
    return (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024)


def mb(b):
    return f"{b / MB:6.1f} Mt"


def write_lists(d, n_names, n_lists):
    per = n_names // n_lists
    paths = []
    for k in range(n_lists):
        p = os.path.join(d, f"lista{k}.txt")
        with open(p, "w") as f:
            f.write("# testilista\n")
            for i in range(k * per, (k + 1) * per):
                f.write(f"0.0.0.0 ad{i}.tracker{i % 5000}.example.com\n")
            if n_lists > 1:
                for i in range(per // 10):
                    j = ((k + 1) % n_lists) * per + i
                    f.write(f"0.0.0.0 ad{j}.tracker{j % 5000}.example.com\n")
        paths.append(p)
    return paths


def main():
    n_names = int(sys.argv[1]) if len(sys.argv) > 1 else 5_000_000
    n_lists = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    if "ei-trim" in sys.argv[4:]:
        filtering._malloc_trim = False
    d = tempfile.mkdtemp(prefix="sihti-muisti-")
    try:
        paths = write_lists(d, n_names, n_lists)
        size = sum(os.path.getsize(p) for p in paths)
        trim = "pois" if filtering._malloc_trim is False else ("käytössä" if filtering.release_memory() else "ei saatavilla")
        print(f"Python {sys.version.split()[0]}, {n_lists} listaa, {n_names:,} eri nimeä, {mb(size)} levyllä, "
              f"malloc_trim {trim}")

        cfg_path = os.path.join(d, "sihti.json")
        with open(cfg_path, "w") as f:
            json.dump({"data_dir": os.path.join(d, "data"),
                       "lists": [{"url": "file://" + p, "enabled": True} for p in paths]}, f)
        filt = Filter(Config(cfg_path))
        gc.collect()
        print(f"pääprosessi ilman listoja:   {mb(vmrss())}")

        for r in range(1, rounds + 1):
            if r > 1:   # muuttunut lista: ladataan ja rakennetaan uudelleen, vanha joukko käytössä sillä aikaa
                with open(paths[0], "a") as f:
                    f.write(f"0.0.0.0 uusi{r}.example.com\n")
            t = time.monotonic()
            filt.update_lists()
            took = time.monotonic() - t
            if filt.build_error:
                sys.exit(f"käsittely epäonnistui: {filt.build_error}")
            gc.collect()
            p_self, p_child = peaks()
            if r == 1:
                b = filt.blocked
                parts = [a.itemsize * len(a) for a in (b._data, b._index, b._masks)]
                print(f"estojoukko: {len(b):,} nimeä, taulukot {mb(sum(parts))} "
                      f"(tiivisteet {mb(parts[0])}, hakemisto {mb(parts[1])}, maskit {mb(parts[2])})")
                del b   # muuten vanha joukko jäisi tämän muuttujan varaan seuraavissa päivityksissä
            print(f"päivitys {r} ({took:4.0f} s): pääprosessi {mb(vmrss())}, "
                  f"huippu {mb(p_self)}, käsittelyprosessin huippu {mb(p_child)}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":   # käsittelyprosessit käynnistetään spawn-tilassa
    main()
