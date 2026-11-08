"""Pysyvien tiedostojen atominen kirjoitus (GEN-008).

Tiedosto kirjoitetaan ensin .tmp-tiedostoon, joka tallennetaan levylle (fsync) ja siirretään
sitten paikalleen (os.replace). Lopuksi tallennetaan hakemisto, jotta myös siirto säilyy.
Sähkökatko kesken kirjoituksen jättää siis joko vanhan tai uuden tiedoston, ei puolikasta tai
tyhjää. Raspberry Pi:ssä sähkökatkot ovat tavallisia, ja kirjoituksia on harvoin, joten
fsync ei kuluta muistikorttia merkittävästi.
"""
import json
import os


def _fsync_path(path, flags):
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_dir(path):
    """Tallentaa tiedoston hakemiston levylle. Windows ei tue hakemiston avaamista: ohitetaan."""
    try:
        _fsync_path(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    except OSError:
        pass


def commit(tmp, path):
    """Siirtää valmiiksi kirjoitetun väliaikaistiedoston paikalleen: fsync, os.replace ja
    hakemiston fsync. Käytetään, kun tiedoston kirjoittaa joku muu (esim. lataus tai openssl)."""
    _fsync_path(tmp, os.O_RDWR)   # Windowsin fsync vaatii kirjoitusoikeuden
    os.replace(tmp, path)
    fsync_dir(path)


def atomic_write(path, data, mode=None):
    """Kirjoittaa tekstin tai tavut atomisesti. mode (esim. 0o600) asettaa oikeudet jo
    väliaikaistiedostolle, joten salainen sisältö ei ole hetkeäkään muiden luettavissa."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666 if mode is None else mode)
    try:
        with os.fdopen(fd, "wb") as f:
            if mode is not None:
                os.chmod(tmp, mode)   # olemassa olevan .tmp-tiedoston oikeudet eivät muutu os.openissa
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    fsync_dir(path)


def atomic_write_json(path, obj, mode=None, **dump_kwargs):
    """JSON-tiedosto atomisesti (json.dump-parametrit kuten indent välitetään sellaisinaan)."""
    atomic_write(path, json.dumps(obj, **dump_kwargs), mode)
