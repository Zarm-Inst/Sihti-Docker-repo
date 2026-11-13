"""Kyselyloki SQLiteen sekä tilastokyselyt käyttöliittymälle."""
import logging
import os
import queue
import sqlite3
import threading
import time

log = logging.getLogger("sihti.loki")

RETRY_DELAY = 5            # s; epäonnistunut erä kirjoitetaan uudelleen uudella yhteydellä (LOG-009)
ERROR_LOG_INTERVAL = 60    # s; toistuva sama virhe sovelluslokiin enintään näin usein
FLUSH_INTERVAL = 10        # s; rivit kerätään ja tallennetaan yhdellä kertaa (vähemmän muistikorttikirjoituksia)
IDLE_WAIT = 60             # s; tyhjän jonon odotus, jonka jälkeen tarkistetaan vanhojen rivien poisto

SCHEMA = """
CREATE TABLE IF NOT EXISTS kyselyt (
    ts REAL NOT NULL,
    client TEXT NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT NOT NULL,
    status TEXT NOT NULL,      -- sallittu | estetty | valimuisti | virhe
    reason TEXT,               -- lista | oma | lauseke | sallinta | ylävirta
    ms REAL,
    detail TEXT                -- listojen osoitteet, osunut sääntö tai lauseke
);
CREATE INDEX IF NOT EXISTS i_ts ON kyselyt(ts);
"""


class QueryLog:
    def __init__(self, config):
        self.config = config
        self.path = os.path.join(config["data_dir"], "kyselyt.db")
        self._q = queue.Queue(maxsize=50000)
        self._read_lock = threading.Lock()
        self._summary_lock = threading.Lock()
        self._summary_cache = {}  # hours -> (aika, tulos)
        self.summary_ttl = 5      # s; usea avoin välilehti tai laite ei aja raskasta kyselyä joka kerta
        self.flush_interval = FLUSH_INTERVAL
        db = self._connect()
        db.executescript(SCHEMA)
        if "detail" not in {r[1] for r in db.execute("PRAGMA table_info(kyselyt)")}:
            db.execute("ALTER TABLE kyselyt ADD COLUMN detail TEXT")  # vanhempi tietokanta
            db.commit()
        db.close()
        # Laskurit muistissa, jotta etusivu on nopea myös ilman lokia
        self.started = time.time()
        # Kirjoituksen tila (LOG-009): viimeisin virhe tai None, ja käynnistyksen jälkeen
        # kirjaamatta jääneet rivit (jono täynnä ruuhkan tai tallennusvirheen vuoksi)
        self.write_error = None
        self.read_error = None
        self.dropped = 0
        self._dropped_lock = threading.Lock()
        self._error_logged = 0.0
        self._failures = 0

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        return db

    def add(self, client, domain, qtype, status, reason=None, ms=None, detail=None):
        if not self.config["log_queries"]:
            return
        try:
            self._q.put_nowait((time.time(), client, domain, qtype, status, reason, ms, detail))
        except queue.Full:
            # Ylikuormassa tai tallennusvirheen aikana lokirivit pudotetaan, DNS jatkaa toimintaa
            with self._dropped_lock:
                self.dropped += 1

    def wake(self):
        """Herättää tyhjää jonoa odottavan kirjoitussäikeen pysäytystä varten."""
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass   # jono ei ole tyhjä, joten säie ei odota

    def _take_batch(self, stop_event):
        """Odottaa ensimmäistä riviä, kerää rivejä flush_interval sekuntia ja palauttaa kaikki
        jonossa olevat. Pysäytys keskeyttää keräämisen, jolloin kerätyt rivit tallennetaan heti."""
        try:
            first = self._q.get(timeout=IDLE_WAIT)
        except queue.Empty:
            return []
        if self.flush_interval > 0:
            stop_event.wait(self.flush_interval)
        batch = [first]
        try:
            while True:
                batch.append(self._q.get_nowait())
        except queue.Empty:
            pass
        return [r for r in batch if r is not None]

    def _write_failed(self, e):
        """Ensimmäinen virhe sovelluslokiin heti, toistuva enintään kerran minuutissa."""
        self._failures += 1
        self.write_error = str(e) or type(e).__name__
        now = time.monotonic()
        if self._failures == 1 or now - self._error_logged >= ERROR_LOG_INTERVAL:
            self._error_logged = now
            log.error("kyselylokin tallennus epäonnistui: %s (yritetään uudelleen %d s välein, "
                      "epäonnistuneita yrityksiä: %d, kirjaamatta jääneitä rivejä: %d)",
                      self.write_error, RETRY_DELAY, self._failures, self.dropped)

    def _write_ok(self):
        if self.write_error is not None:
            log.info("kyselylokin tallennus toimii taas (kirjaamatta jääneitä rivejä: %d)", self.dropped)
        self.write_error = None
        self._failures = 0

    def writer_loop(self, stop_event):
        """Kirjoittaa jonon erissä enintään FLUSH_INTERVAL sekunnin välein ja poistaa vanhat rivit
        (LOG-004, LOG-007). Virhe ei saa pysäyttää säiettä (LOG-009): epäonnistunut erä säilytetään
        ja kirjoitetaan uudelleen uudella yhteydellä. Sillä välin rivit jäävät jonoon, ja täyden jonon rivit pudotetaan."""
        db = None
        batch = []
        last_purge = 0
        while not stop_event.is_set():
            if not batch:
                batch = self._take_batch(stop_event)
            try:
                if db is None:
                    db = self._connect()
                if batch:
                    db.executemany("INSERT INTO kyselyt (ts, client, domain, qtype, status, reason, ms, detail) "
                                   "VALUES (?,?,?,?,?,?,?,?)", batch)
                    db.commit()
                    batch = []
                if time.time() - last_purge > 3600:
                    cutoff = time.time() - self.config["log_retention_days"] * 86400
                    db.execute("DELETE FROM kyselyt WHERE ts < ?", (cutoff,))
                    db.commit()
                    last_purge = time.time()
                self._write_ok()
            except Exception as e:  # noqa: BLE001 – säie ei saa kuolla (esim. levy täynnä, lukko)
                self._write_failed(e)
                if db is not None:
                    try:
                        db.close()   # keskeneräinen tapahtuma perutaan
                    except Exception:  # noqa: BLE001
                        pass
                    db = None
                stop_event.wait(RETRY_DELAY)
        if db is not None:
            db.close()

    # ---------- luku ----------
    def _rows(self, sql, args=()):
        with self._read_lock:
            if not hasattr(self, "_rdb"):
                self._rdb = self._connect()
            return self._rdb.execute(sql, args).fetchall()

    def summary(self, hours=24):
        """Etusivun luvut. Samanaikaiset pyynnöt odottavat yhtä laskentaa ja saavat sen tuloksen,
        joten hidas laite ei kasaa jonoa raskaita kyselyjä."""
        with self._summary_lock:
            hit = self._summary_cache.get(hours)
            if hit and time.monotonic() - hit[0] < self.summary_ttl:
                return hit[1]
            try:
                result = self._summary(hours)
            except sqlite3.Error as e:
                # Tilakysely ei saa kaatua lokin vikaan: muuten käyttöliittymä ei voisi kertoa siitä
                if self.read_error is None:
                    log.error("kyselylokin luku epäonnistui: %s", e)
                self.read_error = str(e) or type(e).__name__
                return dict.fromkeys(("total", "blocked", "passed", "cached", "errors", "clients",
                                      "blocked_domains", "passed_domains"), 0)
            self.read_error = None
            self._summary_cache[hours] = (time.monotonic(), result)
            return result

    def _summary(self, hours):
        """Yhdellä läpikäynnillä. Läpäisseet = sallitut + välimuistista."""
        since = time.time() - hours * 3600
        row = self._rows(
            "SELECT COUNT(*), SUM(status='estetty'), SUM(status='valimuisti'), SUM(status='virhe'), "
            "COUNT(DISTINCT client), "
            "COUNT(DISTINCT CASE WHEN status='estetty' THEN domain END), "
            "COUNT(DISTINCT CASE WHEN status IN ('sallittu','valimuisti') THEN domain END) "
            "FROM kyselyt WHERE ts>=?", (since,))[0]
        total, blocked, cached, errors, clients, blocked_domains, passed_domains = (v or 0 for v in row)
        return {"total": total, "blocked": blocked, "passed": total - blocked - errors, "cached": cached,
                "errors": errors, "clients": clients,
                "blocked_domains": blocked_domains, "passed_domains": passed_domains}

    def timeline(self, hours=24, bucket=600):
        since = time.time() - hours * 3600
        rows = self._rows(
            "SELECT CAST(ts/? AS INT)*? AS b, COUNT(*), SUM(status='estetty') FROM kyselyt "
            "WHERE ts>=? GROUP BY b ORDER BY b", (bucket, bucket, since))
        data = {int(b): (t, bl or 0) for b, t, bl in rows}
        start = int(since // bucket) * bucket
        out = []
        for b in range(start, int(time.time()) + 1, bucket):
            t, bl = data.get(b, (0, 0))
            out.append({"t": b, "allowed": t - bl, "blocked": bl})
        return out

    def top(self, field, status=None, hours=24, limit=10):
        assert field in ("domain", "client")
        since = time.time() - hours * 3600
        sql = f"SELECT {field}, COUNT(*) c FROM kyselyt WHERE ts>=?"
        args = [since]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += f" GROUP BY {field} ORDER BY c DESC LIMIT ?"
        args.append(limit)
        return [{"name": n, "count": c} for n, c in self._rows(sql, args)]

    def recent(self, limit=200, search=None, status=None):
        sql = "SELECT ts, client, domain, qtype, status, reason, ms, detail FROM kyselyt WHERE 1=1"
        args = []
        if search:
            sql += " AND (domain LIKE ? OR client LIKE ?)"
            args += [f"%{search}%", f"%{search}%"]
        if status == "lapaisi":   # läpäisseet: sallitut ja välimuistista vastatut
            sql += " AND status IN ('sallittu','valimuisti')"
        elif status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(max(1, min(int(limit), 2000)))   # LIMIT -1 olisi SQLitessä "ei rajaa"
        keys = ("ts", "client", "domain", "qtype", "status", "reason", "ms", "detail")
        return [dict(zip(keys, r)) for r in self._rows(sql, args)]

    def clear(self):
        self._summary_cache.clear()
        with self._read_lock:
            db = self._connect()
            db.execute("DELETE FROM kyselyt")
            db.commit()
            db.close()
