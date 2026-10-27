"""Kyselyloki SQLiteen sekä tilastokyselyt käyttöliittymälle."""
import os
import queue
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS kyselyt (
    ts REAL NOT NULL,
    client TEXT NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT NOT NULL,
    status TEXT NOT NULL,      -- sallittu | estetty | valimuisti | virhe
    reason TEXT,
    ms REAL
);
CREATE INDEX IF NOT EXISTS i_ts ON kyselyt(ts);
"""


class QueryLog:
    def __init__(self, config):
        self.config = config
        self.path = os.path.join(config["data_dir"], "kyselyt.db")
        self._q = queue.Queue(maxsize=50000)
        self._read_lock = threading.Lock()
        db = self._connect()
        db.executescript(SCHEMA)
        db.close()
        # Laskurit muistissa, jotta etusivu on nopea myös ilman lokia
        self.started = time.time()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        return db

    def add(self, client, domain, qtype, status, reason=None, ms=None):
        if not self.config["log_queries"]:
            return
        try:
            self._q.put_nowait((time.time(), client, domain, qtype, status, reason, ms))
        except queue.Full:
            pass  # ylikuormassa lokirivit pudotetaan, DNS jatkaa toimintaa

    def writer_loop(self, stop_event):
        db = self._connect()
        last_purge = 0
        while not stop_event.is_set():
            batch = []
            try:
                batch.append(self._q.get(timeout=1))
                while len(batch) < 1000:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            if batch:
                db.executemany("INSERT INTO kyselyt VALUES (?,?,?,?,?,?,?)", batch)
                db.commit()
            if time.time() - last_purge > 3600:
                cutoff = time.time() - self.config["log_retention_days"] * 86400
                db.execute("DELETE FROM kyselyt WHERE ts < ?", (cutoff,))
                db.commit()
                last_purge = time.time()
        db.close()

    # ---------- luku ----------
    def _rows(self, sql, args=()):
        with self._read_lock:
            if not hasattr(self, "_rdb"):
                self._rdb = self._connect()
            return self._rdb.execute(sql, args).fetchall()

    def summary(self, hours=24):
        since = time.time() - hours * 3600
        total, blocked, cached = self._rows(
            "SELECT COUNT(*), SUM(status='estetty'), SUM(status='valimuisti') FROM kyselyt WHERE ts>=?",
            (since,))[0]
        clients = self._rows("SELECT COUNT(DISTINCT client) FROM kyselyt WHERE ts>=?", (since,))[0][0]
        return {"total": total or 0, "blocked": blocked or 0, "cached": cached or 0, "clients": clients or 0}

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
        sql = "SELECT ts, client, domain, qtype, status, reason, ms FROM kyselyt WHERE 1=1"
        args = []
        if search:
            sql += " AND (domain LIKE ? OR client LIKE ?)"
            args += [f"%{search}%", f"%{search}%"]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(min(int(limit), 2000))
        keys = ("ts", "client", "domain", "qtype", "status", "reason", "ms")
        return [dict(zip(keys, r)) for r in self._rows(sql, args)]

    def clear(self):
        with self._read_lock:
            db = self._connect()
            db.execute("DELETE FROM kyselyt")
            db.commit()
            db.close()
