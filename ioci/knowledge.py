"""Knowledge base across cases (``<out>/knowledge.db``, SQLite).

Two jobs:

* **memory**: every saved case indexes its confirmed IOCs and infrastructure fingerprints
  (certificate, favicon, HTML / script hash, SOA email, self-hosted NS / MX) with the attribution
  the case reached. A new case that touches any of them is told where they were seen before.
  Noise (known-benign, shared hosting, commodity DNS, too-broad pivots, analyst false positives) and
  unconfirmed candidates are never indexed: they'd link unrelated cases.
* **analyst verdicts**: *false positive* / *confirmed* / an actor or malware-family label on a node, set from the graph
  page or ``--mark``. Verdicts are global: an FP marked once stays out of every case.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from . import graph as g

HOSTS = {g.FILE, g.DOMAIN, g.IP, g.URL}
# JARM is left out: it fingerprints the TLS stack, not the operator (every Cloudflare / default nginx
# server shares one), so remembering it links unrelated cases. It still counts (+1) inside a case.
FINGERPRINTS = {g.CERT, g.FAVICON, g.HTML_HASH, g.SCRIPT, g.SOA, g.NS, g.MX}
MARKABLE = HOSTS | FINGERPRINTS | {g.JARM}
VERDICTS = ("fp", "confirmed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, dir TEXT, seed TEXT, updated INTEGER,
                                  actors TEXT, families TEXT);
CREATE TABLE IF NOT EXISTS observables (case_id TEXT, nid TEXT, type TEXT, value TEXT, role TEXT,
                                        priority TEXT, PRIMARY KEY (case_id, nid));
CREATE INDEX IF NOT EXISTS obs_nid ON observables (nid);
CREATE TABLE IF NOT EXISTS reports (report_id TEXT PRIMARY KEY, source TEXT, title TEXT, url TEXT UNIQUE,
                                    published INTEGER, actors TEXT, families TEXT, ttps TEXT, cves TEXT,
                                    n_iocs INTEGER, stix_path TEXT, ingested INTEGER, summary TEXT);
CREATE TABLE IF NOT EXISTS report_iocs (report_id TEXT, nid TEXT, type TEXT, value TEXT, role TEXT,
                                        PRIMARY KEY (report_id, nid));
CREATE INDEX IF NOT EXISTS rep_nid ON report_iocs (nid);
CREATE TABLE IF NOT EXISTS verdicts (nid TEXT PRIMARY KEY, type TEXT, value TEXT, verdict TEXT, actor TEXT,
                                     note TEXT, case_id TEXT, updated INTEGER, family TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
"""

def _role(n: dict) -> str | None:
    """How a node is worth remembering, or None when it would only link unrelated cases."""
    p = n["props"]
    if (p.get("warninglist") or p.get("shared_hosting") or p.get("commodity") or p.get("broad")
            or p.get("tor_exit") or p.get("c2_fronting") or p.get("analyst_verdict") == "fp"):
        return None
    if n["type"] in HOSTS:
        return "cluster" if p.get("cluster") else ("pinned" if p.get("pinned") else None)
    if n["type"] in FINGERPRINTS:
        return "fingerprint" if p.get("cluster") else None
    return None


def _chunks(xs: list, n: int = 500):
    for i in range(0, len(xs), n):
        yield xs[i:i + n]


class Knowledge:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)   # the pivot server calls from threads
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)
            # knowledge.db made by an earlier version: add the newer columns
            for table, col in (("verdicts", "family"), ("reports", "summary"), ("report_iocs", "role"), ("reports", "feed")):
                if col not in {r[1] for r in self.db.execute(f"PRAGMA table_info({table})")}:
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
            self.db.commit()

    # ------------------------------------------------------------------ memory
    def index_case(self, inv, case_dir: Path, attribution: dict | None = None) -> int:
        """(Re)index one case; returns observables stored."""
        case = case_dir.name
        seed = inv.g.nodes.get(inv.seed_id, {}).get("value", "")
        rows = [(case, nid, n["type"], n["value"], role, n["props"].get("priority"))
                for nid, n in inv.g.nodes.items() if (role := _role(n))]
        att = attribution or {}
        with self.lock, self.db:
            self.db.execute("DELETE FROM observables WHERE case_id = ?", (case,))
            self.db.executemany("INSERT OR REPLACE INTO observables VALUES (?, ?, ?, ?, ?, ?)", rows)
            self.db.execute("INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?, ?, ?)",
                            (case, str(case_dir), seed, int(time.time()),
                             json.dumps(att.get("actors", [])), json.dumps(att.get("families", []))))
        return len(rows)

    def seen_elsewhere(self, nids: list[str], case: str) -> dict[str, list[dict]]:
        """{node id: [earlier sightings in other cases, newest first]}."""
        out: dict[str, list[dict]] = {}
        with self.lock:
            for part in _chunks(sorted(set(nids))):
                q = (f"SELECT o.nid, o.case_id, o.role, o.priority, c.dir, c.seed, c.updated, c.actors, c.families "
                     f"FROM observables o JOIN cases c ON c.case_id = o.case_id "
                     f"WHERE o.nid IN ({','.join('?' * len(part))}) AND o.case_id != ? ORDER BY c.updated DESC")
                for nid, cid, role, pri, d, seed, upd, actors, fams in self.db.execute(q, (*part, case)):
                    out.setdefault(nid, []).append({"case": cid, "dir": d, "seed": seed, "date": upd, "role": role,
                                                    "priority": pri, "actors": json.loads(actors or "[]"),
                                                    "families": json.loads(fams or "[]")})
        return out

    def cases(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]

    # ------------------------------------------------------------------ published reports (--ingest)
    def add_report(self, r: dict, iocs: list[tuple[str, str]], roles: dict[str, str] | None = None) -> None:
        """r: report_id, source, title, url, published, actors, families, ttps, cves, stix_path, summary,
        feed (topic feed name; None for vendor research). iocs: [(graph node type, value)];
        roles: {value: c2 / payload / …} (AI enrichment)."""
        roles = roles or {}
        with self.lock, self.db:
            self.db.execute("DELETE FROM report_iocs WHERE report_id = ?", (r["report_id"],))
            self.db.execute("INSERT OR REPLACE INTO reports (report_id, source, title, url, published, actors, families, "
                            "ttps, cves, n_iocs, stix_path, ingested, summary, feed) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (r["report_id"], r["source"], r["title"], r["url"], r["published"],
                             json.dumps(r["actors"]), json.dumps(r["families"]), json.dumps(r["ttps"]),
                             json.dumps(r["cves"]), len(iocs), r.get("stix_path"), int(time.time()), r.get("summary"),
                             r.get("feed")))
            self.db.executemany("INSERT OR IGNORE INTO report_iocs (report_id, nid, type, value, role) VALUES (?, ?, ?, ?, ?)",
                                [(r["report_id"], g.node_id(t, v), t, v, roles.get(v)) for t, v in iocs])

    def known_report_urls(self) -> set[str]:
        with self.lock:
            return {u for (u,) in self.db.execute("SELECT url FROM reports")}

    def _report_row(self, row) -> dict:
        rid, src, title, url, pub, actors, fams, ttps, cves, n, path, summary, feed, *role = row
        return {"report_id": rid, "source": src, "title": title, "url": url, "published": pub,
                "actors": json.loads(actors or "[]"), "families": json.loads(fams or "[]"),
                "ttps": json.loads(ttps or "[]"), "cves": json.loads(cves or "[]"), "n_iocs": n, "stix_path": path,
                "summary": summary, "feed": feed, "role": role[0] if role else None}

    COLS = ("r.report_id, r.source, r.title, r.url, r.published, r.actors, r.families, r.ttps, r.cves, r.n_iocs, "
            "r.stix_path, r.summary, r.feed")
    # kind filter: topic-feed articles vs vendor research (--ingest)
    KIND = {"news": " AND r.feed IS NOT NULL", "vendor": " AND r.feed IS NULL"}

    def report_hits(self, nid: str) -> list[dict]:
        """Published reports (local dataset) that list this IOC, with its role there (AI enrichment)."""
        with self.lock:
            rows = self.db.execute(f"SELECT {self.COLS}, i.role FROM report_iocs i JOIN reports r "
                                   f"ON r.report_id = i.report_id WHERE i.nid = ? ORDER BY r.published DESC", (nid,)).fetchall()
        return [self._report_row(x) for x in rows]

    def report_by_url(self, url: str) -> dict | None:
        u = url.rstrip("/")
        with self.lock:
            row = self.db.execute(f"SELECT {self.COLS} FROM reports r WHERE rtrim(r.url, '/') = ?", (u,)).fetchone()
        return self._report_row(row) if row else None

    def search_reports(self, term: str, limit: int = 50, kind: str = "") -> list[dict]:
        """By IOC (exact), or actor / family / ATT&CK id / CVE / title words (case-insensitive)."""
        t = term.strip()
        with self.lock:
            rows = self.db.execute(
                f"SELECT DISTINCT {self.COLS} FROM reports r LEFT JOIN report_iocs i ON i.report_id = r.report_id "
                f"WHERE (lower(i.value) = lower(?) OR r.actors LIKE ? OR r.families LIKE ? OR r.ttps LIKE ? "
                f"OR r.cves LIKE ? OR r.title LIKE ? OR r.feed LIKE ?){self.KIND.get(kind, '')} "
                f"ORDER BY r.published DESC LIMIT ?",
                (t, f"%{t}%", f"%{t}%", f"%{t.upper()}%", f"%{t.upper()}%", f"%{t}%", f"%{t}%", limit)).fetchall()
        return [self._report_row(x) for x in rows]

    def recent_reports(self, n: int = 10, kind: str = "") -> list[dict]:
        with self.lock:
            rows = self.db.execute(f"SELECT {self.COLS} FROM reports r WHERE 1=1{self.KIND.get(kind, '')} "
                                   f"ORDER BY r.ingested DESC, r.published DESC LIMIT ?", (n,)).fetchall()
        return [self._report_row(x) for x in rows]

    def report(self, report_id: str) -> dict | None:
        """One report with every IOC it lists ([{type, value, role}])."""
        with self.lock:
            row = self.db.execute(f"SELECT {self.COLS} FROM reports r WHERE r.report_id = ?", (report_id,)).fetchone()
        if not row:
            return None
        return {**self._report_row(row), "iocs": self.report_iocs(report_id)}

    def report_iocs(self, report_id: str, limit: int = 2000) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT nid, type, value, role FROM report_iocs WHERE report_id = ? "
                                   "ORDER BY type, value LIMIT ?", (report_id, limit)).fetchall()
        return [{"nid": nid, "type": t, "value": v, "role": role} for nid, t, v, role in rows]

    def reports_for(self, nids: list[str]) -> list[dict]:
        """Reports listing any of these IOCs, newest first: each with the IOCs it matched ("matched": nids)."""
        found: dict[str, dict] = {}
        with self.lock:
            for part in _chunks(sorted(set(nids))):
                q = (f"SELECT {self.COLS}, i.role, i.nid FROM report_iocs i JOIN reports r ON r.report_id = i.report_id "
                     f"WHERE i.nid IN ({','.join('?' * len(part))})")
                for row in self.db.execute(q, part).fetchall():
                    rep = found.setdefault(row[0], {**self._report_row(row[:-1]), "matched": []})
                    rep["matched"].append(row[-1])
        return sorted(found.values(), key=lambda r: -(r["published"] or 0))

    def report_stats(self) -> dict:
        with self.lock:
            n, iocs = self.db.execute("SELECT COUNT(*), COALESCE(SUM(n_iocs), 0) FROM reports").fetchone()
            by = self.db.execute("SELECT source, COUNT(*) FROM reports GROUP BY source ORDER BY 2 DESC").fetchall()
            news = self.db.execute("SELECT COUNT(*) FROM reports WHERE feed IS NOT NULL").fetchone()[0]
        return {"reports": n, "iocs": iocs, "by_source": by, "news": news}

    # ------------------------------------------------------------------ settings
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))

    # ------------------------------------------------------------------ verdicts
    def verdicts(self, nids: list[str]) -> dict[str, dict]:
        out = {}
        with self.lock:
            for part in _chunks(sorted(set(nids))):
                q = (f"SELECT nid, verdict, actor, family, note, case_id, updated FROM verdicts "
                     f"WHERE nid IN ({','.join('?' * len(part))})")
                for nid, v, actor, fam, note, cid, upd in self.db.execute(q, part):
                    out[nid] = {"verdict": v, "actor": actor, "family": fam, "note": note, "case": cid, "date": upd}
        return out

    def set_verdict(self, n: dict, verdict: str | None, actor: str | None = None, note: str | None = None,
                    case: str | None = None, family: str | None = None) -> None:
        """verdict 'fp' / 'confirmed' / None (actor / malware family label or note only). Nothing left = cleared."""
        if verdict not in (None, *VERDICTS):
            raise ValueError(f"verdict must be one of {VERDICTS}")
        if n["type"] not in MARKABLE:
            raise ValueError(f"can't mark a {n['type']} node")
        actor, family = (actor or "").strip()[:80] or None, (family or "").strip()[:80] or None
        note = (note or "").strip()[:500] or None
        if verdict == "fp":
            actor = family = None   # a false positive isn't anyone's infrastructure or tooling
        with self.lock, self.db:
            if not (verdict or actor or family or note):
                self.db.execute("DELETE FROM verdicts WHERE nid = ?", (n["id"],))
                return
            self.db.execute("INSERT OR REPLACE INTO verdicts (nid, type, value, verdict, actor, note, case_id, updated, "
                            "family) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (n["id"], n["type"], n["value"], verdict, actor, note, case, int(time.time()), family))

    def clear_verdict(self, nid: str) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM verdicts WHERE nid = ?", (nid,))
