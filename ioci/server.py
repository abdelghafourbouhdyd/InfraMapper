"""Local pivot server (--serve): open a case's graph and expand any node on demand.

Clicking "Pivot" on a File / Domain / IP / URL runs the same VT / urlscan / pDNS expansion as the
CLI on that one node, merges what it finds into the case, and saves graph.json / graph.html /
report.md. API keys stay in this process; the server only listens on localhost.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rich.text import Text

from . import graph as g
from . import regex_hunt as rh
from . import share
from .export import case_attribution, render_view, view_data, write_iocs_csv, write_json, write_report
from .investigator import Investigator
from .log import log

EXPANDABLE = {g.FILE, g.DOMAIN, g.IP, g.URL}
PIVOTABLE = EXPANDABLE | {g.CERT}   # a certificate pivot: SAN names, CT history, hunt queries
# search artefacts: their hits are pivot matches, not direct relations of the pivoted node
ARTEFACTS = {g.PATTERN, g.INTEL, g.TITLE, g.FAVICON, g.HTML_HASH, g.SCRIPT}


def load_case(inv: Investigator, case_dir: Path) -> None:
    data = json.loads((case_dir / "graph.json").read_text(encoding="utf-8"))
    for n in data["nodes"]:
        inv.g.nodes[n["id"]] = n
    for e in data["edges"]:
        inv.g.edges[(e["source"], e["target"], e["rel"])] = e["props"]
    inv.seed_id = data["seed"]
    inv.pivots = data.get("pivots", [])
    inv.hunt_queries = data.get("hunt_queries", [])
    inv.timelines = data.get("timelines", {})
    inv.dns_history = data.get("dns_history", {})
    inv.manual_pivots = data.get("manual_pivots", [])
    inv.new_domains = data.get("new_domains", [])
    inv.batch = data.get("batch")
    inv.regex_ladders = data.get("regex_ladders", [])
    inv.seen = set(inv.g.nodes)


class _JobLog(logging.Handler):
    def __init__(self, job: dict):
        super().__init__()
        self.job = job

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.job["log"].append(Text.from_markup(record.getMessage()).plain)
        except Exception:
            self.job["log"].append(record.getMessage())


class PivotServer:
    def __init__(self, inv: Investigator, case_dir: Path, vt, us, pdns, background: bool = True):
        self.inv, self.case_dir = inv, case_dir
        self.clients = {"vt": vt, "urlscan": us, "pdns": pdns, "ct": inv.ct}
        self.lock = threading.Lock()          # one expansion at a time; the rest queue up
        self.jobs: dict[str, dict] = {}
        load_case(inv, case_dir)
        self.title = f"InfraMapper — {inv.g.nodes[inv.seed_id]['value']}"
        inv.recluster()             # verdicts set in other cases since this one was saved
        # what the page shows while the lock is busy (background refresh, a pivot): never blocks
        self.snapshot = view_data(inv, self.title, case_dir)
        self.refreshing, self.refresh_error, self.refreshed = False, None, None
        if background:
            self.refreshing = True
            threading.Thread(target=self._refresh_bg, daemon=True, name=f"refresh-{case_dir.name}").start()
        else:
            self._refresh()

    # ------------------------------------------------------------------ catch-up on open
    def _refresh(self) -> None:
        """Prior reporting / feeds / VT comments for IOCs not checked yet (cases made before those
        checks, new keys), then re-save. Network bound: VT comments alone run at the key's rate (4/min
        on a free key), so the web UI runs this in the background and the page shows the saved case."""
        if self.inv.check_reporting():
            self.inv.recluster()
        self._save()                # also refreshes "seen in earlier cases" and the knowledge base

    def _refresh_bg(self) -> None:
        with self.lock:
            try:
                self._refresh()
            except Exception as exc:   # the saved case stays usable
                log.exception(f"background refresh of {self.case_dir.name} failed: {exc}")
                self.refresh_error = str(exc)
            finally:
                self.refreshing = False
                self.refreshed = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def page(self) -> str:
        """The graph page: live view when the graph is free, else the latest snapshot (no waiting)."""
        if self.lock.acquire(timeout=0.3):
            try:
                self.snapshot = view_data(self.inv, self.title, self.case_dir)
            finally:
                self.lock.release()
        return render_view(self.snapshot, self.title)

    def data(self) -> dict:
        if self.lock.acquire(timeout=0.3):
            try:
                self.snapshot = view_data(self.inv, self.title, self.case_dir)
            finally:
                self.lock.release()
        return self.snapshot

    def status(self) -> dict:
        return {"sources": {k: bool(v) for k, v in self.clients.items()}, "busy": self.lock.locked(),
                "kb": bool(self.inv.kb), "refreshing": self.refreshing, "refresh_error": self.refresh_error,
                "refreshed": self.refreshed}

    # ------------------------------------------------------------------ jobs
    def submit(self, nid: str, sources: list[str], force: bool) -> dict:
        node = self.inv.g.nodes.get(nid)
        if not node:
            raise ValueError("unknown node")
        if node["type"] not in PIVOTABLE:
            raise ValueError(f"can't pivot on a {node['type']} node")
        sources = [s for s in sources if self.clients.get(s)]
        if not sources:
            raise ValueError("no enabled data source selected")
        job = {"id": uuid.uuid4().hex[:12], "node": nid, "value": node["value"], "type": node["type"],
               "sources": sources, "force": force, "state": "queued", "log": [], "result": None}
        self.jobs[job["id"]] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def submit_regex(self, patterns: list[str], domain: str | None = None) -> dict:
        """Regex ladders from the page: the analyst's own regexes, or (none given) one built from the
        naming of ``domain`` / of the cluster's domains."""
        patterns = [p.strip() for p in patterns if isinstance(p, str) and p.strip()][:20]
        if not self.clients.get("urlscan"):
            raise ValueError("urlscan is not configured on the server")
        auto = [domain.lower()] if domain else None
        if not patterns and not rh.start(auto or self.inv.known_domains()):
            raise ValueError("no distinctive name token to build a regex from: type one")
        label = "; ".join(patterns) or f"auto regex from {domain or 'the cluster'}"
        job = {"id": uuid.uuid4().hex[:12], "node": self.inv.seed_id, "value": label, "type": "regex", "auto": auto,
               "patterns": patterns, "sources": ["urlscan"], "force": False, "state": "queued", "log": [], "result": None}
        self.jobs[job["id"]] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run_regex(self, job: dict) -> dict:
        inv = self.inv
        before_n, before_e = set(inv.g.nodes), set(inv.g.edges)
        pids = inv.regex_pivot(job["patterns"]) if job["patterns"] else inv.regex_hunt(job.get("auto"))
        inv.recluster()
        if inv.check_reporting():
            inv.recluster()
        new_nodes = set(inv.g.nodes) - before_n
        direct = sum(self._pin(pid, new_nodes)[0] for pid in pids)   # the analyst asked for these hits: show them
        return {"id": inv.seed_id, "value": job["value"], "type": "regex",
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sources": job["sources"],
                "new_nodes": len(new_nodes), "new_edges": len(set(inv.g.edges) - before_e),
                "direct": direct, "pivot_hits": 0, "patterns": job["patterns"]}

    def submit_query(self, nid: str, query: str, rule: str | None = None, platform: str = "urlscan") -> dict:
        """A custom search pivot from one node (hunting rules): urlscan (same as the CLI's ``-q``) or VT
        Intelligence, hung off ``nid`` so its hits are scored against the node the analyst pivoted from."""
        if nid not in self.inv.g.nodes:
            raise ValueError("unknown node")
        query = (query or "").strip()
        if not query or len(query) > 500:
            raise ValueError("query must be 1-500 characters")
        names = {"urlscan": "urlscan", "vt": "VirusTotal"}
        if platform not in names:
            raise ValueError(f"{platform} queries can't run here")
        src = platform
        if not self.clients.get(src):
            raise ValueError(f"{names[platform]} is not configured: add the key under API keys")
        job = {"id": uuid.uuid4().hex[:12], "node": nid, "value": query, "type": "query", "rule": rule,
               "platform": platform, "sources": [src], "force": False, "state": "queued", "log": [], "result": None}
        self.jobs[job["id"]] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run_query(self, job: dict) -> dict:
        inv, nid, q = self.inv, job["node"], job["value"]
        before_n, before_e = set(inv.g.nodes), set(inv.g.edges)
        if job.get("platform") == "vt":
            pid = inv.g.add_node(g.INTEL, q, kind="custom", rule=job.get("rule"))
            inv.g.add_edge(nid, pid, "ANALYST_PIVOT")
            inv._vt_intel_pivot(pid, q, "custom")
            if "search" in (inv.vt.denied if inv.vt else ()):
                log.warning("VT Intelligence search needs a premium key: no results")
        else:
            pid = inv.g.add_node(g.PATTERN, q, kind="custom", rule=job.get("rule"))
            inv.g.add_edge(nid, pid, "ANALYST_PIVOT")
            inv._urlscan_pivot(pid, q, "custom", 1)
        inv.recluster()
        new_nodes = set(inv.g.nodes) - before_n
        direct, hits = self._pin(nid, new_nodes)
        return {"id": nid, "value": q, "type": "query", "rule": job.get("rule"),
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sources": job["sources"],
                "new_nodes": len(new_nodes), "new_edges": len(set(inv.g.edges) - before_e),
                "direct": direct, "pivot_hits": hits}

    def _run(self, job: dict) -> None:
        with self.lock:
            inv, nid = self.inv, job["node"]
            job["state"] = "running"
            handler = _JobLog(job)
            log.addHandler(handler)
            saved = (inv.vt, inv.us, inv.pdns, inv.ct, inv.cfg.pdns_broad, inv.cfg.ns_broad, inv.cfg.broad)
            try:
                inv.vt = self.clients["vt"] if "vt" in job["sources"] else None
                inv.us = self.clients["urlscan"] if "urlscan" in job["sources"] else None
                inv.pdns = self.clients["pdns"] if "pdns" in job["sources"] else None
                inv.ct = self.clients["ct"] if "ct" in job["sources"] else None
                if job["type"] in ("regex", "query"):
                    rec = self._run_regex(job) if job["type"] == "regex" else self._run_query(job)
                    inv.manual_pivots.append(rec)
                    self._save()
                    job.update(state="done", result=rec)
                    return
                if job["force"]:
                    # analyst asked for it: list co-hosted domains even on shared hosting / big NS
                    inv.cfg.pdns_broad = inv.cfg.ns_broad = inv.cfg.broad = 10 ** 9
                    value = inv.g.nodes[nid]["value"]
                    inv.pivots = [p for p in inv.pivots if not (p["source"] == "pDNS" and p["query"] == value)]
                    inv.g.nodes[nid]["props"].pop("shared_hosting", None)
                before_n, before_e = set(inv.g.nodes), set(inv.g.edges)
                inv.expand_node(nid)
                new_nodes = set(inv.g.nodes) - before_n
                direct, hits = self._pin(nid, new_nodes)
                node = inv.g.nodes[nid]
                rec = {"id": nid, "value": node["value"], "type": node["type"],
                       "parent": node["props"].get("pivot_from"),
                       "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "sources": job["sources"], "force": job["force"] or None,
                       "new_nodes": len(new_nodes), "new_edges": len(set(inv.g.edges) - before_e),
                       "direct": direct, "pivot_hits": hits}
                inv.manual_pivots.append(rec)
                self._save()
                job.update(state="done", result=rec)
            except Exception as exc:
                log.exception(f"pivot on {nid} failed: {exc}")
                job.update(state="error", error=str(exc))
            finally:
                inv.vt, inv.us, inv.pdns, inv.ct, inv.cfg.pdns_broad, inv.cfg.ns_broad, inv.cfg.broad = saved
                log.removeHandler(handler)

    def _pin(self, nid: str, new_nodes: set[str]) -> tuple[int, int]:
        """Keep what the pivoted node links to directly visible, even if the cluster score is low.

        Search-artefact hits (title, favicon, domain pattern…) stay subject to the cluster score:
        they're look-alikes until something ties them to the cluster."""
        gr = self.inv.g
        gr.set_prop(nid, pinned=True)
        direct, hits = set(), set()
        for (s, d, _rel) in gr.edges:
            if nid not in (s, d):
                continue
            other = d if s == nid else s
            if gr.nodes[other]["type"] in ARTEFACTS:
                for (s2, d2, _r2) in gr.edges:
                    if other in (s2, d2):
                        o2 = d2 if s2 == other else s2
                        if o2 != nid and o2 in new_nodes and gr.nodes[o2]["type"] in EXPANDABLE:
                            hits.add(o2)
                continue
            direct.add(other)
            gr.set_prop(other, pinned=True)
            if other in new_nodes:
                gr.nodes[other]["props"].setdefault("pivot_from", nid)
        for o in hits - direct:
            gr.nodes[o]["props"].setdefault("pivot_from", nid)
        if gr.nodes[nid]["type"] == g.CERT:   # CT history: new subdomains of the cert's hosts
            for (s, d, rel) in gr.edges:
                if rel == "HAS_SUBDOMAIN" and d in new_nodes and d not in direct:
                    gr.set_prop(d, pinned=True)
                    gr.nodes[d]["props"].setdefault("pivot_from", nid)
                    direct.add(d)
        return len(direct), len(hits - direct)

    def verdict(self, nid: str, verdict: str | None, actor: str | None, note: str | None,
                family: str | None = None) -> None:
        """Analyst verdict from the graph page: stored globally, applied, case re-saved."""
        with self.lock:
            node = self.inv.g.nodes.get(nid)
            if not node:
                raise ValueError("unknown node")
            if not self.inv.kb:
                raise ValueError("knowledge base disabled (--no-kb)")
            self.inv.kb.set_verdict(node, verdict or None, actor, note, self.case_dir.name, family)
            self.inv.recluster()
            self._save()

    def _save(self) -> None:
        self.inv.cross_case(self.case_dir.name)
        write_json(self.inv, self.case_dir / "graph.json")
        self.snapshot = view_data(self.inv, self.title, self.case_dir)
        (self.case_dir / "graph.html").write_text(render_view(self.snapshot, self.title), encoding="utf-8")
        write_report(self.inv, self.case_dir / "report.md", self.inv.g.nodes[self.inv.seed_id]["value"])
        write_iocs_csv(self.inv, self.case_dir / "iocs.csv")
        share.write_all(self.inv, self.case_dir, self.title, getattr(self.inv, "tlp", "amber"))
        if self.inv.kb:
            self.inv.kb.index_case(self.inv, self.case_dir, case_attribution(self.inv))

    # ------------------------------------------------------------------ http
    def handler(self):
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):   # keep the console for pivot logs
                pass

            def _send(self, code: int, body, ctype: str = "application/json") -> None:
                data = body if isinstance(body, bytes) else (
                    body.encode() if isinstance(body, str) else json.dumps(body, default=str).encode())
                self.send_response(code)
                self.send_header("Content-Type", ctype + "; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path in ("/", "/graph.html"):
                    return self._send(200, srv.page(), "text/html")
                if path == "/api/status":
                    return self._send(200, srv.status())
                if path == "/api/graph":
                    return self._send(200, srv.data())
                if path.startswith("/api/job/"):
                    job = srv.jobs.get(path.rsplit("/", 1)[-1])
                    if not job:
                        return self._send(404, {"error": "no such job"})
                    return self._send(200, {**job, "log": job["log"][-40:]})
                if path == "/report.md":
                    return self._send(200, (srv.case_dir / "report.md").read_bytes(), "text/markdown")
                self._send(404, {"error": "not found"})

            def do_POST(self):
                # custom header = cross-site pages can't trigger pivots (it forces a CORS preflight
                # that this server never answers)
                if self.headers.get("X-IOCI") != "1":
                    return self._send(403, {"error": "missing X-IOCI header"})
                if self.path not in ("/api/pivot", "/api/verdict", "/api/regex"):
                    return self._send(404, {"error": "not found"})
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                    if self.path == "/api/regex":
                        job = srv.submit_regex(body.get("patterns") or [], body.get("domain") or None)
                        return self._send(202, {"job": job["id"]})
                    if self.path == "/api/verdict":
                        srv.verdict(body.get("id", ""), body.get("verdict"), body.get("actor"), body.get("note"),
                                    body.get("family"))
                        return self._send(200, {"ok": True})
                    job = srv.submit(body.get("id", ""), body.get("sources") or list(srv.clients),
                                     bool(body.get("force")))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
                self._send(202, {"job": job["id"]})

        return H

    def serve(self, host: str, port: int, open_browser: bool = True) -> None:
        for p in range(port, port + 20):   # next free port if a previous session still holds this one
            try:
                httpd = ThreadingHTTPServer((host, p), self.handler())
                break
            except OSError:
                continue
        else:
            raise OSError(f"no free port in {port}-{port + 19}")
        url = f"http://{host}:{p}/"
        log.info(f"pivot server on [bold]{url}[/] — case {self.case_dir}")
        # headless Linux: webbrowser would fall back to lynx / w3m in this terminal, so don't
        if open_browser and (sys.platform in ("darwin", "win32")
                             or os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")):
            threading.Timer(0.5, webbrowser.open, (url,)).start()
        log.info("click a node, then Pivot (or right-click it). Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
