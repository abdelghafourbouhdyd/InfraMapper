"""InfraMapper web UI (``python infra-mapper.py --web``).

Pages are server-rendered shells (design system in static/css/theme.css); data comes from
``/api/*``. Investigations run the real CLI in the background (see jobs.py); the interactive pivot
graph of a case is the existing ``graph_template.html`` served live under ``/cases/<case>/graph/``.

Security: binds to 127.0.0.1 by default. Set INFRAMAPPER_WEB_PASSWORD to require a sign-in (mandatory when
binding to another interface). Every POST must carry ``X-InfraMapper: 1`` — the same rule as the original
pivot server — so a cross-site page can't trigger investigations or pivots.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import uuid
from datetime import datetime
from pathlib import Path

from flask import (Blueprint, Flask, abort, jsonify, redirect, render_template, request, send_file, session,
                   url_for)

from .. import rules as rule_svc
from ..keycheck import BY_ID as PROVIDER_BY_ID, PROVIDERS, KeyChecker
from ..rules import RuleStore
from . import analysis
from . import cases as case_svc
from .jobs import JobRunner
from .runtime import KEYS, Runtime, env_set, env_status

UPLOAD_EXT = {".txt", ".md", ".csv", ".html", ".htm", ".pdf", ".json"}
TLPS = ("clear", "green", "amber", "red")


def _md():
    from markdown_it import MarkdownIt
    return MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


def create_app(root: Path, out: Path, preload: bool = False) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static", static_url_path="/static")
    key_file = root / ".cache" / "web_secret"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    app.config.update(SECRET_KEY=os.getenv("INFRAMAPPER_WEB_SECRET") or key_file.read_text().strip(),
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=25 * 1024 * 1024)
    rt = Runtime(root, out)
    if preload:   # warninglists / actor names in the background: the first case opens fast too
        import threading
        threading.Thread(target=rt.preload, daemon=True, name="inframapper-preload").start()
    jobs = JobRunner(root, out)
    keys = KeyChecker(root / ".cache")
    rules = RuleStore(out / "hunt_rules.json")
    rules.apply()   # combinations and pivot tuning for the graph sessions run in this process
    md = _md()
    password = os.getenv("INFRAMAPPER_WEB_PASSWORD", "")
    bp = Blueprint("ui", __name__)

    # ── auth / csrf ─────────────────────────────────────────────────────────
    @app.before_request
    def _guard():
        if request.endpoint in ("ui.login", "static", "ui.healthz"):
            return None
        if password and not session.get("ok"):
            if request.path.startswith("/api/") or "/graph/api/" in request.path:
                return jsonify(error="unauthorized"), 401
            return redirect(url_for("ui.login", next=request.full_path))
        if request.method == "POST" and request.headers.get("X-InfraMapper") != "1" and request.endpoint != "ui.logout":
            return jsonify(error="missing X-InfraMapper header"), 403
        return None

    @bp.route("/login", methods=["GET", "POST"])
    def login():
        if not password:
            return redirect("/")
        err = ""
        if request.method == "POST":
            if hmac.compare_digest(request.form.get("password", ""), password):
                session.clear()
                session["ok"] = True
                nxt = request.args.get("next") or "/"
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
            err = "Wrong password"
        return render_template("login.html", error=err)

    @bp.route("/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        return redirect("/login" if password else "/")

    @bp.get("/healthz")
    def healthz():
        return {"ok": True}

    # ── pages ───────────────────────────────────────────────────────────────
    def page(name, tpl, title):
        def view(**kw):
            return render_template(tpl, active=name, title=title, auth=bool(password), **kw)
        view.__name__ = f"page_{name}"
        return view

    for path, name, tpl, title in (("/", "dashboard", "dashboard.html", "Dashboard"),
                                   ("/new", "new", "new.html", "New investigation"),
                                   ("/cases", "cases", "cases.html", "Cases"),
                                   ("/jobs", "jobs", "jobs.html", "Jobs"),
                                   ("/knowledge", "knowledge", "knowledge.html", "Knowledge base"),
                                   ("/reports", "reports", "reports.html", "Threat reports"),
                                   ("/rules", "rules", "rules.html", "Hunting rules"),
                                   ("/settings", "settings", "settings.html", "Settings")):
        bp.add_url_rule(path, f"page_{name}", page(name, tpl, title))

    @bp.get("/cases/<name>")
    def case_page(name):
        d = _case(name)
        return render_template("case.html", active="cases", title=case_svc.summary(d)["seed"], case=name,
                               auth=bool(password))

    @bp.get("/jobs/<jid>")
    def job_page(jid):
        jobs.get(jid)
        return render_template("job.html", active="jobs", title="Job", jid=jid, auth=bool(password))

    def _case(name) -> Path:
        try:
            return case_svc.case_dir(out, name)
        except LookupError:
            abort(404)

    # ── case files ──────────────────────────────────────────────────────────
    @bp.get("/cases/<name>/files/<fname>")
    def case_file(name, fname):
        d = _case(name)
        if fname not in case_svc.DOWNLOADS or not (d / fname).exists():
            abort(404)
        return send_file(d / fname, mimetype=case_svc.DOWNLOADS[fname], as_attachment=request.args.get("dl") == "1",
                         download_name=f"{name}_{fname}")

    @bp.get("/cases/<name>/hunt/<fname>")
    def case_hunt(name, fname):
        d = _case(name)
        p = (d / "hunt" / fname)
        if "/" in fname or "\\" in fname or p.suffix not in case_svc.HUNT_EXT or not p.is_file():
            abort(404)
        return send_file(p, mimetype="text/plain", as_attachment=True, download_name=f"{name}_{fname}")

    # ── live pivot graph (the existing graph page, unchanged) ────────────────
    @bp.get("/cases/<name>/graph")
    def graph_redirect(name):
        return redirect(url_for("ui.graph_page", name=name))

    @bp.get("/cases/<name>/graph/")
    def graph_page(name):
        # never waits on a running refresh / pivot: srv.page() falls back to the latest snapshot
        html = rt.server(_case(name)).page()
        return html, 200, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}

    @bp.get("/cases/<name>/graph/api/status")
    def graph_status(name):
        return jsonify(rt.server(_case(name)).status())

    @bp.get("/cases/<name>/graph/api/graph")
    def graph_data(name):
        data = rt.server(_case(name)).data()
        return app.response_class(json.dumps(data, default=str), mimetype="application/json")

    @bp.get("/cases/<name>/graph/api/job/<jid>")
    def graph_job(name, jid):
        srv = rt.server(_case(name))
        job = srv.jobs.get(jid)
        if not job:
            return jsonify(error="no such job"), 404
        return app.response_class(json.dumps({**job, "log": job["log"][-40:]}, default=str), mimetype="application/json")

    @bp.get("/cases/<name>/graph/report.md")
    def graph_report(name):
        return send_file(_case(name) / "report.md", mimetype="text/markdown")

    @bp.post("/cases/<name>/graph/api/<action>")
    def graph_action(name, action):
        srv = rt.server(_case(name))
        body = request.get_json(silent=True) or {}
        try:
            if action == "regex":
                job = srv.submit_regex(body.get("patterns") or [], body.get("domain") or None)
                return jsonify(job=job["id"]), 202
            if action == "verdict":
                srv.verdict(body.get("id", ""), body.get("verdict"), body.get("actor"), body.get("note"), body.get("family"))
                return jsonify(ok=True)
            if action == "pivot":
                job = srv.submit(body.get("id", ""), body.get("sources") or list(srv.clients), bool(body.get("force")))
                return jsonify(job=job["id"]), 202
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        abort(404)

    # ── API ─────────────────────────────────────────────────────────────────
    @bp.get("/api/dashboard")
    def api_dashboard():
        cs = case_svc.list_cases(out)
        pri: dict[str, int] = {}
        for c in cs:
            for k, v in c["priorities"].items():
                pri[k] = pri.get(k, 0) + v
        with rt.kb.lock:
            verdicts = dict(rt.kb.db.execute("SELECT verdict, COUNT(*) FROM verdicts GROUP BY verdict").fetchall())
            n_verdicts = rt.kb.db.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        ks = keys.status()
        return jsonify(cases=len(cs), recent=cs[:12], priorities=pri, kb_cases=rt.kb.cases(), verdicts=verdicts,
                       n_verdicts=n_verdicts, reports=rt.kb.report_stats(), jobs=jobs.list(8), active=jobs.active(),
                       sources=rt.sources(), rules=sum(1 for r in rules.list() if r.get("enabled", True)),
                       key_health=[{"id": p["id"], "name": p["name"], "status": ks[p["id"]]["status"],
                                    "message": ks[p["id"]]["message"]} for p in PROVIDERS])

    @bp.get("/api/cases")
    def api_cases():
        q = (request.args.get("q") or "").lower().strip()
        t = request.args.get("type") or ""
        rows = case_svc.list_cases(out)
        if q:
            rows = [r for r in rows if q in r["seed"].lower() or q in r["name"].lower()
                    or any(q in a.lower() for a in r["actors"] + r["families"])]
        if t:
            rows = [r for r in rows if r["seed_type"] == t]
        return jsonify(items=rows)

    @bp.get("/api/cases/<name>")
    def api_case(name):
        d = _case(name)
        s = case_svc.summary(d)
        report = (d / "report.md").read_text(encoding="utf-8") if (d / "report.md").exists() else ""
        return jsonify(summary=s, report_html=md.render(report), iocs=case_svc.iocs(d), hunt=case_svc.hunt_files(d),
                       live=name in rt.servers)

    @bp.post("/api/cases/<name>/warm")
    def api_case_warm(name):
        """Load the live pivot session in the background so the graph tab opens instantly."""
        d = _case(name)
        if name not in rt.servers:
            import threading
            threading.Thread(target=lambda: _safe_warm(d), daemon=True).start()
        return jsonify(live=name in rt.servers)

    def _safe_warm(d: Path) -> None:
        try:
            rt.server(d)
        except Exception as exc:  # noqa: BLE001 — the graph route reports it when opened
            app.logger.warning("warming %s failed: %s", d.name, exc)

    @bp.get("/api/search")
    def api_search():
        """Find an indicator across every case (graph nodes) and the knowledge base."""
        q = (request.args.get("q") or "").strip().lower()
        if len(q) < 3:
            return jsonify(items=[], verdicts=[])
        hits = []
        for c in case_svc.list_cases(out):
            try:
                data = json.loads((out / c["name"] / "graph.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for n in data.get("nodes", []):
                if q in str(n.get("value", "")).lower():
                    p = n.get("props") or {}
                    hits.append({"case": c["name"], "seed": c["seed"], "type": n["type"], "value": n["value"],
                                 "priority": p.get("priority"), "action": p.get("action"), "cluster": p.get("cluster")})
                    if len(hits) >= 300:
                        break
        with rt.kb.lock:
            vs = rt.kb.db.execute("SELECT nid, type, value, verdict, actor, family, note, case_id, updated FROM verdicts"
                                  " WHERE lower(value) LIKE ? LIMIT 50", (f"%{q}%",)).fetchall()
        return jsonify(items=hits, verdicts=[dict(zip(("nid", "type", "value", "verdict", "actor", "family", "note",
                                                       "case", "updated"), v)) for v in vs])

    def _opts(form) -> list[str]:
        args: list[str] = []

        def num(name, flag, lo, hi):
            v = form.get(name)
            if v not in (None, ""):
                n = int(v)
                if not lo <= n <= hi:
                    raise ValueError(f"{name} must be between {lo} and {hi}")
                args.extend([flag, str(n)])

        num("depth", "--depth", 1, 3)
        num("limit", "--limit", 1, 100)
        num("max_expand", "--max-expand", 1, 500)
        num("scans", "--scans", 0, 20)
        num("min_score", "--min-score", 1, 5)
        num("batch_vt", "--batch-vt", 0, 1000)
        for name in ("no_vt", "no_urlscan", "no_pdns", "no_ct", "no_intel", "no_feeds", "no_new_hunt",
                     "no_regex_hunt", "no_hop", "vt_intel"):
            if str(form.get(name, "")).lower() in ("1", "true", "on"):
                args.append("--" + name.replace("_", "-"))
        tlp = form.get("tlp") or "amber"
        if tlp not in TLPS:
            raise ValueError("invalid TLP")
        args.extend(["--tlp", tlp])
        for line in str(form.get("queries") or "").splitlines():
            if line.strip():
                args.extend(["-q", line.strip()])
        for line in str(form.get("regexes") or "").splitlines():
            if line.strip():
                re.compile(line.strip())
                args.extend(["-r", line.strip()])
        return args

    @bp.post("/api/investigate")
    def api_investigate():
        form = request.form if request.form else (request.get_json(silent=True) or {})
        mode = form.get("mode") or "ioc"
        try:
            opts = _opts(form)
            if mode == "report":
                src = ""
                up = request.files.get("file")
                if up and up.filename:
                    ext = Path(up.filename).suffix.lower()
                    if ext not in UPLOAD_EXT:
                        raise ValueError(f"unsupported file type {ext}")
                    d = root / "cases" / ".uploads"
                    d.mkdir(parents=True, exist_ok=True)
                    src_path = d / f"{datetime.now():%Y%m%d-%H%M%S}_{uuid.uuid4().hex[:6]}{ext}"
                    up.save(src_path)
                    src, label = str(src_path), f"report file {up.filename}"
                elif (form.get("report_url") or "").strip():
                    src = form["report_url"].strip()
                    if not re.match(r"^https?://", src, re.I):
                        raise ValueError("report URL must start with http:// or https://")
                    label = f"report {src}"
                elif (form.get("report_text") or "").strip():
                    d = root / "cases" / ".uploads"
                    d.mkdir(parents=True, exist_ok=True)
                    src_path = d / f"{datetime.now():%Y%m%d-%H%M%S}_{uuid.uuid4().hex[:6]}.txt"
                    src_path.write_text(form["report_text"], encoding="utf-8")
                    src, label = str(src_path), "pasted text"
                else:
                    raise ValueError("give a report URL, a file or pasted text")
                job = jobs.submit("triage", label, ["--from", src, "--no-serve", "--no-browser", *opts])
            else:
                iocs = [t for t in re.split(r"[\s,;]+", str(form.get("iocs") or "")) if t]
                if not iocs:
                    raise ValueError("enter at least one IOC")
                bad = [t for t in iocs if t.startswith("-")]
                if bad:
                    raise ValueError(f"not an IOC: {bad[0]}")
                if len(iocs) > 500:
                    raise ValueError("at most 500 IOCs per run")
                kind = "investigate" if len(iocs) == 1 else "triage"
                label = iocs[0] if len(iocs) == 1 else f"{len(iocs)} IOCs ({', '.join(iocs[:3])}…)"
                job = jobs.submit(kind, label, [*iocs, "--no-serve", "--no-browser", *opts])
        except (ValueError, re.error) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(job), 202

    @bp.get("/api/jobs")
    def api_jobs():
        return jsonify(items=jobs.list(200))

    @bp.get("/api/jobs/<jid>")
    def api_job(jid):
        try:
            return jsonify(jobs.get(jid, int(request.args.get("tail") or 400)))
        except LookupError:
            return jsonify(error="no such job"), 404

    @bp.post("/api/jobs/<jid>/cancel")
    def api_job_cancel(jid):
        try:
            return jsonify(jobs.cancel(jid))
        except LookupError:
            return jsonify(error="no such job"), 404

    @bp.get("/api/knowledge")
    def api_knowledge():
        q = (request.args.get("q") or "").strip().lower()
        v = request.args.get("verdict") or ""
        sql, args = ("SELECT nid, type, value, verdict, actor, family, note, case_id, updated FROM verdicts WHERE 1=1", [])
        if q:
            sql += " AND (lower(value) LIKE ? OR lower(actor) LIKE ? OR lower(family) LIKE ? OR lower(note) LIKE ?)"
            args += [f"%{q}%"] * 4
        if v in ("fp", "confirmed"):
            sql += " AND verdict = ?"
            args.append(v)
        elif v == "label":
            sql += " AND verdict IS NULL"
        with rt.kb.lock:
            rows = rt.kb.db.execute(sql + " ORDER BY updated DESC LIMIT 500", args).fetchall()
            n_obs = rt.kb.db.execute("SELECT COUNT(*) FROM observables").fetchone()[0]
        cols = ("nid", "type", "value", "verdict", "actor", "family", "note", "case", "updated")
        return jsonify(items=[dict(zip(cols, r)) for r in rows], cases=rt.kb.cases(), observables=n_obs,
                       path=str(rt.kb.path))

    @bp.post("/api/knowledge/verdict")
    def api_verdict():
        from .. import graph as g
        from ..patterns import detect_type
        body = request.get_json(silent=True) or {}
        ioc = (body.get("ioc") or "").strip()
        if not ioc:
            return jsonify(error="IOC is required"), 400
        t, value = detect_type(ioc)
        ntype = {"file": g.FILE, "domain": g.DOMAIN, "ip": g.IP, "url": g.URL}[t]
        node = {"id": g.node_id(ntype, value), "type": ntype, "value": value}
        verdict = body.get("verdict") or None
        try:
            rt.kb.set_verdict(node, verdict if verdict in ("fp", "confirmed") else None, body.get("actor"),
                              body.get("note"), "web", body.get("family"))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        rt.drop_all()   # open graphs pick the verdict up when reloaded
        return jsonify(ok=True, nid=node["id"])

    @bp.post("/api/knowledge/clear")
    def api_verdict_clear():
        nid = (request.get_json(silent=True) or {}).get("nid", "")
        rt.kb.clear_verdict(nid)
        rt.drop_all()
        return jsonify(ok=True)

    @bp.post("/api/knowledge/reindex")
    def api_reindex():
        return jsonify(jobs.submit("reindex", "rebuild knowledge base", ["--reindex"])), 202

    @bp.get("/api/reports")
    def api_reports():
        q = (request.args.get("q") or "").strip()
        kind = request.args.get("kind") or ""
        rows = rt.kb.search_reports(q, 200, kind) if q else rt.kb.recent_reports(int(request.args.get("n") or 50), kind)
        from ..reports import SOURCES
        return jsonify(items=rows, stats=rt.kb.report_stats(),
                       sources=[{"slug": s[0], "name": s[1]} for s in SOURCES])

    @bp.get("/api/reports/<report_id>")
    def api_report(report_id):
        r = rt.kb.report(report_id)
        if not r:
            return jsonify(error="no such report"), 404
        return jsonify(r)

    @bp.get("/api/cases/<name>/articles")
    def api_case_articles(name):
        """Threat reports that list an IOC of this case, read live from the knowledge base: a report
        ingested after the investigation shows up too."""
        from .. import graph as g
        d = _case(name)
        try:
            data = json.loads((d / "graph.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return jsonify(items=[])
        hosts = {g.FILE, g.DOMAIN, g.IP, g.URL}
        nodes = {n["id"]: n for n in data.get("nodes", []) if n.get("type") in hosts
                 and ((n.get("props") or {}).get("cluster") is not False or (n.get("props") or {}).get("pinned")
                      or (n.get("props") or {}).get("seed"))}
        seed = data.get("seed")
        items = []
        for r in rt.kb.reports_for(list(nodes))[:100]:
            iocs = rt.kb.report_iocs(r["report_id"], 300)
            matched = set(r["matched"])
            items.append({**{k: r[k] for k in ("report_id", "source", "feed", "title", "url", "published", "actors",
                                               "families", "ttps", "n_iocs")},
                          "matched": [{"type": nodes[m]["type"], "value": nodes[m]["value"], "seed": m == seed}
                                      for m in r["matched"] if m in nodes],
                          "others": [{"type": i["type"], "value": i["value"],
                                      "in_case": i["nid"] in nodes} for i in iocs if i["nid"] not in matched]})
        items.sort(key=lambda x: (not any(m["seed"] for m in x["matched"]), -len(x["matched"]), -(x["published"] or 0)))
        return jsonify(items=items)

    @bp.post("/api/reports/ingest")
    def api_ingest():
        from ..reports import SOURCES
        body = request.get_json(silent=True) or {}
        days = int(body.get("days") or 60)
        if not 1 <= days <= 365:
            return jsonify(error="days must be 1-365"), 400
        args = ["--ingest", "--days", str(days)]
        src = [s for s in body.get("sources") or [] if s in {x[0] for x in SOURCES}]
        if src:
            args += ["--sources", ",".join(src)]
        return jsonify(jobs.submit("ingest", f"ingest reports ({days} days)", args)), 202

    @bp.get("/api/settings")
    def api_settings():
        return jsonify(keys=env_status(root), sources=rt.sources(), cases_dir=str(out), cache_dir=str(root / ".cache"),
                       auth=bool(password))

    @bp.post("/api/settings")
    def api_settings_set():
        body = request.get_json(silent=True) or {}
        try:
            env_set(root, body.get("key", ""), body.get("value", ""))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        rt.drop_all()
        return jsonify(keys=env_status(root))

    # ── API keys: providers, validation, quotas ─────────────────────────────
    def _providers() -> list[dict]:
        env = {k["key"]: k for k in env_status(root)}
        st = keys.status()
        return [{**p, "fields": [env[k] for k in p["keys"] if k in env], "state": st[p["id"]]} for p in PROVIDERS]

    def _provider_values(pid: str, values) -> dict:
        if pid not in PROVIDER_BY_ID:
            raise ValueError("unknown provider")
        if not isinstance(values, dict):
            raise ValueError("values must be an object")
        allowed = set(PROVIDER_BY_ID[pid]["keys"])
        bad = [k for k in values if k not in allowed]
        if bad:
            raise ValueError(f"{bad[0][:40]} is not a setting of this provider")
        return {k: str(v or "").strip() for k, v in values.items()}

    @bp.get("/api/keys")
    def api_keys():
        return jsonify(providers=_providers(), auth=bool(password), cases_dir=str(out), cache_dir=str(root / ".cache"))

    @bp.post("/api/keys/test")
    def api_keys_test():
        body = request.get_json(silent=True) or {}
        try:
            vals = _provider_values(body.get("provider", ""), body.get("values") or {})
            res = keys.test(body["provider"], {k: v for k, v in vals.items() if v} or None)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(result=res, providers=_providers())

    @bp.post("/api/keys/save")
    def api_keys_save():
        """Store a provider's values in .env (empty = leave unchanged), optionally test them right away."""
        body = request.get_json(silent=True) or {}
        pid = body.get("provider", "")
        try:
            vals = _provider_values(pid, body.get("values") or {})
            for k, v in vals.items():
                if v:
                    env_set(root, k, v)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        rt.drop_all()   # new pivot sessions pick the key up
        res = None
        if body.get("test"):
            keys.last.pop(pid, None)
            res = keys.test(pid)
        return jsonify(result=res, providers=_providers())

    @bp.post("/api/keys/remove")
    def api_keys_remove():
        key = (request.get_json(silent=True) or {}).get("key", "")
        if key not in {k for k, *_ in KEYS}:
            return jsonify(error="unknown setting"), 400
        env_set(root, key, "")
        rt.drop_all()
        return jsonify(providers=_providers())

    # ── scored pivot results ────────────────────────────────────────────────
    @bp.get("/api/cases/<name>/pivots")
    def api_case_pivots(name):
        d = _case(name)
        res = analysis.pivot_rows(analysis.load(d, rt.servers.get(name)))
        res.pop("scores", None)
        return app.response_class(json.dumps(res, default=str), mimetype="application/json")

    # ── hunting rules ───────────────────────────────────────────────────────
    @bp.get("/api/rules")
    def api_rules():
        return jsonify(items=rules.list(), pivots=rules.pivots(), schema=rule_svc.schema(),
                       cases=[{"name": c["name"], "seed": c["seed"]} for c in case_svc.list_cases(out)])

    def _rule_write(fn, *a, created=False):
        """Run a store change; the engine picks it up right away (graph sessions in this process)."""
        try:
            res = fn(*a)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        rules.apply()
        return jsonify(res if res is not None else {"ok": True}), 201 if created else 200

    @bp.post("/api/rules")
    def api_rule_create():
        return _rule_write(rules.create, request.get_json(silent=True) or {}, created=True)

    @bp.post("/api/rules/preview")
    def api_rule_preview():
        """What a (possibly unsaved) rule would search for each host of a case, filled with that
        host's values. Nothing is searched."""
        body = request.get_json(silent=True) or {}
        raw = body.get("rule") or {}
        raw = {**raw, "name": raw.get("name") or "preview",   # a half-filled form still previews
               **{k: raw[k] if raw.get(k) not in (None, "") else 0 for k in ("confidence", "fidelity")}}
        try:
            rule = rule_svc.validate(raw)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        base = {"template": rule_svc.template(rule), "suggest": rule_svc.suggest(rule["conditions"])}
        if not body.get("case"):
            return jsonify(base)
        d = _case(body["case"])
        gr = analysis.load(d, rt.servers.get(d.name))
        nodes, edges = gr["nodes"], list(gr["edges"])
        hosts = [nid for nid, n in nodes.items() if n["type"] in ("Domain", "IP", "URL", "File")
                 and (nid == gr["seed"] or n["props"].get("cluster") is True)]
        rows, missing = [], 0
        for nid in hosts:
            qs = rule_svc.render(rule, rule_svc.host_attributes(nodes, edges, nid))
            if qs:
                rows.append({"type": nodes[nid]["type"], "value": nodes[nid]["value"], "queries": qs})
            else:
                missing += 1
        return jsonify(**base, hosts=rows[:50], matched=len(rows), missing=missing)

    @bp.post("/api/rules/<rid>")
    def api_rule_update(rid):
        return _rule_write(rules.update, rid, request.get_json(silent=True) or {})

    @bp.post("/api/rules/<rid>/delete")
    def api_rule_delete(rid):
        return _rule_write(rules.delete, rid)

    @bp.post("/api/pivots/<key>")
    def api_pivot_tune(key):
        return _rule_write(rules.tune_pivot, key, request.get_json(silent=True) or {})

    app.register_blueprint(bp)

    @app.errorhandler(404)
    def _404(e):
        if request.path.startswith("/api/") or "/graph/api/" in request.path:
            return jsonify(error="not found"), 404
        return render_template("error.html", title="Not found", message="That page or case does not exist.",
                               active="", auth=bool(password)), 404

    return app


def serve(root: Path, out: Path, host: str = "127.0.0.1", port: int = 8770, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost", "::1") and not os.getenv("INFRAMAPPER_WEB_PASSWORD"):
        raise SystemExit("refusing to listen on a non-local address without INFRAMAPPER_WEB_PASSWORD set")
    app = create_app(root, out, preload=True)
    url = f"http://{host}:{port}/"
    print(f"InfraMapper web UI on {url}  (Ctrl+C to stop)")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(1.0, webbrowser.open, (url,)).start()
    try:
        from waitress import serve as wserve
        wserve(app, host=host, port=port, threads=8)
    except ImportError:
        app.run(host=host, port=port, threaded=True, use_reloader=False)
