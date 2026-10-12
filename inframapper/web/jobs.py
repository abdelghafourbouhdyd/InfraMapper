"""Background jobs for the web UI.

Investigations, report triage, report ingestion and re-indexing run the real CLI
(``infra-mapper.py``) in a subprocess, so the web UI and the command line produce exactly the
same cases. One job runs at a time (they share the VirusTotal / urlscan quotas); the rest queue.
Each job's output is streamed into memory and to ``logs/web/<job>.log``.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CASE_LINE = re.compile(r"graph\s*:\s*(.+?graph\.html)\s*$")


class JobRunner:
    def __init__(self, root: Path, out: Path):
        self.root, self.out = root, out
        self.logdir = root / "logs" / "web"
        self.logdir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.logdir / "jobs.json"
        self.jobs: dict[str, dict] = {}
        self.q: queue.Queue[str] = queue.Queue()
        self.lock = threading.Lock()
        self._load()
        threading.Thread(target=self._worker, daemon=True, name="inframapper-web-jobs").start()

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        try:
            saved = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            saved = []
        for j in saved[-200:]:
            if j.get("state") in ("queued", "running"):
                j["state"], j["error"] = "error", "interrupted (web server restarted)"
            j["log"] = []
            self.jobs[j["id"]] = j

    def _save(self) -> None:
        with self.lock:
            rows = [{k: v for k, v in j.items() if k not in ("log", "proc")} for j in self.jobs.values()]
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(rows[-200:], default=str), encoding="utf-8")
        os.replace(tmp, self.state_file)

    # ------------------------------------------------------------------ API
    def submit(self, kind: str, label: str, args: list[str], meta: dict | None = None) -> dict:
        job = {"id": uuid.uuid4().hex[:10], "kind": kind, "label": label, "args": args, "meta": meta or {},
               "state": "queued", "created": datetime.now().isoformat(timespec="seconds"), "started": None,
               "finished": None, "case": None, "error": None, "returncode": None, "log": []}
        with self.lock:
            self.jobs[job["id"]] = job
        self._save()
        self.q.put(job["id"])
        return self.public(job)

    def cancel(self, jid: str) -> dict:
        job = self.jobs.get(jid)
        if not job:
            raise LookupError("no such job")
        if job["state"] == "queued":
            job.update(state="cancelled", finished=datetime.now().isoformat(timespec="seconds"))
        elif job["state"] == "running" and job.get("proc"):
            job["cancel"] = True
            job["proc"].terminate()
        self._save()
        return self.public(job)

    def get(self, jid: str, tail: int = 400) -> dict:
        job = self.jobs.get(jid)
        if not job:
            raise LookupError("no such job")
        out = self.public(job)
        lines = job["log"] or self._read_log(jid)
        out["log"] = lines[-tail:]
        out["log_lines"] = len(lines)
        return out

    def list(self, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = list(self.jobs.values())
        return [self.public(j) for j in sorted(rows, key=lambda j: j["created"], reverse=True)[:limit]]

    def active(self) -> list[dict]:
        return [j for j in self.list() if j["state"] in ("queued", "running")]

    @staticmethod
    def public(job: dict) -> dict:
        return {k: v for k, v in job.items() if k not in ("log", "proc", "cancel")}

    def _read_log(self, jid: str) -> list[str]:
        p = self.logdir / f"{jid}.log"
        try:
            return p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

    # ------------------------------------------------------------------ execution
    def _worker(self) -> None:
        while True:
            jid = self.q.get()
            job = self.jobs.get(jid)
            if not job or job["state"] != "queued":
                continue
            try:
                self._run(job)
            except Exception as exc:  # noqa: BLE001
                job.update(state="error", error=f"{type(exc).__name__}: {exc}")
            finally:
                job["finished"] = datetime.now().isoformat(timespec="seconds")
                job.pop("proc", None)
                self._save()

    def _run(self, job: dict) -> None:
        before = {p.parent.name for p in self.out.glob("*/graph.json")}
        start = time.time()
        cmd = [sys.executable, "-X", "utf8", str(self.root / "infra-mapper.py"), *job["args"]]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "NO_COLOR": "1", "TERM": "dumb",
               "COLUMNS": "400", "PYTHONUNBUFFERED": "1"}
        job.update(state="running", started=datetime.now().isoformat(timespec="seconds"))
        self._save()
        logf = (self.logdir / f"{job['id']}.log").open("w", encoding="utf-8")
        logf.write("$ infra-mapper.py " + " ".join(job["args"]) + "\n")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(cmd, cwd=str(self.root), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                bufsize=1, creationflags=flags)
        job["proc"] = proc
        for raw in proc.stdout:
            line = ANSI.sub("", raw.rstrip("\n"))
            job["log"].append(line)
            logf.write(line + "\n")
            logf.flush()
            m = CASE_LINE.search(line)
            if m:
                job["case"] = Path(m.group(1).strip()).parent.name
        proc.wait()
        logf.close()
        job["returncode"] = proc.returncode
        if not job["case"] and job["kind"] in ("investigate", "triage"):
            new = [p.parent for p in self.out.glob("*/graph.json") if p.parent.name not in before
                   and p.stat().st_mtime >= start - 1]
            if new:
                job["case"] = max(new, key=lambda p: p.stat().st_mtime).name
        if job.get("cancel"):
            job.update(state="cancelled")
        elif proc.returncode == 0:
            job.update(state="done")
        else:
            tail = [ln for ln in job["log"][-15:] if ln.strip()]
            job.update(state="error", error=(tail[-1] if tail else f"exit code {proc.returncode}")[:500])
        job["log"] = job["log"][-3000:]
