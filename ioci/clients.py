"""VirusTotal v3 and urlscan.io API clients with on-disk caching and rate limiting."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import deque
from pathlib import Path

import requests

from .log import log


class Cache:
    def __init__(self, directory: Path, ttl_hours: float, enabled: bool = True):
        self.dir = directory
        self.ttl = ttl_hours * 3600
        self.enabled = enabled
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.dir / (hashlib.sha1(key.encode()).hexdigest() + ".json")

    def get(self, key: str):
        p = self._path(key)
        if not self.enabled or not p.exists():
            return None
        if time.time() - p.stat().st_mtime > self.ttl:
            return None
        return json.loads(p.read_text())

    def set(self, key: str, value) -> None:
        # write + rename: a lookup thread never reads a half-written entry
        p = self._path(key)
        tmp = p.with_suffix(f".{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(value))
        os.replace(tmp, p)


QUOTA_PAUSE = 15 * 60   # a source that answers 429 sits out this long; the run carries on without it


class _QuotaPause:
    """Out-of-quota switch: once a source is rate limited it's skipped (lookups return nothing,
    nothing is cached) until the pause ends, instead of every remaining call sleeping. Timed rather
    than permanent so a long --serve session picks the source back up once its quota resets."""

    def __init__(self, name: str):
        self.name, self.until, self.lock = name, 0.0, threading.Lock()

    @property
    def active(self) -> bool:
        return time.time() < self.until

    def start(self, seconds: float = QUOTA_PAUSE) -> None:
        with self.lock:
            if self.active:   # parallel lookups hit the limit together: warn once
                return
            self.until = time.time() + seconds
        log.warning(f"{self.name} quota reached: skipping {self.name} for {seconds / 60:.0f} min, "
                    "continuing with the other sources")


class _Limiter:
    """At most ``per_minute`` calls in any rolling 60 s window (VT's quota model): the first calls
    of a run or pivot go out at once instead of 15 s apart. Thread-safe."""

    def __init__(self, per_minute: float):
        self.burst = max(1, int(per_minute)) if per_minute > 0 else 0
        self.sent: deque[float] = deque()
        self.lock = threading.Lock()

    def wait(self) -> None:
        if not self.burst:
            return
        with self.lock:
            while True:
                now = time.time()
                while self.sent and now - self.sent[0] >= 60:
                    self.sent.popleft()
                if len(self.sent) < self.burst:
                    self.sent.append(now)
                    return
                time.sleep(60 - (now - self.sent[0]) + 0.05)


class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, cache: Cache, rpm: float = 4, backup_keys: list[str] | tuple = ()):
        self.s = requests.Session()
        self.s.headers["accept"] = "application/json"
        # primary key first; a backup takes over when the current key's quota runs out (429) or it's rejected (401)
        self.keys = [k for k in dict.fromkeys([api_key, *backup_keys]) if k]
        self.key_idx, self.key_lock = 0, threading.Lock()
        self.cache = cache
        self.rpm, self.limit = rpm, _Limiter(rpm)
        self.calls = 0
        self.denied: set[str] = set()   # relationships the key isn't allowed to use
        self.paused = _QuotaPause("VT")

    def _failover(self, used: int, why: str) -> bool:
        """Switch to the next key after key #``used`` failed; False when none are left. Parallel
        lookups that failed on the same key switch only once."""
        with self.key_lock:
            if used != self.key_idx:   # another thread already moved on: retry with the current key
                return True
            if self.key_idx + 1 >= len(self.keys):
                self.key_idx = 0   # all spent: once the pause ends, start again from the primary
                return False
            self.key_idx += 1
            self.limit = _Limiter(self.rpm)   # the new key has its own per-minute budget
        log.warning(f"VT key #{used + 1} {why}: switching to backup key #{self.key_idx + 1}")
        return True

    def _get(self, path: str, params: dict | None = None) -> dict | None:
        key = f"vt:{path}:{json.dumps(params or {}, sort_keys=True)}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached or None
        for attempt in range(4):
            if self.paused.active:
                return None
            self.limit.wait()
            if self.paused.active:   # the quota ran out while this call queued behind the limiter
                return None
            self.calls += 1
            used = self.key_idx
            try:
                r = self.s.get(self.BASE + path, params=params, timeout=30,
                               headers={"x-apikey": self.keys[used]})
            except requests.RequestException as exc:
                log.warning(f"VT request failed {path}: {exc}")
                time.sleep(5)
                continue
            if r.status_code == 200:
                data = r.json()
                self.cache.set(key, data)
                return data
            if r.status_code == 404:
                self.cache.set(key, {})
                return None
            if r.status_code == 429:
                # the limiter already keeps to the per-minute rate, so this is the daily / monthly quota
                if self._failover(used, "quota reached"):
                    continue
                self.paused.start()
                return None
            if r.status_code == 401 and self._failover(used, "rejected (bad key)"):
                continue
            if r.status_code in (401, 403):
                log.debug(f"VT {r.status_code} on {path} (premium-only or bad key)")
                self.denied.add(path.rsplit("/", 1)[-1])
                self.cache.set(key, {})
                return None
            log.warning(f"VT HTTP {r.status_code} on {path}: {r.text[:150]}")
            return None
        return None

    def obj(self, collection: str, oid: str) -> dict | None:
        data = self._get(f"/{collection}/{oid}")
        return data.get("data") if data else None

    def related(self, collection: str, oid: str, rel: str, limit: int) -> list[dict]:
        data = self._get(f"/{collection}/{oid}/{rel}", {"limit": limit})
        items = data.get("data", []) if data else []
        return [items] if isinstance(items, dict) else items

    def intel_search(self, query: str, limit: int) -> list[dict]:
        data = self._get("/intelligence/search", {"query": query, "limit": limit})
        return data.get("data", []) if data else []


class URLScan:
    BASE = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str | None, cache: Cache):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "inframapper/1.0"
        if api_key:
            self.s.headers["API-Key"] = api_key
        self.cache = cache
        self.calls = 0
        self.paused = _QuotaPause("urlscan")

    def _get(self, url: str, params: dict | None = None, raw: bool = False):
        key = f"us:{url}:{json.dumps(params or {}, sort_keys=True)}:{raw}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached or None
        for attempt in range(5):
            if self.paused.active:
                return None
            self.calls += 1
            try:
                r = self.s.get(url, params=params, timeout=30)
            except requests.RequestException as exc:
                log.warning(f"urlscan request failed: {exc}")
                time.sleep(3)
                continue
            if r.status_code == 200:
                data = r.content.hex() if raw else r.json()
                self.cache.set(key, data)
                return data
            if r.status_code == 404:
                self.cache.set(key, {} if not raw else "")
                return None
            if r.status_code == 429:
                wait = float(r.headers.get("X-Rate-Limit-Reset-After", 30)) + 1
                if wait <= 10 and not attempt:   # per-second burst limit: clears almost at once
                    time.sleep(wait)
                    continue
                self.paused.start(max(wait, 60))   # minute / hour / day quota: pause until it resets
                return None
            if r.status_code in (500, 502, 503, 504):   # ES "over capacity" is common
                time.sleep(3 * (attempt + 1))
                continue
            log.warning(f"urlscan HTTP {r.status_code}: {r.text[:200]}")
            return None
        return None

    def search(self, query: str, size: int = 100) -> tuple[int, list[dict]]:
        data = self._get(f"{self.BASE}/search/", {"q": query, "size": size})
        if not data:
            return 0, []
        return data.get("total", 0), data.get("results", [])

    def result(self, uuid: str) -> dict | None:
        return self._get(f"{self.BASE}/result/{uuid}/")

    def response_body(self, sha256: str) -> bytes | None:
        hexdata = self._get(f"https://urlscan.io/responses/{sha256}/", raw=True)
        return bytes.fromhex(hexdata) if hexdata else None
