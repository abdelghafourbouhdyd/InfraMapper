"""New-domain hunt: has the actor registered / stood up more domains since this activity?

Three ways in, strongest first:

1. **Kit reuse on young domains** (urlscan): every artefact pivot of the case (HTML body, first-party
   script, favicon, URL path, title, domain pattern) is re-run restricted to apex domains younger
   than ``young_days`` (``page.apexDomainAgeDays``). A pivot too broad on the whole internet is
   often specific among new domains.
   urlscan's ``apexDomainAgeDays`` is the age *when that scan ran*, so the registration date is
   estimated as scan date - age, and a lead is only called new if that date is recent; older ones
   are the same kit on earlier domains (block + retro-hunt, not "new").
2. **Newly registered domains** (hagezi/nrd, built from Stamus Labs zone data: ~400k domains a day,
   in 7-day bands; WhoisDS' free 70k/day sample as a fallback) matched against
   look-alike rules built from the actor's own domains: same name on another TLD, name skeleton,
   token combos, one-character typos / homoglyphs.
3. **Certificate Transparency** (crt.sh): fresh certificates for hosts containing the actor's names,
   which also catches subdomains that NRD lists never show.

Look-alike rules are only built from domains the actor probably registered: the seed, cluster
domains younger than ``RULE_MAX_AGE`` per RDAP, and the young domains step 1 just found (so one
kit-reuse hit like ``barbermoo.space`` leads to ``barbermoo.today`` in the NRD lists). A compromised
old site in the cluster would otherwise turn its name into noise. A rule that matches too many new domains is dropped as generic.

Every lead gets live DNS (A / NS) and is compared with the cluster's dedicated IPs and nameservers.
Leads join the graph as Domain nodes, so the normal cluster scoring decides if they're confirmed.
"""

from __future__ import annotations

import base64
import io
import re
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from .clients import Cache
from .log import log
from .patterns import FREE_HOSTING, _looks_random, apex_of, is_ip, skeleton, split_domain

UA = {"User-Agent": "inframapper/1.0"}
WHOISDS = "https://www.whoisds.com//whois-database/newly-registered-domains/{}/nrd"
RULE_MAX_AGE = 180 * 86400       # older cluster domains are likely compromised sites, not the actor's
RULE_MAX_HITS = 40                # a rule matching more new domains than this is generic
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})
ARTEFACT_KINDS = {"html body": 3, "first-party script": 3, "url path": 2, "url path (refined)": 2,
                  "custom": 2, "favicon": 1, "title": 1}   # + "domain pattern (…)": 1


def _within1(a: str, b: str) -> bool:
    """Levenshtein distance <= 1 (one typo), without building the full matrix."""
    if a == b or abs(len(a) - len(b)) > 1:
        return a == b
    if len(a) > len(b):
        a, b = b, a
    i = j = diff = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            diff += 1
            if diff > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return diff + (len(b) - j) + (len(a) - i) <= 1


@dataclass
class NameRule:
    kind: str
    desc: str
    source: str        # the cluster domain it was built from
    name: str          # its registrable label
    regex: str         # for DNS logs / certstream monitoring
    hits: int = 0

    def match(self, label: str) -> bool:
        """Slow path, for one label; ``Matcher`` does the millions."""
        if label == self.name:
            return self.kind == "same name, other TLD"
        if self.kind == "same name, other TLD":
            return False
        if self.kind == "look-alike":
            return len(label) >= 6 and (_within1(label, self.name)
                                        or label.translate(HOMOGLYPHS) == self.name.translate(HOMOGLYPHS))
        return re.search(self.regex, label) is not None


class Matcher:
    """All rules against one label, fast enough for millions of NRDs: dict lookups for exact /
    homoglyph names, one combined regex for skeletons / token combos, and a one-edit check only on
    labels of a close length that keep the first or last character (one edit can't change both)."""

    def __init__(self, rules: list[NameRule]):
        self.rules = rules
        self.exact, self.glyph, self.near = {}, {}, []
        rx = []
        for i, r in enumerate(rules):
            if r.kind == "same name, other TLD":
                self.exact.setdefault(r.name, []).append(i)
            elif r.kind == "look-alike":
                self.glyph.setdefault(r.name.translate(HOMOGLYPHS), []).append(i)
                self.near.append((i, r.name))
            else:
                rx.append(f"(?P<r{i}>{r.regex})")
        self.rx = re.compile("|".join(rx)) if rx else None

    def __call__(self, label: str) -> list[int]:
        out = list(self.exact.get(label, []))
        if len(label) >= 6:
            out += [i for i in self.glyph.get(label.translate(HOMOGLYPHS), []) if self.rules[i].name != label]
            for i, name in self.near:
                if abs(len(label) - len(name)) <= 1 and (label[0] == name[0] or label[-1] == name[-1]) \
                        and label != name and _within1(label, name):
                    out.append(i)
        if self.rx:
            m = self.rx.search(label)
            if m:   # which alternatives match (the combined search only reports the first)
                out += [i for i, r in enumerate(self.rules) if r.kind in ("name skeleton", "token combo")
                        and re.search(r.regex, label)]
        return list(dict.fromkeys(out))


def build_rules(domains: list[str]) -> list[NameRule]:
    rules, seen = [], set()
    for d in domains:
        if is_ip(d) or any(d.endswith("." + s) for s in FREE_HOSTING):
            continue
        _, name, _ = split_domain(d)
        if len(name) < 5:
            continue
        cands = [NameRule("same name, other TLD", f"{name}.*", d, name, f"^{re.escape(name)}$")]
        if len(name) >= 6:
            cands.append(NameRule("look-alike", f"{name} ± 1 character / homoglyph", d, name,
                                  f"^{re.escape(name)}$"))
        sk = skeleton(name)
        if sk and len(sk.strip("-")) >= 4:
            cands.append(NameRule("name skeleton", f"{sk}*", d, name, f"^{re.escape(sk)}"))
        toks = [t for t in name.split("-") if len(t) >= 3 and not _looks_random(t)]
        if len(toks) >= 2:
            # either order: secure-okta-login -> my-okta-secure too
            cands.append(NameRule("token combo", f"*{toks[0]}* + *{toks[1]}*", d, name,
                                  f"^(?=.*{re.escape(toks[0])})(?=.*{re.escape(toks[1])})"))
        for r in cands:
            if (r.kind, r.desc) not in seen:
                seen.add((r.kind, r.desc))
                rules.append(r)
    return rules


HAGEZI = "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/{}.txt"
HAGEZI_BANDS = [(7, "nrd7", "1-7 days ago"), (14, "nrd14-8", "8-14 days ago"), (21, "nrd21-15", "15-21 days ago"),
                (28, "nrd28-22", "22-28 days ago"), (35, "nrd35-29", "29-35 days ago")]


class NRDFeed:
    """Newly registered domains: hagezi/nrd 7-day bands (refreshed daily), WhoisDS daily sample as fallback."""

    def __init__(self, cache_dir: Path):
        self.dir = cache_dir / "nrd"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _hagezi(self, band: str) -> Path | None:
        path = self.dir / f"hagezi-{band}.txt"
        if not path.exists() or time.time() - path.stat().st_mtime > 20 * 3600:
            try:
                r = requests.get(HAGEZI.format(band), headers=UA, timeout=300)
                r.raise_for_status()
                path.write_bytes(r.content)
            except requests.RequestException as exc:
                log.warning(f"hagezi NRD {band} refresh failed ({exc})" + (" — using the stale copy" if path.exists() else ""))
        return path if path.exists() else None

    def stream(self, days: int):
        """Yield (domain, when) for domains registered in the last ``days`` days (line by line: millions)."""
        got = False
        for upto, band, when in HAGEZI_BANDS:
            if upto - 6 > days:
                break
            path = self._hagezi(band)
            if not path:
                continue
            got = True
            with path.open() as f:
                for line in f:
                    if line[0] != "#":
                        yield line.strip().lower(), when
        if not got:   # hagezi unreachable: WhoisDS sample
            yield from self.recent(days)

    def day(self, date: str) -> list[str]:
        path = self.dir / f"{date}.txt"
        if not path.exists():
            url = WHOISDS.format(base64.b64encode(f"{date}.zip".encode()).decode())
            try:
                r = requests.get(url, headers=UA, timeout=90)
                r.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    text = z.read(z.namelist()[0]).decode("utf-8", "replace")
            except (requests.RequestException, zipfile.BadZipFile, IndexError) as exc:
                log.debug(f"NRD list {date} unavailable: {exc}")
                return []
            path.write_text(text)
        return [x.strip().lower() for x in path.read_text().splitlines() if x.strip()]

    def recent(self, days: int) -> list[tuple[str, str]]:
        """[(domain, list date)] for the last ``days`` days (yesterday backwards)."""
        today = datetime.now(timezone.utc).date()
        out = []
        for k in range(1, days + 1):
            date = (today - timedelta(days=k)).isoformat()
            out += [(d, date) for d in self.day(date)]
        for old in self.dir.glob("*.txt"):   # keep a month on disk
            if old.stem < (today - timedelta(days=31)).isoformat():
                old.unlink(missing_ok=True)
        return out


class CrtSh:
    def __init__(self, cache: Cache):
        self.cache, self.calls, self.failed = cache, 0, False

    def hosts(self, needle: str, since: int) -> list[tuple[str, int]]:
        """[(hostname, not_before)] for unexpired certificates containing ``needle`` issued after ``since``."""
        key = f"crtsh:{needle}"
        data = self.cache.get(key)
        if data is None and not self.failed:
            for attempt in range(2):   # crt.sh often answers 502 under load
                self.calls += 1
                try:
                    r = requests.get("https://crt.sh/", params={"q": f"%{needle}%", "output": "json",
                                                                "exclude": "expired"}, headers=UA, timeout=90)
                    r.raise_for_status()
                    data = r.json()
                    self.cache.set(key, data)
                    break
                except (requests.RequestException, ValueError) as exc:
                    if attempt:
                        log.warning(f"crt.sh unavailable ({exc}) — CT hunt skipped")
                        self.failed = True
                    else:
                        time.sleep(5)
        out = {}
        for c in data or []:
            nb = c.get("not_before") or ""
            try:
                ts = int(datetime.fromisoformat(nb[:19]).replace(tzinfo=timezone.utc).timestamp())
            except ValueError:
                continue
            if ts < since:
                continue
            for h in str(c.get("name_value", "")).lower().split("\n"):
                h = h.strip().lstrip("*.")
                if h and needle in h:
                    out[h] = min(out.get(h, ts), ts)
        return list(out.items())


def rdap_created(cache: Cache, domain: str) -> int | None:
    key = f"rdap:{domain}"
    data = cache.get(key)
    if data is None:
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", headers=UA, timeout=30)
            data = r.json() if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            data = {}
        cache.set(key, data)
    for e in data.get("events") or []:
        if e.get("eventAction") == "registration":
            try:
                return int(datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00")).timestamp())
            except (ValueError, KeyError):
                return None
    return None


def strength(score: int) -> tuple[str, str]:
    if score >= 4:
        return "strong", "block proactively + monitor"
    if score == 3:
        return "medium", "watchlist, re-check in a few days"
    return "weak", "review"


def _now() -> int:
    return int(time.time())
