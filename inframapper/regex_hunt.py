"""Progressive regex pivots on domain names: broad -> analyse the hits -> refine -> ... -> best pivot.

Start from the simplest pattern that still says something: the actor's most distinctive name token,
anywhere in the name. Each next step is picked from what the previous search returned, and records
why:

  * one legitimate site swamps the hits (an apex and its subdomains)  -> exclude that apex
  * the token mostly sits in subdomains, the actor's is in the name   -> keep it in the registered name
  * the actor's names start with the token, most hits don't           -> anchor it at the start
  * the actor's names are the token alone, most hits add to it        -> the name itself, any TLD
  * the actor uses bare names, most hits are deeper subdomains        -> no subdomains
  * the actor sticks to a few TLDs, hits are spread over others       -> those TLDs only
  * most hits are old                                                 -> last 90 days

A refinement must still match every known actor domain (checked here, no API call). The caller runs
it and keeps it only if it cuts the hits by a fifth or more.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from .patterns import FREE_HOSTING, _looks_random, split_domain

# words every phishing kit uses: a poor anchor unless nothing better exists
GENERIC = {"login", "secure", "account", "accounts", "update", "verify", "verification", "support", "service",
           "services", "online", "portal", "auth", "signin", "sign", "mail", "webmail", "office", "microsoft",
           "cloud", "info", "help", "team", "center", "security", "customer", "access", "admin", "online",
           "wallet", "bank", "banking", "pay", "payment", "invoice", "docs", "document", "share", "file", "files",
           "download", "server", "host", "site", "page", "pages", "home", "group", "global", "official", "live",
           "apps", "store", "shop", "news", "media", "event", "events", "web", "www", "api", "cdn", "dev", "app"}
SHARE = 0.3        # a pattern in at least this share of the sample is worth a refinement
TLD_SHARE = 0.5    # TLD restriction: only when most hits are elsewhere


def parts(host: str) -> tuple[list[str], str, str]:
    """(subdomain labels, registered name, suffix); on free hosting the customer label is the name."""
    host = host.lower().strip(".")
    for suf in FREE_HOSTING:
        if host.endswith("." + suf):
            labels = host[: -len(suf) - 1].split(".")
            return labels[:-1], labels[-1], suf
    return split_domain(host)


def tokens(label: str) -> list[str]:
    return [t for t in re.split(r"[^a-z]+", label.lower()) if len(t) >= 4 and not _looks_random(t)]


def keyword(domains: list[str]) -> str | None:
    """Most distinctive name token: in most of the known *registered names* (twenty subdomains of one
    site are one vote), not a generic kit word, then the first domain's (the seed's), then longest."""
    names = list(dict.fromkeys(parts(d)[1] for d in domains))
    seen = Counter(t for name in names for t in set(tokens(name)))
    if not seen:
        return None
    first = set(tokens(names[0]))
    return max(seen, key=lambda t: (t not in GENERIC, seen[t], t in first, len(t)))


def _alt(xs) -> str:
    xs = sorted(xs)
    esc = [x.replace(".", "\\.") for x in xs]
    return esc[0] if len(esc) == 1 else "(" + "|".join(esc) + ")"


@dataclass(frozen=True)
class Step:
    """One rung of the ladder: a domain regex plus query-level conditions."""
    base: str                  # the regex the ladder started from (user's, or built from the keyword)
    kw: str | None = None      # set when the regex is built from a keyword (position can then change)
    pos: str = "any"           # any | name | start | exact  (keyword mode only)
    bare: bool = False         # no subdomains (www. allowed)
    tlds: tuple = ()           # restrict to these suffixes
    exclude: tuple = ()        # apexes left out
    recent: bool = False       # date:>now-90d
    multi: bool = False        # a known suffix has two labels (co.uk): TLD part allows it

    def _tld(self) -> str:
        if self.tlds:
            return "\\." + _alt(self.tlds)
        return "\\.[a-z]+(\\.[a-z]+)?" if self.multi else "\\.[a-z]+"

    def regexes(self) -> list[str]:
        sub = "(www\\.)?" if self.bare else "(.*\\.)?"
        if self.kw:
            if self.pos == "any" and not (self.bare or self.tlds):
                return [f".*{self.kw}.*"]
            name = {"any": f"[a-z0-9-]*{self.kw}[a-z0-9-]*", "name": f"[a-z0-9-]*{self.kw}[a-z0-9-]*",
                    "start": f"{self.kw}[a-z0-9-]*", "exact": self.kw}[self.pos]
            return [f"{sub}{name}{self._tld()}"]
        extra = [f"{sub}[a-z0-9-]+{self._tld()}"] if (self.bare or self.tlds) else []
        return [self.base] + extra

    def query(self) -> str:
        q = " AND ".join(f"page.domain:/{r}/" for r in self.regexes())
        # by regex, not page.apexDomain: urlscan counts platform subdomains (x.chatgpt.site) as their own apex
        q += "".join(f" AND NOT page.domain:/(.*\\.)?{_alt([a])}/" for a in self.exclude)
        return q + (" AND date:>now-90d" if self.recent else "")

    def matches(self, domain: str) -> bool:
        d = domain.lower()
        apex = ".".join(parts(d)[1:]) if parts(d)[2] else d
        return all(re.fullmatch(r, d) for r in self.regexes()) and apex not in self.exclude


def start(known: list[str], user_regex: str | None = None) -> Step | None:
    """The broad first rung: the user's regex as given, else the keyword anywhere in the name."""
    multi = any("." in parts(d)[2] for d in known)
    if user_regex:
        return Step(base=user_regex, multi=multi)
    kw = keyword(known)
    return Step(base=f".*{kw}.*", kw=kw, multi=multi) if kw else None


def refinements(step: Step, known: list[str], results: list[dict], capped: bool = False) -> list[tuple[str, str, Step]]:
    """(label, why, next step) justified by this sample, most natural first; each keeps every known
    domain it's about (the ones whose name has the step's keyword). ``capped``: the hit count is at
    urlscan's 10,000 ceiling, so the keyword itself is too common."""
    hosts = [((r.get("page") or {}).get("domain") or "").lower() for r in results]
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    if step.kw:
        known = [d for d in known if step.kw in parts(d)[1]] or known
    n, pct = len(hosts), (lambda k: f"{round(100 * k / len(hosts))}%")
    kparts = [parts(d) for d in known]
    kapex = {f"{p[1]}.{p[2]}" for p in kparts}
    hparts = [parts(h) for h in hosts]
    out: list[tuple[str, str, Step]] = []

    if capped and step.kw and known:   # a more specific word from the actor's own names
        names = list(dict.fromkeys(p[1] for p in kparts))
        longer = Counter(t for name in names for t in set(tokens(name)) if step.kw in t and t != step.kw)
        if longer:
            tok = max(longer, key=lambda t: (longer[t], len(t)))
            out.append((f"specific word '{tok}'",
                        f"'{step.kw}' alone gives 10,000+ hits; {longer[tok]} of the actor's {len(names)} names use{'s' if longer[tok] == 1 else ''} '{tok}'",
                        replace(step, kw=tok, base=f".*{tok}.*", pos="any")))

    apexes = Counter(f"{p[1]}.{p[2]}" for p in hparts)
    top, c = apexes.most_common(1)[0]
    if top not in kapex and top not in step.exclude and len(step.exclude) < 3 and c >= SHARE * n:
        out.append((f"exclude {top}", f"{c}/{n} hits are {top} and its subdomains: one site, not the actor's naming",
                    replace(step, exclude=step.exclude + (top,))))

    kw = step.kw if known else None   # the rest compares with the actor's own names: needs some
    if kw:
        with_kw = [p for p, h in zip(hparts, hosts) if kw in h]
        sub_only = sum(kw not in p[1] for p in with_kw)
        if step.pos == "any" and all(kw in p[1] for p in kparts) and with_kw and sub_only >= SHARE * len(with_kw):
            out.append(("token in the registered name",
                        f"{round(100 * sub_only / len(with_kw))}% of hits have '{kw}' only in a subdomain; the actor's domains have it in the name",
                        replace(step, pos="name")))
        named = [p for p in hparts if kw in p[1]]
        if step.pos in ("any", "name") and named and all(p[1] == kw for p in kparts):
            longer = sum(p[1] != kw for p in named)
            if longer >= SHARE * len(named):
                out.append(("name is the token",
                            f"{pct(longer)} of hits add words around '{kw}'; the actor's names are exactly '{kw}'",
                            replace(step, pos="exact")))
        elif step.pos in ("any", "name") and named and all(p[1].startswith(kw) for p in kparts):
            later = sum(not p[1].startswith(kw) for p in named)
            if later >= SHARE * len(named):
                out.append((f"name starts with '{kw}'",
                            f"{pct(later)} of hits have '{kw}' mid-name; the actor's names start with it",
                            replace(step, pos="start")))

    if known and not step.bare and all(not [s for s in p[0] if s != "www"] for p in kparts):
        deep = sum(bool([s for s in p[0] if s != "www"]) for p in hparts)
        if deep >= SHARE * n:
            out.append(("no subdomains", f"{pct(deep)} of hits are subdomains; the actor registers bare names",
                        replace(step, bare=True)))

    ktlds = {p[2] for p in kparts}
    if not step.tlds and 0 < len(ktlds) <= 3:
        other = [p[2] for p in hparts if p[2] not in ktlds]
        if len(other) >= TLD_SHARE * n:
            seen = ", ".join(f".{t}" for t, _ in Counter(other).most_common(3))
            out.append((f"TLD {' / '.join('.' + t for t in sorted(ktlds))}",
                        f"{pct(len(other))} of hits are on other TLDs ({seen}); the actor uses {', '.join('.' + t for t in sorted(ktlds))}",
                        replace(step, tlds=tuple(sorted(ktlds)))))

    if not step.recent:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        dates = [(r.get("task") or {}).get("time") or "" for r in results]
        old = sum(1 for t in dates if t and t < cutoff)
        if old >= 0.4 * len(dates):
            out.append(("last 90 days", f"{pct(old)} of hits are older than 90 days", replace(step, recent=True)))

    return [(label, why, s) for label, why, s in out
            if all(s.matches(d) for d in known if not s.kw or s.kw in parts(d)[1])]
