"""VirusTotal community comments: who does the community say is behind an IOC, and what else do
they list next to it?

Comments are where analysts (and sandboxes: Joe Sandbox, FileScan, Triage…) write things like
``#APT28 C2, same kit as evil-cdn[.]com / 45.9.148.12`` or ``Malware family: cobaltstrike``. From
each comment we keep:

* **actors**: threat-actor names matched against the MISP threat-actor galaxy (all vendor aliases map
  to one canonical name, so ``Fancy Bear``, ``Forest Blizzard`` and ``#apt28`` are one actor);
  code-named ids (``UNC1234``, ``TA505``, ``Storm-0558``…) are kept even when the galaxy is offline
* **malware families**: sandbox ``Malware family:`` lines, and ``#hashtags`` / VT tags that are a
  Malpedia family (most hashtags are ATT&CK tactics or sandbox names: ``#persistence``,
  ``#jaffacakes118``). Families are normalised through Malpedia too (``wannacry`` = ``WannaCryptor``)
* **references**: report / blog / sandbox links, including any URL carrying a hash (``/analysis/<sha256>``)
* **co-mentioned IOCs**: other hashes / IPs / domains / URLs in the same comment. A comment listing a
  few IOCs together is a (weak) link between them; a bulk dump of a whole feed says nothing, so
  comments listing more than ``MAX_COMENTIONS`` IOCs only contribute actors / families.

Everything is grouped per actor / family into one report per IOC (the same "VT comments: APT28"
report node for every IOC that carries the tag), so overlap across a cluster shows up directly.
"""

from __future__ import annotations

import functools
import json
import re
from collections import Counter
import time
from pathlib import Path

import requests

from urllib.parse import urlsplit

from .extract import HASH_RE, REFERENCE_SITES, extract, url_host
from .log import log

GALAXY = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{}.json"
MAX_COMENTIONS = 25      # comment listing more IOCs than this = bulk dump, no co-mention links
# structured ids vendors give actors before they get a name
CODENAME_RE = re.compile(r"\b(APT-?C?-?\d{1,3}|UNC\d{3,5}|TA(?!00)\d{3,4}|FIN\d{1,2}|Storm-\d{4}|DEV-\d{4}|TAG-\d{2,3}|"
                         r"UAC-\d{4}|TEMP\.[A-Z][a-z]+|G\d{4}|Earth [A-Z][a-z]+|CL-STA-\d{4})\b")
FAMILY_LINE_RE = re.compile(r"(?:malware[ _-]?family|family|signature|threat(?: name)?)\s*[:=]\s*"
                            r"([A-Za-z0-9][\w-]{2,30}(?: [A-Za-z][\w-]{1,20})?)", re.I)
HASHTAG_RE = re.compile(r"(?<![\w&])#([A-Za-z][\w.-]{2,40})")
# sandboxes / malware repositories / vendor blogs: links to them are references, not IOCs
REF_HOST_RE = re.compile(r"blog|research|report|threat|intel|labs|securelist|unit42|mandiant|talos|welive|"
                         r"filescan|joesandbox|tria\.ge|any\.run|hybrid-analysis|bazaar|threatfox|urlhaus|"
                         r"mwdb|virusshare|malshare|metadefender|malprob|virus\.exchange|neiki|nextron|intezer|"
                         r"unpac\.me|vmray|capesandbox|polyswarm|inquest|yoroi|reversinglabs|docguard|"
                         r"threatbook|malwares\.com|sandbox|analysis|centralbox|jaffacakes", re.I)
# family lines that describe the sample, not the family
GENERIC = {"malware", "malicious", "phishing", "c2", "cnc", "botnet", "ransomware", "stealer", "infostealer",
           "rat", "loader", "dropper", "trojan", "backdoor", "apt", "unknown", "generic", "none", "na", "null",
           "benign", "clean", "undetected", "suspicious", "packed", "miner", "worm", "spyware", "adware", "pup",
           "virus", "exploit", "downloader", "agent", "heur", "gen", "notdetected", "nomatch"}

# one-word galaxy aliases that are also everyday words, malware / ransomware names or product names:
# they only count as a #hashtag / VT tag (explicit), never in free text ("Cobalt Strike", "Equation Editor")
AMBIGUOUS = set("""
comment hacking beijing alibaba akira royal silence snake pioneer cardinal superman summit castle copper oxygen
mirage trident reaper hippo koala nitro scarab morpho popeye venom equation poseidon cobalt fallout polaris
moonlight butterfly watchdog wildcard sandman gorilla gorgon indra kairos calypso callisto cicada dogfish
pacifier pickaxe scimitar siesta strider zarya vermin lexus hagga rocke kinsing carbanak winnti havex labubu
mercury silicon calcium helium radium sodium boron nickel gallium platinum krypton potassium cerium chromium
basin elfin foudre luder nazar sarit tonto uteus pacha karba sinobi thrip attor axiom bitter hellsing careto
chronus exilware matanbuchus retefe shamoon slingshot sauron magecart
dragonfly leviathan menupass buckeye budworm elderwood naikon ghostnet ghostwriter guacamaya handala killnet
""".split())
_WORDS = Path("/usr/share/dict/words")


@functools.cache
def _english() -> frozenset[str]:
    try:
        return frozenset(w.strip() for w in _WORDS.read_text(errors="ignore").split() if w.islower())
    except OSError:
        return frozenset()


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _galaxy(directory: Path | None, name: str, max_age_days: float) -> list[dict]:
    """[{value, synonyms}] of a MISP galaxy cluster, cached locally and refreshed weekly."""
    if not directory:
        return []
    path = directory / f"misp-galaxy-{name}.json"
    try:
        if not path.exists() or time.time() - path.stat().st_mtime > max_age_days * 86400:
            log.info(f"downloading MISP galaxy {name}…")
            r = requests.get(GALAXY.format(name), timeout=60)
            r.raise_for_status()
            path.write_text(json.dumps([{"value": v.get("value"), "synonyms": (v.get("meta") or {}).get("synonyms")}
                                        for v in r.json().get("values", [])]))
    except Exception as exc:
        log.warning(f"MISP galaxy {name} unavailable ({exc})")
    try:
        return json.loads(path.read_text()) if path.exists() else []
    except ValueError:
        return []


class ActorNames:
    """Actor aliases (MISP threat-actor galaxy) and malware family names (MISP Malpedia galaxy)."""

    def __init__(self, directory: Path | None, max_age_days: float = 7):
        self.alias: dict[str, str] = {}        # normalised actor alias -> canonical name
        self.families: dict[str, str] = {}     # normalised family name / synonym -> Malpedia name
        self._rx: re.Pattern | None = None
        self._frx: re.Pattern | None = None
        self._load(_galaxy(directory, "threat-actor", max_age_days))
        self._load_families(_galaxy(directory, "malpedia", max_age_days))
        if directory and not self.alias:
            log.warning("no actor aliases: only code-named actors (UNC…, TA…, Storm-…) are recognised in VT comments")

    def _load(self, values: list[dict]) -> None:
        words = []
        english = _english()
        for v in values:
            name = v.get("value")
            if not name:
                continue
            names = [name] + list(v.get("synonyms") or [])
            # "#Lazarus" for "Lazarus Group", "Turla" for "Turla Team"
            names += [re.sub(r"\s+(?:Group|Team|APT)$", "", a) for a in names if re.search(r"\s(?:Group|Team|APT)$", a)]
            for a in names:
                n = _norm(a)
                # short or plain-word aliases ("Gold", "Equation") match everything: skip them
                if len(n) < 5 and not re.search(r"\d", n):
                    continue
                self.alias.setdefault(n, name)
                if re.fullmatch(r"[A-Za-z]+", a) and (a.lower() in AMBIGUOUS or a.lower() in english):
                    continue   # tag-only
                words.append(re.escape(a))
        if words:
            # case-sensitive on purpose: aliases are proper nouns ("Turla", not "turla" in a URL path)
            self._rx = re.compile(r"(?<![\w-])(" + "|".join(sorted(set(words), key=len, reverse=True)) + r")(?![\w-])")

    def _load_families(self, values: list[dict]) -> None:
        words = []
        for v in values:
            name = v.get("value")
            for a in [name] + list(v.get("synonyms") or []) if name else []:
                a = a.strip()
                n = _norm(a)
                if len(n) >= 4 and n not in GENERIC and n not in RULE_NOISE:
                    self.families.setdefault(n, name)
                    # prose matching (threat reports): same guard as actors, everyday words stay tag-only,
                    # and so do all-lower-case names ("systemd", "lockscreen"): reports capitalise malware
                    if not (re.fullmatch(r"[A-Za-z]+", a) and not re.search(r"[a-z][A-Z]", a)
                            and (a.lower() in AMBIGUOUS or a.lower() in _english() or a.lower() in RULE_NOISE)) \
                            and not re.fullmatch(r"[a-z][a-z .-]*", a):
                        words.append(re.escape(a))
        if words:
            self._frx = re.compile(r"(?<![\w-])(" + "|".join(sorted(set(words), key=len, reverse=True)) + r")(?![\w-])")

    def mentions(self, text: str) -> tuple[Counter, Counter]:
        """(actor, family) mention counts in prose: a name in a report once is often a comparison
        ("unlike LockBit…"); the callers keep names mentioned twice or in the title."""
        actors, fams = Counter(), Counter()
        if self._rx:
            actors.update(self.alias.get(_norm(m.group(1)), m.group(1)) for m in self._rx.finditer(text))
        actors.update(self.canonical(m.group(1)) or m.group(1) for m in CODENAME_RE.finditer(text))
        if self._frx:
            fams.update(self.families.get(_norm(m.group(1)), m.group(1)) for m in self._frx.finditer(text))
        for a in list(fams):   # "Lazarus" the actor isn't also a family
            if self.canonical(a):
                del fams[a]
        return actors, fams

    def canonical(self, name: str) -> str | None:
        return self.alias.get(_norm(name))

    def family(self, name: str) -> str | None:
        return self.families.get(_norm(name))

    def from_tokens(self, text: str) -> set[str]:
        """Actors named by identifier-style text (YARA rule names: 'APT_MAL_Sofacy_Zebrocy')."""
        return {a for t in _tokens(text) if t.lower() not in AMBIGUOUS and (a := self.canonical(t))}

    def find(self, text: str) -> set[str]:
        out = set()
        if self._rx:
            out |= {self.alias.get(_norm(m.group(1)), m.group(1)) for m in self._rx.finditer(text)}
        for m in CODENAME_RE.finditer(text):
            out.add(self.canonical(m.group(1)) or m.group(1))
        return out


# a published article: www.jamf.com/blog/…, zscaler.com/blogs/security-research/…, …/reports/…
ARTICLE_PATH_RE = re.compile(r"(?i)^/(?:[a-z]{2}(?:-[a-z]{2})?/)?(?:[\w-]+/)*?(?:blogs?|research|reports?|threat-\w+|labs|"
                             r"security-research|insights|posts?|news|advisor(?:y|ies)|articles?|publications?|"
                             r"resources|stories|analysis)/[\w%.-]{6,}")


def is_article(url: str) -> bool:
    """A link to a published report / blog post (not a sandbox page: those carry a hash)."""
    try:
        path = urlsplit(url).path
    except ValueError:
        return False
    return bool(ARTICLE_PATH_RE.search(path)) and not HASH_RE.search(url)


def article_name(url: str) -> str:
    """'https://www.jamf.com/blog/macsync-stealer-evolution/' -> 'jamf.com: macsync stealer evolution'."""
    host = re.sub(r"^www\.", "", url_host(url))
    slug = [x for x in urlsplit(url).path.split("/") if x][-1] if urlsplit(url).path.strip("/") else ""
    return f"{host}: {re.sub(r'[-_]+', ' ', re.sub(r'\.\w+$', '', slug))[:90]}"


def _is_reference(url: str) -> bool:
    host = url_host(url)
    return bool(host in REFERENCE_SITES or REF_HOST_RE.search(host) or HASH_RE.search(url) or is_article(url))


def parse(text: str, tags: list[str] | None, names: ActorNames, tlds: set[str] | None = None) -> dict:
    """actors / malware / references / co-mentioned IOCs of one comment."""
    found_actors = names.find(text)
    fams: set[str] = set()
    for t in list(tags or []) + HASHTAG_RE.findall(text):
        canon = names.canonical(t) or (t.upper() if CODENAME_RE.fullmatch(t.upper()) else None)
        if canon:
            found_actors.add(canon)
        elif names.family(t):   # only a known family: most hashtags are tactics / sandbox names
            fams.add(names.family(t))
    for m in FAMILY_LINE_RE.finditer(text):
        f = m.group(1).strip()
        if _norm(f) not in GENERIC and not names.canonical(f):
            fams.add(names.family(f) or names.family(f.split()[0]) or f.lower())
    ex = extract(text, source="vt-comment", tlds=tlds)
    refs = [v for kind, v in ex.iocs if kind == "url" and _is_reference(v)]
    ref_hosts = {url_host(u) for u in refs}
    iocs = [(kind, v) for kind, v in ex.iocs
            if not (kind == "url" and v in refs)
            and not (kind == "domain" and (v.lower() in ref_hosts or _is_reference(f"https://{v}/")))]
    return {"actors": sorted(found_actors), "malware": sorted(fams), "references": refs[:5], "iocs": iocs}


GUI_PATH = {"files": "file", "domains": "domain", "ip_addresses": "ip-address", "urls": "url"}


def comment_reports(vt, collection: str, oid: str, names: ActorNames, limit: int = 20,
                    tlds: set[str] | None = None, self_value: str = "") -> tuple[list[dict], list[dict]]:
    """(reports, co-mentions) from the comments on one VT object.

    reports: one per actor / malware family, in the PriorReporting format (source "VT comment").
    co-mentions: [{"kind", "value", "comment", "date", "n"}] from comments listing few IOCs."""
    data = vt._get(f"/{collection}/{oid}/comments", {"limit": limit})
    comments = (data or {}).get("data") or []
    link = f"https://www.virustotal.com/gui/{GUI_PATH[collection]}/{oid}/community"
    groups: dict[str, dict] = {}
    comentions: dict[tuple[str, str], dict] = {}
    for c in comments:
        a = c.get("attributes") or {}
        votes = a.get("votes") or {}
        if (votes.get("negative") or 0) + (votes.get("abuse") or 0) > (votes.get("positive") or 0):
            continue   # the community disagrees with this comment
        p = parse(a.get("text") or "", a.get("tags"), names, tlds)
        when = a.get("date")
        for kind, name in [("actor", x) for x in p["actors"]] + [("malware", x) for x in p["malware"]]:
            key = f"vtc:{kind}:{_norm(name)}"
            cur = groups.setdefault(key, {
                "source": "VT comment", "key": key, "name": f"VT comments: {name}", "date": when, "url": link,
                "references": [], "actor": name if kind == "actor" else None,
                "malware": [name] if kind == "malware" else [], "tags": [], "comments": 0})
            cur["comments"] += 1
            if when and (not cur["date"] or when < cur["date"]):
                cur["date"] = when   # first time the community said so
            cur["references"] = (cur["references"] + [r for r in p["references"] if r not in cur["references"]])[:5]
        for u in p["references"]:
            if is_article(u):   # someone tied this IOC to a published report: a report relation, not a URL IOC
                cur = groups.setdefault(f"vtref:{u}", {
                    "source": "VT comment → linked report", "key": f"vtref:{u}", "name": article_name(u), "date": when,
                    "url": u, "references": [link], "actor": None, "malware": [], "tags": [], "comments": 0,
                    "linked_article": True})
                cur["comments"] += 1
        others = [(k, v) for k, v in p["iocs"] if v.lower() != self_value.lower()]
        if len(others) <= MAX_COMENTIONS:
            for kind, v in others:
                comentions.setdefault((kind, v), {"kind": kind, "value": v, "comment": c.get("id"),
                                                  "date": when, "n": len(others) + 1})
    return list(groups.values()), list(comentions.values())


# ------------------------------------------------------------------ VT object attributes (no extra call)
# words in YARA rule names / AV labels that are never a family
RULE_NOISE = GENERIC | {"win32", "win64", "linux", "windows", "macos", "android", "detects", "detect", "rule", "rules",
                        "hacktool", "webshell", "susp", "mal", "crime", "apt", "gen", "packer", "upx", "embedded",
                        "office", "sample", "samples", "strings", "string", "payload", "exe", "dll", "elf", "file",
                        "indicator", "indicators", "hunting", "hunt", "yara", "signature", "base", "ransom", "encoded"}


def _tokens(text: str) -> list[str]:
    """'APT_MAL_Sofacy_Zebrocy_Go' -> words, plus adjacent pairs ('Cobalt_Strike' -> 'Cobalt Strike')."""
    words = [w for w in re.split(r"[^A-Za-z0-9]+", text) if w]
    return words + [f"{a} {b}" for a, b in zip(words, words[1:])]


def _families(text: str, names: ActorNames) -> set[str]:
    """Malpedia families in identifier-style text. A single everyday word ('Cobalt' is a Pay2Key
    synonym, 'Beacon', 'Agenda', 'Crash') doesn't count on its own; 'Cobalt Strike' and 'BumbleBee' do."""
    return {f for t in _tokens(text) if _norm(t) not in RULE_NOISE and len(_norm(t)) >= 4
            and not (" " not in t and not re.search(r"[a-z][A-Z]", t)   # CamelCase = a name: BumbleBee
                     and (t.lower() in _english() or t.lower() in AMBIGUOUS))
            and (f := names.family(t))}


def object_reports(attrs: dict, names: ActorNames, collection: str, oid: str) -> list[dict]:
    """Attribution VT already returns with the object: crowdsourced YARA rule matches (named authors:
    Nextron, ESET, ReversingLabs…), crowdsourced context (partner intel on IPs / domains), sandbox
    malware names and the AV family consensus. Same report format as comments; one per actor / family."""
    link = f"https://www.virustotal.com/gui/{GUI_PATH[collection]}/{oid}"
    groups: dict[str, dict] = {}

    def add(source: str, kind: str, name: str, date=None, ref=None, detail=None) -> None:
        key = f"{source.lower().replace(' ', '')}:{kind}:{_norm(name)}"
        cur = groups.setdefault(key, {"source": source, "key": key, "name": f"{source}: {name}", "date": date,
                                      "url": ref or link, "references": [], "actor": name if kind == "actor" else None,
                                      "malware": [name] if kind == "malware" else [], "tags": []})
        if date and (not cur["date"] or date < cur["date"]):
            cur["date"] = date
        if detail and detail not in cur["tags"] and len(cur["tags"]) < 6:
            cur["tags"].append(detail)

    for y in attrs.get("crowdsourced_yara_results") or []:
        text = " ".join(str(y.get(k) or "") for k in ("rule_name", "ruleset_name", "description"))
        who = f"{y.get('rule_name')} ({(y.get('author') or '?')[:40]})"
        for a in names.find(text.replace("_", " ")) | names.from_tokens(text):
            add("VT YARA", "actor", a, y.get("match_date"), y.get("source"), who)
        for f in _families(text, names):
            add("VT YARA", "malware", f, y.get("match_date"), y.get("source"), who)
    for c in attrs.get("crowdsourced_context") or []:
        text = " ".join(str(c.get(k) or "") for k in ("title", "details"))
        src = f"{c.get('source') or 'partner'}: {(c.get('title') or '')[:60]}"
        for a in names.find(text):
            add("VT crowdsourced context", "actor", a, c.get("timestamp"), None, src)
        for f in _families(text, names):
            add("VT crowdsourced context", "malware", f, c.get("timestamp"), None, src)
    for v in (attrs.get("sandbox_verdicts") or {}).values():
        for m in v.get("malware_names") or []:
            if (f := names.family(m)) and _norm(m) not in RULE_NOISE:
                add("VT sandbox", "malware", f, None, None, v.get("sandbox_name"))
    ptc = attrs.get("popular_threat_classification") or {}
    for p in ptc.get("popular_threat_name") or []:
        if (p.get("count") or 0) >= 3 and _norm(p.get("value") or "") not in RULE_NOISE \
                and (f := names.family(p.get("value") or "")):
            add("VT AV consensus", "malware", f, None, None, f"{p['value']} ×{p['count']} engines")
    return list(groups.values())
