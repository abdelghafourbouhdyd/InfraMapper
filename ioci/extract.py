"""IOC extraction from threat reports: text / Markdown / CSV / HTML / PDF files, a URL, or stdin.

Vendor reports defang everything differently (hxxps, [.], (.), {.}, [dot], [:]//) and mix IOCs with
noise: reference links, file names that look like domains (``payload.zip``, ``setup.py``), private
IPs, documentation ranges. The extractor refangs first, then only keeps:

* hashes that stand alone (not a slice of a longer hex string)
* public IPv4 / IPv6 (private, loopback, link-local, multicast, documentation ranges dropped)
* domains whose TLD is on the IANA list; TLDs that double as file extensions (.zip .mov .py .sh…)
  only when the report defanged the name, which is how an author says "this is an IOC"
* URLs (+ their host, since the host is usually what gets blocked)
* CVE ids, as context (flagged when on CISA KEV)

The report's own site (``--from https://vendor.com/blog/...``) is never an IOC.
"""

from __future__ import annotations

import html
import ipaddress
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .log import log
from .patterns import apex_of

IANA_TLDS = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
# offline fallback: the TLDs that cover almost every IOC in practice
FALLBACK_TLDS = set("""
com net org info biz io co me ru su cn xyz top online site club shop store live app dev cloud tech pro
icu cc tk ml ga cf gq pw ws in us uk de fr nl be it es pl ua kz by br ar mx cl pe jp kr tw hk sg my id vn
th ph au nz za ng ke eg ir tr il sa ae qa pk bd lk ca ch at se no fi dk cz sk hu ro bg gr pt ie lt lv ee
is lu li md rs hr si ba mk al am ge az uz kg tj tm mn la kh mm np af iq sy jo lb kw bh om ye ly tn dz ma
sn gh ci cm ug tz et zw zm mz ao bw na mu sc mg re yt ai ag bs bb bz bm vg ky dm do gd gy ht jm kn lc vc
sr tt tc vi pr cu ve co ec bo py uy ni hn sv gt cr pa fj pg sb vu to tv nu ki nr fm mh pw as gu mp ck ws
eu asia mobi name tel travel jobs cat aero coop museum int edu gov mil arpa onion link click fun space
website today world email network digital services solutions support center tools systems host win
bid loan date download racing review stream trade science party webcam men work cyber zip mov page
""".split())
# real TLDs that are also common file extensions: only trusted when defanged
FILE_EXTS = {"zip", "mov", "py", "sh", "pl", "rs", "md", "ps", "sys", "bat", "gz", "tar", "exe", "dll", "js",
             "php", "lnk", "doc", "docx", "xls", "xlsx", "pdf", "rar", "iso", "img", "vbs", "hta", "msi", "jar",
             "log", "txt", "csv", "json", "xml", "html", "htm", "png", "jpg", "gif", "dat", "bin", "tmp", "ps1",
             "cmd", "scr", "cpl", "ocx", "vhd", "one", "wsf", "yml", "yaml", "cfg", "ini", "db"}
# ...and TLDs that are code identifiers in the snippets reports quote (process.name, os.run)
CODE_TLDS = {"name", "run", "new", "call", "open", "save", "show", "play", "read", "help", "next", "data", "id"}
AMBIGUOUS_TLDS = FILE_EXTS | CODE_TLDS
# sites every report links to: citations, not IOCs (MISP warninglists catch the rest later)
REFERENCE_SITES = {"attack.mitre.org", "mitre.org", "cve.mitre.org", "nvd.nist.gov", "twitter.com", "x.com",
                   "github.com", "virustotal.com", "urlscan.io", "bazaar.abuse.ch", "threatfox.abuse.ch",
                   "urlhaus.abuse.ch", "otx.alienvault.com", "linkedin.com", "youtube.com", "microsoft.com",
                   "learn.microsoft.com", "docs.microsoft.com", "google.com", "cisa.gov", "shodan.io",
                   "censys.io", "any.run", "app.any.run", "tria.ge", "hybrid-analysis.com", "joesandbox.com",
                   "wikipedia.org", "medium.com", "t.me", "archive.org", "web.archive.org"}

_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}| \[\.\] | \. )"
_DEFANG_SUBS = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bh\[tt\]p(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[:\]//|\[://\]|\(://\)|:\[//\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\s?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s?", re.I), "."),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
]
DEFANG_MARK = re.compile(r"hxxp|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|\[:\]", re.I)

HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\)\]\}|,]+", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)")
IPV6_RE = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}(?::?[0-9a-fA-F]{1,4}|:)(?![0-9a-fA-F:])")
DOMAIN_RE = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z][a-z0-9-]{1,62}))(?![\w-])",
                       re.I)
NON_FILE_HASH = re.compile(r"(imphash|ja3s?|ja4\w*|jarm|ssdeep|tlsh|vhash|authentihash|pehash|telfhash|"
                           r"richhash|rich header|thumbprint|serial|hassh\w*|favicon)\W{0,4}(?:hash)?\W{0,4}$", re.I)
ALGO_LABEL = re.compile(r"(md5|sha-?1|sha-?256)\W{0,3}$", re.I)
VERSION_BEFORE = re.compile(r"(?:version|ver\.?|build|v)\s*$", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
# detection names that parse as domains: Talos 'W32.38D053135D-95.SBX.TG' (.tg is Togo), 'Win.Trojan.X'
DETECTION_NAME = re.compile(r"(?:^|\.)sbx\.tg$|^(?:w32|w64|win32|win64)\.|^win\.(?:trojan|malware|ransomware|dropper|packed)\.")
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "100.64.0.0/10")]


@dataclass
class Extracted:
    source: str
    iocs: list[tuple[str, str]] = field(default_factory=list)   # (file / ip / domain / url, value), report order
    cves: list[str] = field(default_factory=list)
    aliases: dict[str, dict[str, str]] = field(default_factory=dict)  # sha256/sha1 -> other hashes of the file
    fingerprints: list[tuple[str, str]] = field(default_factory=list)  # (imphash / ja3 / …, value): hunt pivots
    dropped: dict[str, int] = field(default_factory=dict)       # reason -> count

    def drop(self, why: str) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + 1

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for t, _ in self.iocs:
            out[t] = out.get(t, 0) + 1
        return out


def url_host(u: str) -> str:
    """Lower-case host of a URL; '' when the URL is malformed (reports are full of broken ones:
    'http://[redacted]/…' raises 'Invalid IPv6 URL')."""
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def refang_text(text: str) -> str:
    for rx, rep in _DEFANG_SUBS:
        text = rx.sub(rep, text)
    return text


def load_tlds(cache_dir: Path | None) -> set[str]:
    """IANA TLD list (cached a week); the built-in list if offline."""
    if cache_dir:
        path = cache_dir / "tlds-alpha-by-domain.txt"
        if not path.exists() or time.time() - path.stat().st_mtime > 7 * 86400:
            try:
                r = requests.get(IANA_TLDS, timeout=20)
                r.raise_for_status()
                path.write_text(r.text)
            except requests.RequestException as exc:
                log.debug(f"IANA TLD list refresh failed: {exc}")
        if path.exists():
            tlds = {ln.strip().lower() for ln in path.read_text().splitlines() if ln and not ln.startswith("#")}
            if len(tlds) > 500:
                return tlds
    return FALLBACK_TLDS


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast and not any(ip in n for n in DOC_NETS)


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:!?'\"")


def extract(text: str, source: str = "input", tlds: set[str] | None = None,
            exclude_hosts: set[str] | None = None, kev: dict | None = None,
            linked_hosts: set[str] | None = None) -> Extracted:
    """``linked_hosts``: hosts the page hyperlinks. Vendors don't hyperlink live malicious
    infrastructure, so a plain-text host that is also a link target is a citation."""
    tlds = tlds or FALLBACK_TLDS
    linked = {h.lower() for h in linked_hosts or set()}
    exclude = {h.lower() for h in exclude_hosts or set()}
    exclude_apex = {apex_of(h) for h in exclude}
    out = Extracted(source)
    seen: set[tuple[str, str]] = set()
    # a name the author defanged is an IOC even on an ambiguous TLD (update[.]zip, not update.zip)
    defanged_names = {refang_text(m.group(0)).lower() for m in
                      re.finditer(rf"[\w-]+(?:{_DOT}[\w-]+)*{_DOT}[a-z]{{2,24}}", text, re.I)
                      if DEFANG_MARK.search(m.group(0))}
    clean = refang_text(text)

    def add(kind: str, value: str) -> None:
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.iocs.append((kind, value))

    def host_ok(host: str) -> bool:
        host = host.lower().rstrip(".")
        if DETECTION_NAME.search(host):
            out.drop("AV / sandbox detection name, not a domain")
            return False
        if host in exclude or apex_of(host) in exclude_apex:
            out.drop("the report's own site")
            return False
        if host in REFERENCE_SITES or apex_of(host) in REFERENCE_SITES:
            out.drop("reference / citation site")
            return False
        if host in linked and host not in defanged_names:
            out.drop("hyperlinked in the report (citation)")
            return False
        return True

    for m in URL_RE.finditer(clean):
        url = _clean_url(m.group(0))
        host = url_host(url)
        if not host:
            continue
        if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host) and not _public_ip(host):
            out.drop("private / reserved IP")
        elif (_public_ip(host) or host.rsplit(".", 1)[-1] in tlds) and host_ok(host):
            add("url", url)
            add("ip" if _public_ip(host) else "domain", host)
    no_urls = URL_RE.sub(" ", clean)
    # hashes outside URLs (a hex run in a URL path is rarely the sample). imphash / JA3 / TLSH…
    # are fingerprints, not samples: kept as hunt pivots, never as file IOCs. One MD5 + SHA1 +
    # SHA256 together (a "md5: / sha1: / sha256:" block, or one row of an IOC table) is one file,
    # kept under its longest hash.
    algo = {32: "md5", 40: "sha1", 64: "sha256"}
    file_hashes: list[tuple[int, str]] = []
    labelled: set[str] = set()   # hash preceded by its own algorithm name ("sha1: …")
    for m in HASH_RE.finditer(no_urls):
        h = m.group(0).lower()
        label = NON_FILE_HASH.search(no_urls[max(0, m.start() - 24):m.start()])
        if label:
            kind = label.group(1).lower()
            if (kind, h) not in out.fingerprints:
                out.fingerprints.append((kind, h))
            out.drop("imphash / JA3 / fingerprint, not a file")
        else:
            file_hashes.append((m.start(), h))
            lab = ALGO_LABEL.search(no_urls[max(0, m.start() - 12):m.start()])
            if lab and lab.group(1).lower().replace("-", "") == algo[len(h)]:
                labelled.add(h)
    alias_of: dict[str, str] = {}

    def group(hs: list[str], block: bool = False) -> bool:
        hs = list(dict.fromkeys(hs))
        if len(hs) < 2 or len({len(h) for h in hs}) != len(hs):
            return False
        if block and len(hs) < 3 and not all(h in labelled for h in hs):
            return False   # "<md5 of A>\n<sha256 of B>" in a list: not provably one file
        main = max(hs, key=len)
        out.aliases.setdefault(main, {}).update({algo[len(h)]: h for h in hs if h != main})
        alias_of.update({h: main for h in hs if h != main})
        return True

    pos = 0
    for block in re.split(r"(\n[ \t]*\n)", no_urls):
        start, pos = pos, pos + len(block)
        hs = [h for at, h in file_hashes if start <= at < pos]
        if not group(hs, block=True):
            line_start = start
            for line in block.split("\n"):
                line_end = line_start + len(line) + 1
                group([h for at, h in file_hashes if line_start <= at < line_end])
                line_start = line_end
    for _, h in file_hashes:
        add("file", alias_of.get(h, h))
    no_urls = HASH_RE.sub(" ", no_urls)

    for m in IPV4_RE.finditer(no_urls):
        v = m.group(0)
        if VERSION_BEFORE.search(no_urls[max(0, m.start() - 12):m.start()]):
            out.drop("version number")
        elif _public_ip(v):
            add("ip", str(ipaddress.ip_address(v)))
        else:
            out.drop("private / reserved IP")
    for m in IPV6_RE.finditer(no_urls):
        try:
            v = str(ipaddress.ip_address(m.group(0)))
        except ValueError:
            continue
        if _public_ip(v):
            add("ip", v)

    for m in DOMAIN_RE.finditer(no_urls):
        d, tld = m.group(1).lower().rstrip("."), m.group(2).lower()
        if tld not in tlds:
            if tld in AMBIGUOUS_TLDS:
                out.drop("file name, not a domain")
            continue
        if tld in AMBIGUOUS_TLDS and d not in defanged_names:
            out.drop("file name, not a domain")
            continue
        if re.fullmatch(r"[\d.]+", d.rsplit(".", 1)[0]):   # version strings: 1.2.3.com never happens
            continue
        if host_ok(d):
            add("domain", d)

    cves = dict.fromkeys(c.upper() for c in CVE_RE.findall(text))
    out.cves = [f"{c} (CISA KEV)" if kev and c in kev else c for c in cves]
    return out


def read_source(src: str) -> tuple[str, str, set[str], set[str]]:
    """(text, label, hosts to exclude, hyperlinked hosts) from a file path, an http(s) URL or '-' for stdin."""
    import sys
    if src == "-":
        return sys.stdin.read(), "stdin", set(), set()
    if re.match(r"https?://", src, re.I):
        r = requests.get(src, timeout=45, headers={"User-Agent": "Mozilla/5.0 (InfraMapper report fetch)"})
        r.raise_for_status()
        host = (urlsplit(src).hostname or "").lower()
        ctype = r.headers.get("content-type", "")
        if "pdf" in ctype or src.lower().endswith(".pdf"):
            return _pdf_text(r.content), src, {host}, set()
        if "html" in ctype or "<html" in r.text[:2000].lower():
            return html_to_text(r.text), src, {host}, link_hosts(r.text)
        return r.text, src, {host}, set()
    path = Path(src)
    if not path.exists():
        raise FileNotFoundError(src)
    if path.suffix.lower() == ".pdf":
        return _pdf_text(path.read_bytes()), path.name, set(), set()
    text = path.read_text(errors="replace")
    if path.suffix.lower() in (".html", ".htm"):
        return html_to_text(text), path.name, set(), link_hosts(text)
    return text, path.name, set(), set()


def link_hosts(page: str) -> set[str]:
    return {url_host(h)
            for h in re.findall(r"""(?i)<a\s[^>]*href=["']([^"']+)""", page)} - {""}


def html_to_text(page: str) -> str:
    """Visible text only: nav bars, scripts and href targets aren't what the author listed as IOCs."""
    page = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer|header)\b.*?</\1>", " ", page)
    page = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d|pre|code|td)>", "\n", page)
    return html.unescape(re.sub(r"<[^>]+>", " ", page))


def _pdf_text(data: bytes) -> str:
    try:
        return subprocess.run(["pdftotext", "-layout", "-", "-"], input=data, capture_output=True,
                              check=True, timeout=120).stdout.decode(errors="replace")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    try:
        import io
        from pypdf import PdfReader
        return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)
    except ImportError:
        raise RuntimeError("reading a PDF needs `pdftotext` (poppler-utils) or `pip install pypdf`")
