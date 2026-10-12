"""IOC type detection and urlscan pivot-pattern generation (domain / URL-path / title)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)

# Registrable-suffix heuristics (no tldextract dependency)
MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.br", "com.au", "net.au", "co.jp",
    "co.in", "com.mx", "com.tr", "co.za", "com.cn", "com.ar", "co.id", "com.ng",
    "co.kr", "com.sg", "com.my", "com.pk", "com.vn", "com.ua", "co.nz", "com.co",
    "com.pe", "com.ph", "com.eg", "com.sa", "co.il", "com.hk", "com.tw",
}
# Hosting platforms where the attacker controls only the left-most label
FREE_HOSTING = {
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "github.io", "web.app",
    "firebaseapp.com", "herokuapp.com", "r2.dev", "glitch.me", "weebly.com",
    "wixsite.com", "blogspot.com", "azurewebsites.net", "onrender.com",
    "replit.app", "repl.co", "ngrok-free.app", "ngrok.io", "trycloudflare.com",
    "webflow.io", "framer.app", "framer.website", "godaddysites.com", "square.site",
    "000webhostapp.com", "appspot.com", "surge.sh", "fly.dev", "gitbook.io",
    "translate.goog", "sharepoint.com", "myshopify.com", "wordpress.com", "cprapid.com",
    "firebasestorage.app", "b-cdn.net", "codeanyapp.com", "live-website.com",
}
GENERIC_SUBS = {"www", "mail", "m", "api", "cdn", "app", "login", "portal", "webmail"}
GENERIC_PATH = {
    "", "index.html", "index.php", "index.htm", "wp-content", "wp-includes", "wp-admin",
    "themes", "plugins", "uploads", "en", "us", "fr", "de", "home", "assets", "static",
    "js", "css", "img", "images", "public", "admin", "login", "api", "v1", "v2", "auth",
    "favicon.ico", "cdn-cgi", "robots.txt", "default.aspx", "_next", "app", "dist",
}
GENERIC_TITLES = {
    "", "404 not found", "403 forbidden", "not found", "just a moment...",
    "attention required! | cloudflare", "index of /", "error", "loading...", "loading",
    "home", "welcome to nginx!", "iis windows server", "document", "untitled",
    "apache2 ubuntu default page: it works", "page not found", "access denied",
    "suspected phishing site | cloudflare", "site not found", "502 bad gateway",
    "503 service temporarily unavailable", "401 authorization required",
    "account suspended", "domain for sale", "redirecting...", "welcome", "test page",
    "default web site page", "coming soon", "under construction", "react app",
    "vite + react", "example domain", "hugedomains.com", "parked domain", "web server's default page",
}

_ES_RESERVED = re.compile(r'([+\-=&|><!(){}\[\]^"~?:\\/])')


def es_escape(term: str) -> str:
    """Escape Elasticsearch query_string reserved characters (keeps '*' wildcards)."""
    return _ES_RESERVED.sub(r"\\\1", term)


def refang(s: str) -> str:
    s = s.strip().strip("'\"")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    return s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[dot]", ".")


def detect_type(ioc: str) -> tuple[str, str]:
    ioc = refang(ioc)
    if HASH_RE.match(ioc):
        return "file", ioc.lower()
    try:
        return "ip", str(ipaddress.ip_address(ioc))
    except ValueError:
        pass
    if "://" in ioc:
        return "url", ioc
    if "/" in ioc:
        return "url", "http://" + ioc
    return "domain", ioc.lower().rstrip(".")


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def split_domain(host: str) -> tuple[list[str], str, str]:
    """-> (subdomain labels, registrable name label, public suffix)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_TLDS:
        return labels[:-3], labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[:-2], labels[-2], labels[-1]
    return [], labels[0], ""


def apex_of(host: str) -> str:
    _, name, suffix = split_domain(host)
    return f"{name}.{suffix}" if suffix else name


def _looks_random(tok: str) -> bool:
    if not tok:
        return False
    if tok.isdigit():
        return True
    has_d = any(c.isdigit() for c in tok)
    has_a = any(c.isalpha() for c in tok)
    if has_d and has_a and len(tok) >= 4:
        return True
    vowels = sum(c in "aeiouy" for c in tok)
    if tok.isalpha() and len(tok) >= 3 and vowels == 0:
        return True
    if len(tok) >= 8 and vowels / len(tok) < 0.25:
        return True
    return False


def skeleton(label: str) -> str | None:
    """Strip random-looking trailing tokens/digits: 'wk-auto-update-dbq' -> 'wk-auto-update-'."""
    toks = label.split("-")
    dropped = 0
    while len(toks) > 1 and dropped < 2 and _looks_random(toks[-1]):
        m = re.fullmatch(r"([a-z]{3,})\d+", toks[-1])
        if m and not _looks_random(m.group(1)):   # 'portal01' -> 'portal*'
            toks[-1] = m.group(1)
            return "-".join(toks)
        toks.pop()
        dropped += 1
    if dropped:
        return "-".join(toks) + "-"
    stripped = re.sub(r"\d+$", "", label)
    if stripped != label and len(stripped) >= 4:
        return stripped
    return None


def domain_patterns(host: str) -> list[tuple[str, str]]:
    """Return (description, urlscan query) lookalike patterns for a hostname."""
    host = host.lower().strip(".")
    out: list[tuple[str, str]] = []
    if not host or is_ip(host):
        return out

    for suf in FREE_HOSTING:
        if host.endswith("." + suf):
            sub = host[: -len(suf) - 1].split(".")[-1]
            sk = skeleton(sub)
            if sk and len(sk.strip("-")) >= 4:
                out.append((f"{suf} prefix", f"page.domain:{es_escape(sk)}*.{es_escape(suf)}"))
            toks = [t for t in sub.split("-") if len(t) >= 4 and not _looks_random(t)]
            if len(toks) >= 2:
                out.append((f"{suf} token combo",
                            f"page.domain:*{es_escape(toks[0])}*{es_escape(toks[1])}*.{es_escape(suf)}"))
            return out

    subs, name, suffix = split_domain(host)
    if len(name) >= 5:
        out.append(("same name, other TLDs", f"page.apexDomain:{es_escape(name)}.*"))
    sk = skeleton(name)
    if sk and len(sk.strip("-")) >= 4:
        out.append(("name skeleton", f"page.apexDomain:{es_escape(sk)}*"))
    toks = [t for t in name.split("-") if len(t) >= 3 and not _looks_random(t)]
    if len(toks) >= 2:
        out.append(("hyphen token combo",
                    f"page.domain:*{es_escape(toks[0])}*{es_escape(toks[1])}*"))
    distinctive = [s for s in subs if s not in GENERIC_SUBS and len(s) >= 4]
    if distinctive:
        sub_part = ".".join(subs)
        sk_sub = skeleton(sub_part) or sub_part
        out.append(("subdomain structure", f"page.domain:{es_escape(sk_sub)}*"))
    return out


def url_path_pattern(url: str) -> tuple[str, str] | None:
    """Distinctive path segments -> ('path', 'page.url:*.*\\/seg1\\/seg2*')."""
    path = urlsplit(url).path
    segs = [s for s in path.split("/")]
    keep: list[str] = []
    for seg in segs:
        low = seg.lower()
        if low in GENERIC_PATH or re.fullmatch(r"[a-f0-9\-]{16,}", low) or len(seg) > 40:
            if keep:
                break
            continue
        keep.append(seg)
        if len(keep) == 2:
            break
    if not keep or (len(keep) == 1 and len(keep[0]) < 5):
        return None
    joined = "\\/".join(es_escape(s) for s in keep)
    # "*.*" before the path: a dot (the host) must come first, so /dynamic can't match https://dynamic…
    return ("/" + "/".join(keep), f"page.url:*.*\\/{joined}*")


class UrlWindow:
    """A slice of a real URL (path segments i..j + the first q query keys) as a page.url wildcard.

    Used to tighten a too-broad url-path pivot one step at a time: widen the slice left / right,
    then pin query-string keys (/dynamic -> /a/dynamic -> /a/dynamic?txd=)."""

    def __init__(self, url: str, path: str):
        parts = urlsplit(url)
        self.segs = [s for s in parts.path.split("/") if s]
        self.keys = [k.split("=")[0] for k in parts.query.split("&") if k.split("=")[0]][:3]
        want = [s for s in path.split("/") if s]
        self.i = next((i for i in range(len(self.segs)) if self.segs[i:i + len(want)] == want), -1)
        self.j = self.i + len(want) - 1
        self.q = 0

    @property
    def ok(self) -> bool:
        return self.i >= 0

    def _with(self, i: int, j: int, q: int) -> "UrlWindow":
        w = object.__new__(UrlWindow)
        w.segs, w.keys, w.i, w.j, w.q = self.segs, self.keys, i, j, q
        return w

    def steps(self) -> list[tuple[str, "UrlWindow"]]:
        out = []
        if self.i > 0:
            out.append((f"path + /{self.segs[self.i - 1]} before", self._with(self.i - 1, self.j, self.q)))
        if self.j < len(self.segs) - 1 and len(self.segs[self.j + 1]) <= 40:
            out.append((f"path + /{self.segs[self.j + 1]} after", self._with(self.i, self.j + 1, self.q)))
        if self.q < len(self.keys):
            out.append((f"query key ?{self.keys[self.q]}=", self._with(self.i, self.j, self.q + 1)))
        return out

    def query(self) -> str:
        q = "*.*\\/" + "\\/".join(es_escape(s) for s in self.segs[self.i:self.j + 1])
        if self.q:
            q += ("" if self.j == len(self.segs) - 1 else "*") + "\\?" + \
                 "*".join(es_escape(k + "=") for k in self.keys[:self.q])
        return f"page.url:{q}*"


# CDN / server error pages: "evil.com | 522: Connection timed out", "Just a moment...", …
ERROR_TITLE = re.compile(r"\|\s*\d{3}\s*:|\b(connection timed out|bad gateway|origin (is )?unreachable|web server is down|"
                         r"just a moment|attention required|service unavailable|gateway time-?out)\b", re.I)


def title_is_generic(title: str | None) -> bool:
    return (not title or title.strip().lower() in GENERIC_TITLES or len(title.strip()) < 4
            or bool(ERROR_TITLE.search(title)))
