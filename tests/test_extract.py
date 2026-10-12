from ioci.extract import extract, html_to_text, refang_text

REPORT = """
The loader (setup.py, payload.zip, invoice.pdf) beacons to hxxps://update-check[.]top/api/v2?id=1 and
45.9.148[.]12:443. Fallback C2: cdn-sync(.)online. Internal: 10.0.0.5, 192.168.1.1, 203.0.113.9.
Second stage: update[.]zip. Code: process.name, os.run(). Version 1.2.3.4. C2 is 185.220.101.4.
SHA256: 7d6f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f

Dropper MD5 d41d8cd98f00b204e9800998ecf8427e. See https://attack.mitre.org/techniques/T1059/ and
https://vendor-blog.com/post. Exploits CVE-2023-4966 and cve-2021-44228.
IPv6 2a01:4f8:c17:1234::1 and fe80::1. evil[dot]example-site[.]ru
"""


def iocs(**kw):
    return set(extract(REPORT, **kw).iocs)


def test_refang_variants():
    assert refang_text("hxxps://a[.]b(.)c{.}d[dot]e[:]80") == "https://a.b.c.d.e:80"


def test_extracts_defanged_iocs():
    got = iocs()
    for want in [("url", "https://update-check.top/api/v2?id=1"), ("domain", "update-check.top"),
                 ("ip", "45.9.148.12"), ("domain", "cdn-sync.online"), ("domain", "evil.example-site.ru"),
                 ("ip", "185.220.101.4"), ("ip", "2a01:4f8:c17:1234::1"),
                 ("file", "7d6f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"),
                 ("file", "d41d8cd98f00b204e9800998ecf8427e")]:
        assert want in got, want


def test_sentence_final_ip():
    assert ("ip", "185.220.101.4") in iocs()


def test_noise_dropped():
    values = {v for _, v in iocs(exclude_hosts={"vendor-blog.com"})}
    for bad in ["10.0.0.5", "192.168.1.1", "203.0.113.9", "fe80::1", "1.2.3.4", "setup.py", "payload.zip",
                "invoice.pdf", "process.name", "os.run", "attack.mitre.org", "vendor-blog.com"]:
        assert not any(bad == v or bad in v for v in values), bad


def test_ambiguous_tld_only_when_defanged():
    values = {v for _, v in iocs()}
    assert "update.zip" in values        # defanged by the author
    assert "payload.zip" not in values   # plain file name


def test_cves_flag_kev():
    ex = extract(REPORT, kev={"CVE-2023-4966": {}})
    assert ex.cves == ["CVE-2023-4966 (CISA KEV)", "CVE-2021-44228"]


def test_hash_inside_longer_hex_ignored():
    ex = extract("blob " + "a" * 70 + " end")
    assert not ex.iocs


def test_html_visible_text_only():
    page = '<html><script>var x="bad.com"</script><p>C2: evil[.]net</p><a href="https://ref.org">ref</a></html>'
    values = {v for _, v in extract(html_to_text(page)).iocs}
    assert values == {"evil.net"}


def test_hyperlinked_hosts_are_citations():
    text = "C2 regsvcast.com. Research by falconforce.nl. Also evil[.]org"
    values = {v for _, v in extract(text, linked_hosts={"falconforce.nl", "evil.org"}).iocs}
    assert values == {"regsvcast.com", "evil.org"}   # defanged wins over hyperlinked


def test_hash_triplet_on_one_line_is_one_file():
    md5, sha1, sha256 = "1" * 32, "2" * 40, "3" * 64
    ex = extract(f"| loader.dll | {md5} | {sha1} | {sha256} |\nother {'4' * 64}")
    assert ex.iocs == [("file", sha256), ("file", "4" * 64)]
    assert ex.aliases[sha256] == {"md5": md5, "sha1": sha1}


def test_labelled_block_and_fingerprints():
    text = ("7f02ab2.exe - Cobalt Strike Beacon\n  md5:" + "a" * 32 + "\n  sha1:" + "b" * 40 +
            "\n  sha256:" + "c" * 64 + "\n  imphash:" + "d" * 32 + "\n\nJA3: " + "e" * 32 + "\n")
    ex = extract(text)
    assert ex.iocs == [("file", "c" * 64)]
    assert ex.aliases["c" * 64] == {"md5": "a" * 32, "sha1": "b" * 40}
    assert ex.fingerprints == [("imphash", "d" * 32), ("ja3", "e" * 32)]
