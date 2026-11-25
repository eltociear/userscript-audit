#!/usr/bin/env python3
"""userscript-audit - scan userscripts (Tampermonkey / Violentmonkey / Greasemonkey) for
malicious patterns before you install them.

A userscript runs inside every page its @match covers, with your logged-in session. With
GM_xmlhttpRequest and `@connect *` it can also talk to any host, bypassing the page's CORS and
CSP. That makes a broad-match userscript the most powerful thing most people ever install from
a stranger, and the store review is a human reading a diff. This scanner reads the
==UserScript== metadata block and the code, and scores the *combinations* that matter:

  * credential / cookie / token / password harvesting next to a send to a third-party host
  * remote code: fetched text passed to eval / new Function / an injected <script>
  * crypto-address clipboard swapping, keyloggers on password fields, miners
  * obfuscated code (banned on Greasy Fork, so present only where review missed it)
  * supply chain: @require / @resource over http://, or from a host that can change it

Capabilities on their own (`*://*/*`, GM_xmlhttpRequest, `@connect *`, unsafeWindow, analytics)
are reported as INFO and never change the score. Deterministic, no LLM, no dependencies.

Usage:
  python userscript_audit.py <file.user.js|dir|->...       # local files (- = stdin)
  python userscript_audit.py --greasyfork <id>[ <id>...]   # Greasy Fork script ids
  python userscript_audit.py --openuserjs <user>/<script>  # OpenUserJS
  python userscript_audit.py --url https://.../x.user.js   # any URL
  python userscript_audit.py --text "<code>"               # a string
  options: --json  --verbose (show INFO)  --all (keep going, no early summary)
Exit code 2 if any target is HIGH or CRITICAL (CI-friendly). MIT licensed.
"""
import bisect
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

__version__ = "0.1.0"
MAX_FILE = 20_000_000
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{4096,}")
NEAR = 600          # chars: "same statement neighbourhood" for source/sink combinations

# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------
CDN_HOSTS = (
    "cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net", "testingcf.jsdelivr.net",
    "unpkg.com", "cdnjs.cloudflare.com", "ajax.googleapis.com", "code.jquery.com",
    "lib.baomitu.com", "lf3-cdn-tos.bytecdntp.com", "lf6-cdn-tos.bytecdntp.com",
    "lf26-cdn-tos.bytecdntp.com", "registry.npmmirror.com", "npm.elemecdn.com", "cdn.baomitu.com",
    "s4.zstatic.net", "cdn.bytedance.com", "unpkg.zhimg.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.datatables.net", "cdn.tailwindcss.com", "esm.sh",
    "ajax.aspnetcdn.com", "cdn.skypack.dev", "momentjs.com", "greasemonkey.github.io",
    "apps.bdimg.com", "libs.baidu.com", "bowercdn.net", "code.highcharts.com", "www.gstatic.com",
    "bytecdntp.com", "cdn.rawgit.com", "gitcdn.link", "gitcdn.xyz", "bundle.run", "jspm.dev",
    "cdn.statically.io", "raw.githack.com", "cdn.jsdmirror.com", "lib.sinaapp.com", "upcdn.b0.upaiyun.com",
)
# polyfill.io was taken over and served malware in 2024; bootcdn / bootcss / staticfile were reported
# the same year as sharing its operator. Treat them as risky hosts, not as trusted CDNs.
COMPROMISED_CDN = ("polyfill.io", "polyfill.com", "polyfillcache.com")
SUSPECT_CDN = ("bootcdn.net", "bootcss.com", "staticfile.org", "staticfile.net")
RECAPTCHA = re.compile(r"^(?:https?:)?//www\.(?:google|recaptcha)\.(?:com|net)/recaptcha/", re.I)
PINNED = re.compile(r"/[0-9a-f]{40}/|@\d{1,4}\.\d{1,4}(?:\.\d{1,4})?|/v?\d{1,4}\.\d{1,4}\.\d{1,4}/|[?&]v(?:ersion)?=\d", re.I)
STORE_HOSTS = ("greasyfork.org", "update.greasyfork.org", "sleazyfork.org", "update.sleazyfork.org",
               "openuserjs.org", "github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
               "gitee.com", "gitlab.com", "userscripts-mirror.org", "scriptcat.org")
EXFIL_HOST = re.compile(
    r"discord(?:app)?\.com/api/webhooks/\d{5,}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}|"
    r"hooks\.slack\.com/services/T\w+/B\w+|webhook\.site/[\w-]{8,}|requestbin\.(?:com|net|io)|"
    r"requestb\.in|pipedream\.net|\.m\.pipedream\.net|\.ngrok(?:-free)?\.(?:io|app|dev)|"
    r"\.trycloudflare\.com|\.oast\.(?:fun|live|me|online|pro|site)|\.interact\.sh|interactsh|"
    r"\.burpcollaborator\.net|canarytokens\.com|beeceptor\.com|hookbin\.com|ptsv2\.com",
    re.I)
RAW_IP_URL = re.compile(r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.))"
                        r"\d{1,3}(?:\.\d{1,3}){3}")
URL_RE = re.compile(r"(?:https?:)?//([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?=[/\"'`?#\s]|$)", re.I)

# ---------------------------------------------------------------------------
# Code signatures. Every repeat is bounded, so a scan is linear in script size.
# ---------------------------------------------------------------------------
SEND = (r"(?:GM_xmlhttpRequest|GM\.xmlHttpRequest|GM_xmlHttpRequest|\bfetch|navigator\.sendBeacon|"
        r"\.open\s{0,4}\(\s{0,4}[\"'](?:POST|GET|PUT)|\$\.(?:ajax|post|get)|axios\.\w{2,6}|"
        r"new\s{1,4}Image\s{0,4}\(\s{0,4}\)\s{0,4}\.src|\.src\s{0,4}=|WebSocket)")
SEND_RE = re.compile(SEND, re.I)
COOKIE_SRC = re.compile(r"document\.cookie(?!\s{0,4}=[^=])|GM_cookie\.list|GM\.cookie\.list|"
                        r"GM_cookie\s{0,4}\(\s{0,4}[\"']list", re.I)
TOKEN_SRC = re.compile(r"(?:localStorage|sessionStorage)(?:\.getItem\s{0,4}\(\s{0,4}|\[)\s{0,4}[\"'`]"
                       r"[\w.:-]{0,40}(?:token|auth|session|jwt|access|refresh|bearer|cred|secret|passw)",
                       re.I)
DUMP_SRC = re.compile(r"JSON\.stringify\s{0,4}\(\s{0,4}(?:localStorage|sessionStorage)\s{0,4}\)|"
                      r"Object\.(?:keys|entries)\s{0,4}\(\s{0,4}localStorage\s{0,4}\)", re.I)
PASS_SRC = re.compile(r"(?:type\s{0,4}=\s{0,4}[\"']?password|\[type=[\"']?password|"
                      r"input\[name\*?=[\"']?pass|getElementById\s{0,4}\(\s{0,4}[\"'][\w-]{0,20}pass)",
                      re.I)
KEY_LISTEN = re.compile(r"addEventListener\s{0,4}\(\s{0,4}[\"']key(?:down|press|up)[\"']|onkey(?:down|press|up)\s{0,4}=",
                        re.I)
EVAL_SINK = re.compile(r"\beval\s{0,4}\(|new\s{1,4}Function\s{0,4}\(|\bFunction\s{0,4}\(\s{0,4}[\w.]{1,40}\)\s{0,4}\(|"
                       r"unsafeWindow\.eval\s{0,4}\(|setTimeout\s{0,4}\(\s{0,4}\w{1,30}\.responseText", re.I)
FETCHED = re.compile(r"\.responseText\b|\.response\b|\.text\s{0,4}\(\s{0,4}\)|\bres(?:ponse)?\.data\b", re.I)
SCRIPT_INJECT = re.compile(r"createElement\s{0,4}\(\s{0,4}[\"']script[\"']|GM_addElement\s{0,4}\(\s{0,4}(?:[\w.]{1,40},\s{0,4})?[\"']script",
                           re.I)
SCRIPT_TEXT_FROM_FETCH = re.compile(r"(?:textContent|innerHTML|innerText|\.text)\s{0,4}=\s{0,4}[\w.]{0,40}(?:responseText|response\b)|"
                                    r"textContent\s{0,4}:\s{0,4}[\w.]{0,40}(?:responseText|response\b)", re.I)
CLIP_WRITE = re.compile(r"navigator\.clipboard\.writeText|GM_setClipboard|GM\.setClipboard|"
                        r"clipboardData\.setData|execCommand\s{0,4}\(\s{0,4}[\"']copy", re.I)
COPY_EVENT = re.compile(r"addEventListener\s{0,4}\(\s{0,4}[\"'](?:copy|cut|paste)[\"']|oncopy\s{0,4}=", re.I)
ADDR_REGEX = re.compile(r"/\^?\(?\s{0,2}(?:bc1|\[13\]|1\|3|0x\[a-fA-F0-9\]|0x\[0-9a-fA-F\]|T\[A-Za-z1-9\]|"
                        r"4\[0-9AB\]|\[LM3\]|r\[0-9a-zA-Z\])", re.I)
ADDR_LIT = re.compile(r"[\"'](?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|"
                      r"T[A-Za-z1-9]{33})[\"']")

PATTERNS = {
    "critical": [],
    "high": [
        {"id": "miner", "name": "Cryptominer",
         "desc": "Browser cryptominer loaded into visited pages",
         "regexes": [r"\b(?:coinhive|coin-hive|cryptonight|coinimp|webminepool|minero\.cc|"
                     r"jsecoin|crypto-loot|cryptoloot|authedmine|webmine\.pro|monerominer)\b",
                     r"stratum\+(?:tcp|ssl)://", r"new\s{1,4}(?:CoinHive|CoinImp|Client)\.(?:Anonymous|User)\s{0,4}\("]},
        {"id": "packed_eval", "name": "Packed / Encoded Eval",
         "desc": "Encoded payload decoded and evaluated (obfuscation is banned on Greasy Fork)",
         "regexes": [r"\beval\s{0,4}\(\s{0,4}function\s{0,4}\(\s{0,4}p\s{0,4},\s{0,4}a\s{0,4},\s{0,4}c\s{0,4},\s{0,4}k\s{0,4},\s{0,4}e\s{0,4},\s{0,4}[dr]",
                     r"(?:\beval|new\s{1,4}Function)\s{0,4}\(\s{0,4}(?:atob|unescape|decodeURIComponent\s{0,4}\(\s{0,4}escape|"
                     r"window\.atob|LZString\.decompress\w{0,20})\s{0,4}\(",
                     r"(?:\beval|new\s{1,4}Function)\s{0,4}\(\s{0,4}String\.fromCharCode\s{0,4}\(",
                     r"(?:\beval|new\s{1,4}Function)\s{0,4}\(\s{0,4}[\"'](?:\\x[0-9a-fA-F]{2}){20,}"]},
    ],
    "medium": [
        {"id": "affiliate_rewrite", "name": "Affiliate / Referral Injection",
         "desc": "Hard-coded affiliate tag or referral redirect (monetises your clicks)",
         "regexes": [r"[?&]tag=[a-z0-9-]{2,30}-2[0-2]\b",
                     r"s\.click\.taobao\.com/|union-click\.jd\.com/|uland\.taobao\.com/coupon|"
                     r"[?&](?:aff_short_key|aff_platform|aff_trace_key)=|click\.linksynergy\.com/|"
                     r"[?&]affid=|\bamzn\.to/|go\.skimresources\.com|redirect\.viglink\.com|"
                     r"[?&]associate[_-]?id=|p\.yiqifa\.com|u\.jd\.com/|mobile\.yangkeduo\.com/duo_coupon"]},
        {"id": "exe_download", "name": "Executable Download",
         "desc": "GM_download / download link to an executable file",
         "regexes": [r"GM_download\s{0,4}\([^\n]{0,200}\.(?:exe|msi|scr|bat|cmd|ps1|vbs|jar|apk|dmg|pkg)[\"'?]"]},
        {"id": "remote_script_src", "name": "Remote Script Injection",
         "desc": "Injects a <script src> from a host that is neither a CDN nor a code store",
         "regexes": [r"\.src\s{0,4}=\s{0,4}[\"'](?:https?:)?//[^\"'\s]{4,200}\.js\b"]},
    ],
    "low": [],
    "info": [
        {"id": "analytics", "name": "Analytics Beacon",
         "desc": "Loads an analytics / tracking script (Greasy Fork requires disclosure)",
         "regexes": [r"google-analytics\.com/(?:collect|analytics\.js|ga\.js)|googletagmanager\.com/gtag|"
                     r"hm\.baidu\.com/hm\.js|cnzz\.com/|51\.la/|umami\.is|plausible\.io/js|"
                     r"clarity\.ms/tag|static\.cloudflareinsights\.com"]},
        {"id": "key_listener", "name": "Keyboard Listener",
         "desc": "Listens to key events (hotkeys are normal)", "regexes": [KEY_LISTEN.pattern]},
        {"id": "cookie_read", "name": "Cookie Read", "desc": "Reads document.cookie / GM_cookie",
         "regexes": [COOKIE_SRC.pattern]},
        {"id": "dynamic_code", "name": "Dynamic Code", "desc": "eval / new Function present",
         "regexes": [r"\beval\s{0,4}\(|new\s{1,4}Function\s{0,4}\("]},
        {"id": "clipboard_write", "name": "Clipboard Write", "desc": "Writes to the clipboard",
         "regexes": [CLIP_WRITE.pattern]},
        {"id": "crypto_address", "name": "Crypto Address Literal",
         "desc": "Hard-coded cryptocurrency address (often a donation link)", "regexes": [ADDR_LIT.pattern]},
    ],
}

_COMPILED = [(sev, pg, re.compile(rx, re.I)) for sev, groups in PATTERNS.items() for pg in groups
             for rx in pg["regexes"]]
# Anchor strings (lower-case): a signature only runs when one of them occurs in the script.
# None = always run.
NEEDLES = {
    "miner": ("coinhive", "coin-hive", "cryptonight", "coinimp", "webminepool", "minero", "jsecoin", "crypto-loot",
              "cryptoloot", "authedmine", "webmine", "monerominer", "stratum+", ".anonymous", ".user"),
    "packed_eval": ("eval", "function"),
    "affiliate_rewrite": ("tag=", "taobao", "jd.com", "aff_", "linksynergy", "affid", "amzn.to", "skimresources",
                          "viglink", "associate", "yiqifa", "yangkeduo"),
    "exe_download": ("gm_download",),
    "remote_script_src": (".src",),
    "analytics": ("google-analytics", "googletagmanager", "hm.baidu", "cnzz", "51.la", "umami", "plausible",
                  "clarity.ms", "cloudflareinsights"),
    "key_listener": ("onkey", "keydown", "keyup", "keypress"),
    "cookie_read": ("cookie",),
    "dynamic_code": ("eval", "function"),
    "clipboard_write": ("clipboard", "copy"),
    "crypto_address": None,
}
OBF_IDENT = re.compile(r"(?<![\"'`\w$])_0x[0-9a-f]{4,6}\b(?![\"'`])")   # identifiers, not quoted names
JSON_EVAL = re.compile(r"eval\s{0,4}\(\s{0,4}[\"']\(\s{0,2}[\"']\s{0,4}\+\s{0,4}[\w.$\[\]]{1,60}\s{0,4}\+\s{0,4}[\"']\s{0,2}\)[\"']\s{0,4}\)")
STRING_ARRAY = re.compile(r"\b(?:var|const|let)\s{1,4}_0x[0-9a-f]{4,6}\s{0,4}=\s{0,4}\[\s{0,4}[\"']")
SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}


# ---------------------------------------------------------------------------
# Metadata block
# ---------------------------------------------------------------------------
META_RE = re.compile(r"//\s{0,8}==UserScript==(.{0,200000}?)//\s{0,8}==/UserScript==", re.S)
META_LINE = re.compile(r"^\s{0,8}//\s{0,8}@([\w:.-]{1,40})(?:\s{1,200}(.{0,4000}))?$", re.M)


def parse_meta(text):
    m = META_RE.search(text[:400000])
    meta = {}
    if not m:
        return meta, 0, 0
    for k, v in META_LINE.findall(m.group(1)):
        meta.setdefault(k.lower(), []).append((v or "").strip())
    return meta, m.start(), m.end()


def _host(url):
    try:
        u = urllib.parse.urlsplit(url if "//" in url else "//" + url)
        return (u.hostname or "").lower()
    except ValueError:
        return ""


def _under(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def _match_domains(meta):
    """Registrable-ish domains the script is meant to run on (from @match / @include)."""
    out = set()
    for key in ("match", "include"):
        for v in meta.get(key, []):
            h = _host(v.replace("*.", "").replace("*", "x"))
            if h and "x" != h and not h.startswith("x."):
                parts = h.split(".")
                out.add(".".join(parts[-2:]) if len(parts[-1]) > 2 or len(parts) < 3 else ".".join(parts[-3:]))
    return out


BROAD = re.compile(r"^(?:\*|<all_urls>|\*://\*/?\*?|https?://\*/?\*?|http\*://\*/?\*?|\*://\*\.\*/?\*?|/\.\*/|"
                   r"https?://\*\.?\*?/\*|\*://\*\.\*\.\*/\*)$")


def _item(sev, pid, name, desc, line, matched="", context=""):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "line": line,
            "matched": matched[:120], "context": context[:200]}


def _meta_findings(meta, add):
    grants = {g for g in meta.get("grant", [])}
    connects = meta.get("connect", [])
    matches = meta.get("match", []) + meta.get("include", [])
    broad = any(BROAD.match(m.strip()) for m in matches)
    caps = []
    if broad:
        caps.append("broad_match")
        add("INFO", "broad_match", "Runs On Every Site", "@match/@include covers all sites", 0, matches[0])
    xhr = grants & {"GM_xmlhttpRequest", "GM.xmlHttpRequest", "GM_xmlHttpRequest"}
    if xhr:
        caps.append("gm_xhr")
        add("INFO", "gm_xhr", "Cross-Origin Requests", "GM_xmlhttpRequest bypasses page CORS/CSP", 0, sorted(xhr)[0])
    if any(c.strip() == "*" for c in connects):
        caps.append("connect_any")
        add("INFO", "connect_any", "@connect *", "May send requests to any host", 0, "@connect *")
    if grants & {"GM_cookie", "GM.cookie"}:
        caps.append("gm_cookie")
        add("INFO", "gm_cookie", "Cookie API", "GM_cookie can read HttpOnly cookies", 0, "GM_cookie")
    if "unsafeWindow" in grants:
        caps.append("unsafe_window")
        add("INFO", "unsafe_window", "unsafeWindow", "Shares objects with the page", 0, "unsafeWindow")
    for key in ("require", "resource"):
        for v in meta.get(key, []):
            url = v.split()[-1] if key == "resource" else v
            h = _host(url)
            sri = "#sha256" in url.lower() or "#sha384" in url.lower() or "#sha512" in url.lower() or "#md5" in url.lower() \
                or re.search(r"#sha(?:256|384|512)[-=]", url, re.I)
            if _under(h, COMPROMISED_CDN):
                add("HIGH", "require_compromised", "@%s from a compromised CDN" % key,
                    "polyfill.io-family host, taken over and used to serve malware in 2024", 0, url)
            elif _under(h, SUSPECT_CDN):
                add("MEDIUM", "require_suspect_cdn", "@%s from a polyfill.io-linked CDN" % key,
                    "Host reported in 2024 to share an operator with polyfill.io; prefer jsDelivr/cdnjs + SRI",
                    0, url)
            elif RAW_IP_URL.match(url) or EXFIL_HOST.search(url):
                add("HIGH", "require_untrusted", "@%s from raw IP / tunnel" % key,
                    "Code pulled from a raw IP or tunnel/collector host", 0, url)
            elif url.lower().startswith("http://"):
                add("MEDIUM", "require_http", "@%s over http://" % key,
                    "Code fetched over plaintext: anyone on the network path can inject into every matched page",
                    0, url)
            elif url.lower().startswith("data:") or _under(h, _match_domains(meta)):
                continue                      # inline data: URI, or the target site's own library
            elif not (_under(h, CDN_HOSTS) or _under(h, STORE_HOSTS)) and not sri and not PINNED.search(url) \
                    and key == "require":
                add("LOW", "require_selfhost", "Unpinned @require from self-hosted domain",
                    "Remote code from a host the author controls, with no SRI hash: it can change after review",
                    0, url)
            elif _under(h, ("raw.githubusercontent.com", "gist.githubusercontent.com")) and \
                    re.search(r"/(?:main|master|HEAD|dev|refs/heads/)", url) and not sri and key == "require":
                add("INFO", "require_mutable", "@require from a mutable branch",
                    "Pinned to a branch, not a commit or version", 0, url)
    for key in ("updateurl", "downloadurl"):
        for v in meta.get(key, []):
            h = _host(v)
            if v.lower().startswith("http://"):
                add("MEDIUM", "update_http", "@%s over http://" % key,
                    "Updates fetched over plaintext can be replaced in transit", 0, v)
            elif h and not _under(h, STORE_HOSTS):
                add("INFO", "update_offstore", "Updates from outside the store",
                    "@%s points off Greasy Fork/OpenUserJS/GitHub: updates skip store review" % key, 0, v)
    return caps, broad


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def _comment_spans(text):
    """Offsets of // line comments and /* */ blocks (rough, string-unaware but bounded)."""
    spans = []
    for m in re.finditer(r"(?<![:\"'\\])//[^\n]{0,2000}|/\*.{0,20000}?\*/", text, re.S):
        spans.append((m.start(), m.end()))
    return spans


def _in_spans(pos, starts, spans):
    i = bisect.bisect_right(starts, pos) - 1
    return i >= 0 and spans[i][0] <= pos < spans[i][1]


def scan(content, label="<text>", listing=None):
    text = content[:MAX_FILE]
    # blobs (embedded images/fonts/wasm) are data: fill with a neutral char, offsets preserved
    if len(text) > 8192:
        text = BLOB_RE.sub(lambda m: "B" * len(m.group(0)), text)
    low = text.lower()
    nl = [m.start() for m in re.finditer("\n", text)]

    def line_of(pos):
        return bisect.bisect_left(nl, pos) + 1

    def ctx(a, b):
        ls = text.rfind("\n", 0, a) + 1
        le = text.find("\n", b)
        le = len(text) if le < 0 else le
        if le - ls > 240:
            ls, le = max(ls, a - 80), min(le, b + 80)
        return text[ls:le].strip()

    findings, info = [], []

    def add(sev, pid, name, desc, line, matched="", context=""):
        (info if sev == "INFO" else findings).append(_item(sev, pid, name, desc, line, matched, context))

    meta, mstart, mend = parse_meta(text)
    caps, broad = _meta_findings(meta, add)
    domains = _match_domains(meta)
    spans = _comment_spans(text) if len(text) < 6_000_000 else []
    starts = [s for s, _ in spans]

    def commented(pos):
        return (mstart <= pos < mend) or _in_spans(pos, starts, spans)

    seen = set()
    for sev, pg, rx in _COMPILED:
        nd = NEEDLES.get(pg["id"])
        if nd and not any(n in low for n in nd):
            continue
        hits = 0
        for m in rx.finditer(text):
            if hits >= 10:
                break
            if commented(m.start()):
                continue
            key = (pg["id"], line_of(m.start()))
            if key in seen:
                continue
            seen.add(key)
            s = sev.upper()
            if pg["id"] == "packed_eval" and "function" not in m.group(0).lower():
                after = text[m.end():m.end() + 120]
                before = text[max(0, m.start() - 2):m.start()]
                if re.match(r"\s{0,2}[\"']{1,2}\s{0,2}\+", after) or (before[-1:] in "\"'" and re.match(r"[\"']\s{0,2}\+", after)):
                    s = "INFO"      # building an eval(atob('...')) string from its own visible code
                elif re.match(r"\s{0,4}[\"'`]", after):
                    lit = re.match(r"\s{0,4}[\"'`]([A-Za-z0-9+/=]{0,40000})[\"'`]", after)
                    if lit and len(lit.group(1)) < 40:
                        # e.g. eval(atob("UElYSQ==")) -> "PIXI": a hidden identifier, not a payload
                        s = "MEDIUM"
                        pg = dict(pg, id="decode_eval", name="Decode-then-eval of a Short Literal",
                                  desc="A short encoded literal is decoded and evaluated (hides an identifier, "
                                       "not a payload)")
                else:
                    arg = re.match(r"\s{0,4}([A-Za-z_$][\w$]{0,40})\s{0,4}\)", after)
                    lit = arg and re.search(r"\b" + re.escape(arg.group(1)) + r"\s{0,4}\+?=\s{0,4}[\"'][A-Za-z0-9+/=]{40,}",
                                            text[max(0, m.start() - 4000):m.start()])
                    if not lit:
                        s = "MEDIUM"
                        pg = dict(pg, id="decode_eval", name="Decode-then-eval of Runtime Data",
                                  desc="Base64/escaped data decoded and evaluated (not a literal payload)")
            if pg["id"] == "remote_script_src":
                h = _host(m.group(0).split("=", 1)[1].strip(" \"'"))
                u = m.group(0).split("=", 1)[1].strip(" \"'")
                if _under(h, CDN_HOSTS) or _under(h, STORE_HOSTS) or _under(h, domains) or RECAPTCHA.match(u):
                    s = "INFO"
            add(s, pg["id"], pg["name"], pg["desc"], key[1], m.group(0), ctx(m.start(), m.end()))
            hits += 1

    def external_urls(a, b):
        out = []
        for m in URL_RE.finditer(text, max(0, a), min(len(text), b)):
            h = m.group(1).lower()
            if _under(h, domains) or _under(h, CDN_HOSTS) or _under(h, STORE_HOSTS) or h.endswith((".png", ".jpg", ".svg", ".gif", ".css", ".js")):
                continue
            if h in ("www.w3.org", "w3.org", "schema.org", "example.com", "localhost"):
                continue
            out.append(h)
        return out

    def _call_end(pos, cap=800):
        """End offset of the call whose name ends at pos: balance (), skipping quoted strings."""
        i, n, depth, q = pos, min(len(text), pos + cap), 0, None
        while i < n:
            c = text[i]
            if q:
                if c == "\\":
                    i += 1
                elif c == q:
                    q = None
            elif c in "\"'`":
                q = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth <= 0:
                    return i + 1
            elif c in ";\n" and depth == 0 and i > pos + 2:
                return i
            i += 1
        return n

    def combo(src_re, name, pid, desc, crit_desc, need_send=True, limit=5):
        n = 0
        for m in src_re.finditer(text):
            if n >= limit or commented(m.start()):
                continue
            a, b = m.start() - NEAR, m.end() + NEAR
            win = text[max(0, a):b]
            if need_send and not SEND_RE.search(win):
                continue
            exfil = EXFIL_HOST.search(win) or RAW_IP_URL.search(win)
            if exfil:
                add("CRITICAL", pid, name, crit_desc, line_of(m.start()), exfil.group(0), ctx(m.start(), m.end()))
                n += 1
                continue
            if not broad:
                continue
            # third-party host: require the harvested value to flow into a send whose own
            # arguments carry a literal third-party URL (a CSRF header to the site's API is normal)
            names = {m.group(0)}
            pre = text[max(0, m.start() - 60):m.start()]
            v = re.search(r"(?:const|let|var)\s{1,4}([A-Za-z_$][\w$]{0,30})\s{0,4}=\s{0,4}[^;\n]{0,20}$", pre)
            if v:
                names.add(v.group(1))
            cb = re.match(r"[^\n]{0,60}?(?:\(\s{0,4}([A-Za-z_$][\w$]{0,30})\s{0,4}\)\s{0,4}=>|function\s{0,4}\(\s{0,4}([A-Za-z_$][\w$]{0,30}))",
                          text[m.end():m.end() + 80])
            if cb:
                names.add(cb.group(1) or cb.group(2))
            for sm in SEND_RE.finditer(text, max(0, a), min(len(text), b + 400)):
                end = _call_end(sm.end())
                span = text[sm.start():end]
                if not any(re.search(r"(?<![\w$.])" + re.escape(nm) + r"(?![\w$])", span) for nm in names):
                    continue
                ext = external_urls(sm.start(), end)
                if ext:
                    add("HIGH", pid, name, desc + " (to %s, from every site)" % ext[0], line_of(m.start()),
                        m.group(0), ctx(m.start(), m.end()))
                    n += 1
                    break

    combo(COOKIE_SRC, "Cookie Exfiltration", "cookie_exfil",
          "Reads cookies next to a request to a third-party host",
          "Reads cookies next to a request to a collector / tunnel / raw-IP endpoint")
    combo(TOKEN_SRC, "Token Exfiltration", "token_exfil",
          "Reads a stored auth token next to a request to a third-party host",
          "Reads a stored auth token next to a request to a collector endpoint")
    combo(DUMP_SRC, "Storage Dump Exfiltration", "storage_exfil",
          "Serialises all of localStorage next to a request to a third-party host",
          "Serialises all of localStorage next to a request to a collector endpoint")

    # password field + key/input listener + send = keylogger
    for m in PASS_SRC.finditer(text):
        if commented(m.start()):
            continue
        a, b = m.start() - 1200, m.end() + 1200
        win = text[max(0, a):b]
        if (KEY_LISTEN.search(win) or re.search(r"addEventListener\s{0,4}\(\s{0,4}[\"'](?:input|change|submit)[\"']", win)) \
                and SEND_RE.search(win):
            exfil = EXFIL_HOST.search(win) or RAW_IP_URL.search(win)
            ext = external_urls(a, b)
            if exfil or ext:
                add("CRITICAL" if exfil else "HIGH", "password_capture", "Password Capture",
                    "Password field value captured by an input/key listener next to a request to %s"
                    % (exfil.group(0) if exfil else ext[0]), line_of(m.start()), m.group(0), ctx(m.start(), m.end()))
                break

    def _flows(assign, win):
        """The variable put into the <script> must come from a fetched response."""
        v = re.search(r"=\s{0,4}([A-Za-z_$][\w$]{0,30})|:\s{0,4}([A-Za-z_$][\w$]{0,30})", assign.group(0))
        if not v:
            return False
        nm = re.escape(v.group(1) or v.group(2))
        return bool(re.search(r"\b" + nm + r"\s{0,4}=\s{0,4}[\w.]{0,40}\.(?:responseText|response)\b|"
                              r"\.text\s{0,4}\(\s{0,4}\)\s{0,4}\)?\s{0,4}\.then\s{0,4}\(\s{0,4}(?:async\s{1,4})?\(?\s{0,4}" + nm + r"\b|"
                              r"\b" + nm + r"\s{0,4}=\s{0,4}await\s{1,4}[^;\n]{0,80}\.text\s{0,4}\(", win))

    def _remote(m, win, desc="Text fetched at runtime is passed to eval/Function"):
        """HIGH when the code comes from a literal third-party URL; MEDIUM when integrity-checked or the
        source URL is computed (often the page's own script, re-injected with modifications)."""
        if re.search(r"hash mismatch|integrity|crypto\.subtle\.digest|calculateHash|sha(?:256|384|512)", win, re.I):
            add("MEDIUM", "remote_code_verified", "Remote Code (Integrity-Checked)",
                desc + ", after a hash check: safer, but behaviour still lives outside the store",
                line_of(m.start()), m.group(0), ctx(m.start(), m.end()))
            return
        ext = [h for h in external_urls(m.start() - len(win), m.end() + 300)]
        if ext:
            add("HIGH", "remote_code", "Remote Code Execution",
                desc + " from %s: the script's behaviour can be changed server-side after review" % ext[0],
                line_of(m.start()), m.group(0), ctx(m.start(), m.end()))
        else:
            add("MEDIUM", "remote_code_dynamic", "Remote Code (Computed Source)",
                desc + "; source URL is computed (often the page's own script, modified)",
                line_of(m.start()), m.group(0), ctx(m.start(), m.end()))

    # remote code: fetched text -> eval / Function / injected script
    for m in EVAL_SINK.finditer(text):
        if commented(m.start()):
            continue
        win = text[max(0, m.start() - 300):m.end() + 300]
        tail = text[m.start():m.end() + 120]
        if FETCHED.search(tail) or re.search(r"\.then\s{0,4}\(\s{0,4}(?:eval|Function)\b", win):
            if SEND_RE.search(win) or "responsetext" in tail.lower():
                if JSON_EVAL.match(text, m.start()):
                    add("MEDIUM", "json_eval", "eval() Used to Parse a Response",
                        "Legacy eval(\"(\" + response + \")\") JSON parsing: a compromised endpoint becomes code "
                        "execution (use JSON.parse)", line_of(m.start()), m.group(0), ctx(m.start(), m.end()))
                    continue
                _remote(m, win)
                break
    if not any(f["id"].startswith("remote_code") for f in findings):
        for m in SCRIPT_INJECT.finditer(text):
            if commented(m.start()):
                continue
            win = text[max(0, m.start() - 500):m.end() + 500]
            fetched_inline = SCRIPT_TEXT_FROM_FETCH.search(win)
            text_assign = re.search(r"(?:\.textContent|\.text|\.innerHTML|\.innerText)\s{0,4}=\s{0,4}[A-Za-z_$][\w$]{0,30}\s{0,4}[;,\n}]|"
                                    r"textContent\s{0,4}:\s{0,4}[A-Za-z_$][\w$]{0,30}\s{0,4}[,}]|createTextNode\s{0,4}\(", win)
            if fetched_inline or (text_assign and _flows(text_assign, win)):
                _remote(m, text[max(0, m.start() - 1500):m.end() + 500], "Fetched text injected as an inline <script>")
                break
    if re.search(r"\.then\s{0,4}\(\s{0,4}eval\s{0,4}\)|\.then\s{0,4}\(\s{0,4}\w{1,20}\s{0,4}=>\s{0,4}eval\s{0,4}\(", text) \
            and not any(f["id"].startswith("remote_code") for f in findings):
        m = re.search(r"\.then\s{0,4}\(\s{0,4}(?:eval|\w{1,20}\s{0,4}=>\s{0,4}eval)", text)
        _remote(m, text[max(0, m.start() - 600):m.end() + 100], "fetch(...).then(eval)")

    # clipboard hijack: copy event + address-format regex + clipboard write (swapping addresses)
    if COPY_EVENT.search(text) or "clipboarddata" in low:
        for m in ADDR_REGEX.finditer(text):
            win = text[max(0, m.start() - 800):m.end() + 800]
            if CLIP_WRITE.search(win) and (ADDR_LIT.search(win) or COPY_EVENT.search(win)):
                add("HIGH", "clipboard_hijack", "Clipboard Address Swap",
                    "Detects crypto addresses being copied and rewrites the clipboard", line_of(m.start()),
                    m.group(0), ctx(m.start(), m.end()))
                break

    # obfuscation (javascript-obfuscator output)
    obf = len(OBF_IDENT.findall(text[:5_000_000])) if "_0x" in text else 0
    if obf >= 40 or (obf >= 15 and STRING_ARRAY.search(text)):
        add("HIGH", "obfuscation", "Obfuscated Code",
            "javascript-obfuscator style code (%d _0x identifiers); obfuscation is banned on Greasy Fork" % obf, 0,
            context="file-level")

    # history leak: every page's URL sent to a third party
    if broad:
        for m in re.finditer(r"(?:location\.href|document\.URL|location\.hostname|document\.title)", text):
            win = text[max(0, m.start() - 250):m.end() + 250]
            if SEND_RE.search(win) and not commented(m.start()):
                ext = external_urls(m.start() - 250, m.end() + 250)
                if ext:
                    add("MEDIUM", "url_leak", "Visited URL Sent to Third Party",
                        "Sends the current page URL/title to %s from every site (browsing-history exposure; "
                        "fine if it is the script's stated purpose)" % ext[0], line_of(m.start()), m.group(0),
                        ctx(m.start(), m.end()))
                    break

    if any(f["id"] in ("cookie_exfil", "token_exfil", "storage_exfil", "password_capture") for f in findings) \
            and "gm_cookie" in caps:
        for f in findings:
            if f["id"] == "cookie_exfil" and f["severity"] == "HIGH":
                f["severity"] = "CRITICAL"
    return _summary(findings, info, label, meta)


def _summary(findings, info, label, meta):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["line"]))
    score = min(100, sum(SEVERITY_SCORE[f["severity"]] for f in findings))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return {"target": label, "name": (meta.get("name") or [""])[0], "version": (meta.get("version") or [""])[0],
            "risk_level": level, "risk_score": score, "summary": ", ".join(parts) or "No issues found",
            "findings": findings, "info": info, "capabilities": sorted({i["id"] for i in info})}


# ---------------------------------------------------------------------------
# Fetching + CLI
# ---------------------------------------------------------------------------
UA = {"User-Agent": "userscript-audit/%s (+https://github.com/eltociear/userscript-audit)" % __version__}


def _get(url, tries=4):
    err = None
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60).read() \
                .decode("utf-8", "replace")
        except Exception as e:  # network is allowed to be flaky
            err = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError("fetch failed: %s (%s)" % (url, err))


def fetch_greasyfork(sid):
    sid = re.sub(r"\D.*$", "", str(sid).rsplit("/scripts/", 1)[-1])
    info = json.loads(_get("https://api.greasyfork.org/en/scripts/%s.json" % sid))
    return "greasyfork:%s" % sid, _get(info["code_url"])


def fetch_openuserjs(ref):
    user, name = ref.strip("/").split("/", 1)
    url = "https://openuserjs.org/install/%s/%s.user.js" % (urllib.parse.quote(user), urllib.parse.quote(name))
    return "openuserjs:%s" % ref, _get(url)


ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "\U0001F535",
        "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    nm = (" \u2014 " + r["name"]) if r["name"] else ""
    print("%s %s%s  [%s]  score=%d  (%s)" % (ICON.get(r["risk_level"], "?"), r["target"], nm, r["risk_level"],
                                            r["risk_score"], r["summary"]))
    for f in r["findings"] + (r["info"] if verbose else []):
        print("    %-8s %s (line %s)  %s" % (f["severity"], f["name"], f["line"], f["description"]))
        if f["context"] or f["matched"]:
            print("             %s" % (f["context"] or f["matched"]))
    if r["info"] and not verbose:
        print("    capabilities: %s" % ", ".join(r["capabilities"]))


def _iter_paths(paths):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.read()
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith((".user.js", ".js")):
                        fp = os.path.join(root, f)
                        yield fp, open(fp, encoding="utf-8", errors="replace").read()
        else:
            yield p, open(p, encoding="utf-8", errors="replace").read()


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    as_json = "--json" in args
    verbose = "--verbose" in args or "-v" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--all")]
    targets = []
    if args[0] == "--greasyfork":
        targets = [lambda s=s: fetch_greasyfork(s) for s in args[1:]]
    elif args[0] == "--openuserjs":
        targets = [lambda s=s: fetch_openuserjs(s) for s in args[1:]]
    elif args[0] == "--url":
        targets = [lambda u=u: (u, _get(u)) for u in args[1:]]
    elif args[0] == "--text":
        targets = [lambda: ("<text>", " ".join(args[1:]))]
    else:
        targets = [lambda lt=lt: lt for lt in _iter_paths(args)]
    results, worst = [], "SAFE"
    for t in targets:
        try:
            label, text = t()
        except Exception as e:
            print("error: %s" % e, file=sys.stderr)
            continue
        r = scan(text, label)
        results.append(r)
        if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
            worst = r["risk_level"]
        if not as_json:
            _print(r, verbose)
    if as_json:
        print(json.dumps(results, indent=1, ensure_ascii=False))
    return 2 if SEV_ORDER[worst] >= SEV_ORDER["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
