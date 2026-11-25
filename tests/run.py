#!/usr/bin/env python3
"""Test runner: inert malicious canaries must trip at the expected level with the expected id;
benign controls must stay below HIGH. No network. `python tests/run.py`"""
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import userscript_audit as ua  # noqa: E402

EXPECT = {
    "mal-cookie-webhook": ("CRITICAL", "cookie_exfil"),
    "mal-token-tunnel": ("CRITICAL", "token_exfil"),
    "mal-storage-dump": ("HIGH", "storage_exfil"),
    "mal-password-keylog": ("CRITICAL", "password_capture"),
    "mal-remote-eval": ("HIGH", "remote_code"),
    "mal-remote-script-inject": ("HIGH", "remote_code"),
    "mal-clipboard-swap": ("HIGH", "clipboard_hijack"),
    "mal-miner": ("HIGH", "miner"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-packed": ("HIGH", "packed_eval"),
    "mal-require-ip": ("HIGH", "require_untrusted"),
    "mal-gmcookie-telegram": ("CRITICAL", "cookie_exfil"),
    "mal-packed-var": ("HIGH", "packed_eval"),
    "med-json-eval": ("MEDIUM", "json_eval"),
    "med-verified-loader": ("MEDIUM", "remote_code_verified"),
    "mal-polyfill": ("HIGH", "require_compromised"),
    "med-suspect-cdn": ("MEDIUM", "require_suspect_cdn"),
    "med-short-decode-eval": ("MEDIUM", "decode_eval"),
    "med-affiliate": ("MEDIUM", "affiliate_rewrite"),
    "med-require-http": ("MEDIUM", "require_http"),
    "med-url-leak": ("MEDIUM", "url_leak"),
}
ORDER = ua.SEV_ORDER
fails = 0
for f in sorted(os.listdir(os.path.join(HERE, "fixtures"))):
    name = f.replace(".user.js", "")
    r = ua.scan(open(os.path.join(HERE, "fixtures", f), encoding="utf-8").read(), f)
    ids = {x["id"] for x in r["findings"]}
    if name.startswith("ok-"):
        ok = ORDER[r["risk_level"]] < ORDER["MEDIUM"]
        want = "< MEDIUM"
    else:
        lvl, fid = EXPECT[name]
        ok = r["risk_level"] == lvl and fid in ids
        want = "%s/%s" % (lvl, fid)
    print("%s %-28s got %-8s %s  want %s" % ("PASS" if ok else "FAIL", name, r["risk_level"], sorted(ids), want))
    fails += not ok

# metadata parsing + string input
r = ua.scan("// ==UserScript==\n// @name x\n// @match *://*/*\n// @grant GM_xmlhttpRequest\n// ==/UserScript==\n", "t")
ok = r["name"] == "x" and "broad_match" in r["capabilities"] and r["risk_level"] == "SAFE"
print("%s metadata parse" % ("PASS" if ok else "FAIL")); fails += not ok

# commented-out payloads are ignored
r = ua.scan("// eval(function(p,a,c,k,e,d){})\n/* new CoinHive.Anonymous('k') */\n", "c")
ok = r["risk_level"] == "SAFE"
print("%s comments ignored" % ("PASS" if ok else "FAIL")); fails += not ok

# performance: a 5 MB single-line bundle plus a 1 MB base64 blob scans fast
big = "var a=" + "\"" + "QUJD" * 250000 + "\";" + ("function f(x){return x+1};" * 180000)
t0, w0 = time.process_time(), time.time(); ua.scan(big, "big"); dt, wt = time.process_time() - t0, time.time() - w0
ok = dt < 8          # CPU time, so a busy machine does not fail the test
print("%s 5 MB single-line bundle in %.1fs CPU (%.1fs wall)" % ("PASS" if ok else "FAIL", dt, wt)); fails += not ok

# no canary credential is in a real provider's token format
REAL = re.compile(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|"
                  r"discord(?:app)?\.com/api/webhooks/[0-9]{17,}/|xox[baprs]-|AIza[0-9A-Za-z_-]{35}")
bad = [f for f in os.listdir(os.path.join(HERE, "fixtures"))
       if REAL.search(open(os.path.join(HERE, "fixtures", f), encoding="utf-8").read())]
ok = not bad
print("%s canary secrets are not provider-format-valid %s" % ("PASS" if ok else "FAIL", bad)); fails += not ok

print("\n%d failure(s)" % fails)
sys.exit(1 if fails else 0)
