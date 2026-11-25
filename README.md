# userscript-audit

**Scan Tampermonkey / Violentmonkey / Greasemonkey userscripts for malicious patterns before you install them.** Zero dependencies, one file, MIT.

```bash
python userscript_audit.py --greasyfork 12345          # a Greasy Fork script id
python userscript_audit.py something.user.js           # a local file (or a directory, or - for stdin)
python userscript_audit.py --url https://example.org/x.user.js
python userscript_audit.py --openuserjs user/script
# 🔴 mal-cookie-webhook.user.js  [CRITICAL]  score=25  (1 CRITICAL)
#     CRITICAL Cookie Exfiltration (line 9)  Reads cookies next to a request to a collector / tunnel / raw-IP endpoint
```

## Why this exists

A userscript runs inside every page its `@match` covers, **with your logged-in session**. Add
`GM_xmlhttpRequest` and `@connect *` and it can also talk to any host, past the page's CORS and
CSP. A broad-match userscript is the most powerful thing most people ever install from a
stranger, and store review is a human reading a diff. Worse, code pulled in at runtime
(`@require`, `eval(response)`, an injected `<script>`) can change after that review.

Extension scanners don't read userscripts, and `@require` lines are invisible to code-only scanners.
`userscript-audit` parses the `==UserScript==` metadata block **and** the code.

## What it scores

| Pattern | Severity |
| --- | --- |
| Cookie / stored-token / `localStorage` dump flowing into a request to a collector (webhook, Telegram bot, ngrok/tunnel, OAST, raw IP) | CRITICAL |
| …the same, to any third-party host, from a script that runs on every site | HIGH |
| Password-field capture (input/key listener + send) | CRITICAL / HIGH |
| Remote code: fetched text → `eval` / `new Function` / an inline `<script>`, from a literal third-party URL | HIGH |
| Clipboard address swap (copy event + crypto-address regex + clipboard write) | HIGH |
| Cryptominers; packed `eval(function(p,a,c,k,e,d)…)` and `eval(atob("<literal payload>"))`; javascript-obfuscator output | HIGH |
| `@require` / `@resource` from polyfill.io-family hosts, raw IPs or tunnels | HIGH |
| `@require` over `http://`; `@updateURL` over `http://`; polyfill.io-linked CDNs (bootcdn / bootcss / staticfile) | MEDIUM |
| Remote code that is hash-verified, or whose source URL is computed (often the page's own script, re-injected) | MEDIUM |
| `eval("(" + response + ")")` JSON parsing; decode-then-eval of runtime data | MEDIUM |
| Affiliate / referral injection; executable downloads; `<script src>` from a self-hosted domain; visited URL sent to a third party from every site | MEDIUM |
| Unpinned `@require` from a self-hosted domain with no SRI hash | LOW |

20 scored pattern ids (plus 3 graded variants), 13 informational. **Capabilities never score**:
`*://*/*`, `GM_xmlhttpRequest`, `@connect *`, `unsafeWindow`, `GM_cookie`, reading
`document.cookie`, key listeners, clipboard writes, `eval`, donation addresses and analytics are
reported as INFO. What scores is the **combination**: the cookie that flows into the request's
own arguments, the response text that reaches `eval`.

## Calibrated, not noisy

Measured on Greasy Fork (2026-11): the top 1,500 scripts by total installs, then a **held-out 700**
scanned once with the rules frozen and committed first (ranks 1,501–2,400 plus 150 newest and 150
recently updated scripts).

| Set | Context-blind rules, HIGH+ | userscript-audit, HIGH+ | benign on review |
| --- | --- | --- | --- |
| Calibration (1,498 scanned) | 276 (18.4%) | 3 (0.20%) | 0 |
| Held-out, rules frozen (700) | 127 (18.1%) | 1 (0.14%) | 1 (0.14%), fixed afterwards |

Every remaining HIGH is a real instance of its pattern (a remote-code loader, a literal base64
`eval`, packed code). **Full results: [FINDINGS.md](FINDINGS.md).**

## Usage

```bash
python userscript_audit.py <file.user.js|dir|->...      # exit code 2 if any HIGH/CRITICAL
python userscript_audit.py --greasyfork <id> [<id>...]  # fetches via api.greasyfork.org
python userscript_audit.py --openuserjs <user>/<script>
python userscript_audit.py --url <url>
python userscript_audit.py --text "<code>"
python userscript_audit.py --json --verbose <file>      # JSON; --verbose also prints INFO capabilities
python tests/run.py                                     # inert canaries + benign controls, no network
```

Installed scripts live inside the browser extension's storage; export them from Tampermonkey
(Utilities → Export → zip), unzip, and point the scanner at the directory.

Design notes: nothing is executed. Embedded base64 blobs ≥4 KB are treated as data. Every repeat is
bounded, and signatures are skipped unless their anchor strings appear, so a 5 MB single-line
bundle scans in a few seconds. Comments and the metadata block are not scanned as code. Line
numbers come from a newline index.

## Siblings

Same engine shape, other ecosystems: [mcp-audit](https://github.com/eltociear/mcp-audit) ·
[npm-audit](https://github.com/eltociear/npm-audit) · [vsix-audit](https://github.com/eltociear/vsix-audit) ·
[obsidian-audit](https://github.com/eltociear/obsidian-audit) · [homebrew-audit](https://github.com/eltociear/homebrew-audit) ·
[winpkg-audit](https://github.com/eltociear/winpkg-audit) · [crate-audit](https://github.com/eltociear/crate-audit) ·
[aur-audit](https://github.com/eltociear/aur-audit)

*Findings are pattern matches for human review, not verdicts. Report suspected malicious scripts to
the store (Greasy Fork: the script's "Report" link) rather than publishing unverified accusations.*

MIT licensed.
