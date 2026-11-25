# What we found scanning 2,198 Greasy Fork userscripts

This is the research behind `userscript-audit`, a real scan of the most-installed userscripts on
Greasy Fork using this exact engine. Like its siblings ([mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md),
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md), [vsix-audit](https://github.com/eltociear/vsix-audit/blob/main/FINDINGS.md)),
it is calibrated so that "clean" means clean before any number is reported.

## Method

1. **Calibration set (1,500):** the top 1,500 scripts by total installs from the Greasy Fork API
   (`api.greasyfork.org/en/scripts.json?sort=total_installs`). 1,498 were downloaded and scanned;
   2 failed on a flaky network.
2. **Held-out set (700):** the API lists only about 2,400 scripts per sort order, so a uniform random
   sample of the whole catalogue isn't available. The held-out set is 400 random scripts from ranks
   1,501–2,400 by installs, plus 150 of the newest and 150 of the most recently updated (seed
   `20261126`, no overlap with calibration). The rules were **frozen and committed first**
   (`2b7de32`), then the held-out set was scanned once.
3. Each script's latest code was downloaded from `update.greasyfork.org` and read as text. Nothing was
   installed or executed. Scan date: 2026-11-26.

## Headline

| Result | Calibration (1,498) | Held-out, rules frozen (700) |
| --- | --- | --- |
| **Clean of HIGH/CRITICAL** | **1,495** | **699** (blind) → **700** after one fix |
| HIGH / CRITICAL | 3 (0.20%) | 1 (0.14%) → 0 |
| …benign on review | 0 | 1 |
| CRITICAL | 0 | 0 |
| Context-blind rules, HIGH+ | 276 (18.4%) | 127 (18.1%) |

**No script in the scanned set harvests credentials, ships a clipboard hijacker or a miner, or sends
data to a collector endpoint.** The three calibration HIGHs are real instances of their patterns,
reported as observed patterns, not verdicts:

- **A remote-code loader.** On every run, a script downloads its real code from a release URL and
  injects it as an inline `<script>`. Whatever that URL serves runs, and the store never reviewed it.
- **A literal base64 payload passed to `eval(atob(...))`.** The decoded code is harmless UI code,
  but hiding code this way is exactly what Greasy Fork's ban on obfuscation exists for.
- **Packed code** (`eval(function(p,a,c,k,e,d)…)`) in a long-lived, very popular script.

The held-out HIGH was a false positive: `eval(atob("UElYSQ=="))` decodes to the identifier `PIXI`,
which hides a variable name, not a payload. Short literals (under 40 characters) now score MEDIUM.
The blind number above is the one that counts; the fix came afterwards.

## The noise: what looks dangerous in a userscript but isn't

A context-blind rule set (cookie / token / `eval` / `<script>` / password / clipboard / `atob`
signatures in a script that makes requests) flags **18%** of the top scripts. Every one of those
was a false positive. The drivers, measured over all 2,198 scripts:

| Signal | Scripts | Why it's noise |
| --- | --- | --- |
| Key listeners | 612 (27.8%) | Hotkeys. A keylogger is a listener on a *password field* that also sends |
| `GM_xmlhttpRequest` | 424 (19.3%) | Talking to the site's own API, a translator, a download host |
| `unsafeWindow` | 271 (12.3%) | Reaching page objects (players, frameworks) |
| Clipboard writes | 205 (9.3%) | "Copy link" buttons. A hijacker rewrites the clipboard *on copy*, matching an address format |
| Runs on every site (`*://*/*`) | 190 (8.6%) | Dark mode, fonts, ad/redirect removal |
| `eval` / `new Function` | 135 (6.1%) | Parsing config, page-context injection of the script's own code |
| Reads `document.cookie` | 116 (5.3%) | CSRF tokens sent as a header to the **same** site's API |
| `@connect *` | 73 (3.3%) | Download helpers that follow redirects to arbitrary CDNs |
| Hard-coded crypto address | 12 (0.5%) | Donation links |
| `_0x…` names in strings | 1 ad blocker | Lists of *ad scripts'* obfuscated globals to delete |

The rules that fixed each class:

- A harvested value must flow into the arguments of a send call that names a literal third-party
  URL. A CSRF header to `/api/like` doesn't count.
- Fetched text must reach `eval` or an inline `<script>`.
- Hash-checked loaders and loaders with a computed URL (often the page's own script, re-injected
  with modifications) score MEDIUM.
- Building an `"eval(atob('" + btoa(ownCode) + "'))"` string from the script's own visible code is INFO.
- Only unquoted `_0x` identifiers count toward obfuscation.

## The real, common weakness: the supply chain in the metadata block

Malice was absent, but the supply chain is shaky:

- **29.1%** of the top 1,500 scripts `@require` remote code. Only **3.0%** of those pin every
  `@require` with an SRI hash (`#sha256=…`); the rest trust whatever the host serves at update time.
- **126 of all 2,198 scripts (5.7%)** load `@require` code over **plain `http://`**, mostly old jQuery URLs. On
  hostile Wi-Fi, anyone on the network path can inject code into every page those scripts match.
- **34 of 2,198 (1.5%)** `@require` from bootcdn / bootcss / staticfile, hosts reported in 2024
  to share an operator with **polyfill.io** (which was taken over and served malware). No `@require`
  pointed at polyfill.io itself.
- **13 scripts** inject a `<script src>` from a self-hosted or retired host (for example rawgit, which
  served straight from mutable GitHub branches).
- **Only 21 of 2,198 (1.0%)** combine all three of "runs on every site", `GM_xmlhttpRequest` and
  `@connect *`, the configuration with the most reach. 61 have the first two.

## Takeaways

1. **Read the metadata block first.** `@match`, `@grant`, `@connect` and `@require` tell you what a
   script *can* do before you read a line of code.
2. **Prefer scripts whose `@require` URLs are versioned on a major CDN with an SRI hash.** Treat
   `http://` `@require` URLs as a bug to report.
3. **A remote-code loader voids the review.** If a script fetches its real code at runtime, you are
   trusting that server, not the store.
4. **Score combinations, not capabilities.** Cookies, `eval`, key listeners and clipboard writes are
   everywhere in legitimate scripts. The attack is the cookie in the request body to someone else's host.

---

Run it yourself: `python userscript_audit.py --greasyfork <id>`.

*Findings are pattern matches warranting human review, not verdicts. No script is named or accused
here. Report suspected malicious scripts to Greasy Fork through the script's "Report" link.*
