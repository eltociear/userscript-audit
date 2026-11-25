// ==UserScript==
// @name         ok csrf header
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      api.example-tracker.org
// ==/UserScript==
const csrf = document.cookie.match(/XSRF-TOKEN=([^;]+);?/)?.[1];
fetch("/api/like", {method: "POST", headers: {"X-XSRF-TOKEN": decodeURIComponent(csrf)}, body: "{}"});
GM_xmlhttpRequest({url: "https://api.example-tracker.org/v1/status", onload: r => console.log(r.status)});
