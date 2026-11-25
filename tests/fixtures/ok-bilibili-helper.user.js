// ==UserScript==
// @name         ok bilibili helper
// @namespace    canary.invalid
// @version      1.0
// @match        *://*.bilibili.com/*
// @grant        GM_xmlhttpRequest
// @connect      api.bilibili.com
// @require      https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js
// ==/UserScript==
const csrf = document.cookie.match(/bili_jct=([^;]+)/)[1];
GM_xmlhttpRequest({method: "POST", url: "https://api.bilibili.com/x/web-interface/coin/add", headers: {Cookie: document.cookie},
  data: "aid=1&multiply=1&csrf=" + csrf, onload: r => { const j = JSON.parse(r.responseText); console.log(j.code); }});
