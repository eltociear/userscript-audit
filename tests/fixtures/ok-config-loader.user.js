// ==UserScript==
// @name         ok config loader
// @namespace    canary.invalid
// @version      1.0
// @match        https://forum.example.org/*
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @connect      forum.example.org
// ==/UserScript==
const raw = GM_getValue("rules", "[]");
const rules = eval("(" + raw + ")");
GM_xmlhttpRequest({url: "https://forum.example.org/api/me", onload: r => { const me = JSON.parse(r.responseText); console.log(me.name, rules.length); }});
