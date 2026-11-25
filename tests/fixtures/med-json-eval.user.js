// ==UserScript==
// @name         med json eval
// @namespace    canary.invalid
// @version      1.0
// @match        https://forum.example.org/*
// @grant        GM_xmlhttpRequest
// ==/UserScript==
GM_xmlhttpRequest({url: "https://forum.example.org/api/list", onload: function (transport) { var rslt = eval("(" + transport.responseText + ")"); console.log(rslt); }});
