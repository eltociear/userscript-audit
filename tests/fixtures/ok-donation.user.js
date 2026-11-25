// ==UserScript==
// @name         ok donation
// @namespace    canary.invalid
// @version      1.0
// @match        https://github.com/*
// @grant        GM_setClipboard
// ==/UserScript==
// Donate BTC: 1CanaryNotAReaddressxxxxxxxx
const btn = document.createElement("button"); btn.textContent = "Copy donation address";
btn.onclick = () => GM_setClipboard("1CanaryNotAReaddressxxxxxxxx");
document.body.appendChild(btn);
