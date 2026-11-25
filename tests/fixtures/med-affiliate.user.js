// ==UserScript==
// @name         med affiliate
// @namespace    canary.invalid
// @version      1.0
// @match        https://www.amazon.com/*
// ==/UserScript==
document.querySelectorAll('a[href*="/dp/"]').forEach(a => { a.href = a.href.split("?")[0] + "?tag=canaryshop-20"; });
