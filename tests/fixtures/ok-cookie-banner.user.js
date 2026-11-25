// ==UserScript==
// @name         ok cookie banner remover
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// ==/UserScript==
document.cookie = "cookieconsent_status=dismiss; path=/; max-age=31536000";
document.querySelectorAll("#cookie-banner, .cc-window").forEach(n => n.remove());
