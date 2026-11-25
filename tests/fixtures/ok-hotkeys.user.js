// ==UserScript==
// @name         ok hotkeys
// @namespace    canary.invalid
// @version      1.0
// @match        https://www.youtube.com/*
// ==/UserScript==
document.addEventListener("keydown", e => { if (e.key === "s" && e.altKey) document.querySelector("video").playbackRate = 2; });
