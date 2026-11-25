// ==UserScript==
// @name         ok lib injector
// @namespace    canary.invalid
// @version      1.0
// @match        https://docs.example.org/*
// ==/UserScript==
const s = document.createElement("script");
s.src = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js";
document.head.appendChild(s);
