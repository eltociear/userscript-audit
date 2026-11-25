// ==UserScript==
// @name         ok own code injector
// @namespace    canary.invalid
// @version      1.0
// @match        https://app.example.org/*
// ==/UserScript==
function main() { console.log("runs in page context"); }
const srcTxt = "(" + main.toString() + ")();";
const s = document.createElement("script");
s.textContent = "eval(atob('" + btoa(srcTxt) + "'))";
document.head.appendChild(s);
