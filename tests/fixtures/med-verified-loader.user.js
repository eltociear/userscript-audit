// ==UserScript==
// @name         med verified loader
// @namespace    canary.invalid
// @version      1.0
// @match        https://judge.example.org/*
// @grant        GM_xmlhttpRequest
// ==/UserScript==
async function load(url, expectedHash) {
  const scriptContent = await (await fetch(url)).text();
  const actualHash = await calculateHash(scriptContent);
  if (actualHash !== expectedHash) throw new Error("SHA-512 hash mismatch");
  const scriptElement = document.createElement("script");
  scriptElement.textContent = scriptContent;
  document.head.prepend(scriptElement);
}
