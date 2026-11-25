// ==UserScript==
// @name         ok translator
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      translate.googleapis.com
// ==/UserScript==
document.addEventListener("mouseup", () => {
  const q = window.getSelection().toString();
  if (!q) return;
  GM_xmlhttpRequest({method: "GET", url: "https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&q=" + encodeURIComponent(q),
    onload: r => { const data = JSON.parse(r.responseText); console.log(data[0][0][0]); }});
});
