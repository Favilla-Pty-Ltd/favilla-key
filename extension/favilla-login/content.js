// content.js - finds a login form on the page (Vault phase 5, 4 Nov 2026).
// Top frame only. When a visible password box (or a username box marked for
// sign-in) appears, it asks the KEY once per page (if automatic asks are on),
// puts the cursor in the username box when the KEY takes the ask, and adds a
// small Favilla button inside the box for asking by hand. It never reads a
// password box and never sends the site: the extension takes that from the
// browser's record of the tab.
(function(){
  'use strict';
  if(window.top !== window) return;
  // 0.5.5: after the extension is reloaded or updated, the service worker puts
  // this script into tabs that were already open. A copy left from the old
  // version can no longer reach the extension: it is stopped and replaced.
  var prev = window.__favillaContent;
  if(prev && typeof prev.alive === 'function' && prev.alive()) return;
  if(prev && typeof prev.stop === 'function'){ try { prev.stop(); } catch(e){} }
  if(prev === true){   // a 0.5.4 or older copy: take its button off the page
    try { Array.prototype.forEach.call(document.querySelectorAll('body > div[style*="2147483646"]:not([data-favilla])'), function(d){ d.remove(); }); } catch(e){}
  }
  // 0.5.22: a button left on the page by an older copy (a reloaded extension's
  // old script cannot always be reached to stop it) is taken off; the page's
  // DOM is shared, the old copy's variables are not.
  try { Array.prototype.forEach.call(document.querySelectorAll('div[data-favilla]'), function(d){ d.remove(); }); } catch(e){}
  var mo = null, iv = 0;
  window.__favillaContent = {
    alive: function(){ try { return !!(chrome.runtime && chrome.runtime.id); } catch(e){ return false; } },
    stop: function(){ try { if(mo) mo.disconnect(); clearInterval(iv); clearTimeout(timer); disarm(); if(btnHost) btnHost.remove(); } catch(e){} }
  };

  var retries = {};   // 0.5.5: an automatic ask the KEY could not take yet is tried again, at most 3 times per page
  var asked = '', btnHost = null, shadow = null, btnField = null, lastExplicit = false;

  function visible(el){
    if(!el || el.disabled || el.readOnly) return false;
    var r = el.getBoundingClientRect(); if(r.width < 8 || r.height < 8) return false;
    var cs = getComputedStyle(el); return cs.visibility !== 'hidden' && cs.display !== 'none' && cs.opacity !== '0';
  }
  function textBox(el){ var t = (el.type || 'text').toLowerCase(); return el.tagName === 'INPUT' && (t === 'text' || t === 'email' || t === 'tel'); }
  // 0.5.6: a password box shown as text by the site's eye button is still a password box
  function pwLike(el){ var tag = ((el.getAttribute('autocomplete') || '') + ' ' + (el.name || '') + ' ' + (el.id || '')).toLowerCase(); return /pass|pwd|secret|otp|one-time-code/.test(tag); }
  function signInPage(){
    var t = document.title || '';
    Array.prototype.forEach.call(document.querySelectorAll('h1, h2, h3, p, button, [role="button"], input[type="submit" i], label'), function(e, k){ if(k < 80) t += ' | ' + (e.textContent || e.value || '').slice(0, 80); });
    return /\b(sign|log)\s?-?in\b|\bsign\s?on\b/i.test(t) && !/(reset|change|new|create)\s+(your\s+)?password/i.test(t);
  }
  function loneIdBox(){
    var boxes = Array.prototype.filter.call(document.querySelectorAll('input'), function(e){ return textBox(e) && visible(e) && !pwLike(e) && !/search/i.test((e.type || '') + ' ' + (e.getAttribute('role') || '') + ' ' + (e.name || '') + ' ' + (e.id || '')); });
    if(boxes.length !== 1) return null;
    var b = boxes[0], tag = ((b.type || '') + ' ' + (b.getAttribute('autocomplete') || '') + ' ' + (b.name || '') + ' ' + (b.id || '') + ' ' + (b.getAttribute('placeholder') || '') + ' ' + (b.getAttribute('aria-label') || '') + ' ' + labelText(b)).toLowerCase();
    if(b.closest && b.closest('header, nav, [role="search"], [role="banner"], [role="navigation"]')) return null;   // 0.5.22: a site's search bar
    if(!/e-?mail|user\s?(name|id)|\bid\b|login|phone/.test(tag)) return null;   // 0.5.22: not "account" (a heading above any box can say it)
    return signInPage() ? b : null;
  }
  // the login form's username box and password box, or null
  function findLogin(){
    var pw = Array.prototype.filter.call(document.querySelectorAll('input[type="password" i]'), visible)[0] || null;
    var root = (pw && pw.form) || document;
    var sel = 'input[autocomplete~="username" i], input[autocomplete~="email" i], input[type="email" i], input[name*="user" i], input[id*="user" i], input[name*="email" i], input[id*="email" i], input[name*="login" i], input[id*="login" i]';
    var user = Array.prototype.filter.call(root.querySelectorAll(sel), function(e){ return textBox(e) && visible(e) && !pwLike(e); })[0] || null;
    if(!user && pw){   // the text box just before the password box
      var all = Array.prototype.filter.call(root.querySelectorAll('input'), function(e){ return visible(e) && (textBox(e) || e === pw); });
      var i = all.indexOf(pw); if(i > 0 && textBox(all[i - 1]) && !pwLike(all[i - 1])) user = all[i - 1];
    }
    if(!pw && !(user && /username|email/i.test(user.getAttribute('autocomplete') || ''))){
      // 0.5.21: the first page of a two-page sign-in that does not mark its box
      // (Samsung: one "Email address" box, then the password on the next page).
      // One visible text or email box whose label says email, user or ID, on a
      // page that says sign in or log in.
      var u1 = loneIdBox();
      if(!u1) return null;   // a lone text box is not a login form
      user = u1;
    }
    return { user: user, pw: pw };
  }

  // 11z: the site's second step: a one-time code box, shown without a password box.
  // autocomplete="one-time-code" is the sure sign; otherwise a short numeric box
  // whose name, id, label or placeholder says code, otp, 2fa, verification or
  // authenticator. Six single-digit boxes count as one (the first).
  function codeLike(el){
    var t = (el.type || 'text').toLowerCase();
    if(el.tagName !== 'INPUT' || !(t === 'text' || t === 'tel' || t === 'number')) return false;
    if(/one-time-code/i.test(el.getAttribute('autocomplete') || '')) return true;
    var tag = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('autocomplete') || '')).toLowerCase();
    if(/pass|pwd|user|email|phone|search|zip|post|card|cvv|expir/.test(tag)) return false;
    var ml = parseInt(el.getAttribute('maxlength') || '0', 10), numeric = /numeric|decimal/i.test(el.getAttribute('inputmode') || '') || t === 'tel' || t === 'number' || /\d/.test(el.getAttribute('pattern') || '');
    if(/\b(otp|totp|2fa|mfa|one.?time|verification|verify|authenticat|security.?code|two.?(step|factor))\b|\bcode\b/.test(tag)) return true;
    return numeric && ml >= 1 && ml <= 8;
  }
  // the words around a box: its label, aria-labelledby, or the nearest heading or label above it
  function labelText(el){
    var t = '';
    try {
      if(el.labels && el.labels.length) t += ' ' + Array.prototype.map.call(el.labels, function(l){ return l.textContent; }).join(' ');
      var by = el.getAttribute('aria-labelledby'); if(by) by.split(/\s+/).forEach(function(id){ var n = document.getElementById(id); if(n) t += ' ' + n.textContent; });
      var p = el.parentElement, hops = 0;
      while(p && hops++ < 4 && t.replace(/\s/g, '').length < 3){ var l = p.querySelector('label, legend, h1, h2, h3, h4, p'); if(l) t += ' ' + l.textContent; p = p.parentElement; }
    } catch(e){}
    return t.toLowerCase();
  }
  function groupOfSingles(inputs){   // 4 to 8 one-character boxes: the first is the code box
    var g = inputs.filter(function(e){ return parseInt(e.getAttribute('maxlength') || '0', 10) === 1; });
    return (g.length >= 4 && g.length <= 8) ? g[0] : null;
  }
  function findCode(){
    if(Array.prototype.filter.call(document.querySelectorAll('input[type="password" i]'), visible).length) return null;   // still the login form
    var all = Array.prototype.filter.call(document.querySelectorAll('input'), function(e){ var t = (e.type || 'text').toLowerCase(); return visible(e) && (t === 'text' || t === 'tel' || t === 'number'); });
    if(!all.length) return null;
    var c = all.filter(codeLike);
    var pick = null, why = '';
    if(c.some(function(e){ return /one-time-code/i.test(e.getAttribute('autocomplete') || ''); })){ pick = c.filter(function(e){ return /one-time-code/i.test(e.getAttribute('autocomplete') || ''); })[0]; why = 'one-time-code'; }
    else if(groupOfSingles(all)){ pick = groupOfSingles(all); why = 'single-digit boxes'; }
    else if(c.length === 1){ pick = c[0]; why = 'named like a code'; }
    else if(all.length === 1 && /\b(code|otp|2fa|mfa|authenticat|verif|two.?(step|factor))/.test(labelText(all[0]))){ pick = all[0]; why = 'label says code'; }
    if(!pick){ dbg('no code box: ' + all.length + ' text box(es), ' + c.length + ' code-like; labels: ' + all.slice(0, 3).map(function(e){ return JSON.stringify((e.name || e.id || e.getAttribute('placeholder') || '?') + ' / ' + labelText(e).trim().slice(0, 40)); }).join(', ')); return null; }
    dbg('code box found (' + why + '): ' + (pick.name || pick.id || pick.getAttribute('autocomplete') || '?'));
    return pick;
  }
  var dbgLast = '';
  function dbg(t){ if(t === dbgLast) return; dbgLast = t; try { console.debug('[Favilla] ' + t); } catch(e){} }
  var codeAsked = '';
  function askCode(box, explicitAsk){
    lastExplicit = explicitAsk;
    try {
      chrome.runtime.sendMessage({ type: 'favilla-code', explicitAsk: explicitAsk, submit: true }, function(r){
        if(chrome.runtime.lastError || !r){ dbg('code ask: no answer from the extension' + (chrome.runtime.lastError ? ' (' + chrome.runtime.lastError.message + ')' : '')); return; }
        dbg('code ask: ' + (r.ok ? 'on the KEY' : 'not sent: ' + (r.why || ('status ' + r.status))));
        if(r.ok){ try { box.focus(); box.select(); } catch(e){} if(explicitAsk) chip('Check the KEY'); }
        else if(explicitAsk) chip(r.why === 'unpaired' ? 'Pair the KEY first (extension Options)' : r.why === 'nokey' ? 'KEY not connected' :
                                  r.status === 4 ? 'KEY not in VAULT mode' : r.status === 5 ? 'Enter the PIN on the KEY' : r.status === 6 ? 'The KEY is busy' : r.status === 3 ? 'No code for this site on the KEY' : 'The KEY could not take it');
      });
    } catch(e){}
  }
  function focusField(f){
    var t = f.user || f.pw; if(!t) return;
    var a = document.activeElement;
    if(a && a !== document.body && a !== f.user && a !== f.pw && a.tagName !== 'HTML') return;   // the person is typing elsewhere: leave the cursor alone
    try { t.focus({ preventScroll: false }); } catch(e){ t.focus(); }
    // 0.5.1 (Josh's bench: the site had filled the email itself, and the KEY's
    // typing was added after it): select what is already in the box, so what
    // the KEY types replaces it. The password box is selected by the Tab.
    // 0.5.4 (bench, GitHub): Chrome's own password manager fills the box on load
    // but hides the value from scripts until the first real keystroke, so
    // t.value read empty and nothing was selected. Select whatever is there.
    try { t.select(); } catch(e){}
  }
  // 0.5.2 (Josh: prefilled usernames must be overridden by default). While an
  // ask is with the KEY, the first keystroke into the username box (the KEY's
  // typing, even if the person clicked in the box first) selects what the site
  // put there, so it is replaced, not added to. Off again after that keystroke,
  // when the KEY reports back, or after 90 seconds.
  var armed = null, armT = 0;
  function arm(f){
    disarm(); if(!f.user) return;
    armed = f.user; armed.addEventListener('keydown', onArmedKey, true);
    armT = setTimeout(disarm, 90000);
  }
  function disarm(){ if(armed) armed.removeEventListener('keydown', onArmedKey, true); armed = null; clearTimeout(armT); }
  function onArmedKey(e){
    if(e.ctrlKey || e.metaKey || e.altKey || e.key.length !== 1) return;   // a printable character only
    var t = e.target; disarm();
    try { t.select(); } catch(x){}   // 0.5.4: always (a value Chrome autofilled reads empty here)
  }
  // 11az: a sign-up or change-password page. The boxes in order: the first (a
  // username box on a sign-up page, the current password on a change page), the
  // new password, the confirm box. Tab order decides whether the KEY can Tab from
  // one to the next, or must ask the person to click (an eye button between two
  // boxes takes a Tab). Never reads a password box: only its attributes and place.
  var FORM = { KNOWN: 0x80, CONFIRM: 0x01, CURRENT: 0x02, USER: 0x04, SPLIT1: 0x08, SPLIT2: 0x10 };
  function hintOf(el){ return ((el.getAttribute('autocomplete') || '') + ' ' + (el.name || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + labelText(el)).toLowerCase(); }
  // names like password_confirmation and newPassword: a word may sit against _ or a capital
  function isCurrentPw(el){ var ac = (el.getAttribute('autocomplete') || '').toLowerCase(); if(/new-password/.test(ac)) return false; return /current-password/.test(ac) || /(^|[^a-z])(current|old|existing)([^a-z]|$)|currentpass|oldpass/.test(hintOf(el)); }
  function isNewPw(el){ var ac = (el.getAttribute('autocomplete') || '').toLowerCase(); if(/new-password/.test(ac)) return true; if(/current-password/.test(ac)) return false;
    return /(^|[^a-z])new|newpass|confirm|repeat|again|verify|retype|re-?enter|password2|passwd2|pass2|pwd2/.test(hintOf(el)); }
  function tabbable(root){
    return Array.prototype.filter.call(root.querySelectorAll('input, select, textarea, button, a[href], [tabindex]'), function(e){
      if(e.tabIndex < 0 || e.disabled) return false; if(e.tagName === 'INPUT' && /^hidden$/i.test(e.type || '')) return false;
      var r = e.getBoundingClientRect(); if(r.width < 1 || r.height < 1) return false;
      var cs = getComputedStyle(e); return cs.visibility !== 'hidden' && cs.display !== 'none';
    });
  }
  // 0.5.19 (25 Nov 2026): a reset or change page says so in its heading, title or
  // submit button ("Reset Password", "Change your password", "Set a new password").
  function newPwPage(){
    var t = document.title || '';
    Array.prototype.forEach.call(document.querySelectorAll('h1, h2, h3, legend, button[type="submit" i], input[type="submit" i]'), function(e){ if(visible(e) || /^H/.test(e.tagName)) t += ' | ' + (e.textContent || e.value || ''); });
    return /(reset|change|update|new|set|choose|create)\s+(your\s+|a\s+)?(new\s+)?password/i.test(t);
  }
  function isConfirmPw(el){ return /confirm|repeat|again|verify|retype|re-?enter|password2|passwd2|pass2|pwd2/.test(hintOf(el)); }
  function nextTab(order, el){ var i = order.indexOf(el); return i >= 0 ? order[i + 1] || null : null; }
  function findForm(){
    var pws = Array.prototype.filter.call(document.querySelectorAll('input[type="password" i]'), visible);
    if(!pws.length) return null;
    var pageNew = newPwPage();
    if(pws.length === 1 && !/new-password/i.test(pws[0].getAttribute('autocomplete') || '') && !pageNew) return null;   // one box: a sign-in unless the site or the page says new
    var cur = pws.filter(isCurrentPw), nw = pws.filter(function(e){ return !isCurrentPw(e) && isNewPw(e); });
    // 0.5.19: "Password" then "Confirm new password": only the confirm box reads as new, but both are
    if(pws.length === 2 && !cur.length && nw.length === 1 && (nw[0] === pws[1] ? isConfirmPw(pws[1]) : true)) nw = pws.slice();
    if(pws.length === 1 && !cur.length && !nw.length && pageNew) nw = pws.slice();
    if(pws.length >= 3 && !cur.length && nw.length < 3){ cur = [pws[0]]; nw = pws.slice(1); }   // three boxes: current, new, confirm
    if(pws.length === 2 && !cur.length && !nw.length) nw = pws.slice();                        // two plain boxes: new and confirm
    if(!nw.length) return null;                                                                   // a sign-in form
    var change = cur.length > 0, first = nw[0], conf = nw[1] || null;
    var order = tabbable(document), bits = FORM.KNOWN, lead = null;
    if(change){ bits |= FORM.CURRENT; lead = cur[0]; }
    else {
      var l = findLogin(); var u = l && l.user;
      if(u && (u.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING)){ bits |= FORM.USER; lead = u; }
    }
    if(lead && nextTab(order, lead) !== first) bits |= FORM.SPLIT1;
    if(conf){ bits |= FORM.CONFIRM; if(nextTab(order, first) !== conf) bits |= FORM.SPLIT2; }
    return { change: change, bits: bits, lead: lead, pw: first };
  }
  // the username a change page carries for password managers (often a hidden box)
  function pageUser(){
    var u = document.querySelector('input[autocomplete~="username" i]');
    var v = u && u.value ? u.value.trim() : '';
    return (v.length <= 100 && !/[^\x20-\x7E]/.test(v)) ? v : '';
  }
  var newAsked = '';
  function askNew(f){
    var u = f.change ? pageUser() : (f.lead && f.lead.value ? f.lead.value.trim() : '');
    lastExplicit = true;
    dbg((f.change ? 'change-password' : 'sign-up') + ' form found (form byte 0x' + f.bits.toString(16) + '); asking the KEY');
    try {
      chrome.runtime.sendMessage({ type: 'favilla-new', user: u, form: f.bits }, function(r){
        if(chrome.runtime.lastError || !r){ dbg('new-login ask: no answer from the extension'); return; }
        dbg('new-login ask: ' + (r.ok ? 'on the KEY' : 'not sent: ' + (r.why || ('status ' + r.status))));
        if(r.ok){ var t = f.lead || f.pw; try { t.focus(); t.select(); } catch(e){} chip(f.change ? 'Change it on the KEY' : f.lead ? 'Make it on the KEY' : 'Set it on the KEY'); }
        else chip(r.why === 'unpaired' ? 'Pair the KEY first (extension Options)' : r.why === 'nokey' ? 'KEY not connected' :
                  r.status === 4 ? 'KEY not in VAULT mode' : r.status === 5 ? 'Enter the PIN on the KEY' : r.status === 6 ? 'The KEY is busy' : 'The KEY could not take it');
      });
    } catch(e){}
  }

  // 11aw: what the page shows, for the KEY to type the right half of a two-page
  // sign-in: 1 = a username box and no password box, 2 = a password box and no
  // username box, 0 = both.
  function shapeOf(f){ return f.pw ? (f.user ? 0 : 2) : 1; }
  function ask(f, explicitAsk){
    var u = f.user && f.user.value ? f.user.value.trim() : '';
    var fields = shapeOf(f);
    lastExplicit = explicitAsk;
    dbg('login form found: ' + (f.user ? 'username box' : 'no username box') + ', ' + (f.pw ? 'password box' : 'no password box') + '; asking the KEY' + (explicitAsk ? ' (button)' : ''));
    try {
      chrome.runtime.sendMessage({ type: 'favilla-ask', explicitAsk: explicitAsk, user: u, fields: fields }, function(r){
        if(chrome.runtime.lastError || !r){ dbg('sign-in ask: no answer from the extension' + (chrome.runtime.lastError ? ' (' + chrome.runtime.lastError.message + ')' : '')); return; }
        dbg('sign-in ask: ' + (r.ok ? 'on the KEY' : 'not sent: ' + (r.why || ('status ' + r.status))));
        if(r.ok){ focusField(f); arm(f); if(explicitAsk) chip('Check the KEY'); }
        else if(!explicitAsk && (r.status === 6 || r.why === 'nokey' || r.why === 'error')){
          var h = location.href, n = retries[h] || 0;
          if(n < 3){ retries[h] = n + 1; setTimeout(function(){ if(asked === h) asked = ''; soon(); }, 3000); }
        }
        else if(explicitAsk) chip(r.why === 'unpaired' ? 'Pair the KEY first (extension Options)' : r.why === 'nokey' ? 'KEY not connected' :
                                  r.status === 4 ? 'KEY not in VAULT mode' : r.status === 5 ? 'Enter the PIN on the KEY' : r.status === 6 ? 'The KEY is busy' : 'The KEY could not take it');
      });
    } catch(e){}
  }

  // ---- the small button inside the username (or password) box ----------------
  function chip(text){
    if(!shadow) return;
    var c = shadow.querySelector('.chip'); c.textContent = text; c.hidden = false;
    clearTimeout(chip.t); chip.t = setTimeout(function(){ c.hidden = true; }, 3500);
  }
  function placeButton(){
    if(!btnHost || !btnField || !btnField.isConnected || !visible(btnField)){ if(btnHost) btnHost.style.display = 'none'; return; }
    var r = btnField.getBoundingClientRect(), s = Math.min(22, Math.max(16, r.height - 10));
    // 0.5.20: the button sits inside the field's dialog (a side drawer closes on a
    // click outside it), so it is placed against its own offset parent.
    var home = hostHome(btnField); if(btnHost.parentNode !== home) home.appendChild(btnHost);
    btnHost.style.display = 'block';
    var op = btnHost.offsetParent, ox = window.scrollX, oy = window.scrollY;
    if(op && op !== document.body && op !== document.documentElement){ var q = op.getBoundingClientRect(); ox = op.scrollLeft - q.left - op.clientLeft; oy = op.scrollTop - q.top - op.clientTop; }
    btnHost.style.left = (ox + r.right - s - 8) + 'px';
    btnHost.style.top = (oy + r.top + (r.height - s) / 2) + 'px';
    btnHost.style.width = btnHost.style.height = s + 'px';
  }
  function hostHome(field){
    var d = field && field.closest && field.closest('dialog, [role="dialog"], [role="alertdialog"], [aria-modal="true"]');
    if(!d) for(var a = field && field.parentElement; a && a !== document.body; a = a.parentElement){ if(getComputedStyle(a).position === 'fixed'){ d = a; break; } }   // a drawer or modal without the attributes
    return d || document.body || document.documentElement;
  }
  var downForm = null;   // 0.5.20: what the page was when the button was pressed (a drawer may close before the click lands)
  function addButton(f){
    var field = f.user || f.pw || f.code; if(!field || field === btnField) return;
    btnField = field;
    if(!btnHost){
      btnHost = document.createElement('div');
      btnHost.setAttribute('data-favilla', '1');
      btnHost.style.cssText = 'position:absolute;z-index:2147483646;display:none;';
      var sh = shadow = btnHost.attachShadow({ mode: 'closed' });
      sh.innerHTML = '<style>button{all:initial;cursor:pointer;display:block;width:100%;height:100%;border-radius:4px;background:#000;box-shadow:0 0 0 1px #5C4A2C}button:hover{box-shadow:0 0 0 1px #C9A45C}svg{display:block;width:100%;height:100%}' +
        '.chip{position:absolute;right:0;top:calc(100% + 6px);white-space:nowrap;font:600 11px/1.3 system-ui,sans-serif;color:#F4F2EE;background:#0d0d0d;border:1px solid #5C4A2C;border-radius:4px;padding:5px 8px}</style>' +
        '<button title="Favilla KEY: sign in, make a password, or type the code" aria-label="Favilla KEY: sign in, make a password, or type the code"><svg viewBox="0 0 100 100" shape-rendering="crispEdges"><path d="M43 7h14v14H43zM43 79h14v14H43zM7 43h14v14H7zM79 43h14v14H79z" fill="#5C4A2C"/><path d="M25 25h14v14H25zM61 25h14v14H61zM25 61h14v14H25zM61 61h14v14H61z" fill="#7A6238"/><path d="M43 25h14v14H43zM43 61h14v14H43zM25 43h14v14H25zM61 43h14v14H61z" fill="#C9A45C"/><path d="M43 43h14v14H43z" fill="#F4F2EE"/></svg></button><div class="chip" hidden></div>';
      sh.querySelector('button').addEventListener('mousedown', function(e){ e.preventDefault(); });   // keep the field's focus
      // 0.5.20: the page never sees a press on the button (an outside-click handler would close its drawer)
      ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'touchstart', 'touchend', 'click'].forEach(function(t){ btnHost.addEventListener(t, function(e){ if(t === 'pointerdown' || t === 'mousedown' || t === 'touchstart'){ downForm = findForm(); } e.stopPropagation(); }); });
      sh.querySelector('button').addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); var nf = findForm() || downForm; downForm = null; if(nf){ askNew(nf); return; } var g = findLogin(); if(g) ask(g, true); else { var c = findCode(); if(c) askCode(c, true); } });
      hostHome(field).appendChild(btnHost);
      window.addEventListener('scroll', placeButton, { passive: true }); window.addEventListener('resize', placeButton);
    }
    placeButton();
  }

  chrome.runtime.onMessage.addListener(function(m){
    if(!m || m.type !== 'favilla-result') return;
    disarm();
    var t = { 1: 'Typed', 2: 'Nothing typed', 3: 'Nothing saved for this site on the KEY', 13: 'Saved on the KEY' }[m.status];
    if(t && (m.status !== 3 || lastExplicit)) chip(t);   // an automatic ask with nothing saved stays silent
  });

  function scan(){
    var nf = findForm();   // 11az: a sign-up or change page: the button makes or changes a password; no automatic sign-in ask
    if(nf){ addButton({ user: nf.change ? null : nf.lead, pw: nf.change ? (nf.lead || nf.pw) : nf.pw }); if(newAsked !== location.href) { newAsked = location.href; dbg((nf.change ? 'change-password' : 'sign-up') + ' page: the Favilla button asks the KEY'); } return; }
    var f = findLogin();
    if(f && asked === location.href + '#' + shapeOf(f)) dbg('login form on the page; already asked for this address');
    if(!f){   // 11z: the second step
      var c = findCode(); if(!c) return;
      dbg('asking for the code' + (codeAsked === location.href + '#' + (c.name || c.id) ? ' (already asked on this page)' : ''));
      addButton({ code: c });
      if(codeAsked === location.href + '#' + (c.name || c.id) || document.visibilityState !== 'visible') return;
      codeAsked = location.href + '#' + (c.name || c.id);
      askCode(c, false);
      return;
    }
    addButton(f);
    var key = location.href + '#' + shapeOf(f);   // 11aw: a page that turns from a username box into a password box is a new ask
    if(asked === key || document.visibilityState !== 'visible') return;
    asked = key;   // once per page (and per address and shape, for single-page apps)
    ask(f, false);
  }
  var timer = 0;
  function soon(){ clearTimeout(timer); timer = setTimeout(scan, 400); }
  mo = new MutationObserver(soon); mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'style', 'class', 'hidden'] });
  // 0.5.3 (Josh's bench: GitHub stayed on the KEY after he moved to Cloudflare):
  // leaving a tab lets it ask again when it comes back (only while a login
  // form is still on the page). The KEY lets the newer ask replace the old one.
  document.addEventListener('visibilitychange', function(){
    if(!window.__favillaContent || !window.__favillaContent.alive()) return;
    if(document.visibilityState === 'hidden'){ asked = ''; codeAsked = ''; disarm(); }
    soon();
  });
  iv = setInterval(placeButton, 1000);
  soon();
})();
