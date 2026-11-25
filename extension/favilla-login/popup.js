// Favilla KEY Login QR (Vault phase 5, P5-2 C / P5-3 A, 4 Nov 2026).
// Click the toolbar button: the popup shows favilla:login?v=1&s=<site>&u=<user>
// for the page you are on. The site is the tab's host name; the username is
// read from the page's username or email box, once, when you click. Password
// fields are never read. Nothing is stored or sent; permissions are activeTab
// and scripting only, so the extension sees a page only when you click it.
(function(){
  'use strict';
  var api = (typeof browser !== 'undefined' && browser.tabs) ? browser : chrome;
  var site = document.getElementById('site'), user = document.getElementById('user');
  var cv = document.getElementById('qr'), empty = document.getElementById('empty');
  var BAD = /[^\x20-\x7E]/;
  var SITE_OK = 'The name the KEY saves it under.', USER_OK = 'Read from this page. Change it if it is wrong.', USER_NONE = 'None found on this page. Type it, or leave it empty.';
  var userHintOk = USER_NONE;

  // Runs inside the page (injected on click). Returns the first username or
  // email box with something in it. Never touches a password field.
  function findUsername(){
    function ok(el){
      if(!el || el.tagName !== 'INPUT') return false;
      var t = (el.type || 'text').toLowerCase();
      if(t !== 'text' && t !== 'email' && t !== 'tel' && t !== '') return false;
      if(el.disabled) return false;
      // 0.5.6 (bench: a password showed as the username): a password box the
      // site's eye button turned into text is still a password box. Its name,
      // id or autocomplete gives it away; never read it.
      var tag = ((el.getAttribute('autocomplete') || '') + ' ' + (el.name || '') + ' ' + (el.id || '')).toLowerCase();
      if(/pass|pwd|secret|otp|one-time-code/.test(tag)) return false;
      var r = el.getBoundingClientRect(); if(r.width < 2 || r.height < 2) return false;
      return !!(el.value && el.value.trim());
    }
    var sels = ['input[autocomplete~="username" i]', 'input[autocomplete~="email" i]', 'input[type="email" i]',
                'input[name*="user" i]', 'input[id*="user" i]', 'input[name*="email" i]', 'input[id*="email" i]',
                'input[name*="login" i]', 'input[id*="login" i]', 'input[name*="account" i]'];
    for(var i = 0; i < sels.length; i++){
      var list = document.querySelectorAll(sels[i]);
      for(var j = 0; j < list.length; j++) if(ok(list[j])) return list[j].value.trim().slice(0, 200);
    }
    var a = document.activeElement;   // 0.5.6: the focused box only when nothing is marked as a username
    if(ok(a)) return a.value.trim().slice(0, 200);
    return '';
  }

  function hostFor(url){
    try { var u = new URL(url); if(u.protocol !== 'https:' && u.protocol !== 'http:') return ''; return u.hostname.replace(/^www\./i, ''); }
    catch(e){ return ''; }
  }

  function check(el, hintId, countId, okText, required){
    var v = el.value, h = document.getElementById(hintId);
    document.getElementById(countId).textContent = v.length + ' / 100';
    var bad = BAD.test(v) ? 'Only plain US keyboard characters: the KEY could not type this.' : (v.length > 100 ? 'Over 100 characters.' : '');
    if(!bad && required && v.length && !v.trim()) bad = 'Needs more than spaces.';
    el.classList.toggle('bad', !!bad); h.classList.toggle('bad', !!bad);
    h.textContent = bad || okText;
    return !bad;
  }

  function draw(text){
    var qr = window.qrcode(0, 'M'); qr.addData(text, 'Byte'); qr.make();
    var n = qr.getModuleCount(), q = 4, px = Math.max(2, Math.floor(200 / (n + 2 * q))), size = (n + 2 * q) * px;   // 4-module quiet zone
    cv.width = size; cv.height = size;
    var c = cv.getContext('2d'); c.fillStyle = '#fff'; c.fillRect(0, 0, size, size); c.fillStyle = '#000';
    for(var r = 0; r < n; r++) for(var k = 0; k < n; k++) if(qr.isDark(r, k)) c.fillRect((k + q) * px, (r + q) * px, px, px);
  }

  // 11x: the two-step setup key as the site shows it (base32, spaces and dashes
  // allowed). Returns the cleaned key, '' when the box is empty, null when bad.
  var otpKey = document.getElementById('otpkey'), otpWrap = document.getElementById('otpwrap');
  function otpCheck(){
    var raw = otpKey.value.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase(), h = document.getElementById('oh');
    document.getElementById('oc').textContent = raw.length ? raw.length + ' characters' : '';
    var bad = '';
    if(raw.length && !/^[A-Z2-7]+$/.test(raw)) bad = 'A setup key has only the letters A to Z and the digits 2 to 7.';
    else if(raw.length && (raw.length < 8 || raw.length > 103)) bad = 'That does not look like a whole setup key.';
    otpKey.classList.toggle('bad', !!bad); h.classList.toggle('bad', !!bad);
    h.textContent = bad || (raw.length ? 'The QR above is now the setup code. On the KEY: VAULT, Codes, ADD BY QR.' : 'Paste the key the site shows under "can\u2019t scan the QR?".');
    return bad ? null : raw;
  }
  // 11aa: recovery codes, one per line (or comma separated): [] when the box is empty, null when bad
  var rcBox = document.getElementById('rccodes'), rcWrap = document.getElementById('rcwrap');
  function rcCheck(){
    var codes = rcBox.value.split(/[\n,;]+/).map(function(c){ return c.replace(/\s+/g, ''); }).filter(function(c){ return c.length; });
    var h = document.getElementById('rch'), bad = '';
    document.getElementById('rcc').textContent = codes.length ? codes.length + ' code' + (codes.length === 1 ? '' : 's') : '';
    for(var i = 0; i < codes.length && !bad; i++){ if(codes[i].length > 24) bad = 'A code is over 24 characters.'; else if(/[^\x21-\x7E]/.test(codes[i])) bad = 'Codes must be plain characters.'; }
    if(!bad && codes.length > 16) bad = 'The KEY keeps up to 16 codes.';
    rcBox.classList.toggle('bad', !!bad); h.classList.toggle('bad', !!bad);
    h.textContent = bad || (codes.length ? 'The QR above now holds the codes. On the KEY: open the entry, UP, UP, ENTER TO ADD BY QR.' : 'Paste the codes the site shows when two-step is turned on.');
    return bad ? null : codes;
  }
  function update(){
    var okS = check(site, 'sh', 'sc', SITE_OK, true);
    var okU = check(user, 'uh', 'uc', user.value ? USER_OK : userHintOk, false);
    var s = site.value.replace(/\s+$/, ''), u = user.value.replace(/\s+$/, '');
    var key = otpWrap.open ? otpCheck() : '';
    var rc = rcWrap.open ? rcCheck() : [];
    if(okS && okU && s.trim() && rc && rc.length){
      var rq = 'favilla:recovery?v=1&s=' + encodeURIComponent(s.trim()) + (u ? '&u=' + encodeURIComponent(u) : '') + '&c=' + encodeURIComponent(rc.join(','));
      draw(rq); cv.hidden = false; empty.hidden = true; cv.title = '';
      document.getElementById('qrbox').hidden = false;
    } else if(okS && okU && s.trim() && key){
      var o = 'otpauth://totp/' + encodeURIComponent(s.trim()) + (u ? ':' + encodeURIComponent(u) : '') + '?secret=' + key + '&issuer=' + encodeURIComponent(s.trim()) +
              '&digits=' + document.getElementById('otpdigits').value + '&period=' + document.getElementById('otpperiod').value + '&algorithm=SHA1';
      draw(o); cv.hidden = false; empty.hidden = true; cv.title = '';
      document.getElementById('qrbox').hidden = false;   // shown even in paired (one-press) mode: the KEY has to scan this one
    } else if(okS && okU && s.trim() && key !== null){
      var t = 'favilla:login?v=1&s=' + encodeURIComponent(s) + (u ? '&u=' + encodeURIComponent(u) : '');
      draw(t); cv.hidden = false; empty.hidden = true; cv.title = t;
    } else {
      cv.hidden = true; empty.hidden = false;
      empty.textContent = (okS && okU) ? 'Type a site to make the code' : 'Fix the field in red';
    }
  }

  // Test hook (also used by the page itself): fill and draw.
  window.__favillaFill = function(s, u){ site.value = (s || '').slice(0, 100); user.value = (u || '').slice(0, 100); update(); if(window.__favillaSyncSite) window.__favillaSyncSite(); };
  window.__favillaFindUsername = findUsername;
  otpKey.addEventListener('input', update); otpWrap.addEventListener('toggle', update);
  document.getElementById('otpdigits').addEventListener('change', update); document.getElementById('otpperiod').addEventListener('change', update);
  rcBox.addEventListener('input', update); rcWrap.addEventListener('toggle', update);
  window.addEventListener('unload', function(){ otpKey.value = ''; rcBox.value = ''; });

  site.addEventListener('input', update); user.addEventListener('input', update);

  // ---- one-press sign-in over the paired USB channel (stage 2) ----
  var D = window.FavillaDev, Fc = window.FavillaChan;
  var kstat = document.getElementById('kstat');
  var WHY = { 4: 'The KEY is not in VAULT mode. Restart it and choose VAULT.', 5: 'Enter the VAULT PIN on the KEY first.', 6: 'The KEY is busy. Finish what is on its screen first.',
              7: 'The KEY could not use that site or username.', 8: 'Not paired with this KEY. Pair it again in Options.', 9: 'Out of step with the KEY. Pair it again in Options.' };
  var DONE = { 1: 'Typed.', 2: 'Nothing typed (BACK on the KEY).', 3: 'No saved login for this site on the KEY.', 13: 'Saved on the KEY. Type it from the KEY when ready.', 5: 'The KEY is locked.' };
  function keyMode(on){
    document.getElementById('keyact').hidden = !on;
    document.getElementById('qrbox').hidden = on;
    document.getElementById('how').hidden = on;
    document.getElementById('foot').hidden = on;
  }
  function stat(t, cls){ kstat.textContent = t; kstat.className = 'kstat' + (cls ? ' ' + cls : ''); }
  function ask(cmd){
    var s = site.value.replace(/\s+$/, ''), u = user.value.replace(/\s+$/, '');
    if(!s.trim() || BAD.test(s) || BAD.test(u) || s.length > 100 || u.length > 100){ stat('Fix the site or username first.', 'bad'); return; }
    var btns = [document.getElementById('kin'), document.getElementById('knew')]; btns.forEach(function(b){ b.disabled = true; });
    stat('Asking the KEY…');
    D.request(cmd, Fc.loginBody(s, u)).then(function(r){
      btns.forEach(function(b){ b.disabled = false; });
      if(r.status !== 0){ stat(WHY[r.status] || ('The KEY said no (' + r.status + ').'), 'bad'); return; }
      stat(cmd === Fc.C.SIGN_IN ? 'On the KEY now. Click the username box on this page, then press ENTER on the KEY.'
                                : 'On the KEY now: pick a length, then click the username box here and press ENTER on the KEY.', 'good');
    }).catch(function(e){ btns.forEach(function(b){ b.disabled = false; }); stat(e.message, 'bad'); });
  }
  D.onEvent(function(m){ D.openEvent(m).then(function(ev){ if(ev) stat(DONE[ev.status] || ('Done (' + ev.status + ').'), ev.status === 1 || ev.status === 13 ? 'good' : ''); }); });
  document.getElementById('kin').addEventListener('click', function(){ ask(Fc.C.SIGN_IN); });
  document.getElementById('knew').addEventListener('click', function(){ ask(Fc.C.NEW_LOGIN); });
  document.getElementById('showqr').addEventListener('click', function(){ keyMode(false); });
  // per-site automatic asks (Options has the global switch and the list)
  var siteBox = document.getElementById('siteauto');
  function syncSite(){
    var h = site.value.trim().toLowerCase();
    return chrome.storage.local.get(['auto', 'noAuto']).then(function(v){
      var list = Array.isArray(v.noAuto) ? v.noAuto : [];
      siteBox.checked = v.auto !== false && list.indexOf(h) < 0; siteBox.disabled = v.auto === false || !h;
      siteBox.parentNode.title = v.auto === false ? 'Automatic asks are off in Options' : '';
    });
  }
  siteBox.addEventListener('change', function(){
    var h = site.value.trim().toLowerCase(); if(!h) return;
    chrome.storage.local.get('noAuto').then(function(v){
      var list = (Array.isArray(v.noAuto) ? v.noAuto : []).filter(function(x){ return x !== h; });
      if(!siteBox.checked) list.push(h);
      return chrome.storage.local.set({ noAuto: list });
    });
  });
  site.addEventListener('input', syncSite);
  // what happened the last time this site asked (helps when the KEY stayed dark)
  function lastAsk(){
    var h = site.value.trim().toLowerCase(); if(!h || !chrome.storage.session) return;
    chrome.storage.session.get('last:' + h).then(function(v){
      var l = v['last:' + h]; if(!l || kstat.textContent.indexOf('On the KEY') === 0) return;
      var what = { 'asked': 'sent, waiting for the KEY', 1: 'typed', 2: 'nothing typed', 3: 'the KEY has no saved login with this exact address (a login saved under a name like "Cloudflare" lights up only when you press the button)',
                   4: 'the KEY was not in VAULT mode', 5: 'the KEY was locked', 6: 'the KEY was busy or in a menu', 13: 'saved' }[l.what] || ('status ' + l.what);
      stat((l.auto ? 'Last automatic ask here: ' : 'Last ask here: ') + what + '.');
    });
  }
  window.__favillaSyncSite = syncSite;
  document.getElementById('pairlink').addEventListener('click', function(e){ e.preventDefault(); if(api.runtime && api.runtime.openOptionsPage) api.runtime.openOptionsPage(); });
  if(D && D.hasHid()){
    D.getPair().then(function(p){ if(!p) return; return D.find().then(function(d){ if(d){ keyMode(true); stat('Paired. The KEY must be in VAULT mode with its PIN entered.'); syncSite(); lastAsk(); } }); }).catch(function(){});
  }

  api.tabs.query({ active: true, currentWindow: true }).then(function(tabs){
    var tab = tabs && tabs[0]; var h = tab ? hostFor(tab.url || '') : '';
    if(!h){ document.getElementById('sh').textContent = 'Open the site’s sign-up page, then click again.'; window.__favillaFill('', ''); return; }
    return api.scripting.executeScript({ target: { tabId: tab.id }, func: findUsername }).then(function(res){
      var u = (res && res[0] && typeof res[0].result === 'string') ? res[0].result : '';
      userHintOk = u ? USER_OK : USER_NONE;
      window.__favillaFill(h, u);
    }, function(){ userHintOk = 'This page cannot be read. Type the username.'; window.__favillaFill(h, ''); });
  }).catch(function(){ window.__favillaFill('', ''); });
  update();
})();
