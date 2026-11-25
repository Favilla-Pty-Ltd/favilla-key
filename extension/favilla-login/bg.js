// bg.js - the extension's service worker (Vault phase 5, 4 Nov 2026).
// Holds the WebHID link to the paired KEY for the in-page button and the
// automatic ask. The site always comes from the browser's record of the tab
// (sender.tab.url), never from the page. Nothing here ever holds a password.
importScripts('chan.js', 'dev.js');
var F = self.FavillaChan, D = self.FavillaDev;

// 0.5.18 (bench 24 Nov: after the KEY restarted or was replugged, sign-ins did
// nothing until the extension was reloaded): this worker kept the old handle.
// Drop it when the KEY goes; dev.js finds the new one on the next ask.
if(self.navigator && navigator.hid){
  navigator.hid.addEventListener('disconnect', function(e){ D.drop(e.device); });
  navigator.hid.addEventListener('connect', function(){ D.drop(); });
}

function hostOf(url){ try { var u = new URL(url); return (u.protocol === 'https:' || u.protocol === 'http:') ? u.hostname.replace(/^www\./i, '') : ''; } catch(e){ return ''; } }
function settings(){ return chrome.storage.local.get(['auto', 'noAuto']).then(function(v){ return { auto: v.auto !== false, noAuto: Array.isArray(v.noAuto) ? v.noAuto : [] }; }); }

// event results go back to the tab that asked: counter -> tab id
var pending = {};
var cont = {};   // 11aw: host -> when the KEY typed its username page (the password page may follow)
// the last ask per site, for the popup to show (session storage: gone when the browser closes)
function note(host, auto, what){ var o = {}; o['last:' + host] = { auto: auto, what: what, at: Date.now() }; try { chrome.storage.session.set(o); } catch(e){} }
D.onEvent(function(m){
  D.openEvent(m).then(function(ev){
    if(!ev) return;
    var p = pending[ev.ctr]; delete pending[ev.ctr];
    if(p){
      if(p.fields === 1 && ev.status === 1) cont[p.host] = Date.now();   // 11aw: 1 = typed (F.STATUS)
      note(p.host, p.auto, ev.status); chrome.tabs.sendMessage(p.tab, { type: 'favilla-result', status: ev.status }).catch(function(){});
    }
  });
});

// 0.5.5 (bench: after a reload of the extension, open tabs did nothing until
// refreshed): put the page script into the tabs already open. Tabs that are
// not web pages refuse it; that is fine.
chrome.runtime.onInstalled.addListener(function(){
  chrome.tabs.query({}).then(function(tabs){
    tabs.forEach(function(t){ chrome.scripting.executeScript({ target: { tabId: t.id }, files: ['content.js'] }).catch(function(){}); });
  }).catch(function(){});
});

// 11z: the page found the site's one-time code box; the KEY types the code (Enter after it when asked)
chrome.runtime.onMessage.addListener(function(msg, sender, reply){
  if(!msg || msg.type !== 'favilla-code' || !sender.tab || sender.frameId !== 0) return;
  var host = hostOf(sender.tab.url || ''), explicitAsk = !!msg.explicitAsk;
  if(!host){ reply({ ok: false, why: 'site' }); return; }
  (async function(){
    var st = await settings();
    if(!explicitAsk && (!st.auto || st.noAuto.indexOf(host) >= 0 || !sender.tab.active)) return { ok: false, why: 'off' };
    var p = await D.getPair(); if(!p) return { ok: false, why: 'unpaired' };
    var dev = await D.find(); if(!dev) return { ok: false, why: 'nokey' };
    var flags = (explicitAsk ? 0 : 1) | (msg.submit ? 2 : 0);
    var r = await D.request(F.C.CODE_TYPE, F.codeBody(host, flags));
    if(r.status === 0 && r.ctr !== undefined) pending[r.ctr] = { tab: sender.tab.id, host: host, auto: !explicitAsk };
    return { ok: r.status === 0, status: r.status };
  })().then(reply, function(e){ reply({ ok: false, why: 'error', message: e.message }); });
  return true;
});

// 11az: a sign-up or change-password page, from the button: NEW_LOGIN with the
// form byte. A KEY older than 11az refuses the byte (status 7): asked again without it.
chrome.runtime.onMessage.addListener(function(msg, sender, reply){
  if(!msg || msg.type !== 'favilla-new' || !sender.tab || sender.frameId !== 0) return;
  var host = hostOf(sender.tab.url || ''), user = typeof msg.user === 'string' ? msg.user : '';
  var form = (typeof msg.form === 'number' && (msg.form & 0xE0) === 0x80) ? msg.form : 0;
  if(!host){ reply({ ok: false, why: 'site' }); return; }
  if(user.length > 100 || /[^\x20-\x7E]/.test(user)) user = '';
  (async function(){
    var p = await D.getPair(); if(!p) return { ok: false, why: 'unpaired' };
    var dev = await D.find(); if(!dev) return { ok: false, why: 'nokey' };
    var r = await D.request(F.C.NEW_LOGIN, F.loginBody(host, user, form));
    if(r.status === 7 && form){ r = await D.request(F.C.NEW_LOGIN, F.loginBody(host, user)); form = 0; }
    if(r.status === 0 && r.ctr !== undefined) pending[r.ctr] = { tab: sender.tab.id, host: host, auto: false, fields: 0 };
    note(host, false, r.status === 0 ? (form & 2 ? 'change asked' : 'new asked') : r.status);
    return { ok: r.status === 0, status: r.status };
  })().then(reply, function(e){ reply({ ok: false, why: 'error', message: e.message }); });
  return true;
});

chrome.runtime.onMessage.addListener(function(msg, sender, reply){
  if(!msg || msg.type !== 'favilla-ask' || !sender.tab || sender.frameId !== 0) return;   // top frame of a real tab only
  var host = hostOf(sender.tab.url || ''), explicitAsk = !!msg.explicitAsk;
  var user = typeof msg.user === 'string' ? msg.user : '';
  var fields = (msg.fields === 1 || msg.fields === 2) ? msg.fields : 0;   // 11aw
  if(!host){ reply({ ok: false, why: 'site' }); return; }
  // 11aw: the password page of a two-page sign-in whose username page the KEY
  // typed within the last 60 s is a continuation of that ask, not a new
  // automatic one: it goes to the KEY whatever the automatic setting says.
  if(!explicitAsk && fields === 2 && cont[host] && Date.now() - cont[host] < 60000) explicitAsk = true;
  if(user.length > 100 || /[^\x20-\x7E]/.test(user)) user = '';   // the KEY's text rules; anything else, ask without it
  (async function(){
    var st = await settings();
    if(!explicitAsk && (!st.auto || st.noAuto.indexOf(host) >= 0 || !sender.tab.active)) return { ok: false, why: 'off' };
    var p = await D.getPair(); if(!p) return { ok: false, why: 'unpaired' };
    var dev = await D.find(); if(!dev) return { ok: false, why: 'nokey' };
    var r = await D.request(explicitAsk ? F.C.SIGN_IN : F.C.AUTO_SIGN_IN, F.loginBody(host, user, fields));
    if(r.status === 0 && r.ctr !== undefined) pending[r.ctr] = { tab: sender.tab.id, host: host, auto: !explicitAsk, fields: fields };
    note(host, !explicitAsk, r.status === 0 ? 'asked' : r.status);
    return { ok: r.status === 0, status: r.status };
  })().then(reply, function(e){ reply({ ok: false, why: 'error', message: e.message }); });
  return true;   // async reply
});
