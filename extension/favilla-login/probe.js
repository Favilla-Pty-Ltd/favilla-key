// Options page: connect the KEY over WebHID, pair this browser (6-digit
// comparison), test it, unpair. Vault phase 5 stage 2 (4 Nov 2026).
(function(){
  'use strict';
  var F = window.FavillaChan, D = window.FavillaDev;
  var $ = function(id){ return document.getElementById(id); };
  var log = $('log');
  function say(t){ log.textContent += t + '\n'; }
  var WHY = { 4: 'The KEY is not in VAULT mode. Restart it and choose VAULT.', 5: 'Enter the VAULT PIN on the KEY first.', 6: 'The KEY is busy. Finish what is on its screen.',
              8: 'This browser is not paired with that KEY.', 9: 'Out of step with the KEY. Unpair and pair again.', 10: 'On the KEY: Settings, Browsers, PAIR A BROWSER, then try again.',
              11: 'Refused on the KEY. Nothing was saved.', 12: 'The KEY already has 4 browsers. Remove one in Settings, Browsers.' };
  var LIFE = { 1: 'VAULT mode, PIN not entered yet', 2: 'VAULT mode, ready', 3: 'NOSTR mode (sign-in works in VAULT mode only)', 4: 'another mode' };

  function setState(html){ $('state').innerHTML = html; }
  function refresh(){
    return D.getPair().then(function(p){
      var d = D.device();
      $('pair').disabled = !d; $('test').disabled = !d || !p; $('ping10').disabled = !d;
      $('flash').disabled = !d; $('con').disabled = !d; $('klogClear').disabled = !d;
      if(d) klogStart(); else klogStop();
      $('forget').hidden = !p;
      if(!D.hasHid()){ setState('<span class="bad">This browser has no WebHID. Use Chrome or Edge.</span>'); $('connect').disabled = true; return; }
      var who = p ? 'Paired as <b>Browser ' + p.keyId.slice(0, 6).toUpperCase() + '</b>.' : 'Not paired yet.';
      setState(who + (d ? ' KEY connected.' : ' KEY not connected.'));
    });
  }
  D.find().then(refresh, refresh);
  // 0.5.13: the page used to reload itself here, which emptied the Bench log at
  // the very moment it mattered (a KEY reset). Now it drops the handle, stops
  // pulling, and polls for the KEY to come back, keeping everything on screen.
  navigator.hid && navigator.hid.addEventListener('disconnect', function(e){
    D.drop(e.device); klogStop(); say('KEY gone (reset or unplugged); waiting for it to come back.');
    refresh();
    var tries = 0, t = setInterval(function(){
      D.find().then(function(d){ if(d){ clearInterval(t); say('KEY back.'); refresh(); } else if(++tries > 240){ clearInterval(t); } }, function(){});
    }, 500);
  });

  $('connect').addEventListener('click', function(){
    D.choose().then(function(d){ if(!d) say('Nothing picked. Is the KEY plugged in?'); else say('Connected: ' + (d.productName || 'KEY')); return refresh(); })
      .catch(function(e){ say('Connect failed: ' + e.message); });
  });

  $('pair').addEventListener('click', function(){
    $('pair').disabled = true;
    D.pair().then(function(r){
      if(r.error !== undefined){ say(WHY[r.error] || ('The KEY said no (' + r.error + ').')); $('pair').disabled = false; return; }
      $('code').textContent = r.code.slice(0, 3) + ' ' + r.code.slice(3);
      $('codeBox').hidden = false;
      say('Compare ' + r.code + ' with the KEY, then press ENTER there.');
      return r.done.then(function(st){
        $('codeBox').hidden = true;
        if(st === 0) say('Paired. This browser can now ask the KEY to sign in.');
        else say(WHY[st] || ('Not paired (' + st + ').'));
        $('pair').disabled = false; return refresh();
      });
    }).catch(function(e){ $('codeBox').hidden = true; say('Pairing stopped: ' + e.message); $('pair').disabled = false; });
  });

  $('test').addEventListener('click', function(){
    D.request(F.C.HELLO, null).then(function(r){
      if(r.plain || r.type !== F.C.R_HELLO){ say(WHY[r.status] || ('The KEY said no (' + r.status + ').')); return; }
      var drop = new TextDecoder().decode(r.body.subarray(2, 10)).replace(/\0.*$/, '');   // 11ah: HELLO now carries 8 more bytes (the pair id) after the drop name
      say('Paired and answering: ' + (LIFE[r.body[1]] || 'unknown mode') + ', firmware drop ' + drop + '.');
    }).catch(function(e){ say('Test failed: ' + e.message); });
  });

  $('forget').addEventListener('click', function(){
    D.forget().then(function(){ say('Unpaired here. Remove it on the KEY too: Settings, Browsers.'); return refresh(); });
  });

  // automatic asks (on by default) and the sites they are off for
  function loadAuto(){
    return chrome.storage.local.get(['auto', 'noAuto']).then(function(v){
      $('auto').checked = v.auto !== false;
      var list = Array.isArray(v.noAuto) ? v.noAuto : [], ul = $('offlist'); ul.textContent = '';
      $('offwrap').hidden = !list.length;
      list.forEach(function(h){
        var li = document.createElement('li'), sp = document.createElement('span'), b = document.createElement('button');
        sp.textContent = h; b.textContent = 'Ask again'; b.className = 'ghost';
        b.addEventListener('click', function(){ chrome.storage.local.set({ noAuto: list.filter(function(x){ return x !== h; }) }).then(loadAuto); });
        li.appendChild(sp); li.appendChild(b); ul.appendChild(li);
      });
    });
  }
  $('auto').addEventListener('change', function(){ chrome.storage.local.set({ auto: $('auto').checked }); say($('auto').checked ? 'Automatic asks on.' : 'Automatic asks off. Use the Favilla button in the login box.'); });
  loadAuto();

  // 11u: the KEY's log and console over the channel (bench builds only; the
  // KEY ignores LOG and CON otherwise). LOG: [0x02][cursor u32 LE][want u8],
  // answered by up to `want` reports [0x82][flags][len][next u32 LE][57 bytes].
  var klog = $('klog'), kcur = 0, ktimer = null, kbusy = false, kquiet = 0, kseen = false;
  function klogAppend(t){
    var stick = klog.scrollTop + klog.clientHeight >= klog.scrollHeight - 4;
    klog.textContent += t;
    if(klog.textContent.length > 200000) klog.textContent = klog.textContent.slice(-150000);
    if(stick) klog.scrollTop = klog.scrollHeight;
  }
  function klogPull(){
    var d = D.device(); if(!d || kbusy) return; kbusy = true;
    var out = new Uint8Array(64); out[0] = 2; out[1] = kcur & 255; out[2] = (kcur >>> 8) & 255; out[3] = (kcur >>> 16) & 255; out[4] = (kcur >>> 24) & 255; out[5] = 32;
    var dec = new TextDecoder(), got = 0, done = false, t;
    function finish(){ if(done) return; done = true; clearTimeout(t); d.removeEventListener('inputreport', h); kbusy = false;
      kquiet = got ? 0 : Math.min(kquiet + 1, 8); }
    function h(e){
      var b = new Uint8Array(e.data.buffer); if(b[0] !== 0x82) return;
      got++; kseen = true;
      var next = (b[3] | (b[4] << 8) | (b[5] << 16) | (b[6] << 24)) >>> 0, n = b[2];
      if(b[1] & 2) klogAppend('[... earlier lines lost ...]\n');
      if(n) klogAppend(dec.decode(b.subarray(7, 7 + n)));
      kcur = next;
      if(!(b[1] & 1)) finish();
      else { clearTimeout(t); t = setTimeout(finish, 400); }
    }
    d.addEventListener('inputreport', h);
    t = setTimeout(finish, 600);
    d.sendReport(0, out).catch(function(){ finish(); });
  }
  // 0.5.13: a reconnect (the KEY restarted, or was replugged) keeps what was pulled before it, under a marker; only Clear log empties the panel
  function klogStart(){ if(ktimer) return; kcur = 0; if(klog.textContent) klogAppend('\n==== KEY reconnected ' + new Date().toLocaleTimeString() + ' ====\n'); ktimer = setInterval(function(){ klogPull(); }, 250); }
  function klogStop(){ if(ktimer){ clearInterval(ktimer); ktimer = null; } }
  $('klogClear').addEventListener('click', function(){ klog.textContent = ''; });
  // 0.5.17: the whole log to the clipboard in one press (works after the KEY has gone too)
  $('klogCopy').addEventListener('click', function(){
    var b = $('klogCopy'), t = klog.textContent;
    function done(m){ b.textContent = m; setTimeout(function(){ b.textContent = 'Copy log'; }, 1500); }
    if(!t){ done('Log is empty'); return; }
    navigator.clipboard.writeText(t).then(function(){ done('Copied ' + Math.round(t.length / 1024) + ' KB'); }, function(){
      var r = document.createRange(); r.selectNodeContents(klog); var s = getSelection(); s.removeAllRanges(); s.addRange(r);
      done(document.execCommand('copy') ? 'Copied' : 'Select and copy by hand'); s.removeAllRanges();
    });
  });
  function conSend(line){
    var d = D.device(); if(!d) return Promise.resolve();
    var b = new TextEncoder().encode(line); if(b.length > 62) b = b.subarray(0, 62);
    var out = new Uint8Array(64); out[0] = 3; out[1] = b.length; out.set(b, 2);
    return d.sendReport(0, out);
  }
  $('conForm').addEventListener('submit', function(ev){
    ev.preventDefault();
    var line = $('con').value.trim(); if(!line) return;
    klogAppend('> ' + line + '\n'); $('con').value = '';
    conSend(line).catch(function(e){ say('Console send failed: ' + e.message); });
  });
  $('flash').addEventListener('click', function(){
    klogAppend('> fido bootloader\n');
    conSend('fido bootloader').then(function(){ say('Flash mode sent. The KEY restarts on its flashing port; run the upload now, or power it off and on to cancel.'); })
      .catch(function(e){ say('Flash mode failed: ' + e.message); });
  });

  // bench: the probe's raw ping (single report, not framed)
  $('ping10').addEventListener('click', function(){
    var d = D.device(); if(!d) return;
    var ok = 0, times = [], i = 0;
    function one(){
      if(i++ === 10){ times.sort(function(a, b){ return a - b; }); say('10 pings: ' + ok + ' ok, median ' + (times[5] || '-') + ' ms'); return; }
      var out = new Uint8Array(64); out[0] = 1; var n = crypto.getRandomValues(new Uint8Array(8)); out.set(n, 1);
      var t0 = performance.now(), done = false;
      function h(e){ var b = new Uint8Array(e.data.buffer); if(b[0] !== 0x81) return; d.removeEventListener('inputreport', h); done = true;
        if(F.hex(b.slice(9, 17)) === F.hex(n)){ ok++; times.push(+(performance.now() - t0).toFixed(1)); } one(); }
      d.addEventListener('inputreport', h); d.sendReport(0, out);
      setTimeout(function(){ if(!done){ d.removeEventListener('inputreport', h); one(); } }, 1000);
    }
    one();
  });
})();
