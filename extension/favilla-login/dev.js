// dev.js - the KEY over WebHID for the extension pages (popup and Options).
// Finds the Favilla channel (usage page 0xFF46), sends framed messages, and
// keeps the pairing (client id, key, counter) in chrome.storage.local.
(function(root){
  'use strict';
  var F = root.FavillaChan;
  var FILTER = [{ usagePage: 0xFF46, usage: 0x01 }];
  var dev = null, ra = new F.Reasm(), waiters = [], listeners = [];
  var store = (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) ? chrome.storage.local : null;

  function onReport(e){
    var d = new Uint8Array(e.data.buffer, e.data.byteOffset, e.data.byteLength);
    var m; try { m = ra.feed(d); } catch(err){ return; }
    if(!m) return;
    if(m[0] === F.C.R_EVENT){ listeners.forEach(function(l){ l(m); }); return; }   // results come later, never as a reply
    for(var i = 0; i < waiters.length; i++){ var w = waiters[i]; if(!w.match || w.match(m)){ waiters.splice(i, 1); w.got(m); return; } }
    // nothing waiting for it: a late answer to a request that timed out, dropped
  }
  function hasHid(){ return typeof navigator !== 'undefined' && 'hid' in navigator; }
  function isChan(d){ return d.collections.some(function(c){ return c.usagePage === 0xFF46; }); }
  function use(d){
    if(dev === d) return Promise.resolve(d);
    dev = d; dev.addEventListener('inputreport', onReport);
    return d.opened ? Promise.resolve(d) : d.open().then(function(){ return d; });
  }
  // a KEY already allowed for this extension (no prompt)
  function find(){
    if(!hasHid()) return Promise.resolve(null);
    // 0.5.18: a handle from before a restart or a replug is closed for good; let it go and look again
    if(dev && !dev.opened) drop(dev);
    if(dev) return Promise.resolve(dev);
    return navigator.hid.getDevices().then(function(list){ var d = list.filter(isChan)[0]; return d ? use(d) : null; });
  }
  // asks the user to pick the KEY (needs a click)
  function choose(){
    return navigator.hid.requestDevice({ filters: FILTER }).then(function(list){ return list.length ? use(list[0]) : null; });
  }
  function send(m){ var p = Promise.resolve(); F.frag(m).forEach(function(r){ p = p.then(function(){ return dev.sendReport(0, r); }); }); return p; }
  // the next message (that matches, if a test is given); late answers to older requests are dropped
  function recv(ms, match){
    return new Promise(function(res, rej){
      var w = { match: match, got: function(m){ clearTimeout(t); res(m); } };
      var t = setTimeout(function(){ var i = waiters.indexOf(w); if(i >= 0) waiters.splice(i, 1); rej(new Error('The KEY did not answer.')); }, ms || 3000);
      waiters.push(w);
    });
  }
  function onEvent(fn){ listeners.push(fn); }

  function getPair(){
    if(!store) return Promise.resolve(null);
    return store.get('pair').then(function(v){ var p = v && v.pair; if(!p || !p.id || !p.k) return null; return { id: F.unhex(p.id), k: F.unhex(p.k), ctr: p.ctr >>> 0, keyId: p.id }; });
  }
  function setPair(p){ return store.set({ pair: p ? { id: F.hex(p.id), k: F.hex(p.k), ctr: p.ctr >>> 0 } : null }); }
  // The next counter, saved before sending (never reused), under a lock shared
  // by the popup and the Options page (review 4 Nov 2026). floor: the KEY's
  // last accepted counter, after a replay answer.
  function withLock(fn){ return (navigator.locks && navigator.locks.request) ? navigator.locks.request('favilla-ctr', fn) : fn(); }
  function nextCtr(floor){
    return withLock(function(){
      return getPair().then(function(p){
        if(!p) throw new Error('not paired');
        p.ctr = (Math.max(p.ctr, floor || 0) + 1) >>> 0;
        return setPair(p).then(function(){ return p; });
      });
    });
  }
  // A signed request; resolves {type, status, body} from the KEY, or rejects.
  // The reply must carry this request's counter and client id.
  function request(cmd, body, ms, floor, retried){
    return nextCtr(floor).then(function(p){
      var ctr = p.ctr;
      return F.buildReq(cmd, p.id, ctr, body, p.k).then(function(m){
        // 0.5.18: the KEY restarted or was replugged since the handle was taken: the
        // send fails. Drop the dead handle, find the KEY again, and send once more.
        return send(m).catch(function(e){
          drop(); return find().then(function(d){ if(!d) throw new Error('The KEY is not connected.'); return send(m); });
        }).then(function(){ return recv(ms, function(r){
          if(r[0] === F.C.R_ERR && r.length === 3) return true;   // an unsigned refusal (not paired)
          return r.length >= 13 && F.hex(r.subarray(1, 9)) === F.hex(p.id) && ((r[9] | (r[10] << 8) | (r[11] << 16) | (r[12] << 24)) >>> 0) === ctr;
        }); });
      }).then(function(r){
        if(r[0] === F.C.R_ERR && r.length === 3) return { type: r[0], status: r[2], plain: true };
        return F.openRsp(r, p.k).then(function(o){
          if(!o) throw new Error('The answer did not check out.');
          if(o.type === F.C.R_ERR && o.body[0] === 9 && o.body.length === 5 && !retried){   // out of step (the KEY restarted): resync once
            var fl = (o.body[1] | (o.body[2] << 8) | (o.body[3] << 16) | (o.body[4] << 24)) >>> 0;
            return request(cmd, body, ms, fl, true);
          }
          return { type: o.type, status: o.body[0], body: o.body, ctr: o.ctr };
        });
      });
    });
  }
  // Pairing: commit, see the KEY's key, reveal (chan_proto.h). Resolves
  // {code, id, done: Promise<status>} or {error}.
  function pair(){
    var kp, nonce = root.crypto.getRandomValues(new Uint8Array(16));
    return F.genKeyPair().then(function(k){ kp = k; return F.commitment(kp.pub, nonce); })
      .then(function(c){ return send(F.cat(new Uint8Array([F.C.PAIR_COMMIT]), c)); })
      .then(function(){ return recv(4000); })
      .then(function(m){
        if(m[0] === F.C.R_ERR) return { error: m[2] };
        if(m[0] !== F.C.R_PAIR_KEY || m.length !== 74) throw new Error('Unexpected answer from the KEY.');
        var keyPub = m.slice(1, 66), id = m.slice(66, 74);
        return send(F.cat(new Uint8Array([F.C.PAIR_REVEAL]), kp.pub, nonce))
          .then(function(){ return F.derive(kp.priv, kp.pub, keyPub); })
          .then(function(d){
            var done = recv(75000).then(function(r){
              if(r[0] === F.C.R_ERR && r.length === 3) return r[2];
              return F.openRsp(r, d.k).then(function(o){
                if(!o || o.type !== F.C.R_PAIR_DONE) throw new Error('The KEY\u2019s answer did not check out.');
                if(o.body[0] !== 0) return o.body[0];
                return setPair({ id: id, k: d.k, ctr: 0 }).then(function(){ return 0; });
              });
            });
            return { code: d.code, id: F.hex(id), done: done };
          });
      });
  }
  // open an event with the stored key: {status, ctr} or null
  function openEvent(m){ return getPair().then(function(p){ return p ? F.openRsp(m, p.k) : null; }).then(function(o){ return o ? { status: o.body[0], ctr: o.ctr } : null; }); }
  // 0.5.13: the KEY went away (reset or unplugged): forget the handle so find() looks again
  function drop(d){ if(dev && (!d || dev === d)){ try { dev.removeEventListener('inputreport', onReport); } catch(e){} dev = null; } }
  root.FavillaDev = { openEvent: openEvent, find: find, drop: drop, choose: choose, request: request, pair: pair, getPair: getPair, forget: function(){ return setPair(null); }, onEvent: onEvent, hasHid: hasHid,
                      device: function(){ return dev; } };
})(typeof globalThis !== 'undefined' ? globalThis : this);
