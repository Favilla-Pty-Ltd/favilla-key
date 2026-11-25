// chan.js - the Favilla channel protocol, extension side (Vault phase 5 stage 2,
// 4 Nov 2026). The same bytes as the KEY's chan_proto.h (cross-checked by the
// host tests). Works in extension pages and in Node 20+ (globalThis.crypto).
(function(root){
  'use strict';
  var subtle = root.crypto.subtle;
  var C = { F_START: 0x10, F_CONT: 0x11, PAIR_COMMIT: 0x20, PAIR_REVEAL: 0x22, HELLO: 0x30, SIGN_IN: 0x31, NEW_LOGIN: 0x32, AUTO_SIGN_IN: 0x33, CODE_TYPE: 0x45,
            R_PAIR_KEY: 0xA0, R_PAIR_DONE: 0xA1, R_HELLO: 0xB0, R_ACK: 0xB1, R_EVENT: 0xB2, R_ERR: 0xBF, MSG_MAX: 512 };
  var STATUS = ['ok', 'typed', 'cancelled', 'no-match', 'not-here', 'locked', 'busy', 'bad-request', 'not-paired', 'replay', 'pair-closed', 'pair-refused', 'full', 'saved', 'storage'];
  var enc = new TextEncoder();
  function cat(){ var n = 0, i; for(i = 0; i < arguments.length; i++) n += arguments[i].length; var o = new Uint8Array(n), off = 0; for(i = 0; i < arguments.length; i++){ o.set(arguments[i], off); off += arguments[i].length; } return o; }
  function u32le(v){ return new Uint8Array([v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255]); }
  function rd32le(b, o){ return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function eq(a, b){ if(a.length !== b.length) return false; var d = 0; for(var i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
  function hex(b){ return Array.prototype.map.call(b, function(x){ return ('0' + x.toString(16)).slice(-2); }).join(''); }
  function unhex(s){ var o = new Uint8Array(s.length / 2); for(var i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16); return o; }

  function frag(msg){
    if(!msg.length || msg.length > C.MSG_MAX) throw new Error('message size');
    var out = [], r = new Uint8Array(64); r[0] = C.F_START; r[1] = msg.length & 255; r[2] = msg.length >> 8;
    var n = Math.min(61, msg.length); r.set(msg.subarray(0, n), 3); out.push(r);
    var off = n, i = 1;
    while(off < msg.length){ var c = new Uint8Array(64); c[0] = C.F_CONT; c[1] = i++; var m = Math.min(62, msg.length - off); c.set(msg.subarray(off, off + m), 2); out.push(c); off += m; }
    return out;
  }
  function Reasm(){ this.reset(); }
  Reasm.prototype.reset = function(){ this.want = 0; this.buf = null; this.have = 0; this.next = 0; };
  // returns a Uint8Array when complete, null when more is needed, throws on a framing error
  Reasm.prototype.feed = function(r){
    if(r[0] === C.F_START){
      var len = r[1] | (r[2] << 8); this.reset();
      if(!len || len > C.MSG_MAX) throw new Error('frame length');
      this.want = len; this.buf = new Uint8Array(len); var n = Math.min(61, len); this.buf.set(r.subarray(3, 3 + n), 0); this.have = n; this.next = 1;
    } else if(r[0] === C.F_CONT){
      if(!this.want || r[1] !== this.next){ this.reset(); throw new Error('frame order'); }
      var m = Math.min(62, this.want - this.have); this.buf.set(r.subarray(2, 2 + m), this.have); this.have += m; this.next++;
    } else return null;
    if(this.have === this.want){ var b = this.buf; this.reset(); return b; }
    return null;
  };

  function hmac(key, data){
    return subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function(k){ return subtle.sign('HMAC', k, data); }).then(function(s){ return new Uint8Array(s); });
  }
  function genKeyPair(){
    return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']).then(function(kp){
      return subtle.exportKey('raw', kp.publicKey).then(function(raw){ return { priv: kp.privateKey, pub: new Uint8Array(raw) }; });
    });
  }
  // z from ECDH, then K and the 6-digit code (chan_proto.h derive)
  function derive(priv, extPub, keyPub){
    return subtle.importKey('raw', keyPub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
      .then(function(pk){ return subtle.deriveBits({ name: 'ECDH', public: pk }, priv, 256); })
      .then(function(z){ return deriveFromZ(new Uint8Array(z), extPub, keyPub); });
  }
  function deriveFromZ(z, extPub, keyPub){
    return hmac(enc.encode('FAVILLA-CHAN-1'), z).then(function(prk){
      return Promise.all([hmac(prk, cat(enc.encode('key'), extPub, keyPub, new Uint8Array([1]))),
                          hmac(prk, cat(enc.encode('code'), extPub, keyPub, new Uint8Array([1])))]);
    }).then(function(r){
      var t = r[1], code = (((t[0] << 24) >>> 0) + (t[1] << 16) + (t[2] << 8) + t[3]) % 1000000;
      return { k: r[0], code: ('00000' + code).slice(-6) };
    });
  }
  // pairing commitment (chan_proto.h): C = HMAC("FAVILLA-COMMIT-1", extPub || nonce)
  function commitment(extPub, nonce){ return hmac(enc.encode('FAVILLA-COMMIT-1'), cat(extPub, nonce)); }
  function mac16(k, dir, data){ return hmac(k, cat(enc.encode(dir), data)).then(function(m){ return m.subarray(0, 16); }); }
  function buildReq(cmd, id, ctr, body, k){
    var head = cat(new Uint8Array([cmd]), id, u32le(ctr), body || new Uint8Array(0));
    return mac16(k, 'REQ', head).then(function(m){ return cat(head, m); });
  }
  // a reply or event: {type, id, ctr, body} if the mac checks, else null
  function openRsp(m, k){
    if(m.length < 1 + 8 + 4 + 16) return Promise.resolve(null);
    var head = m.subarray(0, m.length - 16), tag = m.subarray(m.length - 16);
    return mac16(k, 'RSP', head).then(function(x){
      if(!eq(x, tag)) return null;
      return { type: m[0], id: m.subarray(1, 9), ctr: rd32le(m, 9), body: m.subarray(13, m.length - 16) };
    });
  }
  // 11aw: fields = what the page shows (0 both / absent, 1 a username box only,
  // 2 a password box only), one trailing byte; left off for 0 so older KEYs read it.
  function loginBody(site, user, fields){
    var s = enc.encode(site), u = enc.encode(user || '');
    if(s.length < 1 || s.length > 100 || u.length > 100) throw new Error('field length');
    var b = cat(new Uint8Array([s.length]), s, new Uint8Array([u.length]), u);
    if(fields & 0x80) return cat(b, new Uint8Array([fields & 0x9F]));   // 11az: a NEW_LOGIN form byte (FORM_KNOWN set)
    return fields ? cat(b, new Uint8Array([fields & 3])) : b;
  }
  // 11az: NEW_LOGIN's form byte: what a sign-up or change-password page shows.
  var FORM = { KNOWN: 0x80, CONFIRM: 0x01, CURRENT: 0x02, USER: 0x04, SPLIT1: 0x08, SPLIT2: 0x10 };
  // 11z: a one-time code to type: [sLen][site][unix time 8, big endian][flags]; flags bit0 automatic, bit1 press Enter after
  function codeBody(site, flags){
    var s = enc.encode(site); if(s.length < 1 || s.length > 100) throw new Error('field length');
    var t = Math.floor(Date.now() / 1000), b = new Uint8Array(8); for(var i = 7; i >= 0; i--){ b[i] = t & 255; t = Math.floor(t / 256); }
    return cat(new Uint8Array([s.length]), s, b, new Uint8Array([flags & 255]));
  }
  var api = { C: C, STATUS: STATUS, frag: frag, Reasm: Reasm, hmac: hmac, genKeyPair: genKeyPair, commitment: commitment, derive: derive, deriveFromZ: deriveFromZ,
              mac16: mac16, buildReq: buildReq, openRsp: openRsp, loginBody: loginBody, FORM: FORM, codeBody: codeBody, hex: hex, unhex: unhex, cat: cat, u32le: u32le };
  root.FavillaChan = api;
  if(typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
