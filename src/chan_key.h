// chan_key.h - the KEY's side of the Favilla channel (Vault phase 5 stage 2,
// 4 Nov 2026). Pure C++ over hooks, so the same state machine runs on the KEY
// (passkey_life.inc supplies mbedTLS, NVS and the screens) and in the host
// simulator the extension's chan.js is tested against.
//
// What it decides: pairing only inside the window, ONE attempt per window,
// committed before the KEY's key is seen, and stored only on ENTER for that
// same attempt; every request must carry a known client's mac and a counter
// above the last; sign-in and new-login run only in a life with no radios that
// is unlocked (PASSKEY now); one thing at a time. It never sends a password or
// anything the vault holds: replies are status bytes.
//
// Review fixes (4 Nov 2026): a second pairing message no longer replaces the
// one on screen (one attempt per window, the decision names its client id);
// commitment round; pairing refused while a request is in progress and a
// request refused while pairing; counters persisted in blocks of 64 and a
// failed write refuses the request; a replay answer carries the floor so the
// browser can resync after a restart.
#pragma once
#include "chan_proto.h"

namespace chan {

constexpr int MAX_CLIENTS = 4;
constexpr uint32_t CTR_BLOCK = 64;   // counters are persisted as a ceiling, every 64 requests
struct Client { uint8_t used; uint8_t id[ID]; uint8_t k[KEYLEN]; uint32_t ctr; uint32_t hi; };

struct Hooks {
  HmacFn hmac;
  bool (*myPub)(uint8_t out[PUB]);                       // this window's public key
  bool (*ecdh)(const uint8_t peer[PUB], uint8_t z[32]);  // shared secret with this window's key
  void (*rng)(uint8_t* p, size_t n);
  bool (*save)(const Client* c, int n);                  // persist the table
  uint8_t (*life)();                                     // Life
  bool (*pairWindow)();                                  // the window is open now
  bool (*pairShow)(uint32_t code, const uint8_t id[ID]); // show the code; false if the screen cannot
  // a sign-in or new-login: S_OK if the KEY is now showing it (it calls
  // finish() later), else the reason
  Status (*request)(uint8_t cmd, const char* site, const char* user);
  void (*send)(const uint8_t* msg, size_t n);            // one message; the caller fragments
  const char* drop;
  // 11z: a one-time code to type (C_CODE_TYPE); S_OK if the KEY took it (it
  // calls finish() later). May be left null: the command is then refused.
  Status (*codeRequest)(const char* site, uint64_t t, uint8_t flags);
  // 11ah (issue #22): the KEY's pairing identity, 8 bytes, in HELLO (null: zeros).
  bool (*pairId)(uint8_t out[8]);
  // 11ah (issue #22): the camera has read a favilla:pair QR with exactly this
  // extPub and nonce (null: never). A matching REVEAL is accepted without the
  // code screen.
  bool (*scanned)(const uint8_t extPub[PUB], const uint8_t nonce[NONCE]);
  // 11aw: what the page shows for this sign-in (chan::FIELDS_*), told just
  // before request(). May be left null (every ask is then "both").
  void (*fields)(uint8_t fields);
};

struct Key {
  Hooks h; Client cl[MAX_CLIENTS] = {};
  // pairing: stage 0 none, 1 committed (our key sent), 2 code on screen
  int pairStage = 0; bool pairUsed = false;
  uint8_t pCommit[COMMIT], pKeyPub[PUB], pId[ID], pK[KEYLEN];
  uint8_t pExt[PUB], pNonce[NONCE];   // 11ah: the revealed values, for a scan that lands while the code is on screen
  // request in progress (its event goes to this client and counter)
  bool busy = false; int rqClient = -1; uint32_t rqCtr = 0; uint8_t rqCmd = 0;
  uint32_t stats[8] = {};   // 0 rx, 1 bad mac, 2 replay, 3 paired, 4 requests, 5 refused (life/lock/busy), 6 bad body, 7 framing

  int find(const uint8_t id[ID]) const { for(int i = 0; i < MAX_CLIENTS; i++) if(cl[i].used && ctEq(cl[i].id, id, ID)) return i; return -1; }
  int count() const { int n = 0; for(int i = 0; i < MAX_CLIENTS; i++) n += cl[i].used; return n; }
  void forget(int i){ if(i < 0 || i >= MAX_CLIENTS) return; memset(&cl[i], 0, sizeof cl[i]); h.save(cl, MAX_CLIENTS); }
  // after loading the table: the last accepted counter is the stored ceiling
  void afterLoad(){ for(int i = 0; i < MAX_CLIENTS; i++) if(cl[i].used){ if(cl[i].ctr < cl[i].hi) cl[i].ctr = cl[i].hi; } else memset(&cl[i], 0, sizeof cl[i]); }
  // the UI opened a fresh window: one pairing attempt in it
  void windowOpened(){ pairUsed = false; pairStage = 0; memset(pK, 0, KEYLEN); }
  void windowClosed(){ pairUsed = true; if(pairStage == 1) pairStage = 0; }

  void sendErr(uint8_t cmd, Status s){ uint8_t m[3] = { R_ERR, cmd, (uint8_t)s }; h.send(m, 3); }
  void reply(int ci, uint8_t rsp, uint32_t ctr, const uint8_t* body, size_t bl){
    uint8_t out[64]; size_t n = buildRsp(h.hmac, cl[ci].k, rsp, cl[ci].id, ctr, body, bl, out, sizeof out);
    if(n) h.send(out, n);
  }

  // One complete message from the host.
  void process(const uint8_t* m, size_t n){
    stats[0]++;
    if(n < 1) return;
    if(m[0] == C_PAIR_COMMIT){
      if(n != 1 + COMMIT){ stats[6]++; sendErr(m[0], S_BAD_REQUEST); return; }
      if(!h.pairWindow()){ sendErr(m[0], S_PAIR_CLOSED); return; }
      if(pairUsed || pairStage || busy){ sendErr(m[0], S_BUSY); return; }   // one attempt per window, never over a request
      if(count() >= MAX_CLIENTS){ sendErr(m[0], S_FULL); return; }
      pairUsed = true;
      if(!h.myPub(pKeyPub)){ sendErr(m[0], S_BAD_REQUEST); return; }
      memcpy(pCommit, m + 1, COMMIT); h.rng(pId, ID); pairStage = 1;
      uint8_t out[1 + PUB + ID]; out[0] = R_PAIR_KEY; memcpy(out + 1, pKeyPub, PUB); memcpy(out + 1 + PUB, pId, ID);
      h.send(out, sizeof out);
      return;
    }
    if(m[0] == C_PAIR_REVEAL){
      if(n != 1 + PUB + NONCE || pairStage != 1 || m[1] != 0x04){ stats[6]++; sendErr(m[0], S_BAD_REQUEST); return; }
      pairStage = 0;   // whatever happens next, this attempt is spent unless the code goes on screen
      uint8_t c[COMMIT];
      if(!commitment(h.hmac, m + 1, m + 1 + PUB, c) || !ctEq(c, pCommit, COMMIT)){ stats[6]++; sendErr(m[0], S_BAD_REQUEST); return; }
      uint8_t z[32]; uint32_t code = 0;
      bool ok = h.ecdh(m + 1, z) && derive(h.hmac, z, m + 1, pKeyPub, pK, &code);
      memset(z, 0, 32);
      if(!ok){ stats[6]++; sendErr(m[0], S_BAD_REQUEST); return; }
      memcpy(pExt, m + 1, PUB); memcpy(pNonce, m + 1 + PUB, NONCE);
      if(h.scanned && h.scanned(pExt, pNonce)){ pairStage = 2; pairDecision(true, pId); return; }   // 11ah: the camera saw this phone's key: no code screen
      if(!h.pairShow(code, pId)){ memset(pK, 0, KEYLEN); sendErr(m[0], S_BUSY); return; }
      pairStage = 2;
      return;
    }
    Req r;
    if(!splitReq(m, n, &r)){ stats[1]++; sendErr(m[0], S_NOT_PAIRED); return; }
    int ci = find(r.id);
    if(ci < 0){ stats[1]++; sendErr(r.cmd, S_NOT_PAIRED); return; }
    Status v = verifyReq(h.hmac, m, n, cl[ci].k, cl[ci].ctr);
    if(v == S_NOT_PAIRED){ stats[1]++; sendErr(r.cmd, S_NOT_PAIRED); return; }
    if(v == S_REPLAY){ stats[2]++; uint8_t b[5] = { S_REPLAY }; put32(b + 1, cl[ci].ctr); reply(ci, R_ERR, r.ctr, b, 5); return; }   // the floor: the browser resyncs
    // accepted: persist the ceiling first when this counter passes it
    if(r.ctr > cl[ci].hi){
      uint32_t oldHi = cl[ci].hi; cl[ci].hi = r.ctr + CTR_BLOCK;
      if(!h.save(cl, MAX_CLIENTS)){ cl[ci].hi = oldHi; uint8_t b = S_STORAGE; reply(ci, R_ERR, r.ctr, &b, 1); return; }
    }
    cl[ci].ctr = r.ctr;
    if(r.cmd == C_HELLO){
      uint8_t b[18] = { S_OK, h.life() }; strncpy((char*)b + 2, h.drop ? h.drop : "", 8);
      if(!(h.pairId && h.pairId(b + 10))) memset(b + 10, 0, 8);   // 11ah (issue #22): the KEY's pairing identity; an app reading 10 bytes is unaffected
      reply(ci, R_HELLO, r.ctr, b, 18); return;
    }
    if(r.cmd == C_SIGN_IN || r.cmd == C_NEW_LOGIN || r.cmd == C_AUTO_SIGN_IN){
      stats[4]++;
      char site[FIELD_MAX + 1], user[FIELD_MAX + 1]; uint8_t fields = FIELDS_BOTH;
      Status s;
      uint8_t life = h.life();
      if(!parseLogin(r.body, r.bodyLen, site, user, &fields)){ stats[6]++; s = S_BAD_REQUEST; }
      else if(r.cmd == C_NEW_LOGIN ? (fields != FIELDS_BOTH && !formByte(fields)) : formByte(fields)){ stats[6]++; s = S_BAD_REQUEST; }   // 11az
      else if(life != L_PASSKEY_READY && life != L_PASSKEY_LOCKED){ stats[5]++; s = S_NOT_HERE; }
      else if(life == L_PASSKEY_LOCKED){ stats[5]++; s = S_LOCKED; }
      // 7g (Josh's bench: the KEY stayed on GitHub after he moved to Cloudflare):
      // a newer ask replaces a sign-in still on the KEY (the browser has moved
      // on). The old one is told "nothing typed" first. A new login is never
      // replaced: it may hold a password just typed and not yet saved.
      else if(pairStage || (busy && !isSignIn(rqCmd))){ stats[5]++; s = S_BUSY; }
      else {
        if(busy) finish(S_CANCELLED);
        busy = true; rqClient = ci; rqCtr = r.ctr; rqCmd = r.cmd;
        if(h.fields) h.fields(fields);   // 11aw
        s = h.request(r.cmd, site, user);
        if(s != S_OK){ busy = false; rqClient = -1; stats[5]++; }
      }
      memset(site, 0, sizeof site); memset(user, 0, sizeof user);
      uint8_t b = (uint8_t)s; reply(ci, R_ACK, r.ctr, &b, 1); return;
    }
    if(r.cmd == C_CODE_TYPE){   // 11z
      stats[4]++;
      char site[FIELD_MAX + 1]; uint64_t t = 0; uint8_t fl = 0;
      Status s;
      uint8_t life = h.life();
      const size_t sl = r.bodyLen ? r.body[0] : 0;
      bool ok = r.bodyLen == 1 + sl + 8 + 1 && sl >= 1 && sl <= FIELD_MAX && h.codeRequest;
      for(size_t i = 0; ok && i < sl; i++){ uint8_t c = r.body[1 + i]; if(c < 0x20 || c > 0x7E) ok = false; }
      if(ok){ memcpy(site, r.body + 1, sl); site[sl] = 0; for(int i = 0; i < 8; i++) t = (t << 8) | r.body[1 + sl + i]; fl = r.body[1 + sl + 8]; }
      if(!ok){ stats[6]++; s = S_BAD_REQUEST; }
      else if(life != L_PASSKEY_READY && life != L_PASSKEY_LOCKED){ stats[5]++; s = S_NOT_HERE; }
      else if(life == L_PASSKEY_LOCKED){ stats[5]++; s = S_LOCKED; }
      else if(pairStage || (busy && !isSignIn(rqCmd))){ stats[5]++; s = S_BUSY; }
      else {
        if(busy) finish(S_CANCELLED);
        busy = true; rqClient = ci; rqCtr = r.ctr; rqCmd = r.cmd;
        s = h.codeRequest(site, t, fl);
        if(s != S_OK){ busy = false; rqClient = -1; stats[5]++; }
      }
      memset(site, 0, sizeof site);
      uint8_t b = (uint8_t)s; reply(ci, R_ACK, r.ctr, &b, 1); return;
    }
    sendErr(r.cmd, S_BAD_REQUEST);
  }

  static bool isSignIn(uint8_t c){ return c == C_SIGN_IN || c == C_AUTO_SIGN_IN || c == C_CODE_TYPE; }   // 11z: a code ask is replaceable too
  // 11ah: the camera read a favilla:pair QR while the code was on screen. True
  // when it was this attempt's key and nonce (the pairing is then accepted).
  bool pairScanned(const uint8_t extPub[PUB], const uint8_t nonce[NONCE]){
    if(pairStage != 2 || !ctEq(extPub, pExt, PUB) || !ctEq(nonce, pNonce, NONCE)) return false;
    pairDecision(true, pId); return true;
  }
  // The UI's answer to the code screen, for the attempt with this id.
  void pairDecision(bool accept, const uint8_t id[ID]){
    if(pairStage != 2 || !ctEq(id, pId, ID)) return;   // not the attempt that was on screen
    pairStage = 0;
    Client tmp; memset(&tmp, 0, sizeof tmp); memcpy(tmp.id, pId, ID); memcpy(tmp.k, pK, KEYLEN);
    uint8_t st = S_PAIR_REFUSED;
    if(accept){
      int slot = -1; for(int i = 0; i < MAX_CLIENTS; i++) if(!cl[i].used){ slot = i; break; }
      if(slot < 0) st = S_FULL;
      else { tmp.used = 1; cl[slot] = tmp; st = h.save(cl, MAX_CLIENTS) ? S_OK : S_STORAGE; if(st != S_OK) memset(&cl[slot], 0, sizeof cl[slot]); else stats[3]++; }
    }
    uint8_t out[64]; size_t n = buildRsp(h.hmac, tmp.k, R_PAIR_DONE, tmp.id, 0, &st, 1, out, sizeof out);
    if(n) h.send(out, n);
    memset(&tmp, 0, sizeof tmp); memset(pK, 0, KEYLEN);
  }
  // The UI finished a sign-in or new login.
  void finish(Status s){
    if(!busy) return;
    busy = false;
    if(rqClient >= 0 && cl[rqClient].used){ uint8_t b = (uint8_t)s; reply(rqClient, R_EVENT, rqCtr, &b, 1); }
    rqClient = -1;
  }
};

}  // namespace chan
