// =============================================================================
// ember_check.h - the ESP32's own check of an Emberwill ceremony (G0 v20,
// 20 Nov 2026, issue #40 A1).
//
// At the ceremony the G0 builds every transaction of the plan and signs it,
// sealing the signed result in a blob only it can open (the ESP32 never holds
// a signed transaction before the release rule allows it). From v20 the G0
// also shows, before each signature, the BIP-143 digest it is about to sign
// and, on a transaction's first input, the UNSIGNED transaction.
//
// This file checks those against the plan, written from the plan's rules
// (g0/src/ember_plan.h), not from the G0's builder:
//   - canonical order: C0v0 C0v1 C0v2 | R1 C1v0 C1v1 C1v2 | R2 ...
//   - version 2, every nSequence 0xFFFFFFFD, empty scriptSigs, no witness
//   - inputs: C0 and R1 spend exactly the plan's coins, in order; Ri+1 and
//     Ci spend Ri:0 (Ri's txid as checked here)
//   - outputs: Ri pays one P2WPKH to the owner's address ref_index+i-1 (our
//     own derivation); Ci pays the heirs' scriptPubKeys in order, then the
//     executor's bump
//   - fee = rate * vsize upper bound (refresh rate, or coupon variant rate);
//     heir shares floor(avail * bp / 10000), rounding dust to heir 1
//   - nLockTime: Ci = X0 + i*quiet, Ri = X(i-1) - quiet/2,
//     X0 = ceremony tip + quiet + Afterglow
//   - the digest: BIP-143 SIGHASH_ALL for that input, from the parsed
//     transaction, the input's amount and the key it pays to
// It records each transaction's txid, so a release can be matched to what
// was checked here. Pure code (SHA-256 via mbedtls, hash160.h): the host
// test tests/ember_check_test.cpp runs it against the G0's own builder.
// =============================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "hash160.h"

namespace ewc {

constexpr int MAX_COINS = 3, MAX_HEIRS = 6, MAX_LINKS = 8, CVARS = 3, MAX_IN = 3, MAX_OUT = 7;
constexpr int MAX_TX = CVARS + MAX_LINKS * (1 + CVARS);   // 35
constexpr uint32_t SEQ = 0xFFFFFFFDu;

enum Err {
  OK = 0, E_PLAN = 1, E_ORDER = 2, E_PARSE = 3, E_VERSION = 4, E_INPUTS = 5, E_OUTPUTS = 6,
  E_FEE = 7, E_SHARES = 8, E_LOCKTIME = 9, E_SIGHASH = 10, E_STATE = 11,
};
inline const char* errText(int e){
  switch(e){
    case OK: return "ok"; case E_PLAN: return "plan not readable"; case E_ORDER: return "transaction out of order";
    case E_PARSE: return "transaction not readable"; case E_VERSION: return "version, sequence or witness wrong";
    case E_INPUTS: return "spends the wrong coins"; case E_OUTPUTS: return "pays the wrong addresses";
    case E_FEE: return "fee not the plan's rate"; case E_SHARES: return "heir shares wrong";
    case E_LOCKTIME: return "time lock wrong"; case E_SIGHASH: return "signs something else"; default: return "out of step";
  }
}

struct Plan {
  uint8_t ncoins, nheirs, nlinks;
  struct { uint8_t txid[32]; uint32_t vout; uint64_t amount; uint32_t change, index; } coin[MAX_COINS];
  struct { uint8_t spk[34]; uint8_t len; uint16_t bp; } heir[MAX_HEIRS];
  uint8_t exec_spk[34], exec_len;
  uint32_t quiet, ref_index, bump; uint16_t crate[CVARS], rrate;
};

struct Tx {
  uint32_t version, locktime; uint8_t nin, nout;
  struct { uint8_t txid[32]; uint32_t vout, seq; } in[MAX_IN];
  struct { uint64_t amount; uint8_t spk[34]; uint8_t len; } out[MAX_OUT];
  size_t base;   // serialised length without witness
};

inline uint32_t rd32(const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
inline uint64_t rd64(const uint8_t* p){ return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
inline void dsha(const uint8_t* d, size_t n, uint8_t o[32]){ uint8_t t[32]; mbedtls_sha256(d, n, t, 0); mbedtls_sha256(t, 32, o, 0); }

// The standard scriptPubKey templates a 34-byte slot may hold (zero padded).
inline uint8_t spkLen(const uint8_t s[34]){
  uint8_t len = 0;
  if(s[0] == 0x00 && s[1] == 0x14) len = 22;
  else if((s[0] == 0x00 || s[0] == 0x51) && s[1] == 0x20) len = 34;
  else if(s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) len = 25;
  else if(s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) len = 23;
  else return 0;
  for(int i = len; i < 34; i++) if(s[i]) return 0;
  return len;
}

// The 430-byte EMBER_SET wire (layout in g0/src/ember_plan.c).
inline bool parsePlan(const uint8_t b[430], Plan& p){
  memset(&p, 0, sizeof p);
  p.ncoins = b[0]; p.nheirs = b[1]; p.nlinks = b[2];
  if(b[3] || p.ncoins < 1 || p.ncoins > MAX_COINS || p.nheirs < 1 || p.nheirs > MAX_HEIRS || p.nlinks < 1 || p.nlinks > MAX_LINKS) return false;
  for(int i = 0; i < p.ncoins; i++){ const uint8_t* c = b + 4 + 52 * i;
    memcpy(p.coin[i].txid, c, 32); p.coin[i].vout = rd32(c + 32); p.coin[i].amount = rd64(c + 36);
    p.coin[i].change = rd32(c + 44); p.coin[i].index = rd32(c + 48); if(p.coin[i].change > 1) return false; }
  uint32_t bp = 0;
  for(int i = 0; i < p.nheirs; i++){ const uint8_t* h = b + 160 + 36 * i;
    memcpy(p.heir[i].spk, h, 34); p.heir[i].len = spkLen(h); p.heir[i].bp = (uint16_t)(h[34] | (h[35] << 8));
    if(!p.heir[i].len || !p.heir[i].bp) return false;
    bp += p.heir[i].bp; }
  if(bp != 10000u) return false;
  memcpy(p.exec_spk, b + 376, 34); p.exec_len = spkLen(p.exec_spk); if(!p.exec_len) return false;
  p.quiet = rd32(b + 410); p.ref_index = rd32(b + 414);
  for(int i = 0; i < CVARS; i++) p.crate[i] = (uint16_t)(b[418 + 2 * i] | (b[419 + 2 * i] << 8));
  p.rrate = (uint16_t)(b[424] | (b[425] << 8)); p.bump = rd32(b + 426);
  return p.quiet > 0;
}

// An unsigned transaction, exactly as the G0 serialises one (single-byte
// counts, empty scriptSigs, no witness). Every byte must be consumed.
inline bool parseTx(const uint8_t* r, size_t n, Tx& t){
  memset(&t, 0, sizeof t); size_t p = 0;
  auto need = [&](size_t k){ return p + k <= n; };
  if(!need(5)) return false;
  t.version = rd32(r); p = 4;
  if(r[p] == 0x00) return false;                    // segwit marker: a witness is never shown
  t.nin = r[p++]; if(t.nin < 1 || t.nin > MAX_IN) return false;
  for(int i = 0; i < t.nin; i++){
    if(!need(41)) return false;
    memcpy(t.in[i].txid, r + p, 32); t.in[i].vout = rd32(r + p + 32);
    if(r[p + 36] != 0x00) return false;              // empty scriptSig
    t.in[i].seq = rd32(r + p + 37); p += 41;
  }
  if(!need(1)) return false;
  t.nout = r[p++];
  if(t.nout < 1 || t.nout > MAX_OUT) return false;
  for(int i = 0; i < t.nout; i++){
    if(!need(9)) return false;
    t.out[i].amount = rd64(r + p); uint8_t l = r[p + 8]; p += 9;
    if(l > 34 || !need(l)) return false;
    memcpy(t.out[i].spk, r + p, l); t.out[i].len = l; p += l;
  }
  if(!need(4)) return false;
  t.locktime = rd32(r + p); p += 4;
  if(p != n) return false;
  t.base = n;
  return true;
}

inline uint64_t share(uint64_t a, uint16_t bp){ return (a / 10000u) * bp + ((a % 10000u) * bp) / 10000u; }
inline uint64_t vsizeMax(const Tx& t){ uint64_t wit = 2 + (uint64_t)t.nin * (1 + 1 + 73 + 1 + 33); return ((uint64_t)t.base * 4 + wit + 3) / 4; }

// BIP-143 SIGHASH_ALL for input i of a P2WPKH spend.
inline void sighash(const Tx& t, int i, uint64_t amount, const uint8_t pub[33], uint8_t out[32]){
  uint8_t buf[MAX_OUT * 43 + 64], prev[32], seq[32], outs[32]; size_t k = 0;
  for(int j = 0; j < t.nin; j++){ memcpy(buf + k, t.in[j].txid, 32); k += 32; for(int b = 0; b < 4; b++) buf[k++] = (uint8_t)(t.in[j].vout >> (8 * b)); }
  dsha(buf, k, prev); k = 0;
  for(int j = 0; j < t.nin; j++) for(int b = 0; b < 4; b++) buf[k++] = (uint8_t)(t.in[j].seq >> (8 * b));
  dsha(buf, k, seq); k = 0;
  for(int j = 0; j < t.nout; j++){ for(int b = 0; b < 8; b++) buf[k++] = (uint8_t)(t.out[j].amount >> (8 * b)); buf[k++] = t.out[j].len; memcpy(buf + k, t.out[j].spk, t.out[j].len); k += t.out[j].len; }
  dsha(buf, k, outs);
  uint8_t pre[4 + 32 + 32 + 36 + 26 + 8 + 4 + 32 + 4 + 4]; size_t q = 0;
  auto w32 = [&](uint32_t v){ for(int b = 0; b < 4; b++) pre[q++] = (uint8_t)(v >> (8 * b)); };
  w32(t.version); memcpy(pre + q, prev, 32); q += 32; memcpy(pre + q, seq, 32); q += 32;
  memcpy(pre + q, t.in[i].txid, 32); q += 32; w32(t.in[i].vout);
  pre[q++] = 0x19; pre[q++] = 0x76; pre[q++] = 0xa9; pre[q++] = 0x14; hash160(pub, 33, pre + q); q += 20; pre[q++] = 0x88; pre[q++] = 0xac;
  for(int b = 0; b < 8; b++) pre[q++] = (uint8_t)(amount >> (8 * b));
  w32(t.in[i].seq); memcpy(pre + q, outs, 32); q += 32; w32(t.locktime); w32(1);
  dsha(pre, q, out);
}

// The whole ceremony, one transaction and one digest at a time.
struct Check {
  Plan plan; uint32_t tip0, afterglow;   // plain data: begin() clears it
  uint8_t cpub[MAX_COINS][33]; uint8_t rpub[MAX_LINKS][33];
  uint8_t rtxid[MAX_LINKS + 1][32]; uint64_t ramt[MAX_LINKS + 1];
  uint8_t txid[MAX_TX][32]; uint32_t ntx;   // checked so far, in order
  Tx cur; int curK; uint64_t curAmt[MAX_IN]; const uint8_t* curPub[MAX_IN];
  bool ok;
};

inline uint32_t count(const Plan& p){ return CVARS + (uint32_t)p.nlinks * (1 + CVARS); }
inline void idAt(uint32_t k, char& kind, int& link, int& var){
  if(k < (uint32_t)CVARS){ kind = 'C'; link = 0; var = (int)k; return; }
  k -= CVARS; link = (int)(k / (1 + CVARS)) + 1; uint32_t r = k % (1 + CVARS);
  if(r == 0){ kind = 'R'; var = 0; } else { kind = 'C'; var = (int)r - 1; }
}
inline uint32_t X(const Check& c, uint32_t i){ return c.tip0 + c.plan.quiet + c.afterglow + i * c.plan.quiet; }

// wire: the plan sent as EM_SET; tip0: the ceremony tip the G0 reported;
// cpub/rpub: the coins' and refresh addresses' keys, derived by the ESP32
// from the account xpub (coin i at change/index, refresh i at 0/ref_index+i).
inline int begin(Check& c, const uint8_t wire[430], uint32_t tip0, uint32_t afterglow,
                 const uint8_t cpub[][33], const uint8_t rpub[][33]){
  memset(&c, 0, sizeof c); c.curK = -1;
  if(!parsePlan(wire, c.plan)) return E_PLAN;
  c.tip0 = tip0; c.afterglow = afterglow;
  for(int i = 0; i < c.plan.ncoins; i++) memcpy(c.cpub[i], cpub[i], 33);
  for(int i = 0; i < c.plan.nlinks; i++) memcpy(c.rpub[i], rpub[i], 33);
  c.ok = true;
  return OK;
}

// Transaction k (canonical order), unsigned, as the G0 showed it.
inline int tx(Check& c, uint32_t k, const uint8_t* raw, size_t n){
  if(!c.ok || k != c.ntx || k >= count(c.plan)) return E_ORDER;
  Tx& t = c.cur; if(!parseTx(raw, n, t)) return E_PARSE;
  if(t.version != 2) return E_VERSION;
  for(int i = 0; i < t.nin; i++) if(t.in[i].seq != SEQ) return E_VERSION;
  char kind; int link, var; idAt(k, kind, link, var);
  const Plan& p = c.plan;
  // inputs
  const bool estate = (kind == 'C' && link == 0) || (kind == 'R' && link == 1);
  if(estate){
    if(t.nin != p.ncoins) return E_INPUTS;
    for(int i = 0; i < p.ncoins; i++){
      if(memcmp(t.in[i].txid, p.coin[i].txid, 32) || t.in[i].vout != p.coin[i].vout) return E_INPUTS;
      c.curAmt[i] = p.coin[i].amount; c.curPub[i] = c.cpub[i];
    }
  } else {
    const int from = kind == 'C' ? link : link - 1;            // Ci spends Ri; Ri spends Ri-1
    if(t.nin != 1 || memcmp(t.in[0].txid, c.rtxid[from], 32) || t.in[0].vout != 0) return E_INPUTS;
    c.curAmt[0] = c.ramt[from]; c.curPub[0] = c.rpub[from - 1];
  }
  uint64_t in = 0, outv = 0; for(int i = 0; i < t.nin; i++) in += c.curAmt[i];
  for(int i = 0; i < t.nout; i++) outv += t.out[i].amount;
  if(outv > in) return E_FEE;
  const uint64_t fee = in - outv;
  if(kind == 'R'){
    uint8_t spk[22]; spk[0] = 0x00; spk[1] = 0x14; hash160(c.rpub[link - 1], 33, spk + 2);
    if(t.nout != 1 || t.out[0].len != 22 || memcmp(t.out[0].spk, spk, 22)) return E_OUTPUTS;
    if(fee != (uint64_t)p.rrate * vsizeMax(t)) return E_FEE;
    if(t.locktime != X(c, (uint32_t)link - 1) - p.quiet / 2) return E_LOCKTIME;
  } else {
    if(t.nout != p.nheirs + 1) return E_OUTPUTS;
    for(int h = 0; h < p.nheirs; h++) if(t.out[h].len != p.heir[h].len || memcmp(t.out[h].spk, p.heir[h].spk, p.heir[h].len)) return E_OUTPUTS;
    const int b = p.nheirs;
    if(t.out[b].len != p.exec_len || memcmp(t.out[b].spk, p.exec_spk, p.exec_len) || t.out[b].amount != p.bump) return E_OUTPUTS;
    if(fee != (uint64_t)p.crate[var] * vsizeMax(t)) return E_FEE;
    const uint64_t avail = in - fee - p.bump; uint64_t given = 0;
    for(int h = 0; h < p.nheirs; h++) given += share(avail, p.heir[h].bp);
    for(int h = 0; h < p.nheirs; h++){
      uint64_t want = share(avail, p.heir[h].bp) + (h == 0 ? avail - given : 0);
      if(t.out[h].amount != want) return E_SHARES;
    }
    if(t.locktime != X(c, (uint32_t)link)) return E_LOCKTIME;
  }
  dsha(raw, n, c.txid[k]);
  if(kind == 'R'){ memcpy(c.rtxid[link], c.txid[k], 32); c.ramt[link] = t.out[0].amount; }
  c.curK = (int)k; c.ntx = k + 1;
  return OK;
}

// The digest the G0 is about to sign for input `input` of transaction k.
inline int digest(Check& c, uint32_t k, uint32_t input, const uint8_t sh[32]){
  if(!c.ok || c.curK != (int)k || input >= c.cur.nin) return E_STATE;
  uint8_t mine[32]; sighash(c.cur, (int)input, c.curAmt[input], c.curPub[input], mine);
  return memcmp(mine, sh, 32) ? E_SIGHASH : OK;
}

// Every transaction checked, in order.
inline bool complete(const Check& c){ return c.ok && c.ntx == count(c.plan); }

}  // namespace ewc
