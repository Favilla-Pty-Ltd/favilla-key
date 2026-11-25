// ember_check_test.cpp - the ESP32's Emberwill ceremony check (src/ember_check.h,
// G0 v20) against the G0's own transaction builder (g0/src/ember_plan.c,
// ember_tx.c). Every transaction and digest of a plan must pass; any single
// changed bit in any transaction, a wrong digest, a wrong tip or an
// out-of-order transaction must be refused.
#include <cstdio>
#include <cstring>
#include "ember_check.h"
extern "C" {
#include "ember_plan.h"
#include "ember_tx.h"
}
static int pass = 0, fail = 0;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)
static void wr32(uint8_t* p, uint32_t v){ for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void wr64(uint8_t* p, uint64_t v){ wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

struct Built { uint8_t raw[EP_MAX_LINKS * 4 + 3][700]; size_t n[EP_MAX_LINKS * 4 + 3]; uint8_t sh[EP_MAX_LINKS * 4 + 3][3][32]; uint8_t nin[EP_MAX_LINKS * 4 + 3]; uint32_t count; };

static void makePlan(uint8_t w[430], int ncoins, int nheirs, int nlinks){
  memset(w, 0, 430); w[0] = (uint8_t)ncoins; w[1] = (uint8_t)nheirs; w[2] = (uint8_t)nlinks;
  for (int c = 0; c < ncoins; c++){ uint8_t* p = w + 4 + 52 * c; for (int i = 0; i < 32; i++) p[i] = (uint8_t)(0x40 + c * 7 + i);
    wr32(p + 32, (uint32_t)c); wr64(p + 36, 50000000ull + 1234567ull * c); wr32(p + 44, (uint32_t)(c & 1)); wr32(p + 48, 3u + c); }
  static const uint8_t tmpl[3][2] = { {0x00, 0x14}, {0x51, 0x20}, {0x00, 0x20} };
  uint32_t left = 10000;
  for (int h = 0; h < nheirs; h++){ uint8_t* s = w + 160 + 36 * h; s[0] = tmpl[h % 3][0]; s[1] = tmpl[h % 3][1];
    memset(s + 2, 0x11 * (h + 1), s[1]); uint16_t bp = h == nheirs - 1 ? (uint16_t)left : (uint16_t)(10000 / nheirs - 7 * h); left -= bp; s[34] = (uint8_t)bp; s[35] = (uint8_t)(bp >> 8); }
  w[376] = 0x00; w[377] = 0x14; memset(w + 378, 0x33, 20);
  wr32(w + 410, 4032); wr32(w + 414, 20);
  w[418] = 5; w[420] = 20; w[422] = 80; w[424] = 10; wr32(w + 426, 1000);
}

static void build(const uint8_t w[430], uint32_t tip, uint8_t cpub[][33], uint8_t rpub[][33], Built& b){
  ep_set_t s; ep_set_parse(w, 430, &s);
  b.count = ep_count(&s);
  for (uint32_t k = 0; k < b.count; k++){
    et_tx_t tx; ep_build(&s, tip, (const uint8_t (*)[33])cpub, (const uint8_t (*)[33])rpub, ep_id_at(k), &tx);
    b.n[k] = et_serialize(&tx, 0, b.raw[k], sizeof b.raw[k]); b.nin[k] = tx.nin;
    for (int i = 0; i < tx.nin; i++) et_sighash(&tx, i, b.sh[k][i]);
  }
}

// Runs the whole ceremony through the check; returns the first error and where.
static int run(const uint8_t w[430], uint32_t tip, uint8_t cpub[][33], uint8_t rpub[][33], Built& b, uint32_t* atK = nullptr){
  static ewc::Check c; int e = ewc::begin(c, w, tip, 1008, cpub, rpub); if (e) return e;
  for (uint32_t k = 0; k < b.count; k++){
    if ((e = ewc::tx(c, k, b.raw[k], b.n[k]))) { if (atK) *atK = k; return e; }
    for (int i = 0; i < b.nin[k]; i++) if ((e = ewc::digest(c, k, (uint32_t)i, b.sh[k][i]))) { if (atK) *atK = k; return e; }
  }
  return ewc::complete(c) ? 0 : ewc::E_STATE;
}

int main(){
  uint8_t cpub[3][33], rpub[8][33];
  for (int i = 0; i < 3; i++){ cpub[i][0] = 0x02; for (int j = 1; j < 33; j++) cpub[i][j] = (uint8_t)(0x90 + i * 13 + j); }
  for (int i = 0; i < 8; i++){ rpub[i][0] = 0x03; for (int j = 1; j < 33; j++) rpub[i][j] = (uint8_t)(0x20 + i * 17 + j); }
  const uint32_t tip = 975759;
  static Built b; uint8_t w[430];
  // every shape: 1..3 coins, 1..6 heirs, 1..8 links
  int shapes = 0;
  for (int nc = 1; nc <= 3; nc++) for (int nh = 1; nh <= 6; nh++) for (int nl = 1; nl <= 8; nl++){
    makePlan(w, nc, nh, nl); ep_set_t s; ep_set_parse(w, 430, &s);
    if (ep_validate(&s, tip) != EP_OK){ printf("plan %d/%d/%d not valid for the G0\n", nc, nh, nl); fail++; continue; }
    build(w, tip, cpub, rpub, b);
    uint32_t at = 0; int e = run(w, tip, cpub, rpub, b, &at);
    CHECK(e == 0, "plan %d coins %d heirs %d links: honest ceremony refused at tx %u: %s", nc, nh, nl, at, ewc::errText(e));
    shapes++;
  }
  printf("  %d plan shapes: every transaction and digest the G0 builds passes the ESP32's check\n", shapes);

  // a 2-coin, 3-heir, 4-link plan for the tampering tests
  makePlan(w, 2, 3, 4); build(w, tip, cpub, rpub, b);
  CHECK(run(w, tip, cpub, rpub, b) == 0, "base plan");
  // every single bit of every unsigned transaction
  uint32_t flips = 0, caught = 0;
  for (uint32_t k = 0; k < b.count; k++) for (size_t i = 0; i < b.n[k]; i++) for (int bit = 0; bit < 8; bit++){
    b.raw[k][i] ^= (uint8_t)(1 << bit); flips++;
    if (run(w, tip, cpub, rpub, b) != 0) caught++;
    b.raw[k][i] ^= (uint8_t)(1 << bit);
  }
  CHECK(caught == flips, "bit flips: %u of %u caught", caught, flips);
  printf("  %u single-bit changes across %u transactions: %u refused\n", flips, b.count, caught);
  // every digest
  uint32_t dflip = 0, dcaught = 0;
  for (uint32_t k = 0; k < b.count; k++) for (int i = 0; i < b.nin[k]; i++){ b.sh[k][i][(k * 7 + i) % 32] ^= 0x01; dflip++; if (run(w, tip, cpub, rpub, b) == ewc::E_SIGHASH) dcaught++; b.sh[k][i][(k * 7 + i) % 32] ^= 0x01; }
  CHECK(dcaught == dflip, "digests: %u of %u caught", dcaught, dflip);
  // a G0 that counted the locktimes from another tip
  { static Built b2; build(w, tip + 1, cpub, rpub, b2); CHECK(run(w, tip, cpub, rpub, b2) == ewc::E_LOCKTIME, "other tip -> time lock"); }
  // refresh to a key the ESP32 did not derive
  { uint8_t r2[8][33]; memcpy(r2, rpub, sizeof r2); r2[1][5] ^= 1; static Built b3; build(w, tip, cpub, r2, b3); CHECK(run(w, tip, cpub, rpub, b3) != 0, "refresh to another key"); }
  // a coin key the ESP32 did not derive: the digests differ
  { uint8_t c2[3][33]; memcpy(c2, cpub, sizeof c2); c2[0][9] ^= 1; static Built b4; build(w, tip, c2, rpub, b4); CHECK(run(w, tip, cpub, rpub, b4) == ewc::E_SIGHASH, "coin key"); }
  // out of order
  { static ewc::Check c; ewc::begin(c, w, tip, 1008, cpub, rpub); CHECK(ewc::tx(c, 1, b.raw[1], b.n[1]) == ewc::E_ORDER, "out of order"); }
  // a plan with a heir changed: the G0's honest transactions no longer match it
  { uint8_t w2[430]; memcpy(w2, w, 430); w2[162] ^= 1; CHECK(run(w2, tip, cpub, rpub, b) == ewc::E_OUTPUTS, "heir changed in the plan"); }
  printf("ember check: %d passed, %d failed\n", pass, fail);
  return fail ? 1 : 0;
}
