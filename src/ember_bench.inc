// =============================================================================
// ember_bench.inc — Emberwill bench commands over USB serial. 28 Oct 2026.
// FAVILLA_BENCH_PROBES only (pio run -e favilla_key_bench); the release guard
// already refuses that flag in a release image. Included at the END of
// main.cpp, after bitcoin_menu.inc (it needs btcWitnessedSpendOpen).
//
// This is a bench harness to prove the Emberwill G0 image on silicon, not the
// product UI. Commands (type `em help`):
//   em status            decode EM_STATUS (plan, link, tip, life, Afterglow, next, boot KAT)
//   em src [url]         header source: default https://mempool.space; http://<pc>:8088 = tools/ember_proxy.py
//   em anchor            print 11 mainnet headers S..S+10 for tools/make_anchor.py (Nostr life, WiFi)
//   em sync [max]        fetch headers from mempool.space and feed the G0 up to the tip (WiFi);
//                        caches the last 32 in NVS; EM_SAVE every 500 headers and at the end
//   em p2p [host] [max]  Bitcoin P2P: plain TCP to a node (DNS seed if no host), getheaders from the G0 tip,
//                        each header straight into the G0. No TLS, no JSON. The product fetch path.
//   em feed              re-feed the cached headers (a Bitcoin life has no radio)
//   em hdr <160 hex>     one header over USB serial (tools/ember_feed.py drives this: no WiFi on the KEY)
//   em hdr-done          flush the cache + EM_SAVE after a serial feed
//   em save              EM_SAVE
//   em plan ...          store a REAL plan (coin on the KEY's BIP-84 address, index N or 1/N for change; bc1 heirs): see emPlanCmd
//   em plan show|clear
//   em ceremony <spendpin>  Bitcoin life: the stored plan, else a TEST plan with a fake coin (nothing broadcastable):
//                        every signature anti-exfil; blobs to NVS
//   em proof <hex>       EM_PROOF: kind|link|var|depth|index4|header80|branch20x32 (tools/ember_exec.py sends these)
//   em pulse             Nostr life: G0-built Pulse, signed, relation + BIP-340 checked, fed back as life, PUBLISHED on a relay
//   em away <days>       Nostr life, after an unlock: life stamp <days> ahead
//   em release           try the release the rule allows now (expect "refused" until a window opens),
//                        then a deliberately wrong blob (expect refused)
//   em clear             Bitcoin life: erase the plan
// =============================================================================
#ifdef FAVILLA_EMBERWILL   // 11cd: was FAVILLA_BENCH_PROBES; Emberwill ships as BETA
#include <WiFiClientSecure.h>
#include <WiFiClient.h>
#include <time.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <esp_heap_caps.h>
#include <ctype.h>

static uint32_t emRd32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void emWr32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static bool emHex(const char* h, uint8_t* out, size_t n, bool reverse) {
  if (strlen(h) != 2 * n) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned v; if (sscanf(h + 2 * i, "%2x", &v) != 1) return false;
    out[reverse ? n - 1 - i : i] = (uint8_t)v;
  }
  return true;
}
static void emPrintHex(const uint8_t* d, size_t n, bool reverse) { for (size_t i = 0; i < n; i++) Serial.printf("%02x", d[reverse ? n - 1 - i : i]); }

static const char* emNext(uint8_t w) { return w == 1 ? "REFRESH" : w == 2 ? "COUPON" : "nothing"; }
static const char* emEh(int rc) {
  switch (rc) { case 0: return "TIP"; case 1: return "REORG"; case 2: return "SIDE"; case 3: return "DUP"; case -1: return "ORPHAN";
    case -2: return "POW"; case -3: return "BITS"; case -4: return "TIME"; case -5: return "VER"; case -6: return "DEEP"; }
  return "?";
}

static bool emStatus(uint8_t s[96]) {
  int8_t rc; size_t n = 0;
  return g0_em_cmd(0x37, &rc, s, 96, &n, 800) && n == 96 && s[0] == 'E' && s[1] == 'M';
}
static void emPrintStatus(const uint8_t* s) {
  uint8_t f = s[5];
  if (f & 1)
    Serial.printf("[EMB] status v%u | boot KAT %s | plan yes state %s owner %s | silent %s afterglow %s kindled %s done %s adv-pending %s\n",
                  s[4], s[95] == 1 ? "PASS" : "FAIL", f & 2 ? "ok" : "MISSING", f & 4 ? "bound" : "-",
                  f & 8 ? "YES" : "no", f & 16 ? "SERVED" : "no", f & 32 ? "YES" : "no", f & 64 ? "YES" : "no", f & 128 ? "yes" : "no");
  else
    Serial.printf("[EMB] status v%u | boot KAT %s | plan no\n", s[4], s[95] == 1 ? "PASS" : "FAIL");
  Serial.printf("[EMB]   tip %lu (header time %lu)  restart point %lu  tip hash ", (unsigned long)emRd32(s + 8), (unsigned long)emRd32(s + 12), (unsigned long)emRd32(s + 40));
  emPrintHex(s + 48, 32, true); Serial.println();
  if (f & 1) {
    uint32_t tip = emRd32(s + 8), x = emRd32(s + 16), q = emRd32(s + 36), life = emRd32(s + 20);
    Serial.printf("[EMB]   link %u of %u  X %lu (%ld blocks away)  Quiet %lu  last_life %lu  last_tier1 %lu  last_pulse %lu  afterglow %lu s\n",
                  s[6], s[7], (unsigned long)x, (long)x - (long)tip, (unsigned long)q, (unsigned long)life,
                  (unsigned long)emRd32(s + 24), (unsigned long)emRd32(s + 28), (unsigned long)emRd32(s + 32));
    Serial.printf("[EMB]   refresh window opens at %lu; silent at %lu; next allowed: %s link %u var %u\n",
                  (unsigned long)(x - q / 2), (unsigned long)(life + q), emNext(s[44]), s[45], s[46]);
  }
}

#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
// ── mempool.space (bench only; the G0 verifies every header itself) ─────────
// Source of headers. Default: mempool.space over TLS. `em src http://<pc-ip>:8088`
// switches to tools/ember_proxy.py on your PC (plain HTTP on the LAN, the PC does
// the TLS). Either way the G0 checks every header's proof of work itself, so the
// source only has to be available, not trusted.
static String emBase() {
  Preferences p; String b = "https://mempool.space";
  if (p.begin("emb", true)) { String v = p.getString("src", ""); if (v.length()) b = v; p.end(); }
  return b;
}
static bool emGet(const String& path, String& body) {
  if (WiFi.status() != WL_CONNECTED) { Serial.println("[EMB] no WiFi (this needs a Nostr life with WiFi up)"); return false; }
  String url = emBase() + path;
  HTTPClient h; h.setTimeout(15000);
  WiFiClientSecure cs; WiFiClient cp;
  bool tls = url.startsWith("https://");
  if (tls) cs.setCACert(BTC_CA_BUNDLE);
  if (!(tls ? h.begin(cs, url) : h.begin(cp, url))) { Serial.printf("[EMB] cannot start %s\n", url.c_str()); return false; }
  int code = h.GET();
  if (code != 200) {
    Serial.printf("[EMB] GET %s -> %d (%s)\n", url.c_str(), code, h.errorToString(code).c_str());
    if (tls) {
      char e[120] = {0}; int le = cs.lastError(e, sizeof e);
      time_t now = time(nullptr);
      Serial.printf("[EMB]   TLS: %d %s | free internal %u, largest block %u | clock %ld (%s)\n", le, e,
                    (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
                    (long)now, now > 1700000000 ? "set" : "NOT SET - cert dates cannot be checked");
      Serial.println("[EMB]   fallback: run tools\\ember_proxy.py on your PC, then: em src http://<pc-ip>:8088");
    }
    h.end(); return false;
  }
  body = h.getString(); h.end();
  return true;
}
static bool emNetTip(uint32_t* tip) {
  String b; if (!emGet("/api/blocks/tip/height", b)) return false;
  *tip = (uint32_t)b.toInt(); return *tip > 800000;
}
// Up to 15 headers ending at `top` (mempool returns top, top-1, ...), rebuilt
// from the JSON fields and checked against the block id before use.
// Streamed straight into a filtered JsonDocument held in PSRAM: no String copy
// of the ~20 KB page and nothing big in internal RAM (bench-4 kept both in
// internal heap on every page and the KEY reset part way through a long sync).
struct EmPsramAlloc : ArduinoJson::Allocator {
  void* allocate(size_t n) override { void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); return p ? p : malloc(n); }
  void deallocate(void* p) override { free(p); }
  void* reallocate(void* p, size_t n) override { void* q = heap_caps_realloc(p, n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); return q ? q : realloc(p, n); }
};
static EmPsramAlloc s_emAlloc;
static int emFetch15(uint32_t top, uint8_t (*hdr)[80], uint32_t* hgt) {
  if (WiFi.status() != WL_CONNECTED) { Serial.println("[EMB] no WiFi (this needs a Nostr life with WiFi up)"); return -1; }
  String url = emBase() + "/api/v1/blocks/" + top;
  HTTPClient hc; hc.setTimeout(15000); hc.useHTTP10(true);          // HTTP/1.0: no chunked body, so the stream is plain JSON
  WiFiClientSecure cs; WiFiClient cp;
  bool tls = url.startsWith("https://");
  if (tls) cs.setCACert(BTC_CA_BUNDLE);
  if (!(tls ? hc.begin(cs, url) : hc.begin(cp, url))) { Serial.printf("[EMB] cannot start %s\n", url.c_str()); return -1; }
  int code = hc.GET();
  if (code != 200) { Serial.printf("[EMB] GET %s -> %d (%s)\n", url.c_str(), code, hc.errorToString(code).c_str()); hc.end(); return -1; }
  JsonDocument filter;
  filter[0]["id"] = true; filter[0]["height"] = true; filter[0]["version"] = true; filter[0]["timestamp"] = true;
  filter[0]["bits"] = true; filter[0]["nonce"] = true; filter[0]["merkle_root"] = true; filter[0]["previousblockhash"] = true;
  JsonDocument doc(&s_emAlloc);
  DeserializationError err = deserializeJson(doc, hc.getStream(), DeserializationOption::Filter(filter));
  hc.end();
  if (err) { Serial.printf("[EMB] JSON parse failed: %s\n", err.c_str()); return -1; }
  JsonArray a = doc.as<JsonArray>(); int n = 0;
  for (JsonObject o : a) {
    if (n >= 15) break;
    uint8_t* h = hdr[n]; uint8_t id[32], calc[32], t1[32];
    const char* prev = o["previousblockhash"] | ""; const char* mr = o["merkle_root"] | ""; const char* ids = o["id"] | "";
    emWr32(h, (uint32_t)(o["version"] | 0u));
    if (!emHex(prev, h + 4, 32, true) || !emHex(mr, h + 36, 32, true) || !emHex(ids, id, 32, true)) { Serial.println("[EMB] bad hex in JSON"); return -1; }
    emWr32(h + 68, (uint32_t)(o["timestamp"] | 0u)); emWr32(h + 72, (uint32_t)(o["bits"] | 0u)); emWr32(h + 76, (uint32_t)(o["nonce"] | 0u));   // unsigned: nonces exceed INT_MAX
    mbedtls_sha256(h, 80, t1, 0); mbedtls_sha256(t1, 32, calc, 0);
    if (memcmp(calc, id, 32) != 0) { Serial.printf("[EMB] rebuilt header %lu does not hash to its id - check the field mapping\n", (unsigned long)(o["height"] | 0)); return -1; }
    hgt[n] = (uint32_t)(o["height"] | 0u); n++;
  }
  return n;
}

#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
// ── header cache in NVS (so a Bitcoin life, with no radio, can catch the G0 up) ──
static uint8_t (*s_emRing)[80] = nullptr;   // 32 x 80 in PSRAM, see emCacheLoad
static uint32_t s_emFirst = 0; static int s_emCnt = 0; static bool s_emLoaded = false;
static void emCacheLoad() {
  if (s_emLoaded) return;
  if (!s_emRing) s_emRing = (uint8_t (*)[80])heap_caps_calloc(32, 80, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  Preferences p; if (p.begin("emb", true)) { s_emCnt = p.getBytes("hc", s_emRing, 32 * 80) / 80; s_emFirst = p.getUInt("hf", 0); p.end(); }
  s_emLoaded = true;
}
static void emCacheFlush() {
  Preferences p; if (p.begin("emb", false)) { p.putBytes("hc", s_emRing, s_emCnt * 80); p.putUInt("hf", s_emFirst); p.end(); }
}
static void emCachePut(uint32_t height, const uint8_t hdr[80]) {
  emCacheLoad();
  if (s_emCnt && height != s_emFirst + s_emCnt) s_emCnt = 0;       // not contiguous: start over
  if (!s_emCnt) s_emFirst = height;
  if (s_emCnt == 32) { memmove(s_emRing[0], s_emRing[1], 31 * 80); s_emCnt = 31; s_emFirst++; }
  memcpy(s_emRing[s_emCnt++], hdr, 80);
}

#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
static void emSync(uint32_t maxn) {
  uint8_t s[96]; if (!emStatus(s)) { Serial.println("[EMB] no Emberwill G0 (flash g0w-ember)"); return; }
  uint32_t have = emRd32(s + 8), net = 0;
  if (!emNetTip(&net)) return;
  Serial.printf("[EMB] G0 tip %lu, network tip %lu: %lu headers to feed\n", (unsigned long)have, (unsigned long)net, (unsigned long)(net - have));
  uint32_t fed = 0, t0 = millis(), g0ms = 0; int8_t rc = 0;
  uint32_t h = have + 1;
  static uint8_t (*hdr)[80] = nullptr; uint32_t hgt[15];
  if (!hdr && !(hdr = (uint8_t (*)[80])heap_caps_malloc(15 * 80, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT))) return;
  emCacheLoad();
  while (h <= net && fed < maxn) {
    uint32_t top = h + 9 > net ? net : h + 9;            // pages are 10 or 15 blocks ending at `top`: 10 covers both
    int n = emFetch15(top, hdr, hgt); if (n <= 0) return;
    for (int i = n - 1; i >= 0; i--) {                          // ascending
      if (hgt[i] < h) continue;
      uint32_t a = millis();
      if (!g0_em_header(hdr[i], true, &rc, s)) { Serial.println("[EMB] G0 did not answer EM_HEADER"); return; }
      g0ms += millis() - a;
      if (rc != 0) { Serial.printf("[EMB] header %lu: %s (%d) - stopping\n", (unsigned long)hgt[i], emEh(rc), rc); emCacheFlush(); return; }
      emCachePut(hgt[i], hdr[i]);
      h = hgt[i] + 1; fed++;
      if (fed % 100 == 0) Serial.printf("[EMB]   %lu fed, at %lu | %lu s | internal heap %u, largest %u\n", (unsigned long)fed, (unsigned long)hgt[i],
                                        (unsigned long)((millis() - t0) / 1000), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                                        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
      if (fed % 500 == 0) { size_t sn = 0; int8_t src = 0; if (g0_em_cmd(0x3C, &src, nullptr, 0, &sn, 5000)) Serial.printf("[EMB]   EM_SAVE rc %d (checkpoint)\n", src); }
      esp_task_wdt_reset();
    }
  }
  Serial.printf("[EMB] fed %lu headers in %lu s (G0 time %lu ms, %lu ms per header incl. I2C)\n", (unsigned long)fed,
                (unsigned long)((millis() - t0) / 1000), (unsigned long)g0ms, (unsigned long)(fed ? g0ms / fed : 0));
  emCacheFlush();
  size_t n = 0; if (g0_em_cmd(0x3C, &rc, nullptr, 0, &n, 5000)) Serial.printf("[EMB] EM_SAVE rc %d\n", rc);
  if (emStatus(s)) emPrintStatus(s);
}

static void emFeedCache() {
  emCacheLoad();
  int cnt = s_emCnt; uint32_t first = s_emFirst; uint8_t (*ring)[80] = s_emRing;
  if (!cnt) { Serial.println("[EMB] no cached headers (run em sync in a Nostr life first)"); return; }
  int tips = 0, dups = 0, other = 0; int8_t rc; uint8_t s[96];
  for (int i = 0; i < cnt; i++) {
    if (!g0_em_header(ring[i], false, &rc, s)) { Serial.println("[EMB] G0 did not answer"); return; }
    if (rc == 0) tips++; else if (rc == 3) dups++; else other++;
  }
  Serial.printf("[EMB] cache %lu..%lu re-fed: %d new, %d already held, %d refused/orphan (heights below the G0's restart point are expected to be refused)\n",
                (unsigned long)first, (unsigned long)(first + cnt - 1), tips, dups, other);
  if (emStatus(s)) emPrintStatus(s);
}

static void emAnchor() {
  uint32_t net; if (!emNetTip(&net)) return;
  uint32_t S = ((net - 110) / 2016) * 2016;
  static uint8_t (*hdr)[80] = nullptr; uint32_t hgt[30];
  if (!hdr && !(hdr = (uint8_t (*)[80])heap_caps_malloc(30 * 80, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT))) return;
  int n1 = emFetch15(S + 10, hdr, hgt); if (n1 <= 0) return;             // S+10 and below
  int n2 = emFetch15(S, hdr + n1, hgt + n1); if (n2 <= 0) return;      // S and below (covers a 10-block page size)
  int n = n1 + n2;
  Serial.printf("[EMB] anchor candidate: period start S = %lu, anchor A = S + 10 = %lu (network tip %lu)\n", (unsigned long)S, (unsigned long)(S + 10), (unsigned long)net);
  Serial.println("[EMB] ---- copy the 11 lines between the markers into headers.txt ----");
  Serial.println("----BEGIN----");
  int got = 0;
  for (uint32_t want = S; want <= S + 10; want++)
    for (int i = 0; i < n; i++) if (hgt[i] == want) { emPrintHex(hdr[i], 80, false); Serial.println(); got++; break; }
  Serial.println("----END----");
  if (got != 11) { Serial.printf("[EMB] only %d of 11 headers found - run em anchor again\n", got); return; }
  Serial.printf("[EMB] then: python tools\\make_anchor.py --start %lu headers.txt > include\\ember_anchor.h\n", (unsigned long)S);
}

// ── the test plan ────────────────────────────────────────────────────────────
#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
// ── 11cd (G0 v20, issue #40 A1): the ESP32's own check of the ceremony ──────
// src/ember_check.h does the checking; these hooks feed it from the G0 driver
// (g0_em_ceremony) and keep each checked transaction's txid in NVS ("ct"), so
// a release years later is broadcast only if it is one of them.
#include "ember_check.h"
static ewc::Check* g_ewc = nullptr; static const uint8_t* g_ewcWire = nullptr;
static bool ewcOnSet(uint32_t tip0) {
  if (!g_ewc) g_ewc = (ewc::Check*)heap_caps_malloc(sizeof(ewc::Check), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!g_ewc || !g_ewcWire) return false;
  ewc::Plan p; if (!ewc::parsePlan(g_ewcWire, p)) { Serial.println("[EMC] plan not readable"); return false; }
  uint8_t cpub[ewc::MAX_COINS][33], rpub[ewc::MAX_LINKS][33];
  for (int i = 0; i < p.ncoins; i++)
    if (!btc_derive_pubkey_pub(p.coin[i].change, p.coin[i].index, cpub[i])) { Serial.println("[EMC] no account xpub on this KEY: cannot check the plan's keys"); return false; }
  for (int i = 0; i < p.nlinks; i++)
    if (!btc_derive_pubkey_pub(0, p.ref_index + (uint32_t)i, rpub[i])) { Serial.println("[EMC] no account xpub on this KEY"); return false; }
  const int e = ewc::begin(*g_ewc, g_ewcWire, tip0, 1008, cpub, rpub);
  Serial.printf("[EMC] check started: tip %lu, %lu transactions to check%s\n", (unsigned long)tip0, (unsigned long)ewc::count(p), e ? " - REFUSED" : "");
  return e == 0;
}
static bool ewcOnSig(unsigned k, unsigned input, const uint8_t sh[32], const uint8_t* tx, size_t tl) {
  if (!g_ewc) return false;
  if (tl) {
#ifdef FAVILLA_BENCH_PROBES
    // a short-fuse bench G0 (g0_fuse, Afterglow 6 blocks): learnt from C0's own lock
    if (k == 0 && tl >= 4) { const uint32_t lt = ewc::rd32(tx + tl - 4);
      if (lt == g_ewc->tip0 + g_ewc->plan.quiet + 6u) { g_ewc->afterglow = 6; Serial.println("[EMC] bench G0 (Afterglow 6 blocks)"); } }
#endif
    const int e = ewc::tx(*g_ewc, k, tx, tl);
    if (e) { Serial.printf("[EMC] transaction %u REFUSED: %s\n", k, ewc::errText(e)); return false; }
  }
  const int e = ewc::digest(*g_ewc, k, input, sh);
  if (e) { Serial.printf("[EMC] transaction %u input %u REFUSED: %s\n", k, input, ewc::errText(e)); return false; }
  return true;
}
static bool ewcOnDone() {
  if (!g_ewc || !ewc::complete(*g_ewc)) return false;
  Preferences p; if (!p.begin("emb", false)) return false;
  const size_t n = (size_t)g_ewc->ntx * 32;
  const bool ok = p.putBytes("ct", g_ewc->txid, n) == n; p.end();
  Serial.printf("[EMC] every transaction matched the plan: %lu checked, txids kept\n", (unsigned long)g_ewc->ntx);
  return ok;
}
static const EmCerHooks g_ewcHooks = { ewcOnSet, ewcOnSig, ewcOnDone };
// At release: the transaction must be one the ceremony check passed.
static bool ewcReleaseKnown(unsigned k, const uint8_t txid[32]) {
  uint8_t t[ewc::MAX_TX][32]; size_t n = 0;
  { Preferences p; if (p.begin("emb", true)) { n = p.getBytes("ct", t, sizeof t); p.end(); } }
  if (n < (size_t)(k + 1) * 32) { Serial.println("[EMC] no ceremony check on record (plan sealed before G0 v20): not broadcast, seal the plan again"); return false; }
  if (memcmp(t[k], txid, 32)) { Serial.printf("[EMC] released transaction %u is NOT the one checked at the ceremony: not broadcast\n", k); return false; }
  return true;
}

static bool emBlobSink(uint16_t k, const uint8_t* blob, size_t n) {
  Preferences p; if (!p.begin("emb", false)) return false;
  char key[6]; snprintf(key, sizeof key, "b%u", (unsigned)k);
  bool ok = p.putBytes(key, blob, n) == n; p.putUInt("nb", (uint32_t)k + 1); p.end();
  return ok;
}
#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
static void emTestPlan(uint8_t w[430]) {
  memset(w, 0, 430);
  w[0] = 1; w[1] = 2; w[2] = 2;                                   // 1 coin, 2 heirs, 2 links
  uint8_t* c = w + 4;
  mbedtls_sha256((const uint8_t*)"Favilla Emberwill bench coin - not a real outpoint", 50, c, 0);
  emWr32(c + 32, 0); emWr32(c + 36, 1000000); emWr32(c + 40, 0);  // vout 0, 1,000,000 sats
  emWr32(c + 44, 0); emWr32(c + 48, 0);                           // m/84'/0'/0'/0/0
  uint8_t* h1 = w + 160; h1[0] = 0x00; h1[1] = 0x14; memset(h1 + 2, 0x11, 20); h1[34] = 0x70; h1[35] = 0x17;   // 6000 bp
  uint8_t* h2 = w + 196; h2[0] = 0x51; h2[1] = 0x20; memset(h2 + 2, 0x22, 32); h2[34] = 0xA0; h2[35] = 0x0F;   // 4000 bp (P2TR)
  w[376] = 0x00; w[377] = 0x14; memset(w + 378, 0x33, 20);       // executor
  emWr32(w + 410, 4032); emWr32(w + 414, 1000);                    // Quiet 4032, refresh addresses from /0/1000
  w[418] = 2; w[420] = 10; w[422] = 50; w[424] = 5;               // coupon 2/10/50, refresh 5 sat/vB
  emWr32(w + 426, 1000);                                            // bump 1000 sats
}
// ── a real plan: em plan <txid> <vout> <sats> <index> <addr>:<bp> [<addr>:<bp> ...] [q=12] [links=2] [c=2,6,20] [r=4] [b=1000] [ref=<idx>] [exec=<addr>]
// The coin must sit on the KEY's own BIP-84 receive address m/84'/0'/0'/0/<index>.
// Heir addresses are bc1 (P2WPKH, P2WSH or P2TR); shares in basis points, sum 10000.
// Stored in NVS (emb/plan, 430 bytes); em ceremony uses it when present.
static const char* B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static uint32_t b32Polymod(const uint8_t* v, size_t n) {
  static const uint32_t G[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  uint32_t c = 1;
  for (size_t i = 0; i < n; i++) { uint32_t b = c >> 25; c = ((c & 0x1ffffff) << 5) ^ v[i]; for (int k = 0; k < 5; k++) if ((b >> k) & 1) c ^= G[k]; }
  return c;
}
// bc1... -> scriptPubKey (padded to 34). Returns the script length or 0.
static int emAddrToSpk(const char* a, uint8_t spk[34]) {
  size_t n = strlen(a); if (n < 14 || n > 90) return 0;
  char lo[91]; for (size_t i = 0; i <= n; i++) lo[i] = (char)tolower((unsigned char)a[i]);
  if (strncmp(lo, "bc1", 3) != 0) return 0;
  const char* d = lo + 3; size_t dn = n - 3; if (dn < 7) return 0;
  uint8_t v[96]; size_t vn = 0;
  // hrp expansion for "bc": [b>>5, c>>5, 0, b&31, c&31]
  uint8_t pre[5] = { 'b' >> 5, 'c' >> 5, 0, 'b' & 31, 'c' & 31 }; memcpy(v, pre, 5); vn = 5;
  for (size_t i = 0; i < dn; i++) { const char* q = strchr(B32, d[i]); if (!q) return 0; v[vn++] = (uint8_t)(q - B32); }
  uint32_t pm = b32Polymod(v, vn); uint8_t wver = v[5];
  if (!((wver == 0 && pm == 1) || (wver != 0 && pm == 0x2bc830a3))) return 0;   // bech32 for v0, bech32m for v1+
  // 5-bit groups after the version, minus the 6 checksum groups -> bytes
  uint8_t out[40]; size_t on = 0; uint32_t acc = 0; int bits = 0;
  for (size_t i = 6; i < vn - 6; i++) { acc = (acc << 5) | v[i]; bits += 5; if (bits >= 8) { bits -= 8; if (on >= sizeof out) return 0; out[on++] = (uint8_t)(acc >> bits); } }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) return 0;
  memset(spk, 0, 34);
  if (wver == 0 && (on == 20 || on == 32)) { spk[0] = 0x00; spk[1] = (uint8_t)on; memcpy(spk + 2, out, on); return 2 + (int)on; }
  if (wver == 1 && on == 32) { spk[0] = 0x51; spk[1] = 0x20; memcpy(spk + 2, out, 32); return 34; }
  return 0;
}
#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
static bool emPlanLoad(uint8_t w[430]) {
  Preferences p; if (!p.begin("emb", true)) return false;
  size_t n = p.getBytes("plan", w, 430); p.end(); return n == 430;
}
static void emPlanShow(const uint8_t* w) {
  Serial.printf("[EMB] plan: %u coin(s), %u heir(s), %u link(s), Quiet %lu, refresh from /0/%lu, coupon %u/%u/%u refresh %u sat/vB, bump %lu\n",
                w[0], w[1], w[2], (unsigned long)emRd32(w + 410), (unsigned long)emRd32(w + 414), w[418] | (w[419] << 8), w[420] | (w[421] << 8), w[422] | (w[423] << 8), w[424] | (w[425] << 8), (unsigned long)emRd32(w + 426));
  for (int i = 0; i < w[0]; i++) { const uint8_t* c = w + 4 + i * 52; Serial.printf("[EMB]   coin %d: ", i); emPrintHex(c, 32, true); Serial.printf(":%lu  %lu sats  m/84'/0'/0'/%lu/%lu\n", (unsigned long)emRd32(c + 32), (unsigned long)emRd32(c + 36), (unsigned long)emRd32(c + 44), (unsigned long)emRd32(c + 48)); }
  for (int j = 0; j < w[1]; j++) { const uint8_t* h = w + 160 + j * 36; Serial.printf("[EMB]   heir %d: spk ", j); emPrintHex(h, h[1] + 2, false); Serial.printf("  %u bp\n", h[34] | (h[35] << 8)); }
  Serial.print("[EMB]   executor spk "); emPrintHex(w + 376, w[377] + 2, false); Serial.println();
}
#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
static void emPlanCmd(const String& args) {
  if (args == "show") { uint8_t w[430]; if (emPlanLoad(w)) emPlanShow(w); else Serial.println("[EMB] no stored plan (the built-in test plan would be used)"); return; }
  if (args == "clear") { Preferences p; if (p.begin("emb", false)) { p.remove("plan"); p.end(); } Serial.println("[EMB] stored plan cleared"); return; }
  // tokens
  const int MAXT = 16; String t[MAXT]; int nt = 0; int st = 0;
  for (int i = 0; i <= (int)args.length() && nt < MAXT; i++) { if (i == (int)args.length() || args[i] == ' ') { if (i > st) t[nt++] = args.substring(st, i); st = i + 1; } }
  if (nt < 5) { Serial.println("[EMB] usage: em plan <txid> <vout> <sats> <index|1/index> <bc1addr>:<bp> [<bc1addr>:<bp> ...] [q=12] [links=2] [c=2,6,20] [r=4] [b=1000] [ref=<idx>] [exec=<bc1addr>]"); return; }
  uint8_t w[430]; memset(w, 0, 430);
  uint8_t* c = w + 4;
  if (t[0].length() != 64 || !emHex(t[0].c_str(), c, 32, true)) { Serial.println("[EMB] bad txid (64 hex)"); return; }
  emWr32(c + 32, (uint32_t)t[1].toInt()); emWr32(c + 36, (uint32_t)t[2].toInt()); emWr32(c + 40, 0);
  // index: "N" = receive m/84'/0'/0'/0/N, "1/N" = change m/84'/0'/0'/1/N
  uint32_t branch = 0, index; { String ix = t[3]; int sl = ix.indexOf('/'); if (sl > 0) { branch = (uint32_t)ix.substring(0, sl).toInt(); index = (uint32_t)ix.substring(sl + 1).toInt(); } else index = (uint32_t)ix.toInt(); }
  if (branch > 1) { Serial.println("[EMB] branch must be 0 (receive) or 1 (change)"); return; }
  emWr32(c + 44, branch); emWr32(c + 48, index);
  w[0] = 1;
  uint32_t quiet = 12, links = 2, ref = branch == 0 ? index + 1 : 100, bump = 1000; uint16_t cr[3] = {2, 6, 20}, rr = 4; uint8_t execSpk[34] = {0}; bool execSet = false;
  int nh = 0, bpsum = 0;
  for (int i = 4; i < nt; i++) {
    String a = t[i];
    if (a.startsWith("q=")) quiet = (uint32_t)a.substring(2).toInt();
    else if (a.startsWith("links=")) links = (uint32_t)a.substring(6).toInt();
    else if (a.startsWith("r=")) rr = (uint16_t)a.substring(2).toInt();
    else if (a.startsWith("b=")) bump = (uint32_t)a.substring(2).toInt();
    else if (a.startsWith("ref=")) ref = (uint32_t)a.substring(4).toInt();
    else if (a.startsWith("c=")) { String v = a.substring(2); int p1 = v.indexOf(','), p2 = v.lastIndexOf(','); if (p1 < 0 || p2 <= p1) { Serial.println("[EMB] c=low,mid,high"); return; } cr[0] = (uint16_t)v.substring(0, p1).toInt(); cr[1] = (uint16_t)v.substring(p1 + 1, p2).toInt(); cr[2] = (uint16_t)v.substring(p2 + 1).toInt(); }
    else if (a.startsWith("exec=")) { if (!emAddrToSpk(a.substring(5).c_str(), execSpk)) { Serial.println("[EMB] bad exec address"); return; } execSet = true; }
    else {
      int colon = a.indexOf(':'); if (colon < 0 || nh >= 6) { Serial.printf("[EMB] bad heir '%s' (want bc1addr:bp)\n", a.c_str()); return; }
      uint8_t* h = w + 160 + nh * 36;
      if (!emAddrToSpk(a.substring(0, colon).c_str(), h)) { Serial.printf("[EMB] bad heir address '%s'\n", a.substring(0, colon).c_str()); return; }
      int bp = a.substring(colon + 1).toInt(); if (bp <= 0 || bp > 10000) { Serial.println("[EMB] bp must be 1..10000"); return; }
      h[34] = (uint8_t)bp; h[35] = (uint8_t)(bp >> 8); bpsum += bp; nh++;
    }
  }
  if (!nh) { Serial.println("[EMB] at least one heir"); return; }
  if (bpsum != 10000) { Serial.printf("[EMB] heir shares sum to %d bp, need 10000\n", bpsum); return; }
  if (links < 1 || links > 8) { Serial.println("[EMB] links 1..8"); return; }
  w[1] = (uint8_t)nh; w[2] = (uint8_t)links;
  memcpy(w + 376, execSet ? execSpk : w + 160, 34);                // executor bump: heir 1 unless given
  emWr32(w + 410, quiet); emWr32(w + 414, ref);
  w[418] = (uint8_t)cr[0]; w[419] = (uint8_t)(cr[0] >> 8); w[420] = (uint8_t)cr[1]; w[421] = (uint8_t)(cr[1] >> 8); w[422] = (uint8_t)cr[2]; w[423] = (uint8_t)(cr[2] >> 8);
  w[424] = (uint8_t)rr; w[425] = (uint8_t)(rr >> 8); emWr32(w + 426, bump);
  Preferences p; if (!p.begin("emb", false) || p.putBytes("plan", w, 430) != 430) { Serial.println("[EMB] NVS write failed"); return; }
  p.end();
  Serial.println("[EMB] plan stored; the G0 validates it at em ceremony");
  emPlanShow(w);
}
static void emProof(const String& hex) {
  static uint8_t* b = nullptr; if (!b) b = (uint8_t*)heap_caps_malloc(728, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!b || hex.length() != 1456 || !emHex(hex.c_str(), b, 728, false)) { Serial.println("[EMB] proof: need 1456 hex chars (kind|link|var|depth|index4|header80|branch 20x32)"); return; }
  int8_t rc; size_t n = 0; uint8_t s[96];
  bool ok = g0_em_stage(b, 728) && g0_em_cmd(0x35, &rc, nullptr, 0, &n, 5000);
  Serial.printf("[EMB] EM_PROOF %s rc %d (0 ok, -28 proof does not check, -26 not what the walk is waiting for)\n", ok ? "answered" : "no answer", ok ? rc : -128);
  if (emStatus(s)) emPrintStatus(s);
}
static void emCeremony(const String& pin) {
  if (pin.length() != (size_t)PIN_NEW_LEN) { Serial.println("[EMB] usage: em ceremony <spend PIN>"); return; }
  uint8_t s[96]; if (!emStatus(s)) { Serial.println("[EMB] no Emberwill G0"); return; }
  Serial.printf("[EMB] ceremony at G0 tip %lu (run em feed first in a Bitcoin life so the tip is current)\n", (unsigned long)emRd32(s + 8));
  strncpy(g_psbt_pin, pin.c_str(), sizeof(g_psbt_pin) - 1);
  uint8_t pkt[G0_SEED_IN_LEN]; uint8_t kind = 0;
  I2C_LOCK();
  int wsp = btcWitnessedSpendOpen(false, false, pkt, &kind);
  I2C_UNLOCK();
  if (wsp != 1) { mbedtls_platform_zeroize(pkt, sizeof pkt); Serial.printf("[EMB] spend session failed (%d: 0 wrong PIN, -1 refused / not a Bitcoin life)\n", wsp); return; }
  { Preferences p; if (p.begin("emb", false)) { p.remove("nb"); p.end(); } }
  uint8_t w[430];
  if (emPlanLoad(w)) { Serial.println("[EMB] using the stored plan (em plan show)"); emPlanShow(w); }
  else { Serial.println("[EMB] no stored plan: using the built-in TEST plan (fake coin, nothing can be broadcast)"); emTestPlan(w); }
  g_ewcWire = w;
  bool ok = g0_em_ceremony(w, pkt, kind, emBlobSink, nullptr, &g_ewcHooks);
  mbedtls_platform_zeroize(pkt, sizeof pkt);
  Serial.printf("[EMB] ceremony %s\n", ok ? "COMPLETE - plan committed on the G0, blobs in NVS (emb/b0..)" : "FAILED");
  if (emStatus(s)) emPrintStatus(s);
}

#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
static bool emLoadBlob(unsigned k, uint8_t* b, size_t cap, size_t* n) {
  Preferences p; if (!p.begin("emb", true)) return false;
  char key[6]; snprintf(key, sizeof key, "b%u", k);
  *n = p.getBytes(key, b, cap); p.end();
  return *n > 40;
}
#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
static void emRelease() {
  uint8_t s[96]; if (!emStatus(s) || !(s[5] & 1)) { Serial.println("[EMB] no plan"); return; }
  static uint8_t *b = nullptr, *out = nullptr; size_t bn, n = 0; int8_t rc;
  if (!b) b = (uint8_t*)heap_caps_malloc(1300, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!out) out = (uint8_t*)heap_caps_malloc(1200, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!b || !out) return;
  unsigned what = s[44], link = s[45], var = s[46];
  unsigned k = what == 1 ? 3 + (link - 1) * 4 : what == 2 ? (link == 0 ? var : 3 + (link - 1) * 4 + 1 + var) : 0;
  Serial.printf("[EMB] the rule allows: %s (link %u var %u) -> trying blob %u\n", emNext(what), link, var, k);
  if (!emLoadBlob(k, b, 1300, &bn)) { Serial.println("[EMB] blob not in NVS"); return; }
  bool ok = g0_em_stage(b, bn) && g0_em_cmd(0x38, &rc, out, 1200, &n, 5000);
  if (ok && rc == 0) { Serial.printf("[EMB] RELEASED %u bytes (signed transaction):\n", (unsigned)n); emPrintHex(out, n, false); Serial.println(); }
  else Serial.printf("[EMB] release refused rc %d (%s)\n", rc, rc == -26 ? "the rule does not allow it now - expected while the owner is alive and before the window" : rc == -27 ? "blob check failed" : "?");
  // a wrong blob is always refused
  unsigned nb = 11; { Preferences p; if (p.begin("emb", true)) { nb = p.getUInt("nb", 11); p.end(); } if (!nb) nb = 1; }
  unsigned k2 = (k + 1) % nb;
  if (emLoadBlob(k2, b, 1300, &bn)) {
    b[20] ^= 1;
    ok = g0_em_stage(b, bn) && g0_em_cmd(0x38, &rc, out, 1200, &n, 5000);
    Serial.printf("[EMB] tampered blob %u: %s (rc %d)\n", k2, rc != 0 ? "refused" : "RELEASED - BUG", rc);
  }
}


#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
// Bitcoin P2P fetch and the Pulse publish live in ember_mvp.inc (included after this file).
static uint32_t emwSyncP2p(const String& hostArg, uint32_t maxn, bool ui);
static bool emwPulsePublish(bool ui);
static void emwDebug(const char* why);
static void emwExecute(bool ui);
static void emwXpShow();
static void emwXpClear();

#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
static void emHelp() {
  Serial.println("[EMB] em status | em src [url] | em anchor | em sync [max] | em p2p [host] | em feed | em hdr <hex> | em hdr-done | em save | em plan ... | em ceremony <spendpin> | em proof <hex> | em pulse | em away <days> | em release | em clear");
}

#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
// 28 Oct 2026: a bench host talking over USB serial (tools/ember_exec.py) loses
// the port when the KEY light-sleeps. Any em command holds the chip awake for
// five minutes; emSerialHoldTick (from emwTick) lets go when the host stops.
static uint32_t g_emSerialMs = 0; static bool g_emSerialHeld = false;
static void emSerialTouch() { g_emSerialMs = millis(); if (!g_emSerialHeld) { pmHoldWakeTag("ems"); g_emSerialHeld = true; } }
static void emSerialHoldTick() { if (g_emSerialHeld && millis() - g_emSerialMs > 300000UL) { pmReleaseWakeTag("ems"); g_emSerialHeld = false; } }
#ifdef FAVILLA_BENCH_PROBES   // 11cd: bench serial tools only; the rest is Emberwill itself
static bool emberBenchSerial(const String& line) {
  emSerialTouch();
  String a = line.substring(2); a.trim();
  uint8_t s[96]; int8_t rc; size_t n = 0;
  if (a == "status") {
    if (emStatus(s)) emPrintStatus(s); else Serial.println("[EMB] no answer - is the g0w-ember image flashed?");
    Serial.printf("[EMB]   ESP32 last reset reason %d (1 power-on, 3 software, 4 panic, 5/6/7 watchdog, 9 brownout) | up %lu s\n",
                  (int)esp_reset_reason(), (unsigned long)(millis() / 1000));
  }
  else if (a == "anchor") emAnchor();
  else if (a.startsWith("sync")) { String m = a.substring(4); m.trim(); emSync(m.length() ? (uint32_t)m.toInt() : 100000); }
  else if (a == "feed") emFeedCache();
  else if (a == "mvp") emwDebug("asked");
  else if (a == "exec") emwExecute(true);          // 29 Oct 2026: the KEY's own executor, now (it also runs after every sync)
  else if (a == "xp") emwXpShow();
  else if (a == "xp clear") { emwXpClear(); Serial.println("[EMX] pending cleared"); }
  else if (a.startsWith("plan")) { String r = a.substring(4); r.trim(); emPlanCmd(r); }
  else if (a.startsWith("proof ")) { String h = a.substring(6); h.trim(); emProof(h); }
  else if (a.startsWith("p2p")) { String h = a.substring(3); h.trim(); uint32_t m = 100000; int sp = h.indexOf(' '); if (sp > 0) { m = (uint32_t)h.substring(sp + 1).toInt(); h = h.substring(0, sp); } emwSyncP2p(h, m ? m : 100000, true); }
  else if (a.startsWith("hdr ")) {                       // one header over USB serial, from tools/ember_feed.py: no WiFi involved
    String x = a.substring(4); x.trim(); uint8_t h80[80];
    if (x.length() != 160 || !emHex(x.c_str(), h80, 80, false)) { Serial.println("[EMB] hdr: need 160 hex chars"); return true; }
    uint32_t t0 = millis();
    if (!g0_em_header(h80, true, &rc, s)) { Serial.println("[EMB] hdr: G0 did not answer"); return true; }
    uint32_t tip = emRd32(s + 8);
    if (rc == 0) emCachePut(tip, h80);
    Serial.printf("[EMB] hdr rc %d %s tip %lu %lu ms\n", rc, emEh(rc), (unsigned long)tip, (unsigned long)(millis() - t0));
    if (rc == 0 && tip % 500 == 0) { size_t sn = 0; int8_t src = 0; if (g0_em_cmd(0x3C, &src, nullptr, 0, &sn, 5000)) Serial.printf("[EMB] EM_SAVE rc %d (checkpoint)\n", src); }
  }
  else if (a == "hdr-done") { emCacheFlush(); if (g0_em_cmd(0x3C, &rc, nullptr, 0, &n, 5000)) Serial.printf("[EMB] EM_SAVE rc %d\n", rc); if (emStatus(s)) emPrintStatus(s); }
  else if (a.startsWith("src")) {
    String u = a.substring(3); u.trim();
    Preferences p; if (p.begin("emb", false)) { if (u.length()) p.putString("src", u); else p.remove("src"); p.end(); }
    Serial.printf("[EMB] header source: %s\n", emBase().c_str());
  }
  else if (a == "save") { if (g0_em_cmd(0x3C, &rc, nullptr, 0, &n, 5000)) Serial.printf("[EMB] EM_SAVE rc %d\n", rc); }
  else if (a.startsWith("ceremony")) { String p = a.substring(8); p.trim(); emCeremony(p); }
  else if (a == "pulse") { emwPulsePublish(true); }   // G0 builds + signs, the KEY publishes it on a relay
  else if (a.startsWith("away")) {
    String d = a.substring(4); d.trim(); long days = d.toInt();
    if (days <= 0 || !emStatus(s)) { Serial.println("[EMB] usage: em away <days>"); }
    else { uint8_t arg[64] = {0}; emWr32(arg, emRd32(s + 8) + (uint32_t)days * 144u);
      bool ok = g0_em_write(0x1E, arg, 64) && g0_em_cmd(0x3B, &rc, nullptr, 0, &n, 3000);
      Serial.printf("[EMB] EM_AWAY %ld days: %s rc %d (-26 = no unlock this power-on, or more than a year)\n", days, ok && rc == 0 ? "ok" : "refused", rc);
      if (emStatus(s)) emPrintStatus(s); }
  }
  else if (a == "release") emRelease();
  else if (a == "clear") { if (g0_em_cmd(0x3A, &rc, nullptr, 0, &n, 8000)) Serial.printf("[EMB] EM_CLEAR rc %d\n", rc); else Serial.println("[EMB] EM_CLEAR refused (Bitcoin life only)"); }
  else emHelp();
  return true;
}
#endif  // FAVILLA_BENCH_PROBES (11cd: bench serial tools)
#endif  // FAVILLA_EMBERWILL
