// =============================================================================
// ember_mvp.inc — Emberwill on the KEY, owner + heir loop. 28 Oct 2026.
//
// Included at the END of main.cpp, after ember_bench.inc (it uses the bench's
// emStatus / emRd32 / emEh / header cache). Rides the bench env for now
// (FAVILLA_BENCH_PROBES); nothing here runs unless the G0 reports a plan.
//
// What it does, gated on "the G0 holds an Emberwill plan":
//   heir path   45 s after boot with WiFi (lock screen, no PIN), and every 4 h
//               while powered: pull headers from a Bitcoin node over plain P2P
//               and feed the G0; the chip is held out of light sleep while a
//               sync is owed
//   owner path  after a daily unlock: catch the G0 up, then build + sign a
//               Pulse on the G0 and publish it on a relay as the owner's life
//   screen      the footer carries "ember · ALIVE · 35d" while a plan exists;
//               work in progress paints a full-bleed EMBERWILL card
//
// The header fetch is the Bitcoin P2P protocol over TCP: version/verack, then
// getheaders from the G0's tip, up to 2000 raw 80-byte headers per message,
// each handed to the G0 as it arrives. No TLS, no JSON. The G0 checks every
// proof of work, so a peer can only withhold.
// =============================================================================
#ifdef FAVILLA_EMBERWILL   // 11cd: was FAVILLA_BENCH_PROBES; Emberwill ships as BETA
#include "fonts_ember.h"   // 29 Oct 2026: Archivo Bold 60, digits only, for the countdown

// ── state ────────────────────────────────────────────────────────────────────
static uint8_t  g_emwSt[96];                  // last EM_STATUS
static bool     g_emwPlan = false;            // f & 1
static uint32_t g_emwStMs = 0;                // when g_emwSt was read
static uint32_t g_emwLastSyncMs = 0;          // last P2P sync that reached the peer's tip
static bool     g_emwBootSync = false;        // the boot sync has run (or been tried) this life
static bool     g_emwAtTip = false;           // last sync ended at the peer's tip
static bool     g_emwPulseDue = false;        // a daily unlock happened: sync, then Pulse
static bool     g_emwPrevUnlocked = false;
static uint32_t g_emwNextTryMs = 0;           // back-off after a failed attempt
static char     g_emwLast[48] = "";           // last outcome, for the serial log / card
#ifdef FAVILLA_BENCH_PROBES
static const uint32_t EMW_SYNC_PERIOD_MS = 10UL * 60UL * 1000UL;   // bench: 10 min, so a Quiet-12 lifecycle keeps pace
#else
static const uint32_t EMW_SYNC_PERIOD_MS = 4UL * 3600UL * 1000UL;  // 11cd: product, 4 h
#endif
static const uint32_t EMW_RETRY_MS       = 2UL * 60UL * 1000UL;    // 29 Oct: 10 min left the footer frozen after one bad node
static const uint32_t EMW_BOOT_DELAY_MS  = 20000UL;

// ── status ───────────────────────────────────────────────────────────────────
static bool emwRefresh(bool force) {
  // 29 Oct 2026: EM_STATUS is a blocking G0 round trip on the main loop, and
  // buttons are only acted on between loop passes. Poll every 10 s only while
  // a plan exists (the footer countdown needs it); with no plan, once a minute.
  // Log any call slow enough to be felt.
  uint32_t every = g_emwPlan ? 10000 : 60000;
  if (!force && g_emwStMs && millis() - g_emwStMs < every) return g_emwPlan;
  if (g0_antiexfil_faulted()) return false;
  uint32_t t0 = millis();
  bool got = emStatus(g_emwSt);
  uint32_t dt = millis() - t0;
  if (dt > 80) Serial.printf("[EMW] status took %lu ms%s\n", (unsigned long)dt, got ? "" : " (failed)");
  if (!got) { g_emwPlan = false; g_emwStMs = millis(); return false; }
  g_emwPlan = (g_emwSt[5] & 1) && (g_emwSt[5] & 2);     // plan + state record
  g_emwStMs = millis();
  return g_emwPlan;
}
// Blocks the owner has left before the plan goes silent: last_life + Quiet -
// tip. Every unlock moves it back to a full Quiet. (29 Oct 2026: this used to
// be min(refresh window, silence), which made the footer read 0 at the window
// even though an unlock then still refreshes; the window is only the earliest
// block the refresh may go out, not a deadline. Proven on mainnet: link 2's
// refresh went out on an unlock one block after its window opened.)
static long emwBlocksLeft() {
  uint32_t tip = emRd32(g_emwSt + 8), q = emRd32(g_emwSt + 36), life = emRd32(g_emwSt + 20);
  return (long)(life + q) - (long)tip;
}
static long emwBlocksToRelease() { return (long)emRd32(g_emwSt + 16) - (long)emRd32(g_emwSt + 8); }
// "~45 d" from a block count, at the 144-a-day target. Rounds down, so the
// estimate errs early, never late.
static void emwDays(long blocks, char* out, size_t cap) {
  if (blocks < 0) blocks = 0;
  if (blocks < 6) snprintf(out, cap, "%s", "");
  else if (blocks < 144) snprintf(out, cap, "~%ld h", blocks / 6);
  else snprintf(out, cap, "~%ld d", blocks / 144);
}
// 29 Oct 2026: while the plan is SILENT and not yet kindled, the G0's
// Afterglow clock (powered seconds, credited on each header report, at most
// 30 min per report) must actually run. It runs on SysTick, which stops when
// the ESP32 parks the G0 in Stop on dim. So in that state: no G0 Stop, no
// Auto sleep, and a header sync at least every EMW_SILENT_SYNC_MS.
// The executor's pending broadcast (29 Oct 2026, see "executor on the KEY" below).
struct EmwPend {
  uint8_t  magic;            // 0xE7 = a broadcast is waiting for its proof
  char     kind;             // 'R' refresh, 'C' coupon
  uint8_t  link, ncand;      // ncand: fee variants broadcast for this (kind, link)
  uint8_t  var[3];
  uint8_t  txid[3][32];      // internal byte order
  uint32_t sentTip, scanned; // tip at first broadcast; highest block searched
  uint32_t foundH, foundIdx; // block height and position once found (0 = not yet)
  uint8_t  foundVar, depth;  // which variant confirmed; merkle branch length
  uint8_t  hdr[80];          // that block's header
  uint8_t  branch[20][32];
};
static EmwPend g_xp; static bool g_xpLoaded = false;
static void emwExecute(bool ui);
static void emwXpLoad();
static bool emwKeepG0Awake() { emwXpLoad(); return g_emwPlan && (((g_emwSt[5] & 8) && !(g_emwSt[5] & 32)) || g_xp.magic == 0xE7); }
static const uint32_t EMW_SILENT_SYNC_MS = 15UL * 60UL * 1000UL;   // under the G0's 30-min credit cap
static const char* emwWord() {
  uint8_t f = g_emwSt[5];
  if (f & 64) return "DONE";
  if (f & 32) return "KINDLED";
  if (f & 16) return "AFTERGLOW";
  if (f & 8)  return "SILENT";
  return "ALIVE";
}

// ── screen ───────────────────────────────────────────────────────────────────
// Footer strip (y 220): a 14 px ember after the door label, then the fuse in
// blocks, mono: "6480 BLOCKS" while there is time, brass once it is close
// (Josh, 28 Oct 2026: blocks, not days; the G0 counts blocks and days are a
// guess). Any state other than ALIVE shows its word instead. Sits between the
// door label (ends ~85) and the battery (190): ember at 92, text from 110,
// measured, and "BLK" when "BLOCKS" would run into the battery.
static void emwFooter(int footY) {
  if (!g_emwPlan) return;
  ebMarkSmall(92, footY + 1, 2, 1);
  char t[24]; long left = emwBlocksLeft();
  bool alive = !strcmp(emwWord(), "ALIVE");
  if (alive) snprintf(t, sizeof t, "%ld BLOCK%s", left < 0 ? 0L : left, left == 1 ? "" : "S");
  else snprintf(t, sizeof t, "%s", emwWord());
  fSet(F_MONO);
  if (alive && 110 + spr.textWidth(t) > 186) snprintf(t, sizeof t, "%ld BLK", left < 0 ? 0L : left);
  bool close = alive && left < (long)(emRd32(g_emwSt + 36) / 4);   // last quarter of the Quiet
  spr.setTextColor(close ? C_EB_BRASS : C_EB_GREY);
  spr.drawString(t, 110, footY + 2);
  fEnd();
}
// Full-bleed card while Emberwill is working: brass tracked-caps title, two
// ink lines, one grey mono detail. Only painted on the menu, never over a PIN
// screen or a dimmed panel.
static bool emwUiOk() { return currentState == ST_MENU && nextState == ST_MENU && !dimActive && !fidoPromptActive(); }   // passkey step 3a: never paint over the prompt
static void emwCard(const char* l1, const char* l2, const char* l3) {
  if (!emwUiOk()) return;
  spr.fillSprite(C_BG);
  uiHeader("EMBERWILL BETA", C_EB_BRASS);   // 11cd: ships as BETA
  ebMarkSmall(96, 56, 8, 2);                       // 48 px ember, centred
  fSet(F_BODY); spr.setTextColor(C_EB_INK);
  if (l1) fDrawCentre(l1, 120, 122);
  if (l2) fDrawCentre(l2, 120, 146);
  fSet(F_MONO); spr.setTextColor(C_EB_GREY);
  if (l3) fDrawCentre(l3, 120, 178);
  fEnd();
  uiFooter();
  dispPush();
}

// ── Bitcoin P2P ──────────────────────────────────────────────────────────────
static const uint8_t EMW_MAGIC[4] = {0xf9, 0xbe, 0xb4, 0xd9};
// 23 Nov 2026 (audit #56-2): a peer that trickles bytes reset the per-read
// timeout forever, so one node could hold the KEY (no buttons, no PIN entry).
// Each network job now sets one wall-clock deadline (g_emwDeadline, 0 = none)
// that every read checks, and the handshake and the header sync set
// g_emwReadYield so a read gives way the moment someone presses a button.
static uint32_t g_emwDeadline = 0;
static bool     g_emwReadYield = false;
static bool     g_emwGaveWay = false;   // 23 Nov 2026: set by any give-way, so the callers stop instead of trying the next node
static bool emwUserWaiting();
#define EMW_MAX_MSG 4000000UL   // Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH
static bool emwReadN(WiFiClient& c, uint8_t* d, size_t n, uint32_t tmo = 20000) {
  uint32_t t0 = millis(); size_t got = 0;
  while (got < n) {
    if (!c.connected() && !c.available()) return false;
    if (millis() - t0 > tmo) return false;
    if (g_emwDeadline && (int32_t)(millis() - g_emwDeadline) > 0) { Serial.println("[EMW]   deadline passed: dropping the peer"); return false; }
    int r = c.read(d + got, n - got);
    if (r > 0) { got += r; t0 = millis(); }
    else {
      if (g_emwReadYield && emwUserWaiting()) { Serial.println("[EMW]   button pressed: read gives way"); g_emwGaveWay = true; return false; }
      delay(2); esp_task_wdt_reset();
    }
  }
  return true;
}
static bool emwSkip(WiFiClient& c, uint32_t n) {
  if (n > EMW_MAX_MSG) { Serial.printf("[EMW]   message of %lu bytes refused\n", (unsigned long)n); return false; }   // #56-2
  uint8_t b[64]; while (n) { size_t k = n > sizeof b ? sizeof b : n; if (!emwReadN(c, b, k)) return false; n -= k; esp_task_wdt_reset(); } return true;
}
// Scoped deadline and button-yield for one network job; restores the outer
// values (a handshake runs inside a sync).
struct EmwGuard {
  uint32_t dl; bool y;
  EmwGuard(uint32_t ms, bool yield) : dl(g_emwDeadline), y(g_emwReadYield) {
    uint32_t mine = millis() + ms; if (!mine) mine = 1;
    if (!g_emwDeadline || (int32_t)(mine - g_emwDeadline) < 0) g_emwDeadline = mine;   // never extend an outer deadline
    g_emwReadYield = g_emwReadYield || yield;
  }
  ~EmwGuard() { g_emwDeadline = dl; g_emwReadYield = y; }
};
static void emwSend(WiFiClient& c, const char* cmd, const uint8_t* pl, uint32_t n) {
  uint8_t h[24] = {0}; memcpy(h, EMW_MAGIC, 4); strncpy((char*)h + 4, cmd, 12); emWr32(h + 16, n);
  uint8_t t1[32], t2[32]; mbedtls_sha256(pl, n, t1, 0); mbedtls_sha256(t1, 32, t2, 0); memcpy(h + 20, t2, 4);
  c.write(h, 24); if (n) c.write(pl, n);
}
static uint32_t emwVarint(WiFiClient& c, bool* ok) {
  uint8_t b[8]; if (!emwReadN(c, b, 1)) { *ok = false; return 0; }
  if (b[0] < 0xfd) return b[0];
  int k = b[0] == 0xfd ? 2 : b[0] == 0xfe ? 4 : 8; if (!emwReadN(c, b, k)) { *ok = false; return 0; }
  uint64_t v = 0; for (int i = k - 1; i >= 0; i--) v = (v << 8) | b[i]; return (uint32_t)v;
}
static bool emwHandshake(WiFiClient& c, IPAddress ip, uint32_t height, bool relay = false) {
  EmwGuard guard(14000, true);   // #56-2: connect (4 s) + the 8 s exchange, with margin; any button gives way
  if (!c.connect(ip, 8333, 4000)) { Serial.println("[EMW]   connect failed"); return false; }   // 29 Oct 2026: 8 s -> 4 s (two dead nodes cost 16 s of frozen buttons)
  uint8_t v[128] = {0}; size_t n = 0; const char* ua = "/FavillaKEY:0.1/";
  emWr32(v + n, 70016); n += 4; n += 8; emWr32(v + n, (uint32_t)time(nullptr)); n += 8;
  n += 26; n += 26; esp_fill_random(v + n, 8); n += 8;
  v[n++] = (uint8_t)strlen(ua); memcpy(v + n, ua, strlen(ua)); n += strlen(ua);
  emWr32(v + n, height); n += 4; v[n++] = relay ? 1 : 0;   // relay=1 only on broadcast connections (some nodes ignore tx from a peer that asked for no relay)
  emwSend(c, "version", v, n);
  uint32_t t0 = millis(); bool gotVersion = false, gotVerack = false;
  while (millis() - t0 < 8000 && !(gotVersion && gotVerack)) {
    uint8_t h[24];
    // pass 17: wait for the first byte here, checking the buttons, so a silent
    // peer no longer holds the KEY for the full timeout. Once bytes arrive the
    // header is read whole (a partial read must never be abandoned).
    while (!c.available() && c.connected() && millis() - t0 < 8000) {
      if (emwUserWaiting()) { Serial.println("[EMW]   button pressed: handshake gives way"); g_emwGaveWay = true; c.stop(); return false; }
      delay(5); esp_task_wdt_reset();
    }
    if (!emwReadN(c, h, 24, 8000)) { Serial.println(c.connected() ? "[EMW]   peer silent" : "[EMW]   peer closed (full, or did not like us)"); c.stop(); return false; }
    if (memcmp(h, EMW_MAGIC, 4) != 0) { c.stop(); return false; }
    char cmd[13] = {0}; memcpy(cmd, h + 4, 12); uint32_t len = emRd32(h + 16);
    if (!strcmp(cmd, "version") && (len < 4 || len > 1024)) { Serial.printf("[EMW]   version of %lu bytes refused\n", (unsigned long)len); c.stop(); return false; }   // #56-2: len - 4 underflowed
    if (!strcmp(cmd, "version")) { uint8_t pv[4]; if (!emwReadN(c, pv, 4) || !emwSkip(c, len - 4)) { c.stop(); return false; } Serial.printf("[EMW]   peer version %lu\n", (unsigned long)emRd32(pv)); gotVersion = true; emwSend(c, "verack", nullptr, 0); }
    else if (!strcmp(cmd, "verack")) gotVerack = true;
    else if (!emwSkip(c, len)) { c.stop(); return false; }
  }
  if (!(gotVersion && gotVerack)) { c.stop(); return false; }
  return true;
}
// Pull headers from a node and feed the G0. host "" = walk the DNS seeds.
// maxn caps one call (keeps the main loop breathing on a long catch-up; the
// caller comes back). Returns headers fed; sets g_emwAtTip when the peer had
// nothing more. ui = paint the card while working.
static void emwDsha(const uint8_t* d, size_t n, uint8_t out[32]);   // defined with the executor
static bool emwHeaderAt(uint32_t h, uint8_t out[80]);
// 29 Oct 2026: a person at the lock screen wants the buttons now. Checked
// between nodes so a waiting sync gives way instead of freezing PIN entry.
// Only a tap from the last 2 s counts: a pending flag the current screen never
// consumes must not hold the network off forever.
static bool emwFreshTap(const Button& b) { return b.pending && millis() - b.pressEdge < 2000; }
static bool emwUserWaiting() {
  // stable = held now; pending = a tap the background poller latched since the
  // loop last ran (a quick press would otherwise slip between two checks).
  return btn1.stable == LOW || btn2.stable == LOW || btn3.stable == LOW || btn4.stable == LOW ||
         emwFreshTap(btn1) || emwFreshTap(btn2) || emwFreshTap(btn3) || emwFreshTap(btn4) ||
         fidoPromptActive();   // passkey step 3a: a website waiting for a press counts as the user waiting
}
static uint32_t emwSyncP2pOnce(const String& hostArg, uint32_t maxn, bool ui, int skip, bool* answered) {
  *answered = false;
  g_emwAtTip = false;
  if (!emStatus(g_emwSt)) { Serial.println("[EMW] no Emberwill G0"); return 0; }
  if (!wifiConnected) { Serial.println("[EMW] no WiFi"); return 0; }
  wifiHoldAwake();
  const char* seeds[] = { "seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "seed.bitcoin.sprovoost.nl", "seed.btc.petertodd.org", "dnsseed.emzy.de", "seed.bitcoin.wiz.biz" };
  Serial.printf("[EMW] sync from tip %lu | internal heap %u, largest %u\n", (unsigned long)emRd32(g_emwSt + 8),
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
  if (ui) emwCard("Syncing headers", "finding a node", nullptr);
  WiFiClient c; c.setTimeout(20); bool up = false; IPAddress ip; String peer;
  uint32_t height = emRd32(g_emwSt + 8);
  if (hostArg.length()) {
    if (!WiFi.hostByName(hostArg.c_str(), ip)) { Serial.println("[EMW] cannot resolve host"); return 0; }
    peer = hostArg; Serial.printf("[EMW] %s -> %s:8333\n", hostArg.c_str(), ip.toString().c_str());
    up = emwHandshake(c, ip, height);
  } else {
    for (int si = 0; si < 6; si++) {
      if (g_emwGaveWay || emwUserWaiting()) { Serial.println("[EMW] button pressed: sync gives way"); g_emwGaveWay = true; return 0; }
      const char* sd = seeds[(si + skip) % 6];
      if (!WiFi.hostByName(sd, ip)) { Serial.printf("[EMW] %s: no answer\n", sd); continue; }
      if (ip == IPAddress(0, 0, 0, 0)) { Serial.printf("[EMW] %s: no address (DNS gave 0.0.0.0)\n", sd); continue; }   // 23 Nov 2026: connecting to 0.0.0.0 froze 4 s for nothing
      Serial.printf("[EMW] %s -> %s:8333\n", sd, ip.toString().c_str());
      peer = ip.toString();
      if ((up = emwHandshake(c, ip, height))) break;
      esp_task_wdt_reset();
    }
  }
  if (!up) { snprintf(g_emwLast, sizeof g_emwLast, "no node answered"); Serial.println("[EMW] no peer completed the handshake"); return 0; }
  bool sentGh = false, noBuild = false; uint32_t fed = 0, t0 = millis(), g0ms = 0, batches = 0; int8_t rc = 0;
  EmwGuard guard(600000, true);   // #56-2: the 600 s bound now holds inside every read, and a button press gives way
  uint8_t tipHash[32]; memcpy(tipHash, g_emwSt + 48, 32);
  char l2[40], l3[40];
  if (ui) { snprintf(l2, sizeof l2, "at %lu", (unsigned long)height); snprintf(l3, sizeof l3, "node %s", peer.c_str()); emwCard("Syncing headers", l2, l3); }
  while (millis() - t0 < 600000 && fed < maxn) {
    if (!sentGh) {
      // 29 Oct 2026: a block locator, not just the tip. A node that does not
      // know our tip (lagging, or the tip was reorged out) answers a tip-only
      // request from genesis, which never builds on the G0 tip ("first header
      // does not build"). With tip, tip-1, -2, -4, -8, -16 it answers from the
      // last block we share. Older entries come from the header cache.
      uint8_t gh[4 + 1 + 7 * 32 + 32] = {0}; emWr32(gh, 70016);
      int nh = 0; memcpy(gh + 5, tipHash, 32); nh = 1;
      { static const uint8_t back[5] = {1, 2, 4, 8, 16}; uint8_t hd[80];
        for (int b = 0; b < 5; b++) if (height > back[b] && emwHeaderAt(height - back[b], hd)) { emwDsha(hd, 80, gh + 5 + nh * 32); nh++; } }
      gh[4] = (uint8_t)nh;
      size_t ghn = 5 + (size_t)nh * 32 + 32;            // + hash_stop (zeros)
      emwSend(c, "getheaders", gh, ghn); sentGh = true;
    }
    uint8_t h[24]; if (!emwReadN(c, h, 24, 30000)) { Serial.println(c.connected() ? "[EMW] peer went quiet" : "[EMW] peer closed"); break; }
    if (memcmp(h, EMW_MAGIC, 4) != 0) { Serial.println("[EMW] bad magic"); break; }
    char cmd[13] = {0}; memcpy(cmd, h + 4, 12); uint32_t len = emRd32(h + 16);
    if (!strcmp(cmd, "ping")) { uint8_t nonce[8]; if (!emwReadN(c, nonce, 8)) break; emwSend(c, "pong", nonce, 8); }
    else if (!strcmp(cmd, "headers")) {
      bool ok = true; uint32_t cnt = emwVarint(c, &ok); if (!ok) break;
      if (cnt > 2000) { Serial.printf("[EMW] headers count %lu refused (max 2000)\n", (unsigned long)cnt); break; }   // #56-2
      batches++; uint32_t got = 0; bool bad = false, stop = false;
      for (uint32_t i = 0; i < cnt; i++) {
        uint8_t hdr[80]; if (!emwReadN(c, hdr, 80)) { bad = true; break; }
        uint32_t txn = emwVarint(c, &ok); if (!ok || txn != 0) { bad = true; break; }
        if (i == 0 && memcmp(hdr + 4, tipHash, 32) != 0) { Serial.println("[EMW] first header does not build on the G0 tip (peer does not know it, or a reorg): stopping"); stop = true; noBuild = true; }
        esp_task_wdt_reset();                                 // #56-2: also while draining
        if (stop) { if (emwUserWaiting()) { Serial.println("[EMW] button pressed: drain gives way"); bad = true; break; } continue; }   // drain the rest of the message
        uint32_t a = millis();
        if (!g0_em_header(hdr, true, &rc, g_emwSt)) { Serial.println("[EMW] G0 did not answer"); bad = true; break; }
        g0ms += millis() - a;
        if (rc != 0) { Serial.printf("[EMW] G0 refused header at tip+%lu: %s (%d)\n", (unsigned long)(i + 1), emEh(rc), rc); stop = true; continue; }
        memcpy(tipHash, g_emwSt + 48, 32); emCachePut(emRd32(g_emwSt + 8), hdr); fed++; got++;
        if (fed % 50 == 0 && ui) { snprintf(l2, sizeof l2, "at %lu  (+%lu)", (unsigned long)emRd32(g_emwSt + 8), (unsigned long)fed); emwCard("Syncing headers", l2, l3); }
        if (fed % 100 == 0) Serial.printf("[EMW]   %lu fed, tip %lu | %lu s | internal heap %u, largest %u\n", (unsigned long)fed, (unsigned long)emRd32(g_emwSt + 8),
                                          (unsigned long)((millis() - t0) / 1000), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
        if (fed % 500 == 0) { size_t sn = 0; int8_t src = 0; if (g0_em_cmd(0x3C, &src, nullptr, 0, &sn, 5000)) Serial.printf("[EMW]   EM_SAVE rc %d (checkpoint)\n", src); }
        esp_task_wdt_reset();
        // 23 Nov 2026 (#56-2 bench): a healthy peer streams without a pause, so
        // the read never idles and never sees the button. Check after every
        // header too; what was fed is kept (EM_SAVE after the loop).
        if (emwUserWaiting()) { Serial.printf("[EMW] button pressed: sync gives way after %lu headers\n", (unsigned long)fed); g_emwGaveWay = true; bad = true; break; }
      }
      if (bad || stop) break;
      Serial.printf("[EMW] batch %lu: %lu headers, tip now %lu\n", (unsigned long)batches, (unsigned long)got, (unsigned long)emRd32(g_emwSt + 8));
      if (cnt < 2000) { g_emwAtTip = true; break; }
      sentGh = false;
    }
    else { if (!emwSkip(c, len)) break; }
  }
  c.stop();
  if (fed) {
    emCacheFlush();
    size_t sn = 0; if (g0_em_cmd(0x3C, &rc, nullptr, 0, &sn, 5000)) Serial.printf("[EMW] EM_SAVE rc %d\n", rc);
  }
  if (g_emwAtTip) g_emwLastSyncMs = millis();
  Serial.printf("[EMW] fed %lu headers in %lu s over %lu batches (G0 %lu ms/header)%s | internal heap %u, largest %u\n", (unsigned long)fed,
                (unsigned long)((millis() - t0) / 1000), (unsigned long)batches, (unsigned long)(fed ? g0ms / fed : 0), g_emwAtTip ? ", at the peer's tip" : "",
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
  snprintf(g_emwLast, sizeof g_emwLast, "sync +%lu, tip %lu", (unsigned long)fed, (unsigned long)emRd32(g_emwSt + 8));
  emwRefresh(true);
  *answered = batches > 0 && !noBuild;   // 29 Oct 2026: a node behind us counts as no answer, so the next node is tried now, not in 2 min
  return fed;
}
// 29 Oct 2026: a peer can finish the handshake and then never answer
// getheaders (a node still in its own initial block download ignores it; seen
// on silicon: 34.64.213.1 "went quiet" for 30 s). An empty `headers` reply is
// a real answer ("you are at my tip"); silence is not. So on silence, try
// another seed, up to three nodes per sync, and start each sync at a different
// seed so one bad node is not hit every time.
static uint32_t emwSyncP2p(const String& hostArg, uint32_t maxn, bool ui) {
  static int rot = 0;
  g_emwGaveWay = false;
  for (int attempt = 0; attempt < 3; attempt++) {
    bool answered = false;
    uint32_t fed = emwSyncP2pOnce(hostArg, maxn, ui, rot++, &answered);
    if (g_emwGaveWay) { Serial.println("[EMW] gave way to a button: no more nodes this time"); return fed; }   // 23 Nov 2026: was retrying up to 3 times after a press
    if (answered || hostArg.length()) return fed;
    Serial.println("[EMW] that node did not answer getheaders; trying another");
  }
  return 0;
}

// ── Pulse: G0 builds + signs, we publish it as the owner's life ──────────────
static bool emwPulsePublish(bool ui) {
  if (ui) emwCard("Pulse", "signing on the vault", nullptr);
  char ser[256]; uint8_t id[32], sig[64];
  if (!g0_em_pulse(ser, sizeof ser, id, sig)) { snprintf(g_emwLast, sizeof g_emwLast, "pulse refused"); return false; }
  // ser = [0,"pubkey",created_at,8333,[],"content"] -> the full event
  JsonDocument d; if (deserializeJson(d, ser)) return false;
  char idh[65], sigh[129]; toHex(id, 32, idh); toHex(sig, 64, sigh);
  char ev[640];
  snprintf(ev, sizeof ev, "{\"id\":\"%s\",\"pubkey\":\"%s\",\"created_at\":%lu,\"kind\":%d,\"tags\":[],\"content\":\"%s\",\"sig\":\"%s\"}",
           idh, (const char*)(d[1] | ""), (unsigned long)(d[2] | 0UL), (int)(d[3] | 0), (const char*)(d[5] | ""), sigh);
  if (ui) emwCard("Pulse", "publishing", nullptr);
  bool ok = false, opened = false;
  if (!(ws2Initialised && !g_cipherShareLink)) { if (!cipherShareEnsureRelay()) { snprintf(g_emwLast, sizeof g_emwLast, "no relay"); return false; } opened = true; }
  ok = cipherPublishConfirmed(ev, 8000);
  if (opened) cipherShareRelayDone();
  Serial.printf("[EMW] pulse %s: %s\n", ok ? "published, relay OK" : "NOT confirmed", ev);
  snprintf(g_emwLast, sizeof g_emwLast, ok ? "pulse published" : "pulse not confirmed");
  emwRefresh(true);
  if (ui) { char l3[40]; snprintf(l3, sizeof l3, "life at %lu", (unsigned long)emRd32(g_emwSt + 20)); emwCard(ok ? "Pulse published" : "Pulse not confirmed", "you are alive", l3); delay(1500); }
  return ok;
}

// ── scheduler: called from loop() ────────────────────────────────────────────
static void emwDebug(const char* why) {
  Serial.printf("[EMW] tick %s | plan %d st 0x%02X | wifi %d | state %d next %d dim %d idle %lu | bootSync %d atTip %d pulseDue %d nextTry %lu | heap %u\n",
                why, (int)g_emwPlan, g_emwSt[5], (int)wifiConnected, (int)currentState, (int)nextState, (int)dimActive,
                (unsigned long)(millis() - lastActivity), (int)g_emwBootSync, (int)g_emwAtTip, (int)g_emwPulseDue, (unsigned long)g_emwNextTryMs,
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
}
static void emwTick() {
  emSerialHoldTick();
  if (g_ceremonyBoot) return;                        // Bitcoin life: no radio, nothing to do here
  uint32_t now = millis();
  bool unlocked = wallet.unlocked;
  if (unlocked && !g_emwPrevUnlocked) g_emwPulseDue = true;   // a daily unlock just happened
  g_emwPrevUnlocked = unlocked;
  static uint32_t lastDbg = 0;
  bool plan = emwRefresh(false);
  if (now - lastDbg > 15000) { lastDbg = now; emwDebug("periodic"); }
  if (!plan) return;                                 // no plan: nothing runs, no traffic
  // 29 Oct 2026: repaint the menu when the countdown changes (a new block from
  // any source, or a new life stamp), so the footer ticks down live.
  { static long shown = -0x7fffffff; static uint8_t shownF = 0xff; long left = emwBlocksLeft();
    if ((left != shown || g_emwSt[5] != shownF) && emwUiOk()) { shown = left; shownF = g_emwSt[5]; dispMenu(); } }
  if (!wifiConnected) return;
  if (now < EMW_BOOT_DELAY_MS) return;               // let the boot connect settle
  if (now < g_emwNextTryMs) return;
  // Only two places may hold the loop for a few seconds: the menu (the owner
  // sees the card), or the lock screen once it has dimmed (nobody is typing a
  // PIN; this is the heir path, the KEY sitting on a charger).
  uint32_t period = emwKeepG0Awake() && EMW_SILENT_SYNC_MS < EMW_SYNC_PERIOD_MS ? EMW_SILENT_SYNC_MS : EMW_SYNC_PERIOD_MS;
  bool wantSync = !g_emwBootSync || !g_emwAtTip || (now - g_emwLastSyncMs > period) || g_emwPulseDue;
  // 11cf (power, 21 Nov 2026): the no-light-sleep hold now covers only the
  // sync and pulse work below, while it runs. It used to be taken whenever a
  // sync was owed and released only once the G0 reached the tip, and the
  // early returns above (no Wi-Fi, the retry wait, not on the menu) skipped
  // the release: a KEY that could not reach a node, or lost Wi-Fi, never
  // light-slept again (about 30 to 40 mA dark instead of under 10). Light
  // sleep does not stop this loop: it still runs every 100 ms in the dark and
  // starts the sync on time; Wi-Fi's modem sleep keeps the link meanwhile.
  // 29 Oct 2026 (pass 17): the menu straight after an unlock held the loop for
  // 19 s (sync with a silent peer + pulse + relay) while the owner was trying to
  // use it. Emberwill now waits until the menu has been left alone for 5 s.
  bool onMenu = currentState == ST_MENU && nextState == ST_MENU && now - lastActivity > 5000;
  // 29 Oct 2026: 60 s of no input (was 20 s). On a charger the screen never dims, and the boot sync held the lock screen for 22 s ([STALL] 22712 ms, state 5) just as someone might type a PIN.
  bool lockedIdle = currentState == ST_PIN_ENTRY && (dimActive || now - lastActivity > 60000);
  if (!onMenu && !lockedIdle) return;
  bool ui = emwUiOk();
  struct EmwHold { bool on = false; void take() { if (!on) { pmHoldWakeTag("emw"); on = true; } } ~EmwHold() { if (on) pmReleaseWakeTag("emw"); } } hold;   // 11cf: released on every return below
  if (wantSync || (g_emwPulseDue && unlocked)) hold.take();
  if (wantSync) {
    g_emwBootSync = true;
    uint32_t fed = emwSyncP2p(String(""), 2000, ui);   // one batch per tick; the loop breathes between
    if (!fed && !g_emwAtTip) { g_emwNextTryMs = now + EMW_RETRY_MS; if (ui) dispMenu(); return; }
    if (!g_emwAtTip) { if (ui) dispMenu(); return; }  // more to come next tick
    emwExecute(ui);                                   // the G0 is current: release, broadcast, find, prove
  }
  if (g_emwPulseDue && unlocked) {
    g_emwPulseDue = false;
    if (!emwPulsePublish(ui)) g_emwNextTryMs = now + EMW_RETRY_MS;
  }
  if (ui) dispMenu();
}

// =============================================================================
// Screens (28 Oct 2026, from the Emberwill mockup canvas)
//   emwStatusScreen  Settings > Device > Emberwill in the Nostr life, and the
//                    EMBERWILL door card in the Bitcoin life once a plan exists:
//                    the word, blocks to the deadline, blocks to release, life
//   emwDoorScreen    the EMBERWILL door card with no plan: "scan the plan"
//   emwPlanFromPsbt  the scanned PSBT -> plan -> review -> seal (ceremony)
// =============================================================================
static bool g_emwScanPlan = false;    // the door asked for a PSBT scan to become a plan
static bool emwScanPlanTake() { bool v = g_emwScanPlan; g_emwScanPlan = false; return v; }

static void emwShortAddr(const uint8_t* spk, char* out, size_t cap);   // defined with the PSBT flow below
static void emwPumpUi() { pumpInputs(); btn3.poll(); btn4.poll(); esp_task_wdt_reset(); delay(10); }   // pumpInputs polls 1 and 2 only
static void emwRightText(const char* s, int rightX, int y) { spr.drawString(s, rightX - spr.textWidth(s), y); }

// ── the page language (29 Oct 2026, canvas "Status, redesigned") ─────────────
// Every Emberwill screen: a tracked caps label at the top, one hero element,
// one or two plain lines, position dots at the bottom. No pills, no footer.
static const uint16_t C_EMW_DEAD = 0x2104;                  // a burnt-out ember cell
static int emwTrackW(const char* s, int sp) { int w = 0; for (const char* q = s; *q; q++) { char c[2] = {*q, 0}; w += spr.textWidth(c) + sp; } return w > 0 ? w - sp : 0; }
static void emwTrackAt(const char* s, int x, int y, uint16_t col, int sp) { spr.setTextColor(col); for (const char* q = s; *q; q++) { char c[2] = {*q, 0}; spr.drawString(c, x, y); x += spr.textWidth(c) + sp; } }
static void emwLabel(const char* s, int y, uint16_t col) { fSet(F_BRAND_B12); emwTrackAt(s, 120 - emwTrackW(s, 3) / 2, y, col, 3); fEnd(); }
static void emwLabelL(const char* s, int x, int y, uint16_t col) { fSet(F_BRAND_B12); emwTrackAt(s, x, y, col, 2); fEnd(); }
// 29 Oct 2026: the shipped Archivo Light 12 and Bold 28 carry only capitals
// and digits (they were cut for the wordmark), so Emberwill brings full-alphabet
// Archivo 400 13 (body) and 700 28 (values) in fonts_ember.h. emwUse loads one
// directly; the next fSet() reloads its own font (fEndHard resets the tracker).
static void emwUse(const uint8_t* f) { fEndHard(); spr.loadFont(f); }
#define EMW_BODY  FONT_Archivo_Regular_13
#define EMW_VALUE FONT_Archivo_Bold_28_full
static void emwLine(const char* s, int y, uint16_t col) { emwUse(EMW_BODY); spr.setTextColor(col); spr.drawString(s, 120 - spr.textWidth(s) / 2, y); }
static void emwDots(int on, int k) { int w = k * 5 + (k - 1) * 7, x = 120 - w / 2; for (int i = 0; i < k; i++) spr.fillRect(x + i * 12, 224, 5, 5, i == on ? C_EB_BRASS : C_EB_LINE); }
static void emwBig(const char* s, int y, uint16_t col) {
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_60_num);
  spr.setTextColor(col); spr.drawString(s, 120 - spr.textWidth(s) / 2, y);
  spr.unloadFont();
}
// The ember as the fuse: `alive` of its 13 cells lit (0..13). The outer ring
// burns first, the centre last. hot = the kindled ember, inner cells white.
static void emwEmber(int x, int y, int cell, int gap, int alive, bool hot) {
  int i1 = 1, i2 = 5;
  for (int r = 0; r < 5; r++) for (int c = 0; c < 5; c++) {
    int d = abs(r - 2) + abs(c - 2); if (d > 2) continue;
    int idx = d == 0 ? 0 : d == 1 ? i1++ : i2++;
    uint16_t col = idx < alive ? (hot ? (d < 2 ? C_EB_INK : C_EB_BRASS) : ebTarget(r, c)) : C_EMW_DEAD;
    spr.fillRect(x + c * (cell + gap), y + r * (cell + gap), cell, cell, col);
  }
}
static void emwRing(int cx, int cy, int r, float p, uint16_t col) {
  spr.drawArc(cx, cy, r, r - 3, 0, 360, C_EB_LINE, C_BG, true);
  if (p <= 0) return;
  if (p > 1) p = 1;
  uint32_t deg = (uint32_t)(p * 360.0f); if (deg < 2) deg = 2;
  if (180 + deg <= 360) spr.drawArc(cx, cy, r, r - 3, 180, 180 + deg, col, C_BG, true);   // 0 = six o'clock: start at twelve
  else { spr.drawArc(cx, cy, r, r - 3, 180, 360, col, C_BG, true); spr.drawArc(cx, cy, r, r - 3, 0, 180 + deg - 360, col, C_BG, true); }
}
static void emwComma(uint64_t v, char* out, size_t cap) {
  char t[24]; snprintf(t, sizeof t, "%llu", (unsigned long long)v); int n = strlen(t), o = 0;
  for (int i = 0; i < n && o < (int)cap - 2; i++) { if (i && (n - i) % 3 == 0) out[o++] = ','; out[o++] = t[i]; }
  out[o] = 0;
}
// "about a day", "about 9 hours", "about 3 months": blocks at the 10-minute target
static void emwPlain(long b, char* out, size_t cap) {
  if (b <= 0) { snprintf(out, cap, "now"); return; }
  if (b < 9)  { snprintf(out, cap, "about an hour"); return; }
  if (b < 132) { snprintf(out, cap, "about %ld hours", (b + 3) / 6); return; }
  if (b < 216) { snprintf(out, cap, "about a day"); return; }
  if (b < 1512) { snprintf(out, cap, "about %ld days", (b + 72) / 144); return; }
  if (b < 6480) { long w = (b + 504) / 1008; snprintf(out, cap, w == 1 ? "about a week" : "about %ld weeks", w); return; }
  if (b < 47520) { long m = (b + 2160) / 4320; snprintf(out, cap, m == 1 ? "about a month" : "about %ld months", m); return; }
  long y = (b + 26280) / 52560; snprintf(out, cap, y == 1 ? "about a year" : "about %ld years", y);
}
// Afterglow length in blocks. The G0 does not report it, so it is worked out
// from the seal: X0 = seal tip + Quiet + Afterglow (saved at the seal as "st0").
static uint32_t emwAg() {
  uint32_t q = emRd32(g_emwSt + 36), x = emRd32(g_emwSt + 16), link = g_emwSt[6], st0 = 0;
  { Preferences p; if (p.begin("emb", true)) { st0 = p.getUInt("st0", 0); p.end(); } }
  uint32_t x0 = x - link * q;
  if (st0 && x0 > st0 + q && x0 - st0 - q <= 2016) return x0 - st0 - q;
  return q < 1000 ? 6 : 1008;
}
static uint32_t emwPaidAt() {
  uint32_t x = emRd32(g_emwSt + 16), life = emRd32(g_emwSt + 20), q = emRd32(g_emwSt + 36), quiet = life + q + emwAg();
  return quiet > x ? quiet : x;
}

// ── clear the plan (Bitcoin door) ───────────────────────────────────────────
// 29 Oct 2026. EM_CLEAR erases the plan on the G0, and with it the only key
// that opens the sealed transactions: the copies in NVS become unreadable
// bytes. They, the stored plan record and the executor's pending state are
// erased here too so nothing stale is left. The coins are not touched.
static bool emwClearNow() {
  int8_t rc = 0; size_t n = 0;
  bool ok = g0_em_cmd(0x3A, &rc, nullptr, 0, &n, 8000) && rc == 0;
  Serial.printf("[EMW] EM_CLEAR %s (rc %d)\n", ok ? "done" : "FAILED", rc);
  if (!ok) { dispError("Clear refused"); errorPause(); return false; }
  { Preferences p; if (p.begin("emb", false)) {
      unsigned nb = p.getUInt("nb", 0); if (nb > 64) nb = 64;
      for (unsigned k = 0; k < nb; k++) { char key[6]; snprintf(key, sizeof key, "b%u", k); p.remove(key); }
      p.remove("nb"); p.remove("plan"); p.remove("xp"); p.remove("st0"); p.remove("ho"); p.end(); } }
  memset(&g_xp, 0, sizeof g_xp); g_xpLoaded = true;
  emwRefresh(true);
  dispSuccessFor("Plan cleared", "Your coins are untouched", C_EB_BRASS);
  return true;
}

// ── the four status pages ────────────────────────────────────────────────────
static void emwPageCount() {
  uint8_t f = g_emwSt[5]; uint32_t tip = emRd32(g_emwSt + 8), q = emRd32(g_emwSt + 36);
  char n[16], l[48];
  if (f & 32) {                                              // KINDLED
    emwLabel("KINDLED", 15, C_EB_BRASS);
    emwEmber(99, 34, 7, 2, 13, true);
    emwLine("The coins are on their way", 104, C_EB_INK);
    emwLine("to the people they chose.", 120, C_EB_INK);
    if (g_xp.magic == 0xE7 && g_xp.kind == 'C' && g_xp.foundH) {
      char b[16]; emwComma(g_xp.foundH, b, sizeof b); snprintf(l, sizeof l, "block %s", b);
      fSet(F_MONO); spr.setTextColor(C_EB_GREY); fDrawCentre(l, 120, 148); fEnd();
    }
    emwLine("Keep this KEY plugged in", 172, C_EB_BRASS);
    emwLine("until it says done.", 188, C_EB_BRASS);
    return;
  }
  if (f & 8) {                                               // SILENT: the Afterglow, then paying
    emwLabel("AFTERGLOW", 15, C_EB_BRASS);
    emwEmber(102, 34, 6, 2, 1, false);
    long until = (long)emwPaidAt() - (long)tip; if (until < 0) until = 0;
    snprintf(n, sizeof n, "%ld", until); emwBig(n, 84, C_EB_INK);
    emwLabel("BLOCKS UNTIL PAID", 155, C_EB_BRASS);
    emwLine("You have gone quiet.", 174, C_EB_GREY);
    emwLine("Unlock now to stop it.", 190, C_EB_GREY);
    return;
  }
  long left = emwBlocksLeft(); if (left < 0) left = 0;       // ALIVE
  int alive = q ? (int)((left * 13 + q - 1) / q) : 13; if (alive < 1) alive = 1; if (alive > 13) alive = 13;
  bool close = left < (long)(q / 4);
  emwLabel("EMBERWILL BETA", 15, C_EB_GREY);   // 11cd
  emwEmber(102, 34, 6, 2, alive, false);
  snprintf(n, sizeof n, "%ld", left); emwBig(n, 84, close ? C_EB_BRASS : C_EB_INK);
  emwLabel(left == 1 ? "BLOCK" : "BLOCKS", 155, C_EB_BRASS);
  char pl[24]; emwPlain(left, pl, sizeof pl);
  if (close) snprintf(l, sizeof l, "unlock soon, %s", pl); else snprintf(l, sizeof l, "%s to unlock", pl);
  emwLine(l, 176, C_EB_GREY);
}
static void emwPageHeirs() {
  emwLabel("GOES TO", 15, C_EB_GREY);
  uint8_t w[430]; uint8_t own = 0; uint32_t st0 = 0;
  { Preferences p; if (p.begin("emb", true)) { own = p.getUChar("ho", 0); st0 = p.getUInt("st0", 0); p.end(); } }
  if (!emPlanLoad(w)) { emwLine("The plan is sealed on the vault.", 100, C_EB_GREY); return; }
  int shown = w[1] < 3 ? w[1] : 3;
  for (int j = 0; j < shown; j++) {
    const uint8_t* h = w + 160 + j * 36; int y = 44 + j * 22;
    char lab[8]; snprintf(lab, sizeof lab, (own >> j) & 1 ? "YOU" : "HEIR %d", j + 1);
    fSet(F_BRAND_B12); int lw = emwTrackW(lab, 2); fEnd();
    emwLabelL(lab, 20, y + 3, C_EB_BRASS);
    char a[32]; emwShortAddr(h, a, sizeof a);
    fSet(F_MONO); spr.setTextColor(C_EB_INK); spr.drawString(a, 20 + lw + 8, y + 2); fEnd();
    unsigned bp = h[34] | (h[35] << 8); char s[12];
    if (bp % 100) snprintf(s, sizeof s, "%u.%u%%", bp / 100, (bp % 100) / 10); else snprintf(s, sizeof s, "%u%%", bp / 100);
    fSet(F_BRAND_B14); spr.setTextColor(C_EB_INK); emwRightText(s, 220, y); fEnd();
  }
  if (w[1] > 3) { char m[24]; snprintf(m, sizeof m, "and %u more", w[1] - 3); emwLine(m, 44 + 3 * 22, C_EB_GREY); }
  spr.drawFastHLine(20, 116, 200, C_EB_LINE);
  emwLabelL("FROM THIS KEY", 20, 128, C_EB_GREY);
  uint64_t sats = 0; for (int i = 0; i < w[0]; i++) { const uint8_t* c = w + 4 + i * 52; sats += (uint64_t)emRd32(c + 36) | ((uint64_t)emRd32(c + 40) << 32); }
  char s[24]; emwComma(sats, s, sizeof s);
  emwUse(EMW_VALUE); spr.setTextColor(C_EB_INK); spr.drawString(s, 20, 144); int sw = spr.textWidth(s); fEnd();
  emwUse(EMW_BODY); spr.setTextColor(C_EB_GREY); spr.drawString("sats", 20 + sw + 6, 158); fEnd();
  char l[48];
  if (st0) { char b[16]; emwComma(st0, b, sizeof b); snprintf(l, sizeof l, "%u coin%s, sealed at block %s", w[0], w[0] == 1 ? "" : "s", b); }
  else snprintf(l, sizeof l, "%u coin%s", w[0], w[0] == 1 ? "" : "s");
  emwUse(EMW_BODY); spr.setTextColor(C_EB_GREY); spr.drawString(l, 20, 182); fEnd();
}
static void emwWhenRow(int y, const char* lab, const char* val, const char* sub, bool brass, bool last) {
  uint16_t col = brass ? C_EB_BRASS : C_EB_INK;
  spr.fillRect(20, y + 3, 7, 7, col);
  if (!last) spr.drawFastVLine(23, y + 14, 44, C_EB_LINE);
  emwLabelL(lab, 38, y, C_EB_GREY);
  fSet(F_MONO); spr.setTextColor(col); spr.drawString(val, 38, y + 15); fEnd();
  emwUse(EMW_BODY); spr.setTextColor(C_EB_GREY); spr.drawString(sub, 38, y + 31); fEnd();
}
static void emwPageWhen() {
  emwLabel("WHEN", 15, C_EB_GREY);
  uint32_t tip = emRd32(g_emwSt + 8), x = emRd32(g_emwSt + 16), life = emRd32(g_emwSt + 20), q = emRd32(g_emwSt + 36);
  char v[32], s[48], b[16], pl[24];
  emwComma(life, b, sizeof b); snprintf(v, sizeof v, "block %s", b);
  if (tip <= life) snprintf(s, sizeof s, "just now"); else { emwPlain(tip - life, pl, sizeof pl); snprintf(s, sizeof s, "%s ago", pl); }
  emwWhenRow(40, "LAST SEEN", v, s, false, false);
  uint32_t link = g_emwSt[6], nl = g_emwSt[7];
  if (link + 1 >= nl) { snprintf(v, sizeof v, "no moves left"); snprintf(s, sizeof s, "seal a fresh plan soon"); emwWhenRow(98, "NEXT MOVE", v, s, true, false); }
  else {
    uint32_t win = x - q / 2; emwComma(win, b, sizeof b); snprintf(v, sizeof v, "block %s", b);
    if (tip >= win) snprintf(s, sizeof s, "due now, on your next unlock"); else { emwPlain(win - tip, pl, sizeof pl); snprintf(s, sizeof s, "in %s", pl); }
    emwWhenRow(98, "NEXT MOVE", v, s, false, false);
  }
  uint32_t paid = emwPaidAt(); emwComma(paid, b, sizeof b); snprintf(v, sizeof v, "paid at %s", b);
  emwPlain(q + emwAg(), pl, sizeof pl); snprintf(s, sizeof s, "%s after your last unlock", pl);
  emwWhenRow(156, "IF YOU GO QUIET NOW", v, s, true, true);
}
static void emwPageAction(float p) {
  bool btc = g_ceremonyBoot;
  emwLabel(btc ? "BITCOIN DOOR" : "NOSTR DOOR", 15, C_EB_GREY);
  uint16_t col = btc ? C_RED : C_EB_BRASS;
  emwRing(120, 88, 50, p, col);
  fSet(F_BRAND_B14); int w = emwTrackW(btc ? "CLEAR" : "PULSE", 3); emwTrackAt(btc ? "CLEAR" : "PULSE", 120 - w / 2, 81, col, 3); fEnd();
  if (btc) { emwLine("Hold ENTER to end this plan.", 158, C_EB_INK); emwLine("Your coins stay where they are.", 174, C_EB_GREY); }
  else if (!wallet.unlocked) { emwLine("Unlock the KEY first.", 158, C_EB_INK); emwLine("Unlocking counts as alive too.", 174, C_EB_GREY); }
  else { emwLine("Hold ENTER to show you are here.", 158, C_EB_INK); emwLine("The count goes back to full.", 174, C_EB_GREY); }
}
static const int EMW_PAGES = 4;
static void emwStatusDraw(int page, float hold) {
  spr.fillSprite(C_BG);
  switch (page) { case 0: emwPageCount(); break; case 1: emwPageHeirs(); break; case 2: emwPageWhen(); break; default: emwPageAction(hold); }
  emwDots(page, EMW_PAGES);
  dispPush();
}
// Blocking. UP/DOWN pages, BACK leaves, ENTER held 2 s on page 4 acts:
// Clear in the Bitcoin door, Pulse in the Nostr door (unlocked).
static void emwStatusScreen() {
  if (!emwRefresh(true)) { dispError("No Emberwill plan"); errorPause(); return; }
  emwXpLoad();
  drainButtonsAfterTransition();
  int page = 0; float last = 0;
  emwStatusDraw(page, 0);
  uint32_t t0 = millis(), lastRefresh = millis();
  while (true) {
    emwPumpUi();
    if (btn4.isPressed()) return;
    if (btn1.isPressed()) { page = (page + 1) % EMW_PAGES; t0 = millis(); btn2.resetHold(); emwStatusDraw(page, 0); }
    if (btn3.isPressed()) { page = (page + EMW_PAGES - 1) % EMW_PAGES; t0 = millis(); btn2.resetHold(); emwStatusDraw(page, 0); }
    (void)btn2.isPressed();                                 // a tap does nothing; only a hold acts, and only on page 4
    if (page == EMW_PAGES - 1 && (g_ceremonyBoot || wallet.unlocked)) {
      float p = btn2.holdProgress(2000);
      if (p != last && (p - last > 0.04f || p == 0)) { last = p; emwStatusDraw(page, p); }
      if (p >= 1.0f) {
        last = 0; btn2.resetHold();
        if (g_ceremonyBoot) { if (emwClearNow()) return; }
        else if (!wifiConnected) { dispError("No WiFi for a Pulse"); errorPause(); }
        else emwPulsePublish(false);
        drainButtonsAfterTransition(); emwRefresh(true); emwStatusDraw(page, 0); t0 = millis();
      }
    }
    if (millis() - lastRefresh > 30000) { lastRefresh = millis(); emwRefresh(true); emwStatusDraw(page, last); }
    if (millis() - t0 > 180000) return;
  }
}

// ── the door card with no plan: setup step 1 ─────────────────────────────────
// Returns true when the owner asked to scan the plan (the caller routes to the
// scanner with g_emwScanPlan set).
static bool emwDoorScreen() {
  if (emwRefresh(true)) { emwStatusScreen(); return false; }
  drainButtonsAfterTransition();
  spr.fillSprite(C_BG);
  emwLabel("NEW PLAN", 15, C_EB_GREY);
  // viewfinder: brass corners, a dim QR hint inside
  const int x0 = 70, y0 = 36, s = 100, a = 20;
  spr.fillRect(x0, y0, a, 3, C_EB_BRASS);         spr.fillRect(x0, y0, 3, a, C_EB_BRASS);
  spr.fillRect(x0 + s - a, y0, a, 3, C_EB_BRASS); spr.fillRect(x0 + s - 3, y0, 3, a, C_EB_BRASS);
  spr.fillRect(x0, y0 + s - 3, a, 3, C_EB_BRASS); spr.fillRect(x0, y0 + s - a, 3, a, C_EB_BRASS);
  spr.fillRect(x0 + s - a, y0 + s - 3, a, 3, C_EB_BRASS); spr.fillRect(x0 + s - 3, y0 + s - a, 3, a, C_EB_BRASS);
  spr.fillRect(x0 + 26, y0 + 26, 17, 17, C_EB_LINE); spr.fillRect(x0 + 57, y0 + 26, 17, 17, C_EB_LINE); spr.fillRect(x0 + 26, y0 + 57, 17, 17, C_EB_LINE);
  spr.fillRect(x0 + 57, y0 + 57, 7, 7, C_EB_LINE); spr.fillRect(x0 + 67, y0 + 67, 7, 7, C_EB_LINE); spr.fillRect(x0 + 45, y0 + 45, 10, 10, C_EB_LINE);
  emwLine("Show the payment from your wallet.", 146, C_EB_INK);
  emwLine("Send it all, one line per person.", 164, C_EB_GREY);
  emwLine("Nothing is signed by this scan.", 178, C_EB_GREY);
  emwLabel("ENTER TO SCAN", 200, C_EB_BRASS);
  emwDots(0, 3);
  dispPush();
  uint32_t t0 = millis();
  while (true) {
    emwPumpUi();
    if (btn4.isPressed()) return false;
    if (btn2.isPressed()) { g_emwScanPlan = true; return true; }
    if (millis() - t0 > 120000) return false;
  }
}

// ── the scanned PSBT becomes a plan ──────────────────────────────────────────
// Rules (the G0 re-checks every one of them at EM_SET, this is the screen's
// honesty, not the security):
//   every input is this KEY's own BIP-84 coin (fingerprint + path + script,
//   verified seed-free from the account xpub), at most 3 of them;
//   every output is an heir: not ours, native segwit, at most 6;
//   shares come from the output amounts, in basis points summing to 10000.
// The PSBT's own fee is ignored: the G0 builds the release transactions with
// the plan's fee rule. Quiet is chosen on the review screen.
static const uint32_t EMW_QUIET_CHOICES[] = { 12, 144, 1008, 4032, 12960, 25920, 52560 };
static const char*    EMW_QUIET_WORDS[]   = { "bench", "1 day", "1 week", "1 month", "3 months", "6 months", "1 year" };
static bool g_emwHeirOwn[6];   // heir j is one of this KEY's own receive addresses (allowed: people test with themselves)
static void emwShortAddr(const uint8_t* spk, char* out, size_t cap) {
  char a[96]; if (!psbtSpkToAddr(spk, spk[1] + 2, a)) { snprintf(out, cap, "?"); return; }
  size_t n = strlen(a); if (n <= 13) { snprintf(out, cap, "%s", a); return; }
  snprintf(out, cap, "%.7s..%s", a, a + n - 4);   // 13 chars: clears the share column at F_MONO 12
}
static void emwReviewDraw(const uint8_t* w, uint64_t sats, int qi, float hold) {
  spr.fillSprite(C_BG);
  emwLabel("REVIEW", 15, C_EB_GREY);
  int shown = w[1] < 3 ? w[1] : 3;
  for (int j = 0; j < shown; j++) {
    const uint8_t* h = w + 160 + j * 36; int y = 40 + j * 20;
    char lab[8]; snprintf(lab, sizeof lab, g_emwHeirOwn[j] ? "YOU" : "HEIR %d", j + 1);
    fSet(F_BRAND_B12); int lw = emwTrackW(lab, 2); fEnd();
    emwLabelL(lab, 20, y + 3, C_EB_BRASS);
    char a[32]; emwShortAddr(h, a, sizeof a);
    fSet(F_MONO); spr.setTextColor(C_EB_INK); spr.drawString(a, 20 + lw + 8, y + 2); fEnd();
    unsigned bp = h[34] | (h[35] << 8); char s[12];
    if (bp % 100) snprintf(s, sizeof s, "%u.%u%%", bp / 100, (bp % 100) / 10); else snprintf(s, sizeof s, "%u%%", bp / 100);
    fSet(F_BRAND_B14); spr.setTextColor(C_EB_INK); emwRightText(s, 220, y); fEnd();
  }
  if (w[1] > 3) { char m[24]; snprintf(m, sizeof m, "and %u more", w[1] - 3); emwLine(m, 40 + 3 * 20, C_EB_GREY); }
  spr.drawFastHLine(20, 100, 200, C_EB_LINE);
  emwLabel("QUIET FOR", 108, C_EB_GREY);
  emwUse(EMW_VALUE); spr.setTextColor(C_EB_INK); spr.drawString(EMW_QUIET_WORDS[qi], 120 - spr.textWidth(EMW_QUIET_WORDS[qi]) / 2, 124); int vw = spr.textWidth(EMW_QUIET_WORDS[qi]); fEnd();
  // chevrons: UP / DOWN change it
  int cy = 138, lx = 120 - vw / 2 - 16, rx = 120 + vw / 2 + 16;
  spr.drawWideLine(lx + 4, cy - 6, lx - 2, cy, 2, C_EB_BRASS2); spr.drawWideLine(lx - 2, cy, lx + 4, cy + 6, 2, C_EB_BRASS2);
  spr.drawWideLine(rx - 4, cy - 6, rx + 2, cy, 2, C_EB_BRASS2); spr.drawWideLine(rx + 2, cy, rx - 4, cy + 6, 2, C_EB_BRASS2);
  char q[16], s[24], l[48]; emwComma(EMW_QUIET_CHOICES[qi], q, sizeof q); emwComma(sats, s, sizeof s);
  snprintf(l, sizeof l, "%s blocks  %s sats", q, s);
  fSet(F_MONO); spr.setTextColor(C_EB_GREY); fDrawCentre(l, 120, 162); fEnd();
  emwLabel("HOLD ENTER TO SEAL", 194, C_EB_BRASS);
  if (hold > 0) { fSet(F_BRAND_B12); int tw = emwTrackW("HOLD ENTER TO SEAL", 3); fEnd(); spr.fillRect(120 - tw / 2, 210, (int)(tw * (hold > 1 ? 1 : hold)), 2, C_EB_BRASS); }
  emwDots(1, 3);
  dispPush();
}
static void emwSealProgress(unsigned s, unsigned n) {
  spr.fillSprite(C_BG);
  emwLabel("SEALING", 15, C_EB_GREY);
  emwRing(120, 88, 50, n ? (float)s / (float)n : 0, C_EB_BRASS);
  emwEmber(102, 70, 6, 2, 13, false);
  char t[24]; if (n) snprintf(t, sizeof t, "%u of %u", s, n); else snprintf(t, sizeof t, "preparing");
  emwUse(EMW_VALUE); spr.setTextColor(C_EB_INK); spr.drawString(t, 120 - spr.textWidth(t) / 2, 152); fEnd();
  emwLine("The vault signs. The KEY checks.", 190, C_EB_GREY);
  emwDots(2, 3);
  dispPush();
}
// Build the 430-byte plan from the PSBT. Returns NULL on success, else the
// reason (short, for dispError).
static const char* emwPlanBuild(const uint8_t* psbt, size_t len, uint8_t w[430], uint64_t* satsOut) {
  static psbt_t* P = nullptr;
  if (!P) P = (psbt_t*)heap_caps_calloc(1, sizeof(psbt_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!P) return "No memory";
  memset(P, 0, sizeof(psbt_t));
  if (!psbt_parse(psbt, len, P)) return "PSBT parse failed";
  if (P->tx.n_inputs < 1 || P->tx.n_inputs > 3) return "1 to 3 coins only";
  if (P->tx.n_outputs < 1 || P->tx.n_outputs > 6) return "1 to 6 heirs only";
  memset(w, 0, 430); memset(g_emwHeirOwn, 0, sizeof g_emwHeirOwn);
  uint64_t in = 0, out = 0; uint32_t maxRecv = 0; bool anyRecv = false;
  for (uint8_t i = 0; i < P->tx.n_inputs; i++) {
    const psbt_input_t* pi = &P->inputs[i];
    if (!pi->witness_utxo_present) return "PSBT missing witness UTXO";
    if (!pi->nwu_verified) return "Needs full previous txs";   // 23 Nov 2026 (#57): plan amounts proven, every coin
    uint32_t change, index;
    if (!psbt_verify_input_ownership_pub(pi, &P->tx.inputs[i], psbt_derive_pub_adapter, g_btc_master_fp, &change, &index)) return "A coin is not this KEY's";
    if (change > 1) return "Odd derivation path";
    uint8_t* c = w + 4 + i * 52;
    memcpy(c, P->tx.inputs[i].prev_txid, 32);
    emWr32(c + 32, P->tx.inputs[i].prev_vout);
    emWr32(c + 36, (uint32_t)pi->witness_utxo_value); emWr32(c + 40, (uint32_t)(pi->witness_utxo_value >> 32));
    emWr32(c + 44, change); emWr32(c + 48, index);
    in += pi->witness_utxo_value;
    if (change == 0) { anyRecv = true; if (index > maxRecv) maxRecv = index; }
  }
  w[0] = P->tx.n_inputs;
  for (uint8_t j = 0; j < P->tx.n_outputs; j++) {
    const psbt_txout_t* o = &P->tx.outputs[j];
    uint8_t* h = w + 160 + j * 36;
    bool segwit = (o->script_pubkey_len == 22 && o->script_pubkey[0] == 0x00 && o->script_pubkey[1] == 0x14) ||
                  (o->script_pubkey_len == 34 && o->script_pubkey[0] == 0x00 && o->script_pubkey[1] == 0x20) ||
                  (o->script_pubkey_len == 34 && o->script_pubkey[0] == 0x51 && o->script_pubkey[1] == 0x20);
    if (!segwit) return "Heir must be bc1";
    // Our own address is not an heir: a claimed change path that verifies is
    // change (send the whole coin), and any output that re-derives to one of
    // the coins' own scripts is refused the same way.
    const psbt_output_t* po = &P->outputs[j];
    uint8_t nb = po->n_bip32 ? po->n_bip32 : (po->bip32.present ? 1 : 0);
    for (uint8_t k = 0; k < nb; k++) {
      const psbt_bip32_t* b = po->n_bip32 ? &po->bip32s[k] : &po->bip32;
      if (!b->present || memcmp(b->fingerprint, g_btc_master_fp, 4) != 0 || b->path_len != 5) continue;
      uint8_t pub[33]; if (!psbt_derive_pub_adapter(b->path[3], b->path[4], pub)) continue;
      uint8_t wp[20]; hash160(pub, 33, wp);
      if (o->script_pubkey_len == 22 && memcmp(o->script_pubkey + 2, wp, 20) == 0) { if (b->path[3] == 1) return "Change output: send it all"; g_emwHeirOwn[j] = true; }
    }
    memcpy(h, o->script_pubkey, o->script_pubkey_len);
    out += o->value;
  }
  if (!out) return "Outputs carry nothing";
  if (out > in) return "Outputs exceed the coins";
  unsigned sum = 0;
  for (uint8_t j = 0; j < P->tx.n_outputs; j++) {
    uint8_t* h = w + 160 + j * 36;
    unsigned bp = (unsigned)((P->tx.outputs[j].value * 10000ULL + out / 2) / out);
    if (j == P->tx.n_outputs - 1) bp = 10000 - sum;                 // the last share absorbs the rounding
    if (bp < 1 || bp > 10000) return "A share rounds to nothing";
    h[34] = (uint8_t)bp; h[35] = (uint8_t)(bp >> 8); sum += bp;
  }
  if (sum != 10000) return "Shares do not sum";
  w[1] = P->tx.n_outputs; w[2] = 2;                                // two links
  memcpy(w + 376, w + 160, 34);                                     // executor bump pays heir 1
  emWr32(w + 410, EMW_QUIET_CHOICES[0]);
  emWr32(w + 414, anyRecv ? maxRecv + 1 : 100);                     // refresh addresses from /0/<n>
  w[418] = 5; w[420] = 15; w[422] = 40; w[424] = 10;                // coupon 5/15/40, refresh 10 sat/vB
  emWr32(w + 426, 1000);                                            // bump 1000 sats
  *satsOut = in;
  return nullptr;
}
// The whole flow after the scanner handed us PSBT bytes. Blocking; returns to
// the door whatever happens.
static void emwPlanFromPsbt(const uint8_t* psbt, size_t len) {
  static uint8_t w[430]; uint64_t sats = 0;
  const char* why = emwPlanBuild(psbt, len, w, &sats);
  if (why) { Serial.printf("[EMW] plan refused: %s\n", why); dispError(why); errorPause(); return; }
  Serial.println("[EMW] plan from PSBT:"); emPlanShow(w);
  int qi = 0; const int nq = (int)(sizeof(EMW_QUIET_CHOICES) / sizeof(EMW_QUIET_CHOICES[0]));
  drainButtonsAfterTransition();
  btn2.resetHold();
  emwReviewDraw(w, sats, qi, 0);
  uint32_t t0 = millis(); bool sealed = false; float last = 0;
  while (true) {
    emwPumpUi();
    if (btn4.isPressed()) return;
    if (btn1.isPressed()) { qi = (qi + 1) % nq; emwReviewDraw(w, sats, qi, 0); }
    if (btn3.isPressed()) { qi = (qi - 1 + nq) % nq; emwReviewDraw(w, sats, qi, 0); }
    (void)btn2.isPressed();
    float p = btn2.holdProgress(1500);
    if (p != last && (p - last > 0.05f || p == 0)) { last = p; emwReviewDraw(w, sats, qi, p); }
    if (p >= 1.0f) { sealed = true; break; }
    if (millis() - t0 > 300000) return;
  }
  if (!sealed) return;
  emWr32(w + 410, EMW_QUIET_CHOICES[qi]);
  { Preferences p; if (!p.begin("emb", false) || p.putBytes("plan", w, 430) != 430) { dispError("NVS write failed"); errorPause(); return; } p.end(); }
  // Spend PIN on screen, then the ceremony with progress.
  if (!btcCollectSpendPin()) { psbtClearSpendPin(); return; }
  uint8_t s[96]; if (!emStatus(s)) { psbtClearSpendPin(); dispError("No Emberwill G0"); errorPause(); return; }
  uint8_t pkt[G0_SEED_IN_LEN]; uint8_t kind = 0;
  I2C_LOCK();
  int wsp = btcWitnessedSpendOpen(false, false, pkt, &kind);
  I2C_UNLOCK();
  psbtClearSpendPin();
  if (wsp != 1) { mbedtls_platform_zeroize(pkt, sizeof pkt); dispError(wsp == 0 ? "Wrong PIN" : "Spend session refused"); errorPause(); return; }
  { Preferences p; if (p.begin("emb", false)) { p.remove("nb"); p.end(); } }
  emwSealProgress(0, 0);
  g_ewcWire = w;   // 11cd: the ESP32 checks every transaction against this plan
  bool ok = g0_em_ceremony(w, pkt, kind, emBlobSink, emwSealProgress, &g_ewcHooks);
  mbedtls_platform_zeroize(pkt, sizeof pkt);
  Serial.printf("[EMW] ceremony %s\n", ok ? "COMPLETE" : "FAILED");
  if (!ok) { dispError("Seal failed"); errorPause(); return; }
  { uint8_t own = 0; for (int j = 0; j < 6; j++) if (g_emwHeirOwn[j]) own |= (uint8_t)(1u << j);
    Preferences p; if (p.begin("emb", false)) { p.putUInt("st0", emRd32(s + 8)); p.putUChar("ho", own); p.remove("xp"); p.end(); } }   // seal tip (Afterglow length, "sealed at") and which heirs are YOU
  memset(&g_xp, 0, sizeof g_xp); g_xpLoaded = true;
  emwRefresh(true);
  dispSuccessFor("Sealed", "Unlock now and then to stay alive", C_EB_BRASS);
}

// =============================================================================
// Executor on the KEY (29 Oct 2026). Replaces tools/ember_exec.py: after each
// sync that reaches the tip it
//   1. asks the G0 what the rule allows (EM_STATUS next), and if that is a
//      refresh or a coupon fee variant not yet sent, releases it (EM_RELEASE)
//      and pushes it to three Bitcoin nodes (inv, then tx);
//   2. downloads each new block (getdata MSG_BLOCK, no witness) and streams it:
//      every transaction is hashed as it arrives, the txids are kept in PSRAM,
//      the merkle root is recomputed and checked against the header the G0
//      already accepted, and if one of ours is there its branch is kept;
//   3. once the block is deep enough (refresh 3, coupon 1, as the walk wants)
//      hands the G0 the proof (EM_PROOF: kind|link|var|depth|index|header|branch).
// Nothing here is trusted by the G0: it re-checks every header's work and every
// proof against its own chain. A node can only withhold, so the push goes to
// three nodes and repeats every 20 min until the transaction is found.
// =============================================================================
static const uint32_t EMW_REPUSH_MS = 20UL * 60UL * 1000UL;
static const uint32_t EMW_MAX_TX    = 16384;          // txids per block kept in PSRAM (512 KB)
static uint32_t g_emwLastPush = 0;
static uint8_t (*g_emwTxids)[32] = nullptr;

static void emwDsha(const uint8_t* d, size_t n, uint8_t out[32]) { uint8_t t[32]; mbedtls_sha256(d, n, t, 0); mbedtls_sha256(t, 32, out, 0); }
static void emwXpClear();
static void emwXpLoad() {
  if (g_xpLoaded) return;
  g_xpLoaded = true;
  Preferences p; if (p.begin("emb", true)) { if (p.getBytes("xp", &g_xp, sizeof g_xp) != sizeof g_xp) memset(&g_xp, 0, sizeof g_xp); p.end(); }
  if (g_xp.magic != 0xE7) memset(&g_xp, 0, sizeof g_xp);
  // 11dc (#54, audit 21 Nov): the record is plaintext NVS that any code on the
  // ESP32 can write, and depth / ncand are used as sizes (memcpy into a 728-byte
  // stack buffer, loops over the 3-entry arrays). A record outside what this
  // code ever writes is dropped, never used: depth <= 20 (branch[20]), ncand <=
  // 3 with every var a coupon variant (0..2) and foundVar one of them, kind 'R'
  // or 'C', and a found height no later than the highest block searched.
  if (g_xp.magic == 0xE7) {
    bool ok = g_xp.depth <= 20 && g_xp.ncand <= 3 && (g_xp.kind == 'R' || g_xp.kind == 'C')
           && (g_xp.foundH == 0 || g_xp.foundH <= g_xp.scanned);
    for (uint8_t i = 0; ok && i < g_xp.ncand; i++) if (g_xp.var[i] > 2) ok = false;
    if (ok && g_xp.foundH && g_xp.foundVar > 2) ok = false;
    if (!ok) { Serial.printf("[EMW] pending-broadcast record out of range (depth %u, ncand %u): dropped\n", (unsigned)g_xp.depth, (unsigned)g_xp.ncand); emwXpClear(); }
  }
}
static void emwXpSave() { Preferences p; if (p.begin("emb", false)) { p.putBytes("xp", &g_xp, sizeof g_xp); p.end(); } }
static void emwXpClear() { memset(&g_xp, 0, sizeof g_xp); emwXpSave(); }

// blob index for (what, link, var): 3 coupon variants per link, one refresh between links
static unsigned emwBlobIndex(unsigned what, unsigned link, unsigned var) {
  return what == 1 ? 3 + (link - 1) * 4 : (link == 0 ? var : 3 + (link - 1) * 4 + 1 + var);
}
// varint from a buffer
static bool emwBufVarint(const uint8_t* b, size_t n, size_t* pos, uint64_t* v) {
  if (*pos >= n) return false;
  uint8_t f = b[(*pos)++];
  if (f < 0xfd) { *v = f; return true; }
  int k = f == 0xfd ? 2 : f == 0xfe ? 4 : 8; if (*pos + k > n) return false;
  uint64_t x = 0; for (int i = k - 1; i >= 0; i--) x = (x << 8) | b[*pos + i]; *pos += k; *v = x; return true;
}
// txid of a raw transaction (segwit or not): hash of the serialization without marker, flag and witness
static bool emwTxid(const uint8_t* raw, size_t n, uint8_t out[32]) {
  if (n < 10) return false;
  bool sw = raw[4] == 0x00 && raw[5] == 0x01;
  if (!sw) { emwDsha(raw, n, out); return true; }
  size_t pos = 6; uint64_t cnt, l;
  if (!emwBufVarint(raw, n, &pos, &cnt)) return false;
  for (uint64_t i = 0; i < cnt; i++) { pos += 36; if (!emwBufVarint(raw, n, &pos, &l)) return false; pos += l + 4; if (pos > n) return false; }
  if (!emwBufVarint(raw, n, &pos, &cnt)) return false;
  for (uint64_t i = 0; i < cnt; i++) { pos += 8; if (!emwBufVarint(raw, n, &pos, &l)) return false; pos += l; if (pos > n) return false; }
  size_t bodyLen = pos - 6;
  uint8_t* s = (uint8_t*)heap_caps_malloc(4 + bodyLen + 4, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); if (!s) return false;
  memcpy(s, raw, 4); memcpy(s + 4, raw + 6, bodyLen); memcpy(s + 4 + bodyLen, raw + n - 4, 4);
  emwDsha(s, 8 + bodyLen, out); heap_caps_free(s);
  return true;
}
// merkle root of ids (internal order); scratch must hold n entries. With idx < n, also the branch.
static int emwMerkle(const uint8_t (*ids)[32], uint32_t n, uint8_t (*scratch)[32], uint8_t root[32], int32_t idx, uint8_t (*branch)[32]) {
  if (!n) return -1;
  memcpy(scratch, ids, (size_t)n * 32);
  int depth = 0; uint8_t pair[64];
  while (n > 1) {
    if (idx >= 0) { uint32_t sib = (uint32_t)idx ^ 1u; if (sib >= n) sib = (uint32_t)idx; if (depth >= 20) return -1; memcpy(branch[depth], scratch[sib], 32); }
    depth++;
    uint32_t m = (n + 1) / 2;
    for (uint32_t i = 0; i < m; i++) {
      memcpy(pair, scratch[2 * i], 32); memcpy(pair + 32, scratch[(2 * i + 1 < n) ? 2 * i + 1 : 2 * i], 32);
      emwDsha(pair, 64, scratch[i]);
      esp_task_wdt_reset();
    }
    n = m; if (idx >= 0) idx >>= 1;
  }
  memcpy(root, scratch[0], 32);
  return depth;
}

// ── a connection to some node (seed rotation) ───────────────────────────────
// 29 Oct 2026: a broadcast while the KEY sat dimmed on the lock screen froze
// the buttons for 42 s (three nodes, two dead connects at 8 s each, 4 s inv
// and 8 s pong waits). Every network wait below now checks for a press and
// gives way; the push is retried on a later sync.
static bool g_emwYielded = false;
// Cap (29 Oct 2026): a broadcast may give way to the buttons for at most
// 10 minutes. After that it goes out even if someone is pressing, and the
// buttons freeze for the few seconds it takes. A payout or refresh must not
// be put off indefinitely by a KEY in constant use.
static uint32_t g_emwDeferSince = 0;           // 0 = not deferring
static const uint32_t EMW_DEFER_CAP_MS = 10UL * 60UL * 1000UL;
static bool emwPushYield() {
  if (g_emwDeferSince && millis() - g_emwDeferSince > EMW_DEFER_CAP_MS) return false;
  return emwUserWaiting();
}
static bool emwConnect(WiFiClient& c, bool relay, String* peer) {
  static int rot = 0;
  const char* seeds[] = { "seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "seed.bitcoin.sprovoost.nl", "seed.btc.petertodd.org", "dnsseed.emzy.de", "seed.bitcoin.wiz.biz" };
  uint32_t height = emRd32(g_emwSt + 8);
  for (int si = 0; si < 6; si++) {
    if (emwPushYield()) { Serial.println("[EMW] button pressed: network work gives way"); g_emwYielded = true; return false; }
    const char* sd = seeds[(rot++) % 6]; IPAddress ip;
    if (!WiFi.hostByName(sd, ip) || ip == IPAddress(0, 0, 0, 0)) continue;   // 23 Nov 2026: 0.0.0.0 = no address
    c.setTimeout(20);
    if (emwHandshake(c, ip, height, relay)) { if (peer) *peer = ip.toString(); return true; }
    esp_task_wdt_reset();
  }
  return false;
}

// ── push a transaction to up to three nodes ──────────────────────────────────
static int emwPush(const uint8_t* raw, size_t n, const uint8_t txid[32]) {
  int sent = 0;
  g_emwYielded = false;
  for (int k = 0; k < 3; k++) {
    WiFiClient c; String peer;
    if (emwPushYield()) { g_emwYielded = true; Serial.println("[EMX]   button pressed: push gives way"); break; }
    if (!emwConnect(c, true, &peer)) break;
    uint8_t inv[37]; inv[0] = 1; emWr32(inv + 1, 1); memcpy(inv + 5, txid, 32);   // MSG_TX
    emwSend(c, "inv", inv, sizeof inv);
    bool asked = false; uint32_t t0 = millis();
    while (millis() - t0 < 2000 && !emwPushYield()) {
      uint8_t h[24]; if (!emwReadN(c, h, 24, 2000)) break;
      if (memcmp(h, EMW_MAGIC, 4) != 0) break;
      char cmd[13] = {0}; memcpy(cmd, h + 4, 12); uint32_t len = emRd32(h + 16);
      if (!strcmp(cmd, "getdata") && len >= 37 && len <= 50000) {
        uint8_t* g = (uint8_t*)malloc(len); if (!g) break;
        if (!emwReadN(c, g, len)) { free(g); break; }
        for (uint32_t i = 1; i + 36 <= len; i += 36) if (memcmp(g + i + 4, txid, 32) == 0) asked = true;
        free(g);
        if (asked) break;
      } else if (!strcmp(cmd, "ping") && len == 8) { uint8_t nn[8]; if (!emwReadN(c, nn, 8)) break; emwSend(c, "pong", nn, 8); }
      else if (!emwSkip(c, len)) break;
    }
    emwSend(c, "tx", raw, (uint32_t)n);               // asked for it, or (no answer) push it anyway
    // 29 Oct 2026: the first PC-free payout (faa0a14d...) never reached the
    // network although two nodes asked for it: we closed 300 ms after "tx",
    // and a node drops a disconnected peer's unprocessed messages. Now send a
    // ping right behind it and wait for the matching pong: nodes handle a
    // peer's messages in order, so the pong proves the tx was processed.
    bool processed = false;
    { uint8_t nonce[8]; esp_fill_random(nonce, 8); emwSend(c, "ping", nonce, 8);
      uint32_t t1 = millis();
      while (millis() - t1 < 8000) {
        if (emwPushYield()) { g_emwYielded = true; break; }
        uint8_t h[24]; if (!emwReadN(c, h, 24, 8000 - (millis() - t1))) break;   // a partial read must not be retried (it would desync the stream)
        if (memcmp(h, EMW_MAGIC, 4) != 0) break;
        char cmd[13] = {0}; memcpy(cmd, h + 4, 12); uint32_t len = emRd32(h + 16);
        if (!strcmp(cmd, "pong") && len == 8) { uint8_t pn[8]; if (!emwReadN(c, pn, 8)) break; if (!memcmp(pn, nonce, 8)) { processed = true; break; } }
        else if (!strcmp(cmd, "ping") && len == 8) { uint8_t nn[8]; if (!emwReadN(c, nn, 8)) break; emwSend(c, "pong", nn, 8); }
        else if (!emwSkip(c, len)) break;
      } }
    c.stop(); if (processed) sent++;
    Serial.printf("[EMX]   pushed to %s (%s, %s)\n", peer.c_str(), asked ? "it asked for it" : "it did not ask: it may already have it",
                  processed ? "processed" : "NOT confirmed processed - not counted");
  }
  return sent;
}

// ── stream one block, find our txids, keep the branch ───────────────────────
// Returns 1 found, 0 not in this block, -1 failure. Reads MSG_BLOCK (no witness):
// each transaction's bytes are exactly what its txid hashes.
struct EmwRd { WiFiClient* c; mbedtls_sha256_context* s; uint32_t left; bool ok; };
static bool emwRd(EmwRd& r, uint8_t* d, size_t n) {
  if (!r.ok || n > r.left) { r.ok = false; return false; }
  if (!emwReadN(*r.c, d, n)) { r.ok = false; return false; }
  r.left -= n; if (r.s) mbedtls_sha256_update(r.s, d, n); return true;
}
static uint64_t emwRdVarint(EmwRd& r) {
  uint8_t b[9]; if (!emwRd(r, b, 1)) return 0;
  if (b[0] < 0xfd) return b[0];
  int k = b[0] == 0xfd ? 2 : b[0] == 0xfe ? 4 : 8; if (!emwRd(r, b + 1, k)) return 0;
  uint64_t v = 0; for (int i = k; i >= 1; i--) v = (v << 8) | b[i]; return v;
}
static bool emwRdSkip(EmwRd& r, uint64_t n) { uint8_t b[256]; while (n && r.ok) { size_t k = n > sizeof b ? sizeof b : (size_t)n; emwRd(r, b, k); n -= k; esp_task_wdt_reset(); } return r.ok; }
static int emwScanBlock(WiFiClient& c, const uint8_t hdr[80]) {
  uint8_t hash[32]; emwDsha(hdr, 80, hash);
  uint8_t gd[37]; gd[0] = 1; emWr32(gd + 1, 2); memcpy(gd + 5, hash, 32);       // MSG_BLOCK
  emwSend(c, "getdata", gd, sizeof gd);
  uint32_t len = 0; uint32_t t0 = millis();
  EmwGuard guard(180000, false);   // #56-2: one block (up to 4 MB) gets 3 minutes in all, however slowly it trickles
  while (true) {
    if (millis() - t0 > 60000) return -1;
    uint8_t h[24]; if (!emwReadN(c, h, 24, 30000)) return -1;
    if (memcmp(h, EMW_MAGIC, 4) != 0) return -1;
    char cmd[13] = {0}; memcpy(cmd, h + 4, 12); len = emRd32(h + 16);
    if (!strcmp(cmd, "block")) break;
    if (!strcmp(cmd, "notfound")) { emwSkip(c, len); return -1; }
    if (!strcmp(cmd, "ping") && len == 8) { uint8_t nn[8]; if (!emwReadN(c, nn, 8)) return -1; emwSend(c, "pong", nn, 8); }
    else if (!emwSkip(c, len)) return -1;
  }
  if (len > EMW_MAX_MSG) { Serial.printf("[EMX]   block of %lu bytes refused\n", (unsigned long)len); return -1; }   // #56-2
  if (!g_emwTxids && !(g_emwTxids = (uint8_t (*)[32])heap_caps_malloc((size_t)EMW_MAX_TX * 2 * 32, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT))) return -1;
  EmwRd r = { &c, nullptr, len, true };
  uint8_t bh[80]; if (!emwRd(r, bh, 80) || memcmp(bh, hdr, 80) != 0) { Serial.println("[EMX]   block header is not the one asked for"); return -1; }
  uint64_t ntx = emwRdVarint(r); if (!r.ok || !ntx || ntx > EMW_MAX_TX) { Serial.printf("[EMX]   bad tx count %llu\n", (unsigned long long)ntx); return -1; }
  mbedtls_sha256_context s; uint32_t ta = millis();
  for (uint64_t i = 0; i < ntx && r.ok; i++) {
    mbedtls_sha256_init(&s); mbedtls_sha256_starts(&s, 0); r.s = &s;
    uint8_t b[36];
    emwRd(r, b, 4);                                               // version
    uint64_t nin = emwRdVarint(r);
    for (uint64_t k = 0; k < nin && r.ok; k++) { emwRd(r, b, 36); emwRdSkip(r, emwRdVarint(r)); emwRd(r, b, 4); }
    uint64_t nout = emwRdVarint(r);
    for (uint64_t k = 0; k < nout && r.ok; k++) { emwRd(r, b, 8); emwRdSkip(r, emwRdVarint(r)); }
    emwRd(r, b, 4);                                               // locktime
    uint8_t one[32]; mbedtls_sha256_finish(&s, one); mbedtls_sha256_free(&s); r.s = nullptr;
    mbedtls_sha256(one, 32, g_emwTxids[i], 0);
    if ((i & 255) == 0) esp_task_wdt_reset();
  }
  if (!r.ok) { Serial.println("[EMX]   block stream broke off"); return -1; }
  // find ours
  int32_t at = -1; uint8_t fv = 0;
  for (uint8_t k = 0; k < g_xp.ncand && at < 0; k++)
    for (uint32_t i = 0; i < (uint32_t)ntx; i++) if (memcmp(g_emwTxids[i], g_xp.txid[k], 32) == 0) { at = (int32_t)i; fv = g_xp.var[k]; break; }
  uint8_t root[32], br[20][32];
  int depth = emwMerkle(g_emwTxids, (uint32_t)ntx, g_emwTxids + EMW_MAX_TX, root, at, br);
  if (depth < 0 || memcmp(root, hdr + 36, 32) != 0) { Serial.println("[EMX]   merkle root does not match the header: block not trusted"); return -1; }
  Serial.printf("[EMX]   block checked: %llu transactions, root matches (%lu ms)%s\n", (unsigned long long)ntx, (unsigned long)(millis() - ta), at >= 0 ? ", OURS IS IN IT" : "");
  if (at < 0) return 0;
  g_xp.foundIdx = (uint32_t)at; g_xp.foundVar = fv; g_xp.depth = (uint8_t)depth;
  memcpy(g_xp.hdr, hdr, 80); memset(g_xp.branch, 0, sizeof g_xp.branch); memcpy(g_xp.branch, br, (size_t)depth * 32);
  return 1;
}
static bool emwHeaderAt(uint32_t h, uint8_t out[80]) {
  emCacheLoad();
  if (!s_emCnt || h < s_emFirst || h >= s_emFirst + (uint32_t)s_emCnt) return false;
  memcpy(out, s_emRing[h - s_emFirst], 80); return true;
}

// ── release what the rule allows and push it ────────────────────────────────
static bool emwReleaseAndPush(uint8_t what, uint8_t link, uint8_t var) {
  static uint8_t *b = nullptr, *out = nullptr;
  if (!b) b = (uint8_t*)heap_caps_malloc(1300, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!out) out = (uint8_t*)heap_caps_malloc(1200, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!b || !out) return false;
  unsigned k = emwBlobIndex(what, link, var); size_t bn = 0, n = 0; int8_t rc = 0;
  if (!emLoadBlob(k, b, 1300, &bn)) { Serial.printf("[EMX] blob %u not in NVS\n", k); return false; }
  if (!(g0_em_stage(b, bn) && g0_em_cmd(0x38, &rc, out, 1200, &n, 5000)) || rc != 0) { Serial.printf("[EMX] G0 refused the release (rc %d)\n", rc); return false; }
  uint8_t txid[32]; if (!emwTxid(out, n, txid)) { Serial.println("[EMX] cannot parse the released transaction"); return false; }
  if (!ewcReleaseKnown(k, txid)) { snprintf(g_emwLast, sizeof g_emwLast, "release refused by the check"); return false; }   // 11cd (A1a)
  Serial.printf("[EMX] RELEASED %s link %u var %u, %u bytes, txid ", what == 1 ? "REFRESH" : "COUPON", link, var, (unsigned)n); emPrintHex(txid, 32, true); Serial.println();
  // record before pushing, so a reboot mid-push still looks for it
  bool have = false;
  for (uint8_t i = 0; i < g_xp.ncand; i++) if (g_xp.var[i] == var) have = true;
  if (!have && g_xp.ncand < 3) { g_xp.var[g_xp.ncand] = var; memcpy(g_xp.txid[g_xp.ncand], txid, 32); g_xp.ncand++; }
  emwXpSave();
  int sent = emwPush(out, n, txid); g_emwLastPush = millis();
  if (g_emwYielded && !sent) {
    g_emwLastPush = millis() - EMW_REPUSH_MS + 60000UL;   // gave way to a button: try again in about a minute
    if (!g_emwDeferSince) g_emwDeferSince = millis() | 1;
    Serial.printf("[EMX] deferred for the buttons (%lu s so far, cap %lu s)\n", (unsigned long)((millis() - g_emwDeferSince) / 1000), (unsigned long)(EMW_DEFER_CAP_MS / 1000));
  } else if (sent) g_emwDeferSince = 0;
  Serial.printf("[EMX] broadcast to %d node(s)\n", sent);
  snprintf(g_emwLast, sizeof g_emwLast, "%s sent to %d nodes", what == 1 ? "refresh" : "payment", sent);
  return sent > 0;
}

static void emwExecute(bool ui) {
  emwXpLoad();
  if (!emStatus(g_emwSt) || !(g_emwSt[5] & 1)) return;
  uint8_t what = g_emwSt[44], link = g_emwSt[45], var = g_emwSt[46];
  uint32_t tip = emRd32(g_emwSt + 8);
  char kind = what == 1 ? 'R' : what == 2 ? 'C' : 0;
  // 1. something new allowed?
  if (kind) {
    bool same = g_xp.magic == 0xE7 && g_xp.kind == kind && g_xp.link == link;
    if (!same && g_xp.magic == 0xE7 && g_xp.foundH)
      ;   // the older one is found and only waiting for depth: finish it first
    else {
      if (!same) { memset(&g_xp, 0, sizeof g_xp); g_xp.magic = 0xE7; g_xp.kind = kind; g_xp.link = link; g_xp.sentTip = tip; g_xp.scanned = tip; }
      bool have = false; for (uint8_t i = 0; i < g_xp.ncand; i++) if (g_xp.var[i] == var) have = true;
      bool due = !have || (!g_xp.foundH && g_xp.scanned >= tip && millis() - g_emwLastPush > EMW_REPUSH_MS);   // 29 Oct 2026: look in the blocks first; a mined tx needs no re-push
      if (due && !g_xp.foundH) { if (ui) emwCard(kind == 'R' ? "Moving coins" : "Paying heirs", "sending to the network", nullptr); emwReleaseAndPush(what, link, var); }
    }
  }
  if (g_xp.magic != 0xE7) return;
  // 2. look for it in the blocks since it was sent (at most 6 per call)
  if (!g_xp.foundH && g_xp.scanned < tip) {
    WiFiClient c; String peer; int looked = 0;
    if (ui) emwCard("Checking blocks", "looking for it", nullptr);
    if (emwConnect(c, false, &peer)) {
      while (g_xp.scanned < tip && looked < 6) {
        uint32_t h = g_xp.scanned + 1; uint8_t hdr[80];
        if (!emwHeaderAt(h, hdr)) { Serial.printf("[EMX] header %lu not in the cache; skipping it\n", (unsigned long)h); g_xp.scanned = h; continue; }
        Serial.printf("[EMX] block %lu from %s\n", (unsigned long)h, peer.c_str());
        int r = emwScanBlock(c, hdr); looked++;
        if (r < 0) break;                                   // try again next sync, from this block
        g_xp.scanned = h;
        if (r == 1) { g_xp.foundH = h; Serial.printf("[EMX] %s link %u var %u confirmed in block %lu at position %lu\n", g_xp.kind == 'R' ? "REFRESH" : "COUPON", g_xp.link, g_xp.foundVar, (unsigned long)h, (unsigned long)g_xp.foundIdx); break; }
      }
      c.stop();
    }
    emwXpSave();
  }
  // 3. deep enough: prove it to the G0
  if (g_xp.foundH) {
    uint32_t conf = tip - g_xp.foundH + 1, need = g_xp.kind == 'R' ? 3 : 1;
    if (conf < need) { Serial.printf("[EMX] depth %lu of %lu\n", (unsigned long)conf, (unsigned long)need); return; }
    uint8_t p[728]; memset(p, 0, sizeof p);
    p[0] = (uint8_t)g_xp.kind; p[1] = g_xp.link; p[2] = g_xp.foundVar; p[3] = g_xp.depth; emWr32(p + 4, g_xp.foundIdx);
    memcpy(p + 8, g_xp.hdr, 80); memcpy(p + 88, g_xp.branch, (size_t)g_xp.depth * 32);
    int8_t rc = 0; size_t n = 0;
    bool ok = g0_em_stage(p, sizeof p) && g0_em_cmd(0x35, &rc, nullptr, 0, &n, 5000);
    Serial.printf("[EMX] EM_PROOF %c %u %u -> rc %d\n", g_xp.kind, g_xp.link, g_xp.foundVar, ok ? rc : 99);
    if (ok && (rc == 0 || rc == -26)) { emwXpClear(); emwRefresh(true); }        // accepted, or the walk has already moved past it
    else if (ok && rc == -28) { g_xp.scanned = g_xp.foundH - 1; g_xp.foundH = 0; emwXpSave(); }   // proof does not check (reorg?): look again
  }
}
static void emwXpShow() {
  emwXpLoad();
  if (g_xp.magic != 0xE7) { Serial.println("[EMX] nothing pending"); return; }
  Serial.printf("[EMX] pending %c link %u, %u variant(s), sent at tip %lu, searched to %lu, found %lu\n", g_xp.kind, g_xp.link, g_xp.ncand,
                (unsigned long)g_xp.sentTip, (unsigned long)g_xp.scanned, (unsigned long)g_xp.foundH);
  for (uint8_t i = 0; i < g_xp.ncand; i++) { Serial.printf("[EMX]   var %u txid ", g_xp.var[i]); emPrintHex(g_xp.txid[i], 32, true); Serial.println(); }
}
#endif  // FAVILLA_EMBERWILL
