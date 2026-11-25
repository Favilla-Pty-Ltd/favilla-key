// ble_app.inc - the Favilla app's channel over Bluetooth (9g, 7 Nov 2026).
// Included by passkey_life.inc (PASSKEY life, FAVILLA_BLE_KBD + PK_RESTORABLE).
// Ruled (Josh, 7 Nov 2026, item 5 "start"): lock the Bluetooth link to the
// Favilla app. On an iPhone the bond is the phone's, not the app's, so any app
// on it could otherwise write a FILL or a CTAP request and read the answer.
//
// The USB channel's pairing and macs (chan_proto.h / chan_key.h), carried over
// 8f1a0005 (write) and 8f1a0006 (notify) in 64-byte reports:
//  - Pairing: only while PAIR A PHONE is open, one attempt per window, commit /
//    key / reveal, the 6-digit code compared on the KEY and in the app, stored on
//    ENTER. Up to 4 app installs.
//  - Requests [cmd][client 8][ctr u32 LE][body][mac16], mac over "REQ" || the
//    rest, ctr above the last. FILL 0x34, CTAP 0x35, CTAP_CANCEL 0x36, LIST 0x37
//    (LIST not yet: refused), and HELLO 0x30.
//  - Answers macced ("RSP"); a login (R_LOGIN 0xB3) and a CTAP response
//    (R_CTAP 0xB4) encrypted first (chan::encBody). R_KEEPALIVE 0xB5 is macced only.
//  - Once an app is paired the raw paths (8f1a0003 FILL, 8f1a0010 and 0xFFFD
//    CTAP) are refused with ATT 0x8F (0x80 + S_APP_ONLY).
// The KEY never answers on this channel to a client it has not paired, and a
// login or a signature still needs ENTER on the KEY, as on the raw paths.
bool chanc_hmac(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]);
bool chanc_hmac2(const uint8_t* k, size_t kl, const uint8_t* a, size_t al, const uint8_t* b, size_t bl, uint8_t out[32]);
bool chanc_open(const uint8_t seed[32]);
void chanc_close();
void chanc_rng(uint8_t* p, size_t n);
bool chanc_ecdh(const uint8_t peer[65], uint8_t z[32]);
bool chanc_mypub(uint8_t mine[65]);
bool chanc_ready();
#include "chan_key.h"
static bool vaImportUsed();   // 11bf: vault_api.inc (included after this file): this life's import window was opened
namespace ag {
static chan::Key g_key;
static SemaphoreHandle_t g_mx = nullptr; static StaticSemaphore_t g_mxBuf;
static bool g_loaded = false;
static volatile int g_count = 0;              // paired app installs (read without the lock by the raw-path check)
static volatile uint32_t g_winUntil = 0;
// the code on screen (1), set by pairShow under the lock
static volatile uint8_t g_ask = 0; static uint32_t g_askCode = 0; static uint8_t g_askId[chan::ID];
// the request in progress per kind: its client and counter (the answer echoes them)
static int g_fillCi = -1; static uint32_t g_fillCtr = 0;
static int g_ctapCi = -1; static uint32_t g_ctapCtr = 0;
// item 4 LIST: one ask waiting for the life's loop (it reads the vault and asks
// the owner); a yes lets the same app page on for 30 s without asking again.
static volatile uint8_t g_listOn = 0; static int g_listCi = -1; static uint32_t g_listCtr = 0, g_listAt = 0; static uint16_t g_listStart = 0;
static int g_listOkCi = -1; static uint32_t g_listOkUntil = 0;
// 9i: a one-time code ask, also answered by the life's loop (otpTick)
static volatile uint8_t g_otpOn = 0; static int g_otpCi = -1; static uint32_t g_otpCtr = 0, g_otpAt = 0; static uint64_t g_otpT = 0; static char g_otpSite[chan::FIELD_MAX + 1];
static void lock(){ xSemaphoreTake(g_mx, portMAX_DELAY); }
static void unlock(){ xSemaphoreGive(g_mx); }
static void recount(){ g_count = g_key.count(); }
static bool save(const chan::Client* c, int n){
  Preferences p; if(!p.begin("vapp", false, NVSPART_SEC)) return false;
  size_t w = p.putBytes("cl", c, sizeof(chan::Client) * n); p.end();
  const bool ok = w == sizeof(chan::Client) * n;
  int k = 0; for(int i = 0; i < n; i++) k += c[i].used; g_count = k;
  return ok;
}
static void load(){
  if(g_loaded) return;
  g_loaded = true;
  Preferences p; if(p.begin("vapp", true, NVSPART_SEC)){ if(p.getBytesLength("cl") == sizeof(g_key.cl)) p.getBytes("cl", g_key.cl, sizeof(g_key.cl)); p.end(); }
  g_key.afterLoad(); recount();
}
static uint8_t life(){ if(g_nostrBtLife) return chan::L_NOSTR; return g_pkPinHeld ? chan::L_PASSKEY_READY : chan::L_PASSKEY_LOCKED; }   // 9k: L_NOSTR in the NOSTR Bluetooth life
static bool window(){ return g_winUntil && (int32_t)(g_winUntil - millis()) > 0 && blek::windowOpen() && chanc_ready(); }
static bool pairShow(uint32_t code, const uint8_t id[chan::ID]){   // under lock
  if(g_ask) return false;
  g_askCode = code; memcpy(g_askId, id, chan::ID); g_ask = 1;
  return true;
}
static chan::Status request(uint8_t, const char*, const char*){ return chan::S_BAD_REQUEST; }   // SIGN_IN / NEW_LOGIN are the browser's, not the app's
static void send(const uint8_t* m, size_t n){ blek::appSend(m, n); }
static bool ecdh(const uint8_t peer[65], uint8_t z[32]){ return chanc_ecdh(peer, z); }
// 11ah (issue #22): the KEY's pairing identity for HELLO: dev_pair_pub[0..7],
// the key the PWA pins. Read only (deviceIdentityInit runs in onMsg before the
// lock, so no SE traffic happens under it); zeros until it is known.
static bool pairIdHook(uint8_t out[8]){ if(!fsec::g_devIdReady) return false; memcpy(out, fsec::g_qDevice, 8); return true; }
// 11ah: what the camera read in PAIR A PHONE (the pairing screen's side, under lock)
static uint8_t g_scanExt[65]; static uint8_t g_scanNonce[16]; static bool g_scanHave = false;
static bool scannedHook(const uint8_t extPub[65], const uint8_t nonce[16]){   // under lock, from REVEAL
  return g_scanHave && chan::ctEq(extPub, g_scanExt, 65) && chan::ctEq(nonce, g_scanNonce, 16);
}
static void hooks(){ if(!g_key.h.hmac){ g_key.h = { chanc_hmac, chanc_mypub, ecdh, chanc_rng, save, life, window, pairShow, request, send, FAVILLA_BENCH_DROP }; g_key.h.pairId = pairIdHook; g_key.h.scanned = scannedHook; } }

// A macced (and, for secrets, encrypted) answer of any size. Builds outside the
// lock with a copy of the client's key; ci < 0 or a forgotten client: nothing.
static bool answer(int ci, uint8_t rsp, uint32_t ctr, const uint8_t* body, size_t bl, bool enc){
  uint8_t k[chan::KEYLEN], id[chan::ID];
  lock(); const bool ok0 = ci >= 0 && ci < chan::MAX_CLIENTS && g_key.cl[ci].used; if(ok0){ memcpy(k, g_key.cl[ci].k, sizeof k); memcpy(id, g_key.cl[ci].id, sizeof id); } unlock();
  if(!ok0) return false;
  const size_t n = 1 + chan::ID + 4 + bl;
  if(n + chan::MAC > chan::APP_MAX){ mbedtls_platform_zeroize(k, sizeof k); return false; }
  uint8_t* o = (uint8_t*)heap_caps_malloc(n + chan::MAC, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!o){ mbedtls_platform_zeroize(k, sizeof k); return false; }
  o[0] = rsp; memcpy(o + 1, id, chan::ID); chan::put32(o + 1 + chan::ID, ctr); if(bl) memcpy(o + 1 + chan::ID + 4, body, bl);
  bool ok = !enc || chan::encBody(chanc_hmac, k, rsp, id, ctr, o + 1 + chan::ID + 4, bl);   // encrypt, then mac
  uint8_t mac[32];
  ok = ok && chanc_hmac2(k, chan::KEYLEN, (const uint8_t*)"RSP", 3, o, n, mac);
  if(ok){ memcpy(o + n, mac, chan::MAC); ok = blek::appSend(o, n + chan::MAC); }
  mbedtls_platform_zeroize(o, n + chan::MAC); free(o);
  mbedtls_platform_zeroize(k, sizeof k); mbedtls_platform_zeroize(mac, sizeof mac);
  return ok;
}
static void err(int ci, uint32_t ctr, chan::Status s){ const uint8_t b = (uint8_t)s; answer(ci, chan::R_ERR, ctr, &b, 1, false); }

// Check a request of any size (under the lock). Returns the client, or -1 after
// answering why not. Same rules as chan::Key::process (mac, counter, ceiling).
static int verify(const uint8_t* m, size_t n, chan::Req* r){
  if(!chan::splitReq(m, n, r)){ g_key.sendErr(m[0], chan::S_NOT_PAIRED); return -1; }
  const int ci = g_key.find(r->id);
  if(ci < 0){ g_key.sendErr(r->cmd, chan::S_NOT_PAIRED); return -1; }
  uint8_t mac[32];
  if(!chanc_hmac2(g_key.cl[ci].k, chan::KEYLEN, (const uint8_t*)"REQ", 3, m, n - chan::MAC, mac) || !chan::ctEq(mac, m + n - chan::MAC, chan::MAC)){
    mbedtls_platform_zeroize(mac, sizeof mac); g_key.sendErr(r->cmd, chan::S_NOT_PAIRED); return -1; }
  mbedtls_platform_zeroize(mac, sizeof mac);
  if(r->ctr <= g_key.cl[ci].ctr){ uint8_t b[5] = { chan::S_REPLAY }; chan::put32(b + 1, g_key.cl[ci].ctr); g_key.reply(ci, chan::R_ERR, r->ctr, b, 5); return -1; }   // the floor: the app resyncs
  if(r->ctr > g_key.cl[ci].hi){
    const uint32_t oldHi = g_key.cl[ci].hi; g_key.cl[ci].hi = r->ctr + chan::CTR_BLOCK;
    if(!save(g_key.cl, chan::MAX_CLIENTS)){ g_key.cl[ci].hi = oldHi; const uint8_t b = chan::S_STORAGE; g_key.reply(ci, chan::R_ERR, r->ctr, &b, 1); return -1; }
  }
  g_key.cl[ci].ctr = r->ctr;
  return ci;
}

// ---- 9k (issue #7): one HTTP call to the KEY's own /api handlers ---------------
// Request body: [method 1: 0x01 GET, 0x02 POST][path len u16 LE][path, with its
// query][header count 1] then per header [id 1][len u16 LE][value] (0x01
// X-Favilla-Session, 0x02 X-Favilla-Auth, 0x03 X-Favilla-Ctr) then [body len
// u16 LE][body]. Answer R_API 0xB8, encrypted: [status u16 LE][type 1: 0x00
// none, 0x01 application/json, 0x02 text/plain][body len u16 LE][body].
// Runs on this task (camServerTask's place in a life with no Wi-Fi), one at a
// time; the handlers answer at once (a press is polled by the PWA).
static void apiRequest(int ci, const chan::Req& r){
  // 9u: the decode is chan::apiDecode (chan_proto.h, fuzzed on a host).
  chan::ApiReq q; const bool ok = chan::apiDecode(r.body, r.bodyLen, &q);
  // 11by (issue #25): GET /api/link is answered while locked too, as over Wi-Fi
  // (it says only up, unlocked and signing). The page's lock probe reads
  // "unlocked":false from it and drops its DMs at once; a refusal looked like
  // a busy KEY to the page, which retried instead of wiping.
  const bool linkProbe = ok && q.meth == 0x01 && q.pathLen == 9 && memcmp(q.full, "/api/link", 9) == 0;
  if(!wallet.unlocked && !linkProbe){ err(ci, r.ctr, chan::S_LOCKED); LOG_BOOT("[APP] API refused: the NOSTR PIN is not entered\n"); return; }
  uint8_t meth = q.meth; String path, query, hs, ha, hc; const uint8_t* body = q.body; size_t bn = q.bodyLen;
  if(ok){
    path.concat(q.full, q.pathLen);
    if(q.pathLen < q.fullLen) query.concat(q.full + q.pathLen + 1, q.fullLen - q.pathLen - 1);
    if(q.hv[1]) hs.concat(q.hv[1], q.hl[1]);
    if(q.hv[2]) ha.concat(q.hv[2], q.hl[2]);
    if(q.hv[3]) hc.concat(q.hv[3], q.hl[3]);
  }
  if(!ok){ err(ci, r.ctr, chan::S_BAD_REQUEST); LOG_BOOT("[APP] API request not well formed\n"); return; }
  int code = 500; String type, out;
  const uint32_t t0 = millis();
  uint8_t appId[chan::ID]; lock(); memcpy(appId, g_key.cl[ci].id, chan::ID); unlock();
  apiTunnelRun(meth == 0x02 ? HTTP_POST : HTTP_GET, path, query, hs, ha, hc, body, bn, &code, &type, &out, appId);   // 9l: which app client (issue #8)
  if(out.length() > chan::API_BODY_MAX){ code = 500; type = "application/json"; out = "{\"error\":\"answer_too_large\"}"; }
  const size_t on = out.length();
  uint8_t* a = (uint8_t*)heap_caps_malloc(5 + on, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!a){ err(ci, r.ctr, chan::S_BUSY); return; }
  a[0] = (uint8_t)code; a[1] = (uint8_t)(code >> 8);
  a[2] = type.startsWith("application/json") ? 0x01 : type.startsWith("text/plain") ? 0x02 : 0x00;
  a[3] = (uint8_t)on; a[4] = (uint8_t)(on >> 8); if(on) memcpy(a + 5, out.c_str(), on);
  // 9r (bench, 8 Nov 2026: a 1202-byte answer queued whole, only its first
  // notification reached the phone; internal heap 3520 free, largest 1140).
  // The Bluetooth controller takes its transmit buffers from internal RAM as
  // each packet goes in, and these Strings (the answer, the headers) sit in
  // internal RAM. Hand them back before sending: the answer is in PSRAM now.
  char pathLog[49]; snprintf(pathLog, sizeof pathLog, "%s", path.c_str());
  out = String(); type = String(); path = String(); query = String(); hs = String(); ha = String(); hc = String();
  const bool sent = answer(ci, chan::R_API, r.ctr, a, 5 + on, true);
  if(!sent) err(ci, r.ctr, chan::S_BUSY);   // 11ad: never leave the app waiting out its timeout on an answer that could not go
  mbedtls_platform_zeroize(a, 5 + on); free(a);
  LOG_BOOT("[APP] API %s %s -> %d, %u bytes in %lu ms, %s\n", meth == 0x02 ? "POST" : "GET", pathLog, code, (unsigned)on, (unsigned long)(millis() - t0), sent ? "sent" : "NOT sent");
}
// ---- 10p (issue #11): the Bluetooth bunker --------------------------------------
// NIP46 0x3B: one kind-24133 event (the event object, UTF-8 JSON, up to 32768
// bytes). The main loop runs it as if it had come in on a relay socket; the
// answer comes at once and carries no reply (11m, see nip46Request). NIP46_POLL
// 0x3C: the replies ready. Both answer R_NIP46 0xB9, macced, not
// encrypted (each reply is NIP-44 to its client and goes to a public relay):
// [flags: bit0 more to come][count] then [len u16 LE][relay message] per reply.
// btbSubmit, btbDoneFor, btbBuild, btbCommit, btbInfo: main.cpp (included before this file).
static void nip46Answer(int ci, uint32_t ctr, const char* why){
  const size_t cap = chan::APP_MAX - (1 + chan::ID + 4 + chan::MAC);
  uint8_t* b = (uint8_t*)heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!b){ err(ci, ctr, chan::S_BUSY); return; }
  char* taken[8]; const size_t n = btbBuild(b, cap, taken);
  const bool sent = answer(ci, chan::R_NIP46, ctr, b, n, false);
  if(sent) btbCommit(taken);
  if(b[1] || why || (b[0] & 1)) LOG_BOOT("[APP] NIP46 %s: %u repl%s, %u bytes, more %d%s%s, %s\n", why ? why : "poll", (unsigned)b[1], b[1] == 1 ? "y" : "ies", (unsigned)n, b[0] & 1,
                                           (b[0] & 1) ? " (" : "", (b[0] & 1) ? btbBusyWhy() : "", sent ? "sent" : "NOT sent (kept)");   // 11l: says why "more"
  if(b[0] & 1) LOG_BOOT("%s", (b[0] & 1) ? ")\n" : "");
  free(b);
}
static void nip46Request(int ci, const chan::Req& r){
  if(r.bodyLen == 0 || r.bodyLen > 32768 || r.body[0] != '{'){ err(ci, r.ctr, chan::S_BAD_REQUEST); LOG_BOOT("[APP] NIP46 request not an event object (%u bytes)\n", (unsigned)r.bodyLen); return; }
  // An approval on the KEY's screen: the relay path would drop a new request
  // here. Refused instead, so it stays at the phone's bridge for later.
  if(pendingApproval || currentState == ST_APPROVAL){ err(ci, r.ctr, chan::S_BUSY); LOG_BOOT("[APP] NIP46 request refused: an approval is on the KEY's screen\n"); return; }
  const uint32_t t = btbSubmit(r.body, r.bodyLen);
  if(!t){ err(ci, r.ctr, chan::S_BUSY); LOG_BOOT("[APP] NIP46 request refused: queue full\n"); return; }
  // 11m (9 Nov 2026): answered at once, always "taken, more to come, 0 replies".
  // Until 11l this waited up to 4 s and carried the reply inline when signing
  // finished in time (240 MHz: 2.7 s), which the app on TestFlight ignores; it
  // only reads replies from a POLL. So requests in succession were lost while
  // ones after an idle spell (80 MHz, > 4 s) worked. Replies now travel only on
  // POLL 0x3C, and the Bluetooth task is not parked for 4 s per request.
  const uint8_t b[2] = { 1, 0 };
  const bool sent = answer(ci, chan::R_NIP46, r.ctr, b, sizeof b, false);
  LOG_BOOT("[APP] NIP46 request: taken (#%lu), %u repl%s already waiting, %s - poll for the reply\n", (unsigned long)t, (unsigned)btbWaiting(), btbWaiting() == 1 ? "y" : "ies", sent ? "sent" : "NOT sent");
}
// ---- 11i (issue #11, path B): the KEY wakes the app -----------------------------
// iOS lets an app that holds a Bluetooth link stay registered in the background
// and wakes it for a few seconds whenever the device it is connected to sends it
// something. So the app keeps the link and asks the KEY to nudge it every few
// seconds (NUDGE_SET 0x3E, [seconds 1], 0 = off); on each R_NUDGE 0xBB it checks
// the bridge for waiting requests and hands them over on the link it already
// holds: no push, no extension start, no reconnect. Per connection: the app asks
// again after each connect. NOSTR Bluetooth life, after the NOSTR PIN.
// R_NUDGE body: [seq u32 LE][replies waiting in the KEY's outbox 1]. Macced,
// counter 0 (unsolicited), to the client that last spoke on this connection.
static volatile uint8_t g_nudgeSec = 0; static uint32_t g_nudgeLast = 0, g_nudgeSeq = 0; static int g_nudgeCi = -1;
static bool g_nudgeConn = false; static uint32_t g_lastAppReqMs = 0;   // btbWaiting(), btbOn(): main.cpp, defined before this file
// 11bt (issue #39): CIPHER's daily block through the phone. DAILY raises the
// ask (bit2 of the nudge's third byte) and nudges at once; the app answers with
// CIPHER_DAY 0x50, which the app task checks and leaves here for the game.
static volatile bool g_cgAsk = false; static volatile uint32_t g_cgAskAt = 0;
static char g_cgPush[200]; static volatile bool g_cgPushSet = false;
static portMUX_TYPE g_cgMux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t nudgeAsks(){
  if(g_cgAsk && millis() - g_cgAskAt > 30000UL) g_cgAsk = false;   // an ask nobody answered lapses
  return (uint8_t)(g_vpWant | (g_cgAsk ? chan::NUDGE_CIPHER_DAY : 0));
}
static bool cgDayTake(char* out, size_t n){   // the block the phone sent, taken once
  bool got = false;
  portENTER_CRITICAL(&g_cgMux);
  if(g_cgPushSet && n > strlen(g_cgPush)){ strcpy(out, g_cgPush); g_cgPushSet = false; got = true; }
  portEXIT_CRITICAL(&g_cgMux);
  return got;
}
static bool nudgeNow();
static void cgDayAskPhone(){ g_cgAskAt = millis(); g_cgAsk = true; nudgeNow(); }
static void cgDayAskDrop(){ g_cgAsk = false; }
// 11bx (issue #25): the lock state rides in a 7th byte, and a change of it
// (PIN in, or the KEY locking: lock, sleep, timeout) sends one nudge at once,
// so the app probes /api/link straight away and the page drops its DMs within
// about a second. bit0 unlocked now, bit1 changed since the last nudge sent.
static int8_t g_lockPrev = -1; static bool g_lockChanged = false;
static uint8_t nudgeLockByte(){ return (uint8_t)((btbOn() ? 0x01 : 0) | (g_lockChanged ? 0x02 : 0)); }
static bool nudgeNow();
static void nudgeTick(){
  if(!blek::s_conn){ if(g_nudgeConn){ g_nudgeConn = false; g_nudgeSec = 0; g_nudgeCi = -1; g_lockPrev = -1; g_lockChanged = false; } return; }
  g_nudgeConn = true;
  { const int8_t un = btbOn() ? 1 : 0;   // 11bx
    if(g_lockPrev >= 0 && un != g_lockPrev){
      g_lockPrev = un; g_lockChanged = true;
      if(g_nudgeSec && g_nudgeCi >= 0 && blek::s_aSub){ LOG_BOOT("[APP] %s: nudging the app now\n", un ? "unlocked" : "locked"); nudgeNow(); }
      return;
    }
    g_lockPrev = un; }
  if(!g_nudgeSec || g_nudgeCi < 0 || !blek::s_aSub || !btbOn()) return;
  const uint32_t now = millis();
  if(now - g_nudgeLast < (uint32_t)g_nudgeSec * 1000UL) return;
  // 11l: an app that has spoken in the last interval is awake and working;
  // an unsolicited 0xBB in the middle of its request/poll exchange is noise.
  if(now - g_lastAppReqMs < (uint32_t)g_nudgeSec * 1000UL){ g_nudgeLast = now; return; }
  g_nudgeLast = now;
  uint8_t b[7]; chan::put32(b, ++g_nudgeSeq); b[4] = (uint8_t)btbWaiting(); b[5] = nudgeAsks();   // 11q: third byte, the vault asks; 11bt: and bit2, the CIPHER block
  b[6] = nudgeLockByte();   // 11bx (issue #25): the lock state
  if(answer(g_nudgeCi, chan::R_NUDGE, 0, b, sizeof b, false)) g_lockChanged = false;
}
// 11o: one nudge now, whatever the interval and whether or not the app asked for
// nudges: the KEY has just put something in the outbox for the phone to publish
// (a CIPHER score). Needs a paired client that has spoken on this connection.
static bool nudgeNow(){
  if(!blek::s_conn || !blek::s_aSub || g_nudgeCi < 0) return false;
  g_nudgeLast = millis();
  uint8_t b[7]; chan::put32(b, ++g_nudgeSeq); b[4] = (uint8_t)btbWaiting(); b[5] = nudgeAsks();
  b[6] = nudgeLockByte();   // 11bx (issue #25)
  const bool ok = answer(g_nudgeCi, chan::R_NUDGE, 0, b, sizeof b, false);
  if(ok) g_lockChanged = false;
  LOG_BOOT("[APP] nudge now: seq %lu, %u replies waiting, asks 0x%02X, lock 0x%02X, %s\n", (unsigned long)g_nudgeSeq, b[4], b[5], b[6], ok ? "sent" : "NOT sent");
  return ok;
}
static bool appLinkUp(){ return blek::s_conn && blek::s_aSub && g_nudgeCi >= 0; }

// 11q: vault backup and restore through the phone. The records and the G0 are
// touched on the main loop only (vpPump); this task hands the job over and
// waits a little, then says busy so the app asks again.
// 11ad (11 Nov 2026): the waits were 8 s. The app gives a request 6 s plus
// 1 s per 8 KB sent (NostrLink.transmit), so a 31 KB VAULT_PUT whose merge
// took longer than about 7 s after the transfer timed out on the phone
// ("The KEY didn't answer in time") although the KEY was fine. Now 2 s on a
// PUT and 3 s on a GET stage; the doc already has the app asking again.
static bool vpWaitJob(int job, volatile int* result, uint32_t ms){
  *result = -1; g_vpJob = job;
  const uint32_t t0 = millis();
  while(g_vpJob && millis() - t0 < ms) vTaskDelay(pdMS_TO_TICKS(20));
  return !g_vpJob;
}
static void vaultRequest(int ci, uint8_t cmd, const chan::Req& r){
  if(cmd == chan::C_VAULT_INFO){
    // [status][vault pub 32][last backup u32][records in it u16][dirty][asked bits][relay]
    uint8_t pub[32], chk[8]; uint8_t b[1 + 32 + 4 + 2 + 1 + 1 + 64]; memset(b, 0, sizeof b);
    vbMountNow();   // 11ad: not "too old" just because the 5 s idle mount has not run yet
    uint8_t st = favilla::rk_ready() ? (vbKeysLoad(pub, chk) ? 0 : (uint8_t)VBR_NOKEYS) : (uint8_t)VBR_NOG0;
    b[0] = st; if(!st) memcpy(b + 1, pub, 32);
    uint32_t lt = 0; uint16_t ln = 0; vbLastLoad(&lt, &ln); chan::put32(b + 33, lt); b[37] = ln; b[38] = ln >> 8;
    b[39] = favilla::rk_dirty() ? 1 : 0; b[40] = g_vpWant;
    const size_t rl = strlen(favilla::VB_RELAY); memcpy(b + 41, favilla::VB_RELAY, rl);
    const bool sent = answer(ci, chan::R_VAULT_INFO, r.ctr, b, 41 + rl, false);
    LOG_BOOT("[APP] VAULT_INFO: status %u, %u records backed up, dirty %u, asked %u, %s\n", st, (unsigned)ln, b[39], b[40], sent ? "sent" : "NOT sent");
    return;
  }
  if(cmd == chan::C_VAULT_GET){
    // [offset u32] -> [status][total u32][offset u32][bytes]; offset 0 stages the frame first
    if(r.bodyLen != 4){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    const uint32_t off = chan::get32(r.body);
    if(off == 0){
      if(!vpWaitJob(1, &g_vpStageR, 3000)){ err(ci, r.ctr, chan::S_BUSY); LOG_BOOT("[APP] VAULT_GET: still staging - told the app busy\n"); return; }
      if(g_vpStageR){ uint8_t b[9] = { (uint8_t)g_vpStageR }; answer(ci, chan::R_VAULT_CHUNK, r.ctr, b, 9, false); LOG_BOOT("[APP] VAULT_GET: could not stage (%d)\n", (int)g_vpStageR); return; }
    }
    vpLock();
    const size_t total = g_vpFrameN;
    if(!g_vpFrame || off >= total){ vpUnlock(); uint8_t b[9] = { (uint8_t)VBR_BUSY }; chan::put32(b + 1, total); chan::put32(b + 5, off); answer(ci, chan::R_VAULT_CHUNK, r.ctr, b, 9, false); return; }
    const size_t n = (total - off) < chan::VAULT_CHUNK ? (total - off) : chan::VAULT_CHUNK;
    uint8_t* b = (uint8_t*)heap_caps_malloc(9 + n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(!b){ vpUnlock(); err(ci, r.ctr, chan::S_BUSY); return; }
    b[0] = 0; chan::put32(b + 1, total); chan::put32(b + 5, off); memcpy(b + 9, g_vpFrame + off, n);
    g_vpFrameAt = millis();
    vpUnlock();
    const bool sent = answer(ci, chan::R_VAULT_CHUNK, r.ctr, b, 9 + n, false);
    if(sent) g_vpSentTo = (uint32_t)(off + n);   // 11cg: the KEY's bar
    free(b);
    LOG_BOOT("[APP] VAULT_GET: %u..%u of %u %s\n", (unsigned)off, (unsigned)(off + n), (unsigned)total, sent ? "sent" : "NOT sent");
    return;
  }
  if(cmd == chan::C_VAULT_DONE){
    // [ok 0/1/2][relay message]: 1 = accepted, 0 = refused, 2 = the app could not reach the relay
    if(r.bodyLen < 1){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    const uint8_t ok = r.body[0];
    size_t ml = r.bodyLen - 1; if(ml > sizeof(g_vpDoneMsg) - 1) ml = sizeof(g_vpDoneMsg) - 1;
    memcpy(g_vpDoneMsg, r.body + 1, ml); g_vpDoneMsg[ml] = 0;
    uint8_t s = chan::S_OK;
    vpLock(); const bool staged = g_vpFrame != nullptr; vpUnlock();
    if(!staged){ s = chan::S_BAD_REQUEST; }
    else if(ok == 1){ vbLastSave(g_vpCreated, (uint16_t)g_vpNrec); if(!favilla::rk_set_clean(g_vpGen)) LOG_BOOT("[VAULT] a change landed during the backup - another backup will follow\n"); g_vpDone = 0; }
    else { g_vpDone = ok == 0 ? 1 : 2; }
    if(staged) vpFrameFree();
    g_vpWant = 0;
    answer(ci, chan::R_ACK, r.ctr, &s, 1, false);
    LOG_BOOT("[VAULT] backup through the phone: %s%s%s\n", ok == 1 ? "accepted by the relay" : ok == 0 ? "refused by the relay" : "the app could not reach the relay", g_vpDoneMsg[0] ? ": " : "", g_vpDoneMsg);
    return;
  }
  // C_VAULT_PUT: [total u32][offset u32][bytes] -> [state][result][added u16][removed u16]
  // state 0 = more chunks wanted, 1 = done (result is VBR_*), 2 = still merging, ask again with an empty chunk at offset total
  if(r.bodyLen < 8){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  const uint32_t total = chan::get32(r.body), off = chan::get32(r.body + 4); const size_t n = r.bodyLen - 8;
  if(total > 200000 || off > total || off + n > total){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  uint8_t b[6] = { 0, 0, 0, 0, 0, 0 };
  if(total == 0 || off + n == total){
    if(total){
      vpLock();
      if(off == 0){ if(g_vpIn) free(g_vpIn); g_vpIn = (char*)heap_caps_malloc(total + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); g_vpInN = 0; g_vpInTotal = g_vpIn ? total : 0; }
      const bool okb = g_vpIn && g_vpInTotal == total && g_vpInN == off;
      if(okb && n){ memcpy(g_vpIn + off, r.body + 8, n); g_vpInN = off + n; g_vpInAt = millis(); }
      const bool complete = okb && g_vpInN == total;
      vpUnlock();
      if(!okb && !(n == 0 && off == total && g_vpMergeR >= 0)){ err(ci, r.ctr, chan::S_BAD_REQUEST); LOG_BOOT("[APP] VAULT_PUT: out of order (have %u, got %u)\n", (unsigned)g_vpInN, (unsigned)off); return; }
      if(complete && n){ vpWaitJob(2, &g_vpMergeR, 2000); }
    } else { vpInFree(); vpWaitJob(2, &g_vpMergeR, 2000); }
    if(g_vpJob){ b[0] = 2; answer(ci, chan::R_VAULT_PUT, r.ctr, b, 6, false); return; }
    b[0] = 1; b[1] = (uint8_t)g_vpMergeR; b[2] = g_vpMergeSt.added; b[3] = g_vpMergeSt.added >> 8; b[4] = g_vpMergeSt.removed; b[5] = g_vpMergeSt.removed >> 8;
    if(g_vpWant == 2) g_vpWant = 0;   // a restore ends here; a backup carries on to GET
    answer(ci, chan::R_VAULT_PUT, r.ctr, b, 6, false);
    LOG_BOOT("[APP] VAULT_PUT: %u bytes in all, merge result %d (%d added, %d removed)\n", (unsigned)total, (int)g_vpMergeR, g_vpMergeSt.added, g_vpMergeSt.removed);
    return;
  }
  vpLock();
  if(off == 0){ if(g_vpIn) free(g_vpIn); g_vpIn = (char*)heap_caps_malloc(total + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); g_vpInN = 0; g_vpInTotal = g_vpIn ? total : 0; }
  const bool okb = g_vpIn && g_vpInTotal == total && g_vpInN == off;
  if(okb){ memcpy(g_vpIn + off, r.body + 8, n); g_vpInN = off + n; g_vpInAt = millis(); }
  vpUnlock();
  if(!okb){ err(ci, r.ctr, chan::S_BUSY); return; }
  answer(ci, chan::R_VAULT_PUT, r.ctr, b, 6, false);   // state 0: next chunk
}
static bool g_listHealth = false;   // 11s: LIST with health and ids
static int g_showIdx = -1; static uint32_t g_showAt = 0;   // 11s: SHOW: the entry index the life's loop should open
// 11s: the breach check. No body: the prefixes still to check. With a body
// [prefix 3][n u16][suffix 18 x n]: the bucket's suffixes, matched here.
// Answer R_HEALTH [status][pending u16][count][prefix 3 x count].
// 11bt: CIPHER_DAY 0x50, the day's block the app fetched from favillakey.io.
// Checked here exactly as a Wi-Fi fetch or a scanned QR (cipher_block.h): the
// app is a courier and need not be trusted.
static void cipherDayRequest(int ci, const chan::Req& r){
  uint8_t b[5] = { chan::S_BAD_REQUEST, 0, 0, 0, 0 };
  CgBlock blk = {};
  if(r.bodyLen >= 1 && r.bodyLen < sizeof g_cgPush){
    char t[sizeof g_cgPush]; memcpy(t, r.body, r.bodyLen); t[r.bodyLen] = 0;
    time_t now; time(&now);
    if(cgblock::parse(t, (long)now > 1700000000L ? (int64_t)now : 0, blk)){
      portENTER_CRITICAL(&g_cgMux); memcpy(g_cgPush, t, r.bodyLen + 1); g_cgPushSet = true; portEXIT_CRITICAL(&g_cgMux);
      g_cgAsk = false; b[0] = chan::S_OK; chan::put32(b + 1, blk.height);
    }
  }
  const bool sent = answer(ci, chan::R_ACK, r.ctr, b, sizeof b, false);
  if(b[0] == chan::S_OK) LOG_BOOT("[CIPHER] day block from the phone: height %lu, checked%s\n", (unsigned long)blk.height, sent ? "" : " (answer NOT sent)");
  else LOG_BOOT("[CIPHER] day block from the phone: %u bytes, REFUSED (format, proof of work, height or age)%s\n", (unsigned)r.bodyLen, sent ? "" : " (answer NOT sent)");
}
static void healthRequest(int ci, const chan::Req& r){
  const bool in = g_nostrBtLife ? wallet.unlocked : g_pkPinHeld;
  if(!in){ err(ci, r.ctr, chan::S_LOCKED); return; }
  if(r.bodyLen >= 5){
    // 11bc (13 Nov 2026, bench): busy buckets hold about 2,000 lines, so the old
    // 1,200 cap refused them. Now up to what one message carries (about 2,200),
    // and bit 15 of n marks a part with more of the same bucket to follow.
    const uint16_t nw = (uint16_t)(r.body[3] | (r.body[4] << 8)), n = nw & 0x7FFF; const bool more = nw & 0x8000;
    if(r.bodyLen != 5 + (size_t)n * 18){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    const int d = favilla::rk_health_bucket(r.body, r.body + 5, n, !more);
    if(d < 0){   // 24 Nov 2026: far too few suffixes for a real bucket (a failed fetch): no verdict, say so
      LOG_BOOT("[APP] HEALTH bucket %02X%02X%X: %u suffixes in all is too few for a real bucket, REFUSED (no verdict, the entries stay pending)\n", r.body[0], r.body[1], r.body[2] >> 4, (unsigned)n);
      err(ci, r.ctr, chan::S_BAD_REQUEST); return;
    }
    LOG_BOOT("[APP] HEALTH bucket %02X%02X%X: %u suffixes%s, %d entr%s decided\n", r.body[0], r.body[1], r.body[2] >> 4, (unsigned)n, more ? " (a part, more to follow)" : "", d, d == 1 ? "y" : "ies");
  } else if(r.bodyLen){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  uint8_t (*pf)[3] = (uint8_t (*)[3])heap_caps_malloc(3 * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!pf){ err(ci, r.ctr, chan::S_BUSY); return; }
  const int np = favilla::rk_health_prefixes(pf, favilla::RK_MAX), pend = favilla::rk_health_pending();
  uint8_t* b = (uint8_t*)heap_caps_malloc(4 + 3 * np, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!b){ free(pf); err(ci, r.ctr, chan::S_BUSY); return; }
  b[0] = chan::S_OK; b[1] = (uint8_t)pend; b[2] = (uint8_t)(pend >> 8); b[3] = (uint8_t)np; memcpy(b + 4, pf, 3 * np);
  const bool sent = answer(ci, chan::R_HEALTH, r.ctr, b, 4 + 3 * np, true);   // encrypted: the prefixes say a little about the passwords
  free(pf); free(b);
  LOG_BOOT("[APP] HEALTH: %d prefix%s to fetch, %d entr%s pending, %s\n", np, np == 1 ? "" : "es", pend, pend == 1 ? "y" : "ies", sent ? "sent" : "NOT sent");
}
// The life's loop: an entry the app asked to see. Returns the index once, or -1.
static int showTake(){
  lock(); int i = g_showIdx; if(i >= 0 && millis() - g_showAt > 30000UL) i = -1; g_showIdx = -1; unlock();
  return i;
}
// ---- 11ax (issue #30): VAULT mode edits from the Accounts page ------------------
// The app task checks and queues; the PASSKEY life's loop shows it and runs it
// with the PWA's own job code (vault_api.inc: vaAppRun -> vaDoSave/vaDoDelete*),
// so screens, limits and record handling are the same as /api/vault/pw/*.
// One job at a time across all app installs; PW_RESULT answers only the install
// that asked.
struct PwJob {
  uint8_t kind;                  // 1 save, 2 delete
  bool edit;                     // save: an existing entry (id from LIST)
  int slot; uint8_t id8[8];      // save: the edited entry
  int n; int slots[chan::PW_DELETE_MAX]; uint8_t ids[chan::PW_DELETE_MAX][8];   // delete
  favilla::RkPass* e;            // save: PSRAM, wiped when taken or dropped
  bool keepPass, keepNote;
  bool keepOld;                  // 11bi: PW_SAVE flags bit0, a changed password keeps the old one as "<site> (old)"
  char site[favilla::RK_SITE_MAX + 1], user[favilla::RK_PW_FIELD_MAX + 1];      // what the screen shows
};
static volatile uint8_t g_pwqOn = 0;          // 1 queued for the loop, 2 the loop has it
static PwJob g_pwq;                            // under the lock while queued
static int g_pwqCi = -1; static uint32_t g_pwqAt = 0;
static int g_pwResCi = -1; static uint8_t g_pwResState = chan::PW_NONE, g_pwResReason = 0; static uint8_t g_pwResId[8] = {0};
static void pwJobDrop(PwJob& j){ if(j.e){ favilla::rk_pw_wipe(j.e); free(j.e); j.e = nullptr; } mbedtls_platform_zeroize(&j, sizeof j); }
// The loop takes the queued job (a copy; the queue is cleared). False: none.
static bool pwJobTake(PwJob* out){
  if(g_pwqOn != 1) return false;
  lock();
  const bool ok = g_pwqOn == 1;
  if(ok){ memcpy(out, &g_pwq, sizeof g_pwq); g_pwq.e = nullptr; mbedtls_platform_zeroize(&g_pwq, sizeof g_pwq); g_pwqOn = 2; }
  unlock();
  return ok;
}
// The loop's verdict: state is a chan::PwState, reason a chan::Status for PW_FAILED.
static void pwJobDone(uint8_t state, const uint8_t id8[8], uint8_t reason){
  lock(); g_pwResState = state; g_pwResReason = reason; if(id8) memcpy(g_pwResId, id8, 8); else memset(g_pwResId, 0, 8); g_pwqOn = 0; unlock();
}
static void pwAck(int ci, uint32_t ctr, uint8_t s){ answer(ci, chan::R_ACK, ctr, &s, 1, false); }
// ---- 11bf (16 Nov 2026): import from another manager's export, VAULT mode -------
// The PWA's import window (vault_api.inc: the PIN on the KEY, then entries with
// no press each) over the channel, for the PASSKEY life: G0 v19 seals an import
// only there. One import at a time, owned by the app install that began it.
// This task checks, decrypts and queues ONE item; the PASSKEY life's loop
// (vaAppImport) asks the PIN, opens the G0's window and seals each item, and
// publishes the state that IMPORT_STATUS answers.
static int g_impCi = -1;                                 // the install that began the import (-1 none)
static volatile uint8_t g_impBegin = 0;                  // 1: IMPORT_BEGIN waits for the loop
static uint32_t g_impAt = 0;                             // when IMPORT_BEGIN was queued
static volatile uint8_t g_impEnd = 0;                    // 1: IMPORT_END asked the loop to close the window
static uint8_t g_impState = chan::IMP_NONE, g_impReason = 0, g_impLast = 0;
static uint16_t g_impSaved = 0, g_impFailed = 0, g_impSkipped = 0, g_impDone = 0;
// 11bh (bench 17 Nov 2026): up to IMPORT_QUEUE items wait, and the loop seals
// all that are waiting under one passkey window (one window per item cost
// about 2 s each). The last IMPORT_HIST results are kept for IMPORT_STATUS.
static constexpr int IMPORT_QUEUE = 8, IMPORT_HIST = 16;
static chan::ImportItem* g_impq[IMPORT_QUEUE] = {};      // PSRAM, wiped when taken or dropped; FIFO from index 0
static volatile uint8_t g_impqN = 0, g_impWorking = 0;   // waiting / being sealed now
static uint8_t g_impHist[IMPORT_HIST];                   // results, by g_impDone % IMPORT_HIST
static bool impActive(){ return g_impState == chan::IMP_ASKING || g_impState == chan::IMP_OPEN || g_impState == chan::IMP_WORKING; }
static void impDropItem(){   // caller holds the lock
  for(int i = 0; i < g_impqN; i++) if(g_impq[i]){ mbedtls_platform_zeroize(g_impq[i], sizeof *g_impq[i]); free(g_impq[i]); g_impq[i] = nullptr; }
  g_impqN = 0;
}
// The loop's side.
static bool impBeginTake(){ if(g_impBegin != 1) return false; lock(); const bool b = g_impBegin == 1; g_impBegin = 0; unlock(); return b; }
static bool impEndAsked(){ return g_impEnd == 1 && !g_impqN; }   // items already queued are sealed first
static int impItemsTake(chan::ImportItem** out, int max){   // the loop owns out[0..n) (wipe and free each)
  if(!g_impqN) return 0;
  lock();
  int n = g_impqN < max ? g_impqN : max;
  for(int i = 0; i < n; i++) out[i] = g_impq[i];
  for(int i = n; i < g_impqN; i++) g_impq[i - n] = g_impq[i];
  for(int i = g_impqN - n; i < IMPORT_QUEUE; i++) g_impq[i] = nullptr;
  g_impqN -= n; g_impWorking = n;
  if(n) g_impState = chan::IMP_WORKING;
  unlock();
  return n;
}
static void impItemDone(uint8_t st){   // st: S_OK sealed, S_EXISTS kept the KEY's entry, else why not
  lock();
  if(st == chan::S_OK) g_impSaved++; else { g_impFailed++; if(st == chan::S_EXISTS) g_impSkipped++; }
  g_impLast = st; g_impHist[g_impDone % IMPORT_HIST] = st; g_impDone++;
  if(g_impWorking) g_impWorking--;
  if(!g_impWorking && !g_impqN && g_impState == chan::IMP_WORKING) g_impState = chan::IMP_OPEN;
  unlock();
}
static void impSet(uint8_t state, uint8_t reason){
  lock(); g_impState = state; g_impReason = reason; if(state == chan::IMP_CLOSED || state == chan::IMP_REFUSED){ impDropItem(); g_impWorking = 0; g_impEnd = 0; g_impBegin = 0; } unlock();
}
static void impCounts(uint16_t* saved, uint16_t* failed){ lock(); *saved = g_impSaved; *failed = g_impFailed; unlock(); }

// Checks shared by SAVE and DELETE. Returns S_OK or the refusal.
static uint8_t pwGate(){
  if(!g_pkPinHeld) return chan::S_LOCKED;
  if(!favilla::rk_ready() || !g0_v15_present()) return chan::S_NOT_HERE;
  // A job queued but never taken (the KEY sat in a menu, or the life ended)
  // is dropped after 90 s and reported as timed out, so it cannot block the
  // next one. A job the loop has taken (2) always ends on its own (60 s).
  if(impActive()) return chan::S_BUSY;   // 11bf: an import has the KEY's screen
  lock();
  if(g_pwqOn == 1 && millis() - g_pwqAt > 90000UL){ pwJobDrop(g_pwq); g_pwqOn = 0; g_pwResState = chan::PW_TIMEOUT; g_pwResReason = 0; LOG_BOOT("[APP] a queued save or delete was never shown: dropped\n"); }
  const bool busy = g_pwqOn != 0;
  unlock();
  return busy ? chan::S_BUSY : chan::S_OK;
}
static void pwSaveRequest(int ci, const chan::Req& r){
  uint8_t s = pwGate();
  if(s != chan::S_OK){ pwAck(ci, r.ctr, s); return; }
  if(r.bodyLen < chan::ID + 4 || r.bodyLen > chan::ID + 4 + chan::VAULT_SITE_MAX + 3 * chan::VAULT_FIELD_MAX + 1){ pwAck(ci, r.ctr, chan::S_BAD_REQUEST); return; }   // 11bi: + the flags byte
  // The body is encrypted (cmd 0x47 in the keystream's rsp place): open a copy.
  uint8_t* b = (uint8_t*)heap_caps_malloc(r.bodyLen, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_calloc(1, sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!b || !e){ if(b) free(b); if(e) free(e); pwAck(ci, r.ctr, chan::S_BUSY); return; }
  uint8_t k[chan::KEYLEN];
  lock(); const bool known = ci >= 0 && ci < chan::MAX_CLIENTS && g_key.cl[ci].used; if(known) memcpy(k, g_key.cl[ci].k, sizeof k); unlock();
  memcpy(b, r.body, r.bodyLen);
  uint8_t id8[8] = {0}, flags = 0;
  bool ok = known && chan::encBody(chanc_hmac, k, chan::C_PW_SAVE, r.id, r.ctr, b, r.bodyLen) &&
            chan::parsePwSave(b, r.bodyLen, id8, e->site, e->user, e->pass, e->note, &flags);
  mbedtls_platform_zeroize(k, sizeof k); mbedtls_platform_zeroize(b, r.bodyLen); free(b);
  bool zero = true; for(int i = 0; i < 8; i++) if(id8[i]) zero = false;
  const size_t sn = strlen(e->site), un = strlen(e->user), pn = strlen(e->pass), nn = strlen(e->note);
  int slot = -1;
  if(!ok) s = chan::S_BAD_REQUEST;
  else if(zero && pn == 0) s = chan::S_BAD_REQUEST;                       // a new entry needs a password
  else if(!zero){ const int i = favilla::rk_pw_index_of_id(id8); if(i < 0) s = chan::S_NO_MATCH; else slot = favilla::rk_pw_slot_at(i); }
  if(s == chan::S_OK && favilla::rk_pw_check(sn, un, pn ? pn : 1, nn)) s = chan::S_TOO_LONG;
  const bool keepOld = !zero && pn > 0 && (flags & chan::PW_KEEP_OLD);   // 11bi: only a change of password has an old one to keep
  if(s == chan::S_OK && (zero || keepOld) && favilla::rk_count_all() >= favilla::RK_MAX) s = chan::S_VAULT_FULL;   // the old copy is a record too
  // 25 Nov 2026: no early S_BUDGET here any more. The site may already have the
  // new password; the save runs on the KEY (vaDoSave), which asks for the PIN if
  // the vault limit stops it, and only then fails.
  if(s != chan::S_OK){ favilla::rk_pw_wipe(e); free(e); pwAck(ci, r.ctr, s); LOG_BOOT("[APP] PW_SAVE refused: status %u\n", (unsigned)s); return; }
  lock();
  if(g_pwqOn){ unlock(); favilla::rk_pw_wipe(e); free(e); pwAck(ci, r.ctr, chan::S_BUSY); return; }
  mbedtls_platform_zeroize(&g_pwq, sizeof g_pwq);
  g_pwq.kind = 1; g_pwq.edit = !zero; g_pwq.slot = slot; memcpy(g_pwq.id8, id8, 8); g_pwq.e = e;
  g_pwq.keepPass = !zero && pn == 0; g_pwq.keepNote = !zero && nn == 0; g_pwq.keepOld = keepOld;
  e->slot = -1;
  snprintf(g_pwq.site, sizeof g_pwq.site, "%s", e->site); snprintf(g_pwq.user, sizeof g_pwq.user, "%s", e->user);
  g_pwqCi = ci; g_pwqAt = millis(); g_pwResCi = ci; g_pwResState = chan::PW_ASKING; g_pwResReason = 0; memset(g_pwResId, 0, 8);
  g_pwqOn = 1;
  unlock();
  pwAck(ci, r.ctr, chan::S_OK);
  LOG_BOOT("[APP] PW_SAVE from the app: %s, %u + %u characters, password %s, note %s\n", zero ? "new entry" : "edit", (unsigned)sn, (unsigned)un,
           pn ? "new" : "kept", nn ? "new" : (zero ? "none" : "kept"));
  if(keepOld) LOG_BOOT("[APP] PW_SAVE: a change of password, the old one is kept as (old)\n");
}
static void pwDeleteRequest(int ci, const chan::Req& r){
  uint8_t s = pwGate();
  if(s != chan::S_OK){ pwAck(ci, r.ctr, s); return; }
  const size_t n = r.bodyLen ? r.body[0] : 0;
  if(n < 1 || n > chan::PW_DELETE_MAX || r.bodyLen != 1 + 8 * n){ pwAck(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  PwJob j; memset(&j, 0, sizeof j); j.kind = 2;
  for(size_t k = 0; k < n; k++){
    const uint8_t* id = r.body + 1 + 8 * k;
    const int i = favilla::rk_pw_index_of_id(id); if(i < 0) continue;   // gone already: skipped, never another record
    bool dup = false; for(int q = 0; q < j.n; q++) if(!memcmp(j.ids[q], id, 8)) dup = true;
    if(dup) continue;
    j.slots[j.n] = favilla::rk_pw_slot_at(i); memcpy(j.ids[j.n], id, 8); j.n++;
  }
  if(!j.n){ pwAck(ci, r.ctr, chan::S_NO_MATCH); return; }
  snprintf(j.site, sizeof j.site, j.n == 1 ? "1 entry" : "%d entries", j.n);
  lock();
  if(g_pwqOn){ unlock(); pwAck(ci, r.ctr, chan::S_BUSY); return; }
  memcpy(&g_pwq, &j, sizeof j);
  g_pwqCi = ci; g_pwqAt = millis(); g_pwResCi = ci; g_pwResState = chan::PW_ASKING; g_pwResReason = 0; memset(g_pwResId, 0, 8);
  g_pwqOn = 1;
  unlock();
  pwAck(ci, r.ctr, chan::S_OK);
  LOG_BOOT("[APP] PW_DELETE from the app: %d of %u entr%s found\n", j.n, (unsigned)n, n == 1 ? "y" : "ies");
}
static void pwResultRequest(int ci, const chan::Req& r){
  if(r.bodyLen){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  uint8_t b[10];
  lock();
  if(g_pwResCi != ci){ b[0] = chan::PW_NONE; memset(b + 1, 0, 9); }
  else { b[0] = g_pwResState; memcpy(b + 1, g_pwResId, 8); b[9] = g_pwResReason; }
  unlock();
  answer(ci, chan::R_ACK, r.ctr, b, sizeof b, false);
}
// 11bi (issue #38): GEN_PW, iPhone AutoFill's "suggest a strong password". A
// password to the site's rules from the KEY's generator (SE TRNG and ESP32 RNG,
// as every password the KEY makes), at once: no screen, no press, nothing
// stored (iOS fills it, then sends the save, which the owner confirms on the KEY
// with PW_SAVE). Length: 20, or the nearest the site allows. At most 10 a
// minute. Answer encrypted: R_GEN_PW [status][pLen][password]; a refusal is
// [status][0] (S_LOCKED, S_BAD_REQUEST, S_BUSY for the rate, S_STORAGE when the
// secure element's random generator does not answer).
static uint32_t g_genAt[10] = {0}; static uint8_t g_genN = 0;
static void genPwRequest(int ci, const chan::Req& r){
  uint8_t out[2 + pwgen::MAX_LEN + 1] = {0};
  chan::GenPwRules R;
  uint8_t s = chan::S_OK; int len = 0;
  if(!g_pkPinHeld) s = chan::S_LOCKED;
  else if(!chan::parseGenPw(r.body, r.bodyLen, &R)) s = chan::S_BAD_REQUEST;
  else {
    lock();
    const uint32_t now = millis(); const uint32_t oldest = g_genAt[g_genN % 10];
    const bool full = oldest && now - oldest < 60000UL;
    if(!full){ g_genAt[g_genN % 10] = now ? now : 1; g_genN++; }
    unlock();
    if(full) s = chan::S_BUSY;
  }
  // 25 Nov 2026: the save that follows must be able to go through (an old copy
  // and the new one), or iOS fills a password the KEY then cannot keep. No
  // room: S_BUDGET, and the KEY asks for the PIN on its screen.
  if(s == chan::S_OK && !favilla::rk_save_room(2, 1)){ s = chan::S_BUDGET; g_vlAskPin = true; }
  if(s == chan::S_OK){
    len = 20; if(len < R.minLen) len = R.minLen; if(len > R.maxLen) len = R.maxLen;
    uint8_t seed[32];
    if(!pwGenSeed(seed)) s = chan::S_STORAGE;
    else if(!pwgen::generateRules(seed, len, R.required, R.allowed, R.specials, (char*)out + 2)) s = chan::S_BAD_REQUEST;
    mbedtls_platform_zeroize(seed, sizeof seed);
  }
  out[0] = s; out[1] = s == chan::S_OK ? (uint8_t)len : 0;
  const bool sent = answer(ci, chan::R_GEN_PW, r.ctr, out, 2 + out[1], true);
  mbedtls_platform_zeroize(out, sizeof out); mbedtls_platform_zeroize(&R, sizeof R);
  LOG_BOOT("[APP] GEN_PW from the app: %s%s\n", s == chan::S_OK ? "made (not stored)" : s == chan::S_LOCKED ? "locked" : s == chan::S_BUSY ? "more than 10 a minute" :
           s == chan::S_STORAGE ? "the secure element's RNG did not answer" : s == chan::S_BUDGET ? "no room to save: PIN asked on the KEY" : "bad rules", sent ? "" : " (NOT sent)");
  if(s == chan::S_OK) LOG_BOOT("[APP] GEN_PW: %d characters, required 0x%X, allowed 0x%X, %u specials\n", len, (unsigned)R.required, (unsigned)R.allowed, (unsigned)R.sN);
}
// 11bf: the import requests (VAULT mode only; onMsg refuses them elsewhere).
static void impAck(int ci, uint32_t ctr, uint8_t s){ answer(ci, chan::R_ACK, ctr, &s, 1, false); }
static void impBeginRequest(int ci, const chan::Req& r){
  if(r.bodyLen){ impAck(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  if(!g_pkPinHeld){ impAck(ci, r.ctr, chan::S_LOCKED); return; }
  if(!favilla::rk_ready() || !g0_v15_present() || !g0_doorpin_present()){ impAck(ci, r.ctr, chan::S_NOT_HERE); return; }
  if(vaImportUsed()){ impAck(ci, r.ctr, chan::S_USED); return; }   // one window per power-on life (the G0 enforces it too)
  lock();
  if(g_impBegin == 1 && millis() - g_impAt > 90000UL){ g_impBegin = 0; g_impState = chan::IMP_REFUSED; g_impReason = chan::S_CANCELLED; LOG_BOOT("[APP] an IMPORT_BEGIN was never shown: dropped\n"); }   // the KEY sat in a menu
  const bool busy = impActive() || g_pwqOn != 0;
  if(!busy){ g_impAt = millis(); g_impCi = ci; g_impState = chan::IMP_ASKING; g_impReason = 0; g_impLast = 0; g_impSaved = g_impFailed = g_impSkipped = g_impDone = 0; g_impEnd = 0; impDropItem(); g_impWorking = 0; g_impBegin = 1; }
  unlock();
  impAck(ci, r.ctr, busy ? chan::S_BUSY : chan::S_OK);
  LOG_BOOT("[APP] IMPORT_BEGIN from the app: %s\n", busy ? "busy" : "asking for the passkey PIN on the KEY");
}
static void impItemRequest(int ci, const chan::Req& r){
  lock(); const bool mine = g_impCi == ci; const uint8_t st = g_impState; const uint8_t q = g_impqN; unlock();
  if(!mine || (st != chan::IMP_OPEN && st != chan::IMP_WORKING)){ impAck(ci, r.ctr, mine && st == chan::IMP_ASKING ? chan::S_BUSY : chan::S_NO_WINDOW); return; }
  if(q >= IMPORT_QUEUE){ impAck(ci, r.ctr, chan::S_BUSY); return; }   // 8 waiting: send it again shortly
  if(r.bodyLen < 1 || r.bodyLen > 1 + 4 + chan::VAULT_SITE_MAX + 3 * chan::VAULT_FIELD_MAX){ impAck(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  uint8_t* b = (uint8_t*)heap_caps_malloc(r.bodyLen, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  chan::ImportItem* it = (chan::ImportItem*)heap_caps_calloc(1, sizeof(chan::ImportItem), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!b || !it){ if(b) free(b); if(it) free(it); impAck(ci, r.ctr, chan::S_BUSY); return; }
  uint8_t k[chan::KEYLEN];
  lock(); const bool known = ci >= 0 && ci < chan::MAX_CLIENTS && g_key.cl[ci].used; if(known) memcpy(k, g_key.cl[ci].k, sizeof k); unlock();
  memcpy(b, r.body, r.bodyLen);
  const bool ok = known && chan::encBody(chanc_hmac, k, chan::C_IMPORT_ITEM, r.id, r.ctr, b, r.bodyLen) && chan::parseImportItem(b, r.bodyLen, it);
  mbedtls_platform_zeroize(k, sizeof k); mbedtls_platform_zeroize(b, r.bodyLen); free(b);
  uint8_t s = ok ? chan::S_OK : chan::S_BAD_REQUEST;
  if(s == chan::S_OK && it->kind == chan::IMPORT_PW && favilla::rk_pw_check(strlen(it->site), strlen(it->user), strlen(it->pass), strlen(it->note))) s = chan::S_TOO_LONG;
  if(s == chan::S_OK && it->kind == chan::IMPORT_OTP && !g0_v17_present()) s = chan::S_NOT_HERE;
  if(s == chan::S_OK && favilla::rk_count_all() + q >= favilla::RK_MAX) s = chan::S_VAULT_FULL;
  if(s != chan::S_OK){ mbedtls_platform_zeroize(it, sizeof *it); free(it); impAck(ci, r.ctr, s); LOG_BOOT("[APP] IMPORT_ITEM refused: status %u\n", (unsigned)s); return; }
  lock();
  const bool open = g_impCi == ci && (g_impState == chan::IMP_OPEN || g_impState == chan::IMP_WORKING) && g_impqN < IMPORT_QUEUE && !g_impEnd;
  if(open){ g_impq[g_impqN++] = it; it = nullptr; }
  unlock();
  if(it){ mbedtls_platform_zeroize(it, sizeof *it); free(it); impAck(ci, r.ctr, chan::S_BUSY); return; }
  impAck(ci, r.ctr, chan::S_OK);
}
// 11bh: the 7 bytes of 11bf, then [queued][skipped u16 LE][done u16 LE][n][n results, oldest first]:
// the results of items done-n .. done-1 in the order they were sent (n at most 16).
static void impStatusRequest(int ci, const chan::Req& r){
  if(r.bodyLen){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  uint8_t b[7 + 6 + IMPORT_HIST] = {0}; size_t n = 7;
  lock();
  if(g_impCi != ci) b[0] = chan::IMP_NONE;
  else {
    b[0] = g_impState; b[1] = g_impReason; b[2] = (uint8_t)g_impSaved; b[3] = (uint8_t)(g_impSaved >> 8); b[4] = (uint8_t)g_impFailed; b[5] = (uint8_t)(g_impFailed >> 8); b[6] = g_impLast;
    b[7] = (uint8_t)(g_impqN + g_impWorking); b[8] = (uint8_t)g_impSkipped; b[9] = (uint8_t)(g_impSkipped >> 8); b[10] = (uint8_t)g_impDone; b[11] = (uint8_t)(g_impDone >> 8);
    const int h = g_impDone < IMPORT_HIST ? g_impDone : IMPORT_HIST; b[12] = (uint8_t)h;
    for(int i = 0; i < h; i++) b[13 + i] = g_impHist[(g_impDone - h + i) % IMPORT_HIST];
    n = 13 + h;
  }
  unlock();
  answer(ci, chan::R_ACK, r.ctr, b, n, false);
}
static void impEndRequest(int ci, const chan::Req& r){
  if(r.bodyLen){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  uint8_t b[5] = { chan::S_OK, 0, 0, 0, 0 };
  lock();
  if(g_impCi != ci || !impActive()) b[0] = chan::S_NO_WINDOW;
  else if(g_impBegin == 1){ g_impBegin = 0; g_impState = chan::IMP_REFUSED; g_impReason = chan::S_CANCELLED; }   // never reached the screen: withdrawn here
  else if(g_impqN || g_impWorking) b[0] = chan::S_BUSY;   // items are still being sealed: ask again shortly
  else g_impEnd = 1;                                   // the loop closes it (and the PIN screen, if still asking)
  b[1] = (uint8_t)g_impSaved; b[2] = (uint8_t)(g_impSaved >> 8); b[3] = (uint8_t)g_impFailed; b[4] = (uint8_t)(g_impFailed >> 8);
  unlock();
  answer(ci, chan::R_ACK, r.ctr, b, sizeof b, false);
  if(b[0] == chan::S_OK) LOG_BOOT("[APP] IMPORT_END from the app\n");
}
// 11ay: [id 8] -> R_ACK [status][state][prefix 3]. state 0 refused (see status),
// 1 opening it now (ask again in about half a second), 2 ready: prefix is this
// entry's (fetch that one bucket and send it with HEALTH), 3 the verdict is
// already known (nothing to fetch). Asking again is how the app learns 2.
static void assessOneRequest(int ci, const chan::Req& r){
  if(r.bodyLen != 8){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  const bool in = g_nostrBtLife ? wallet.unlocked : g_pkPinHeld;
  uint8_t b[5] = { chan::S_OK, 0, 0, 0, 0 };
  if(!in) b[0] = chan::S_LOCKED;
  else if(!favilla::rk_ready()) b[0] = chan::S_NOT_HERE;
  else { const int i = favilla::rk_pw_index_of_id(r.body);
    if(i < 0) b[0] = chan::S_NO_MATCH;
    else { const int slot = favilla::rk_pw_slot_at(i);
      const int k = favilla::rk_health_prefix_of(slot, b + 2);
      if(k == 1) b[1] = 2;
      else if(k == 2) b[1] = 3;
      else if(k < 0) b[0] = chan::S_NO_MATCH;
      else if(g_hbOneSlot == slot) b[1] = 1;                      // already opening it
      else if(g_hbOneSlot >= 0) b[0] = chan::S_BUSY;
      else if(favilla::rk_open_left() == 0) b[0] = chan::S_BUDGET;
      else { g_hbOneSlot = slot; b[1] = 1; } } }
  const bool sent = answer(ci, chan::R_ACK, r.ctr, b, sizeof b, true);   // encrypted: a prefix says a little about one password
  mbedtls_platform_zeroize(b + 2, 3);
  LOG_BOOT("[APP] ASSESS_ONE from the app: %s%s\n", b[1] == 2 ? "prefix ready" : b[1] == 3 ? "verdict already known" : b[1] == 1 ? "opening it" :
           b[0] == chan::S_LOCKED ? "locked" : b[0] == chan::S_NO_MATCH ? "no such entry" : b[0] == chan::S_BUDGET ? "no record opens left" : "busy", sent ? "" : " (NOT sent)");
}
// On the app task (blek::appTask): one whole message from the app.
static void onMsg(const uint8_t* m, size_t n){
  if(n < 1) return;
  const uint8_t cmd = m[0];
  if(cmd == chan::C_HELLO) fsec::deviceIdentityInit();   // 11ah: the pairing id for HELLO, learned outside the lock (SE traffic)
  lock(); hooks(); load();
  if(cmd == chan::C_PAIR_COMMIT || cmd == chan::C_PAIR_REVEAL || cmd == chan::C_HELLO){
    if(n <= chan::MSG_MAX) g_key.process(m, n); else g_key.sendErr(cmd, chan::S_BAD_REQUEST);
    unlock();
    if(cmd == chan::C_PAIR_COMMIT) LOG_BOOT("[APP] pairing: the app sent its commitment\n");
    return;
  }
  if(cmd != chan::C_FILL && cmd != chan::C_CTAP && cmd != chan::C_CTAP_CANCEL && cmd != chan::C_LIST && cmd != chan::C_OTP && cmd != chan::C_TIME && cmd != chan::C_API &&
     cmd != chan::C_NIP46 && cmd != chan::C_NIP46_POLL && cmd != chan::C_BUNKER_INFO && cmd != chan::C_NUDGE_SET &&
     cmd != chan::C_VAULT_INFO && cmd != chan::C_VAULT_GET && cmd != chan::C_VAULT_DONE && cmd != chan::C_VAULT_PUT &&
     cmd != chan::C_SHOW && cmd != chan::C_HEALTH && cmd != chan::C_ASSESS &&
     cmd != chan::C_PW_SAVE && cmd != chan::C_PW_DELETE && cmd != chan::C_PW_RESULT && cmd != chan::C_ASSESS_ONE &&
     cmd != chan::C_IMPORT_BEGIN && cmd != chan::C_IMPORT_ITEM && cmd != chan::C_IMPORT_STATUS && cmd != chan::C_IMPORT_END && cmd != chan::C_GEN_PW && cmd != chan::C_CIPHER_DAY){ g_key.sendErr(cmd, chan::S_BAD_REQUEST); unlock(); return; }
  chan::Req r; const int ci = verify(m, n, &r);
  unlock();
  if(ci < 0){ LOG_BOOT("[APP] request 0x%02X refused (not paired, bad mac or replay)\n", cmd); return; }
  g_nudgeCi = ci; g_lastAppReqMs = millis();   // 11i: the client the nudges go to; 11l: when it last spoke
  // 9k: each life its own requests. The NOSTR Bluetooth life: API (and TIME);
  // the PASSKEY life: everything but API.
  // 10p: and NIP46, NIP46_POLL, BUNKER_INFO are the NOSTR Bluetooth life's too.
  const bool vaultCmd = cmd == chan::C_VAULT_INFO || cmd == chan::C_VAULT_GET || cmd == chan::C_VAULT_DONE || cmd == chan::C_VAULT_PUT;   // 11q
  const bool nostrCmd = cmd == chan::C_API || cmd == chan::C_NIP46 || cmd == chan::C_NIP46_POLL || cmd == chan::C_BUNKER_INFO || cmd == chan::C_NUDGE_SET || cmd == chan::C_CIPHER_DAY || vaultCmd;   // 11bt: CIPHER_DAY
  if(nostrCmd ? !g_nostrBtLife : (g_nostrBtLife && cmd != chan::C_TIME && cmd != chan::C_HEALTH && cmd != chan::C_ASSESS && cmd != chan::C_ASSESS_ONE)){ err(ci, r.ctr, chan::S_NOT_HERE); LOG_BOOT("[APP] request 0x%02X refused: not in this life\n", cmd); return; }
  if(cmd == chan::C_HEALTH){ healthRequest(ci, r); return; }   // 11s: both lives, the PIN of the life in
  if(cmd == chan::C_PW_SAVE){ pwSaveRequest(ci, r); return; }          // 11ax: VAULT mode only (the PASSKEY life)
  if(cmd == chan::C_PW_DELETE){ pwDeleteRequest(ci, r); return; }
  if(cmd == chan::C_PW_RESULT){ pwResultRequest(ci, r); return; }
  if(cmd == chan::C_ASSESS_ONE){ assessOneRequest(ci, r); return; }    // 11ax: both lives, like ASSESS
  if(cmd == chan::C_IMPORT_BEGIN){ impBeginRequest(ci, r); return; }   // 11bf: VAULT mode only (the PASSKEY life)
  if(cmd == chan::C_IMPORT_ITEM){ impItemRequest(ci, r); return; }
  if(cmd == chan::C_IMPORT_STATUS){ impStatusRequest(ci, r); return; }
  if(cmd == chan::C_IMPORT_END){ impEndRequest(ci, r); return; }
  if(cmd == chan::C_GEN_PW){ genPwRequest(ci, r); return; }           // 11bi: VAULT mode only (the PASSKEY life)
  if(cmd == chan::C_ASSESS){   // 11ab (issue #15): score up to [max] never-assessed entries now, as the PWA's Check all
    const bool in = g_nostrBtLife ? wallet.unlocked : g_pkPinHeld;
    if(!in){ err(ci, r.ctr, chan::S_LOCKED); return; }
    if(r.bodyLen != 1){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    const int unseen = favilla::rk_health_unseen();
    int n = r.body[0]; if(n > 24) n = 24; if(n > unseen) n = unseen;
    g_hbDoneNow = 0; g_hbWant = n;
    uint8_t b[4] = { chan::S_OK, (uint8_t)n, (uint8_t)unseen, (uint8_t)(unseen >> 8) };
    answer(ci, chan::R_ACK, r.ctr, b, sizeof b, false);
    LOG_BOOT("[APP] ASSESS from the app: %d entr%s never assessed, %d to open now\n", unseen, unseen == 1 ? "y" : "ies", n);
    return;
  }
  if(cmd == chan::C_SHOW){   // 11s: [id 8] -> the entry on the KEY's screen (the life's loop draws it)
    if(r.bodyLen != 8){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    uint8_t s = chan::S_OK;
    if(!g_pkPinHeld) s = chan::S_LOCKED;
    else { const int i = favilla::rk_pw_index_of_id(r.body); if(i < 0) s = chan::S_NO_MATCH; else { lock(); g_showIdx = i; g_showAt = millis(); unlock(); } }
    answer(ci, chan::R_ACK, r.ctr, &s, 1, false);
    LOG_BOOT("[APP] SHOW from the app: %s\n", s == chan::S_OK ? "on the KEY" : s == chan::S_LOCKED ? "locked" : "no such entry");
    return;
  }
  if(cmd == chan::C_CIPHER_DAY){ cipherDayRequest(ci, r); return; }   // 11bt: NOSTR Bluetooth life, before or after the PIN
  if(cmd == chan::C_API){ apiRequest(ci, r); return; }
  if(cmd == chan::C_NUDGE_SET){   // 11i: allowed before the PIN too (nudges start once btbOn)
    if(r.bodyLen != 1 || r.body[0] > 60){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    g_nudgeSec = r.body[0]; g_nudgeLast = millis();
    const uint8_t ok = chan::S_OK; answer(ci, chan::R_ACK, r.ctr, &ok, 1, false);
    if(g_nudgeSec) LOG_BOOT("[APP] nudges every %u s\n", (unsigned)g_nudgeSec); else LOG_BOOT("[APP] nudges off\n");
    return;
  }
  if(vaultCmd){
    if(!wallet.unlocked){ err(ci, r.ctr, chan::S_LOCKED); LOG_BOOT("[APP] request 0x%02X refused: the NOSTR PIN is not entered\n", cmd); return; }
    vaultRequest(ci, cmd, r); return;
  }
  if(cmd == chan::C_NIP46 || cmd == chan::C_NIP46_POLL || cmd == chan::C_BUNKER_INFO){
    if(!wallet.unlocked){ err(ci, r.ctr, chan::S_LOCKED); LOG_BOOT("[APP] request 0x%02X refused: the NOSTR PIN is not entered\n", cmd); return; }
    if(cmd == chan::C_NIP46){ nip46Request(ci, r); return; }
    if(cmd == chan::C_NIP46_POLL){ nip46Answer(ci, r.ctr, nullptr); return; }
    uint8_t b[33 + 4 * 256]; const size_t n = btbInfo(b, sizeof b);
    const bool sent = answer(ci, chan::R_BUNKER_INFO, r.ctr, b, n, false);
    LOG_BOOT("[APP] BUNKER_INFO: %u relay(s), %s\n", (unsigned)b[32], sent ? "sent" : "NOT sent");
    return;
  }
  if(cmd == chan::C_FILL){
    char site[chan::FIELD_MAX + 1], user[chan::FIELD_MAX + 1];
    uint8_t s = chan::S_BAD_REQUEST;
    if(chan::parseLogin(r.body, r.bodyLen, site, user)){
      lock(); g_fillCi = ci; g_fillCtr = r.ctr; unlock();
      s = blek::appFill(site, user);
      if(s != chan::S_OK){ lock(); if(g_fillCi == ci && g_fillCtr == r.ctr) g_fillCi = -1; unlock(); }
    }
    mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user);
    answer(ci, chan::R_ACK, r.ctr, &s, 1, false);
    LOG_BOOT("[APP] FILL from the app: %s\n", s == chan::S_OK ? "on the KEY" : "refused");
    return;
  }
  if(cmd == chan::C_CTAP){
    if(r.bodyLen == 0 || r.bodyLen > fido::MAX_MSG){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    lock(); g_ctapCi = ci; g_ctapCtr = r.ctr; unlock();
    LOG_BOOT("[APP] CTAP request from the app: %u bytes, command 0x%02X\n", (unsigned)r.bodyLen, r.body[0]);
    if(!blek::appCtap(fido::CMD_CBOR, r.body, r.bodyLen)){ lock(); g_ctapCi = -1; unlock(); err(ci, r.ctr, chan::S_BUSY); }
    return;
  }
  if(cmd == chan::C_CTAP_CANCEL){
    lock(); const bool mine = g_ctapCi == ci; unlock();
    if(mine) blek::appCtap(fido::CMD_CANCEL, nullptr, 0);
    return;   // the CTAP request itself answers (status 0x2D)
  }
  if(cmd == chan::C_TIME){   // 9j: [unix time 8, big endian], sent by the app on every connect; the KEY has no other clock in a PASSKEY life
    if(r.bodyLen != 8){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    uint64_t t = 0; for(int i = 0; i < 8; i++) t = (t << 8) | r.body[i];
    uint8_t s = chan::S_BAD_REQUEST;
    if(t > 1700000000ull && t < 4102444800ull){   // 2023 to 2100
      const int64_t now = (int64_t)time(nullptr), d = (int64_t)t - now;
      if(now < 1700000000 || d > 2 || d < -2){ struct timeval tv = { (time_t)t, 0 }; settimeofday(&tv, nullptr);
        LOG_BOOT("[APP] the KEY's clock set from the app (%s%lld s)\n", now < 1700000000 ? "it was not known, " : "off by ", now < 1700000000 ? 0LL : (long long)d); }
      s = chan::S_OK;
    }
    answer(ci, chan::R_ACK, r.ctr, &s, 1, false);
    return;
  }
  if(cmd == chan::C_OTP){   // 9i: [sLen][site][unix time 8, big endian]; the life's loop answers (otpTick)
    const size_t sl = r.bodyLen ? r.body[0] : 0;
    bool ok = r.bodyLen == 1 + sl + 8 && sl >= 1 && sl <= chan::FIELD_MAX;
    for(size_t i = 0; ok && i < sl; i++){ const uint8_t c = r.body[1 + i]; if(c < 0x20 || c > 0x7E) ok = false; }
    if(!ok){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
    uint64_t t = 0; for(int i = 0; i < 8; i++) t = (t << 8) | r.body[1 + sl + i];
    lock(); const bool busy = g_otpOn;
    if(!busy){ g_otpCi = ci; g_otpCtr = r.ctr; g_otpT = t; memcpy(g_otpSite, r.body + 1, sl); g_otpSite[sl] = 0; g_otpAt = millis(); g_otpOn = 1; }
    unlock();
    if(busy) err(ci, r.ctr, chan::S_BUSY); else LOG_BOOT("[APP] one-time code ask from the app (%u characters)\n", (unsigned)sl);
    return;
  }
  // C_LIST [start hi][start lo]: the life's loop answers (listTick). 11s: a third byte, flags bit0 = password entries with health and id (type 0x02)
  if(r.bodyLen != 2 && r.bodyLen != 3){ err(ci, r.ctr, chan::S_BAD_REQUEST); return; }
  lock();
  const bool busy = g_listOn;
  if(!busy){ g_listCi = ci; g_listCtr = r.ctr; g_listStart = (uint16_t)((r.body[0] << 8) | r.body[1]); g_listAt = millis(); g_listOn = 1; g_listHealth = r.bodyLen == 3 && (r.body[2] & 1); }
  unlock();
  if(busy) err(ci, r.ctr, chan::S_BUSY);
  else LOG_BOOT("[APP] LIST from the app, from entry %u\n", (unsigned)((r.body[0] << 8) | r.body[1]));
}
// From the FIDO task: its replies to the app's CTAP request.
static void ctapTx(uint8_t cmd, const uint8_t* d, size_t n){
  lock(); const int ci = g_ctapCi; const uint32_t ctr = g_ctapCtr; if(cmd != fido::CMD_KEEPALIVE) g_ctapCi = -1; unlock();
  if(ci < 0) return;
  if(cmd == fido::CMD_KEEPALIVE){ answer(ci, chan::R_KEEPALIVE, ctr, d, n ? 1 : 0, false); return; }
  if(cmd == fido::CMD_CBOR){ const bool ok = answer(ci, chan::R_CTAP, ctr, d, n, true); LOG_BOOT("[APP] CTAP answer to the app (%u bytes, status 0x%02X): %s\n", (unsigned)n, n ? d[0] : 0, ok ? "sent" : "NOT sent"); return; }
  if(cmd == fido::CMD_ERROR){ err(ci, ctr, chan::S_BUSY); return; }
}
// From the life's task: the answer to the app's FILL.
static bool fillTx(uint8_t status, const char* user, const char* pass){
  lock(); const int ci = g_fillCi; const uint32_t ctr = g_fillCtr; g_fillCi = -1; unlock();
  if(ci < 0) return false;
  uint8_t b[3 + 2 * 128]; size_t n = 0;
  b[n++] = status;
  if(status == 0 && user && pass){
    const size_t ul = strnlen(user, 128), pl = strnlen(pass, 128);
    b[n++] = (uint8_t)ul; memcpy(b + n, user, ul); n += ul;
    b[n++] = (uint8_t)pl; memcpy(b + n, pass, pl); n += pl;
  }
  const bool ok = answer(ci, chan::R_LOGIN, ctr, b, n, true);
  mbedtls_platform_zeroize(b, sizeof b);
  Serial.printf("[APP] sign-in answer to the app: status %u%s, %s\n", (unsigned)status, status == 0 ? " (the login, encrypted)" : "", ok ? "sent" : "NOT sent");
  return ok;
}
static int count(){ return g_count; }

// ---- item 4: LIST (issue #3) --------------------------------------------------------
// Answer R_LIST 0xB6 (encrypted): [0x00][total hi][total lo][count] entries [more],
// or one status byte (0x02 refused or timed out, 0x05 locked). Entries in a fixed
// order: passwords newest first, then passkeys in slot order. Password entry:
// [0x00][sLen][site][uLen][user]; passkey: [0x01][sLen][site][uLen][name]
// [idLen 34][credential id][hLen][user handle]. A password whose name is not read
// yet (labels still loading after the PIN) is left out and not counted. Opening a
// passkey record costs one of the sitting's record opens the first time (then it
// is cached until the KEY locks); one that cannot be opened is left out.
static constexpr size_t LIST_BODY = 1024;
static void listAnswer(int ci, uint32_t ctr, uint8_t status){ answer(ci, chan::R_LIST, ctr, &status, 1, true); }
static bool listSend(int ci, uint32_t ctr, uint16_t start, int* totalOut = nullptr, int* sentOut = nullptr, bool* moreOut = nullptr){
  favilla::RkRow* rows = (favilla::RkRow*)heap_caps_malloc(sizeof(favilla::RkRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  uint8_t* b = (uint8_t*)heap_caps_malloc(LIST_BODY, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  favilla::RkAcct* a = (favilla::RkAcct*)heap_caps_malloc(sizeof(favilla::RkAcct), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!rows || !b || !a){ free(rows); free(b); free(a); listAnswer(ci, ctr, chan::S_CANCELLED); return false; }
  const int nr = favilla::rk_pw_rows(rows, favilla::RK_MAX);
  const int nk = favilla::rk_count();
  int total = 0; for(int i = 0; i < nr; i++) if(rows[i].nameKnown && !rows[i].pending) total++;
  // passkeys: count the ones that open (cached after the first page)
  int pkOk = 0; for(int i = 0; i < nk; i++) if(favilla::rk_at(i, a) == favilla::RK_OK) pkOk++;
  total += pkOk;
  size_t o = 4; int cnt = 0, idx = 0; bool more = false;
  auto put = [&](const uint8_t* e, size_t n)->bool{ if(o + n + 1 > LIST_BODY) return false; memcpy(b + o, e, n); o += n; cnt++; return true; };
  uint8_t e[1 + 1 + favilla::RK_SITE_MAX + 1 + favilla::RK_PW_FIELD_MAX + 1 + 34 + 1 + favilla::RK_HANDLE_MAX];
  for(int i = 0; i < nr && !more; i++){
    const favilla::RkRow& w = rows[i];
    if(!w.nameKnown || w.pending) continue;
    if(idx++ < start) continue;
    const size_t sl = strnlen(w.site, 255), ul = w.userKnown ? strnlen(w.user, 255) : 0; size_t n = 0;
    e[n++] = g_listHealth ? 0x02 : 0x00; e[n++] = (uint8_t)sl; memcpy(e + n, w.site, sl); n += sl; e[n++] = (uint8_t)ul; memcpy(e + n, w.user, ul); n += ul;
    if(g_listHealth){ e[n++] = w.health; memcpy(e + n, w.id8, 8); n += 8; }   // 11s
    if(!put(e, n)) more = true;
  }
  for(int i = 0; i < nk && !more; i++){
    if(favilla::rk_at(i, a) != favilla::RK_OK) continue;
    if(idx++ < start) continue;
    const size_t sl = strnlen(a->site, 255), ul = strnlen(a->name, 255); size_t n = 0;
    e[n++] = 0x01; e[n++] = (uint8_t)sl; memcpy(e + n, a->site, sl); n += sl; e[n++] = (uint8_t)ul; memcpy(e + n, a->name, ul); n += ul;
    e[n++] = 34; memcpy(e + n, a->id34, 34); n += 34; e[n++] = a->handleN; memcpy(e + n, a->handle, a->handleN); n += a->handleN;
    if(!put(e, n)) more = true;
  }
  b[0] = 0x00; b[1] = (uint8_t)(total >> 8); b[2] = (uint8_t)total; b[3] = (uint8_t)cnt; b[o++] = more ? 1 : 0;
  const bool ok = answer(ci, chan::R_LIST, ctr, b, o, true);
  if(totalOut) *totalOut = total; if(sentOut) *sentOut = (int)start + cnt; if(moreOut) *moreOut = more;   // 11cg: the KEY's count
  LOG_BOOT("[APP] LIST page to the app: from %u, %d of %d entr%s, %s%s\n", (unsigned)start, cnt, total, total == 1 ? "y" : "ies", more ? "more to come, " : "", ok ? "sent" : "NOT sent");
  mbedtls_platform_zeroize(rows, sizeof(favilla::RkRow) * favilla::RK_MAX); mbedtls_platform_zeroize(b, LIST_BODY); mbedtls_platform_zeroize(a, sizeof *a); mbedtls_platform_zeroize(e, sizeof e);
  free(rows); free(b); free(a);
  return ok;
}
// From the life's loop (home screen): true when it drew a screen.
// 11cg (22 Nov 2026, UX drop 1, Josh's ruling): no question. The list is site
// names and usernames only, it needs the VAULT PIN already entered
// (g_pkPinHeld), and it goes only to an app paired with two matching numbers
// over the encrypted app channel, so ENTER guarded nothing. The KEY shows it
// is working instead: the ember flickers and the count rises as each page
// goes, and the home screen comes back by itself. The page stays up while the
// app asks for the next page (it pages at 1 KB), up to 2.5 s after the last.
// g_listOkCi / g_listOkUntil (the old 30 s "yes") are no longer needed.
static bool listTick(uint32_t& lp){
  if(!g_listOn) return false;
  bool drew = false; uint32_t lastPage = 0;
  for(;;){
    if(g_listOn){
      lock(); const int ci = g_listCi; const uint32_t ctr = g_listCtr, at = g_listAt; const uint16_t start = g_listStart; unlock();
      auto done = [&](){ lock(); g_listOn = 0; g_listCi = -1; unlock(); };
      if(millis() - at > 30000UL){ listAnswer(ci, ctr, chan::S_CANCELLED); done(); LOG_BOOT("[APP] LIST not taken in 30 s\n"); }
      else if(!g_pkPinHeld || !favilla::rk_ready()){ listAnswer(ci, ctr, chan::S_LOCKED); done(); if(!drew) return false; break; }
      else {
        if(!drew){
          if(dimActive) idleDimWake();
          wp::Page& p = wp::ember("VAULT", "Sharing list");
          snprintf(p.line1, sizeof p.line1, "Site names and usernames only.");
          snprintf(p.count, sizeof p.count, "READING");
          wp::show(); drew = true;
        }
        int total = 0, sent = 0; bool more = false;
        listSend(ci, ctr, start, &total, &sent, &more);
        done(); lastPage = millis();
        snprintf(wp::P.count, sizeof wp::P.count, "%d OF %d", sent, total);
        wp::P.bar = total > 0 ? (float)sent / (float)total : 1.0f;
        wp::show();
        LOG_BOOT("[APP] LIST shared on the KEY's screen (%d of %d)\n", sent, total);
        if(!more){ const uint32_t h = millis(); while(millis() - h < 500){ pumpInputs(); pkSerialTick(); delay(10); } break; }   // let the count be read
      }
    }
    if(drew && millis() - lastPage > 2500UL) break;      // the app stopped asking
    if(!drew) return false;
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || !g_pkPinHeld) break;
    if(btn4.isPressed()) break;                           // BACK leaves the page; the app keeps its next page request queued
    delay(10);
  }
  wp::stop();
  lp = millis();
  return true;
}
// ---- 9i: a one-time code for the app ------------------------------------------------
// Answer R_OTP 0xB7 (encrypted): [0x00][n][the n digits, ASCII], or one status
// byte (0x02 refused or timed out, 0x03 no code saved, 0x05 locked). The owner
// picks on the KEY (one press even for a single match); the G0 computes the code
// for the app's time, which also sets the KEY's clock if it does not know it.
static void otpAnswer(int ci, uint32_t ctr, uint8_t st){ answer(ci, chan::R_OTP, ctr, &st, 1, true); }
static void otpDraw(const favilla::RkTotp* T, const int* idx, int n, int sel, const char* asked, bool all, const char* foot = "SEND"){   // 11z: the browser's ask types instead
  const int VIS = 3, CH = 42, PITCH = 46, Y0 = 52;
  int off = 0; if(n > VIS){ off = sel - 1; if(off < 0) off = 0; if(off > n - VIS) off = n - VIS; }
  fEnd(); spr.fillSprite(C_BG);
  uiTrackLabel("CODE", 120, 14, C_EB_BRASS);
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  { char t[96]; snprintf(t, sizeof t, all ? "None saved for %s. Pick one?" : "For %s", asked); pkFitText(t, sizeof t, 216, false); spr.drawString(t, 120 - spr.textWidth(t) / 2, 32); }
  fEndHard();
  for(int r = 0; r < VIS && off + r < n; r++){
    const favilla::RkTotp& t = T[idx[off + r]]; char nm[48], sb[48];
    snprintf(nm, sizeof nm, "%s", t.site); snprintf(sb, sizeof sb, "%s", t.acct);
    fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14, true); fEnd();
    fSet(F_BODY); pkFitText(sb, sizeof sb, 216 - 24 - 14, false); fEnd();
    uiListCard(12, Y0 + r * PITCH, 216, CH, off + r == sel, C_EB_BRASS, nm, sb[0] ? sb : nullptr, 24);
  }
  if(n > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 8; int thumb = TH * VIS / n; if(thumb < 8) thumb = 8; int ty = TY + (TH - thumb) * off / (n - VIS);
    spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
  uiCornerAnswers("DECLINE", foot);   // 11cw: the answers in the corners
  dispPush();
}
static bool otpTick(uint32_t& lp){
  if(!g_otpOn) return false;
  char asked[chan::FIELD_MAX + 1];
  lock(); const int ci = g_otpCi; const uint32_t ctr = g_otpCtr, at = g_otpAt; const uint64_t t = g_otpT; memcpy(asked, g_otpSite, sizeof asked); unlock();
  auto done = [&](){ lock(); g_otpOn = 0; g_otpCi = -1; mbedtls_platform_zeroize(g_otpSite, sizeof g_otpSite); unlock(); mbedtls_platform_zeroize(asked, sizeof asked); };
  if(millis() - at > 30000UL){ otpAnswer(ci, ctr, chan::S_CANCELLED); done(); return false; }
  if(!g_pkPinHeld || !favilla::rk_ready() || !g0_v17_present()){ otpAnswer(ci, ctr, chan::S_LOCKED); done(); return false; }
  if(t > 1700000000ull && time(nullptr) < 1700000000){ struct timeval tv = { (time_t)t, 0 }; settimeofday(&tv, nullptr); LOG_BOOT("[OTP] the KEY's clock set from the app's time\n"); }
  favilla::RkTotp* T = (favilla::RkTotp*)heap_caps_malloc(sizeof(favilla::RkTotp) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  int* idx = (int*)heap_caps_malloc(sizeof(int) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!T || !idx){ free(T); free(idx); otpAnswer(ci, ctr, chan::S_CANCELLED); done(); return false; }
  const int n = favilla::rk_totp_rows(T, favilla::RK_MAX);
  int m = 0; bool all = false;
  // 11v: the code linked to the login the KEY sent this phone in the last 60 s
  // (a two-step sign-in: password, then code) comes first and alone.
  if(g_lastFill.on && millis() - g_lastFill.at < 60000UL){
    favilla::RkRow row; int ts = -1;
    if(favilla::rk_pw_row(g_lastFill.idx, &row)) ts = favilla::rk_pw_totp_slot(row.slot);
    for(int i = 0; ts >= 0 && i < n; i++) if(T[i].slot == ts){ idx[m++] = i; break; }
    if(m) LOG_BOOT("[OTP] the code linked to the login just sent\n");
  }
  // then codes whose linked account is on the asked site, then the label's own site
  if(m == 0){
    favilla::RkRow* rows = (favilla::RkRow*)heap_caps_malloc(sizeof(favilla::RkRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    const int nr = rows ? favilla::rk_pw_rows(rows, favilla::RK_MAX) : 0;
    for(int i = 0; i < n; i++){
      if(!T[i].known) continue;
      bool hit = otpauth::siteMatch(T[i].site, asked);
      if(!hit && rows){ const int lp2 = favilla::rk_totp_linked_pw(T[i].slot); for(int k = 0; lp2 >= 0 && k < nr; k++) if(rows[k].slot == lp2){ hit = rows[k].nameKnown && otpauth::siteMatch(rows[k].site, asked); break; } }
      if(hit) idx[m++] = i;
    }
    if(rows){ mbedtls_platform_zeroize(rows, sizeof(favilla::RkRow) * favilla::RK_MAX); free(rows); }
  }
  if(m == 0){ for(int i = 0; i < n; i++) if(T[i].known) idx[m++] = i; all = true; }   // as 9d's passwords: pick one when nothing matches
  auto freeAll = [&](){ mbedtls_platform_zeroize(T, sizeof(favilla::RkTotp) * favilla::RK_MAX); free(T); free(idx); };
  if(m == 0){ freeAll(); otpAnswer(ci, ctr, chan::S_NO_MATCH); done(); LOG_BOOT("[OTP] no code saved\n"); return false; }
  if(dimActive) idleDimWake();
  int sel = 0; otpDraw(T, idx, m, sel, asked, all); clearButtonPending();
  bool yes = false; const uint32_t t0 = millis();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || btn4.isPressed() || millis() - t0 > 30000UL || !g_pkPinHeld) break;
    if(m > 1 && btn1.isPressed()){ sel = (sel + 1) % m; otpDraw(T, idx, m, sel, asked, all); }
    else if(m > 1 && btn3.isPressed()){ sel = (sel + m - 1) % m; otpDraw(T, idx, m, sel, asked, all); }
    if(btn2.isPressed()){ yes = true; break; }
    delay(10); }
  if(yes){
    uint32_t code = 0; uint8_t dg = 0;
    const int r = rkWithPin([&]()->int{ return favilla::rk_totp_code(T[idx[sel]].slot, t, &code, &dg); }, nullptr);   // 25 Nov 2026
    LOG_BOOT("[OTP] code for the app: %s | record opens left this sitting: %d\n", r == 0 ? "computed by the G0" : favilla::rk_err_name(r), favilla::rk_open_left());
    if(r == 0){ uint8_t b[2 + 8]; b[0] = 0; b[1] = dg; char d[12]; snprintf(d, sizeof d, "%0*lu", (int)dg, (unsigned long)code); memcpy(b + 2, d, dg);
      const bool ok = answer(ci, chan::R_OTP, ctr, b, 2 + dg, true); LOG_BOOT("[OTP] sent to the app: %s\n", ok ? "yes" : "NOT sent");
      mbedtls_platform_zeroize(b, sizeof b); mbedtls_platform_zeroize(d, sizeof d); code = 0; }
    else otpAnswer(ci, ctr, chan::S_CANCELLED);
  } else { otpAnswer(ci, ctr, chan::S_CANCELLED); LOG_BOOT("[OTP] refused on the KEY\n"); }
  freeAll(); done(); lp = millis();
  return true;
}
static void listForget(){ lock(); g_listOkCi = -1; g_listOkUntil = 0; unlock(); }

// The pairing screen's side.
static void windowOpened(uint32_t ms){ lock(); hooks(); load(); g_key.windowOpened(); g_ask = 0; g_scanHave = false; mbedtls_platform_zeroize(g_scanExt, sizeof g_scanExt); mbedtls_platform_zeroize(g_scanNonce, sizeof g_scanNonce); g_winUntil = millis() + ms; unlock(); }
static void windowClosed(){ lock(); g_key.windowClosed(); g_ask = 0; g_scanHave = false; mbedtls_platform_zeroize(g_scanExt, sizeof g_scanExt); mbedtls_platform_zeroize(g_scanNonce, sizeof g_scanNonce); g_winUntil = 0; unlock(); }
// 11ah: the pairing screen read the app's QR. Kept for a REVEAL still to come;
// if the code is already on screen (stage 2) and it is this attempt, the
// pairing is accepted here. Returns true when it was accepted now.
static bool pairScanned(const uint8_t extPub[65], const uint8_t nonce[16]){
  lock(); hooks();
  memcpy(g_scanExt, extPub, 65); memcpy(g_scanNonce, nonce, 16); g_scanHave = true;
  const int before = g_key.count(); bool now = false;
  if(g_ask && g_key.pairScanned(extPub, nonce)){ g_ask = 0; recount(); now = g_key.count() > before; }
  unlock();
  return now;
}
static bool askPending(uint32_t* code, uint8_t id[chan::ID]){ if(!g_ask) return false; lock(); const bool a = g_ask; if(a){ *code = g_askCode; memcpy(id, g_askId, chan::ID); } unlock(); return a; }
static bool decide(bool accept, const uint8_t id[chan::ID]){
  lock(); const int before = g_key.count(); g_key.pairDecision(accept, id); g_ask = 0; recount(); const bool added = g_key.count() > before; unlock();
  LOG_BOOT("[APP] pairing %s on the KEY: %s (%d app%s paired)\n", accept ? "accepted" : "refused", added ? "app paired" : "nothing saved", (int)g_count, g_count == 1 ? "" : "s");
  return added;
}
static bool forgetAll(){ lock(); hooks(); load(); bool ok = true; for(int i = 0; i < chan::MAX_CLIENTS; i++) if(g_key.cl[i].used){ memset(&g_key.cl[i], 0, sizeof g_key.cl[i]); } ok = save(g_key.cl, chan::MAX_CLIENTS); recount(); unlock();
  fsec::phonesForgetApp(nullptr);   // 9l (issue #8): the PWA pairings those app installs enrolled go with them
  return ok; }
// Registered at start-up: the Bluetooth module reaches the logic through these.
static void init(){ lock(); hooks(); load(); unlock(); LOG_BOOT("[APP] app channel ready: %d app install%s paired%s\n", (int)g_count, g_count == 1 ? "" : "s", g_count ? " (raw Bluetooth sign-in paths shut)" : ""); }
struct Reg { Reg(){ g_mx = xSemaphoreCreateMutexStatic(&g_mxBuf); g_pkLockHook = listForget; g_appForgetAllHook = forgetAll; /* 11ah: a wipe forgets the paired apps */ blek::s_appOnMsg = onMsg; blek::s_appCount = count; blek::s_appCtapTx = ctapTx; blek::s_appFillTx = fillTx; } };
static Reg s_reg;
}  // namespace ag
