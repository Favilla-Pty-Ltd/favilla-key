#pragma once
// ============================================================================
// session_sec_http.h — HTTP glue for the encrypted transport.
//
// Splice point: include AFTER session_sec.h and AFTER camServer/apiAddCORS/
// apiCheckOrigin are declared. Provides:
//   - handleApiSession                        : no-PIN reconnect (IK handshake).
//                                               Also promotes a pending FK1 pair
//                                               to trusted once possession is
//                                               proven (Option A).
//   - apiBeginRequest / apiReadBody / apiSend : the seal/open chokepoint every
//                                               sealed handler routes through
//   - apiCheckAuth2                           : "valid AEAD body under sk" auth
//
// Per-request state: ESP32 WebServer is single-threaded per request on the
// HTTP task, so a single set of request-scoped globals is safe (one request
// in flight at a time on camServer).
// ============================================================================

#include "session_sec.h"

// Forward decls from main.cpp (defined earlier in the TU)
void   apiAddCORS();
bool   apiCheckOrigin();
extern WebServer camServer;
extern volatile bool pendingReturnToMenu;
extern Wallet wallet;

namespace fsec {

// ── Per-request scope ──────────────────────────────────────────────────────
// Set by apiBeginRequest() at the top of each sealed handler. apiReadBody()
// and apiSend() consult these so a request that arrived sealed leaves sealed,
// and a cleartext (legacy/bypass) request stays cleartext.
struct ReqCtx {
  bool      sealed = false;       // this request used the encrypted channel
  Session*  sess = nullptr;       // resolved session (if sealed)
  char      aad[200] = {0};       // "METHOD PATH[?QUERY]" for AEAD binding (11bv: the query too, issue #47 item 3)
  size_t    aadLen = 0;
  uint32_t  counter = 0;          // counter pulled from the opened plaintext
};
static ReqCtx g_req;

// Set true by handleApiSession() when a PENDING pairing is promoted to trusted
// (Option A: possession proven). The main loop polls this on the ST_PAIR_CONFIRM
// / menu path to render the "Paired ✓" success reveal AFTER the crypto proof,
// then clears it. volatile: written on the web-server task, read on loopTask.
volatile bool g_pairPromoted = false;

// ── Option B: SAS (short-authentication-string) pairing confirmation ────────
// Option A proved POSSESSION (the enrolled key completed the IK handshake).
// Option B additionally proves IDENTITY: both ends independently derive
//   code = first 6 decimal digits of HMAC-SHA256(sk, "favilla-pair-confirm")
// (identical to pq_confirm_code in pair_qr.h) and the user compares them.
// Because sk mixes ee‖se‖es under HKDF, a MITM who substituted ANY key in the
// handshake cannot make both sides derive the same sk — the codes mismatch and
// the user rejects on-device. Enrolment now happens at code-Confirm, not at
// handshake completion, and the session the user confirms is byte-for-byte the
// session that goes live (same sk).
//
// Single-slot by design (pairing is a one-at-a-time physical act). State is
// written by handleApiSession (Core 0) when arming, and by sasResolve (Core 1,
// from the confirm modal) when resolving — never both at once: handleApiSession
// refuses to arm while SAS_WAITING, and sasResolve only runs while SAS_WAITING.
enum SasState : uint8_t { SAS_NONE=0, SAS_WAITING, SAS_CONFIRMED, SAS_REJECTED };
static volatile SasState g_sasState = SAS_NONE;
static char     g_sasCode[7]    = {0};   // 6 digits + NUL — shown on the device
static uint8_t  g_sasPub[32]    = {0};   // pending pubkey, enrolled on Confirm
static char     g_sasPairId[17] = {0};   // session awaiting confirmation
static volatile bool g_sasIsReconnect = false;  // true = trusted-phone reconnect
                                                // approval (already enrolled), not
                                                // a first pairing. Lets the device
                                                // screen show "approve connection"
                                                // vs "confirm pairing code".
static volatile uint32_t g_sasDeadlineMs = 0;
static constexpr uint32_t SAS_TTL_MS        = 90000;   // user has 90 s to compare
static constexpr uint32_t SAS_RESULT_TTL_MS = 120000;  // result readable this long
static uint32_t g_sasResultExpiryMs = 0;

// Same derivation as pq_confirm_code (pair_qr.h), via the project hmac_sha256
// so this header stays self-contained.
//
// SEC_1 hardening (transcript binding): the code now commits EXPLICITLY to
// both static pubkeys, not just to sk. sk is already transcript-dependent
// (it's HKDF over three ECDH terms, each of which incorporates both keys, so
// a MITM running two handshakes already derives two different sk → two
// different codes). But that binding was *implicit* — it held only by
// reasoning about ECDH. Folding devPub‖phonePub into the HMAC input makes the
// property provable by inspection and belt-and-braces against any single DH
// term being weak. Domain tag bumped to -v2 so the value can't collide with
// the old sk-only derivation.
//   code = first 6 decimal digits of
//          HMAC-SHA256(sk, "favilla-pair-confirm-v2" ‖ devPub(32) ‖ phonePub(32))
static void sasCodeFromSk(const uint8_t sk[32], const uint8_t devPub[32],
                          const uint8_t phonePub[32], char out[7]) {
  uint8_t msg[23 + 32 + 32];
  memcpy(msg,        "favilla-pair-confirm-v2", 23);   // 23 bytes, no NUL
  memcpy(msg + 23,   devPub,   32);
  memcpy(msg + 55,   phonePub, 32);
  uint8_t mac[32];
  hmac_sha256(sk, 32, msg, sizeof(msg), mac);
  uint32_t n = ((uint32_t)mac[0] << 24) | ((uint32_t)mac[1] << 16) |
               ((uint32_t)mac[2] << 8)  |  (uint32_t)mac[3];
  n %= 1000000UL;
  snprintf(out, 7, "%06lu", (unsigned long)n);
  memset(mac, 0, 32);
  memset(msg, 0, sizeof(msg));
}

// Resolve the pending SAS. Called ONLY from the main-loop confirm modal
// (sasConfirmTick in main.cpp) — Core 1 owns resolution, including timeout.
//   accept=true  → enrol the pubkey (NVS), mark the session confirmed.
//   accept=false → kill the session (sk zeroed), nothing enrolled.
// Either way the pending FK1 slot is cleared: a rejected pair must re-scan.
static void sasResolve(bool accept) {
  if (g_sasState != SAS_WAITING) return;
  Session* s = sessionByPairId(g_sasPairId);
  if (accept) {
    int slot = phonesEnrol(g_sasPub);   // persists to NVS (Core 1 write; a
                                        // concurrent phonesFind on Core 0 that
                                        // races the memcpy just fails and the
                                        // caller retries — benign)
    phonesTouch(slot);                  // stamp last-seen for idle-expiry
    if (s) { s->phoneSlot = slot; s->confirmed = true; }
    // Single-session: the approval that promotes THIS session evicts every
    // other live session, so at most one confirmed session exists at a time.
    // Only in the opt-in mode — default multi-session behaviour is untouched.
    if (requireReconnectConfirm() && s) {
      for (int i = 0; i < MAX_SESSIONS; i++)
        if (&g_sessions[i] != s && g_sessions[i].active)
          memset(&g_sessions[i], 0, sizeof(Session));
    }
    fsecSyncPowerMode();               // radio awake while session is live
    g_sasState = SAS_CONFIRMED;
    Serial.println(g_sasIsReconnect
      ? "[PAIR] reconnect approved — session live (single-session)"
      : "[PAIR] SAS confirmed — pubkey enrolled, session live");
  } else {
    if (s) memset(s, 0, sizeof(Session));   // active=false, sk zeroed
    fsecSyncPowerMode();               // back to MIN_MODEM if no sessions remain
    g_sasState = SAS_REJECTED;
    Serial.println("[PAIR] SAS rejected/expired — session killed, nothing enrolled");
  }
  pendingPairClear();
  g_sasIsReconnect = false;
  memset(g_sasPub, 0, 32);
  memset(g_sasCode, 0, sizeof(g_sasCode));
  g_sasDeadlineMs = 0;
  g_sasResultExpiryMs = millis() + SAS_RESULT_TTL_MS;  // g_sasPairId kept for the
                                                       // status endpoint until then
}

// 11bv (issue #47 item 3): "METHOD PATH", then "?" and the canonical query
// when there is one, so a sealed GET's ?id= is inside the MAC. false (and the
// request is refused) when it does not fit.
static bool buildAad(ReqCtx& r) {
  const char* m = (httpIo.method() == HTTP_POST) ? "POST" :
                  (httpIo.method() == HTTP_GET)  ? "GET"  : "OPT";
  String a = String(m) + " " + httpIo.uri();
  const String q = httpIo.canonQuery();
  if (q.length()) { a += '?'; a += q; }
  r.aadLen = 0; r.aad[0] = 0;
  if (a.length() >= sizeof(r.aad)) return false;
  memcpy(r.aad, a.c_str(), a.length() + 1); r.aadLen = a.length();
  return true;
}

// F6: the ONLY caller is pairId, which is a public session LABEL mixed into
// the HKDF info string alongside three ECDH outputs. Its secrecy is not load
// bearing: a predictable pairId does not weaken sk while the ECDH terms are
// secret. So the fallback is tolerable here — but it is logged rather than
// silent, and this helper must NOT be reused for key material. If you need
// random bytes for anything that is a secret, call se_random directly and
// fail closed (see the devEphPriv site below).
static void randHex(char* out, int nbytes) {
  uint8_t* b = (uint8_t*)alloca(nbytes);
  if (!favilla::se_random(b, nbytes)) {
    Serial.println("[AUTH2] se_random failed for pairId label — degraded (not key material)");
    for (int i=0;i<nbytes;i++) b[i]=(uint8_t)esp_random();
  }
  toHex(b, nbytes, out);
}

// ── Common IK handshake: given the phone's static + ephemeral pubkeys and a
// device ephemeral priv, derive sk. Returns false if any ECDH fails. ────────
static bool ikDeriveSk(const uint8_t qPhoneStatic[32], const uint8_t qPhoneEph[32],
                       const uint8_t dDevEph[32], const char* pairId,
                       uint8_t sk_out[32]) {
  if (!deviceIdentityInit()) return false;
  uint8_t ee[32], se[32], es[32];
  // ee = ECDH(dev_eph, phone_eph)
  if (!ecdh_raw(dDevEph, qPhoneEph, ee)) return false;
  // se = ECDH(dev_eph, phone_static)   ← authenticates the phone
  if (!ecdh_raw(dDevEph, qPhoneStatic, se)) return false;
  // es = ECDH(dev_static, phone_eph)   ← authenticates this device
  if (!ecdh_ct(g_dDevice, qPhoneEph, es)) return false;   // 23 Nov 2026 (#61): long-term key, constant-time scalar multiply
  bool ok = deriveSk(ee, se, es, pairId, sk_out);
  memset(ee,0,32); memset(se,0,32); memset(es,0,32);
  return ok;
}

// ════════════════════════════════════════════════════════════════════════
// /api/session — reconnect, NO PIN. Works for any already-trusted phone.
//   Req (cleartext): { "phone_pub":<64hex static>, "phone_eph":<64hex> }
//   Device: verifies phone_pub is trusted, makes an ephemeral, derives sk,
//           opens a session, returns its ephemeral + SEALED confirmation.
//   Resp: { "device_eph":<64hex>, "pair_id":<16hex>, "sealed":<{n,ct}> }
//   The sealed blob proves the device derived the same sk (so the phone can
//   verify it's talking to its real device — es term authenticates us).
// ════════════════════════════════════════════════════════════════════════
void handleApiSession() {
  apiAddCORS();
  if (!apiCheckOrigin()) { httpIo.send(403,"application/json","{\"error\":\"Bad origin\"}"); return; }
  if (!deviceIdentityInit()) { httpIo.send(500,"application/json","{\"error\":\"Device identity unavailable\"}"); return; }
  JsonDocument doc;
  if (deserializeJson(doc, httpIo.arg("plain"))) {
    httpIo.send(400,"application/json","{\"error\":\"Invalid JSON\"}"); return;
  }
  const char* phonePubHex = doc["phone_pub"] | "";
  const char* phoneEphHex = doc["phone_eph"] | "";
  uint8_t phonePub[32], phoneEph[32];
  if (strlen(phonePubHex)!=64 || !fromHex(phonePubHex, phonePub, 32) ||
      strlen(phoneEphHex)!=64 || !fromHex(phoneEphHex, phoneEph, 32)) {
    httpIo.send(400,"application/json","{\"error\":\"Bad params\"}"); return;
  }
  // Idle-pairing expiry: drop any trusted phone that hasn't completed a
  // confirmed session within PAIRING_IDLE_TTL_S BEFORE we look it up, so a
  // stolen-but-stale kv_phone_id reads as "not paired" and must re-pair.
  // Fail-safe (no-op unless the clock is synced and last-seen is known).
  phonesExpireStale();
  // Option A: accept the caller if it is ALREADY trusted, OR if it is the
  // PENDING pubkey the user just confirmed on-device via the FK1 scan. A
  // pending caller must still complete the sealed handshake below (which
  // cryptographically proves it holds phonePub's private key) before we
  // promote it to trusted. This is the possession-proof gate that replaces
  // "enrol whatever was scanned".
  int  slot      = phonesFind(phonePub);
  bool isPending = (slot < 0) && pendingPairMatches(phonePub);
  // 9l (issue #8, NOSTR BT life): a tunnelled /api/session from a paired app
  // client whose MAC verified (httpIo.tAppSet is only ever set by apiTunnelRun,
  // which only runs for a verified API request in the NOSTR Bluetooth life) for
  // a phone_pub that is neither trusted nor pending. That client was confirmed
  // on the KEY with its own 6-digit code at PAIR THE APP, so it stands in for the
  // FK1 scan and Confirm. No SAS: the same press is not asked twice. The sealed
  // handshake below still runs, and the phone is enrolled only when its first
  // request opens under sk, which proves it holds phone_pub's key. Over Wi-Fi
  // httpIo.tAppSet is never set, so nothing changes there.
  const bool appEnrol = (slot < 0) && !isPending && httpIo.tun && httpIo.tAppSet;
  // Confirm-on-reconnect (opt-in): when ON, a trusted reconnect ALSO needs an
  // on-device approval, exactly like a first pairing. When OFF (default),
  // needApprove == isPending, so everything below behaves as before.
  bool needApprove = isPending || (slot >= 0 && requireReconnectConfirm());   // appEnrol: no approval (see above)
  // Only one confirmation may be on the device screen at a time: refuse to arm
  // a second while one is pending (a fresh handshake would derive a fresh sk and
  // therefore a different code, desynchronising the compare). The PWA holds off
  // re-handshaking during the wait; this is the backstop for anything that
  // doesn't. Refusing here also means an attacker cannot clobber a legit pending
  // confirm, nor (single-session mode) evict the live session without approval.
  if (needApprove && g_sasState == SAS_WAITING) {
    httpIo.send(409,"application/json","{\"error\":\"Confirmation pending on device\",\"sas_busy\":true}"); return;
  }
  if (slot < 0 && !isPending && !appEnrol) {
    // Neither trusted nor pending — the browser must run the FK1 scan pairing
    // (show its QR, have the device scan + confirm) first.
    httpIo.send(403,"application/json","{\"error\":\"Not paired\",\"need_pair\":true}"); return;
  }
  // device ephemeral for this session
  uint8_t devEphPriv[32], devEphPub[32];
  // F6: FAIL CLOSED. This is a secp256k1 PRIVATE KEY, and devEphPub goes on
  // the wire — so an observer who captures the transcript has a validation
  // oracle for candidate keys. Recovering it yields sk and the whole session.
  // Structurally the same path Block flagged as directly exploitable in
  // COLDCARD's paper-wallet generation (2026-07-30). A session that cannot be
  // established is a retry; a session with a guessable ephemeral key is a
  // silent compromise. Never fall back to esp_random for key material.
  if (!favilla::se_random(devEphPriv, 32)) {
    Serial.println("[AUTH2] se_random failed for device ephemeral key — refusing handshake");
    mbedtls_platform_zeroize(devEphPriv, 32);
    httpIo.send(503,"application/json","{\"error\":\"entropy_unavailable\"}"); return;
  }
  if (!bip340_make_key(devEphPriv, devEphPub)) {
    httpIo.send(500,"application/json","{\"error\":\"keygen\"}"); return;
  }
  char pairId[17]; randHex(pairId, 8);
  uint8_t sk[32];
  // ikDeriveSk mixes se = ECDH(dev_eph, phone_static). If the caller does NOT
  // hold phone_static's private key, the sk it derives on its side will not
  // match ours, so its subsequent sealed requests fail to open — AND, for a
  // pending caller, the sealed-confirm round below is what the PWA verifies to
  // prove WE hold sk. Either way, possession is enforced cryptographically.
  if (!ikDeriveSk(phonePub, phoneEph, devEphPriv, pairId, sk)) {
    memset(devEphPriv,0,32);
    httpIo.send(500,"application/json","{\"error\":\"handshake\"}"); return;
  }
  memset(devEphPriv, 0, 32); // burn ephemeral → forward secrecy

  // ── Option B: pending → UNCONFIRMED session + SAS, not immediate trust ─────
  // We reach here only after ikDeriveSk succeeded against phonePub, i.e.
  // possession is proven (Option A's property, retained). But possession alone
  // doesn't prove the key belongs to YOUR browser — a substituted QR whose
  // attacker holds the key also passes. So: create the session UNCONFIRMED
  // (apiCheckAuth2 rejects it), derive the 6-digit code from sk, and hand the
  // decision to the physical Confirm on the device. Enrolment moves to
  // sasResolve(true). The session the user confirms is the one that goes live.
  Session* s = sessionAllocSlot();
  s->active = true;
  s->confirmed = !needApprove;         // auto-confirm ONLY when no approval needed
  strncpy(s->pairId, pairId, 16); s->pairId[16]=0;
  memcpy(s->sk, sk, 32);
  s->phoneSlot = slot;                 // -1 for pending; set at sasResolve(true)
  s->lastCounter = 0;
  s->lastSeenMs = millis();
  s->appEnrol = appEnrol;   // 9l: enrolled on its first request that opens under sk
  if (appEnrol) { memcpy(s->enrolPub, phonePub, 32); memcpy(s->enrolApp, httpIo.tApp, 8);
    Serial.println("[PAIR] PWA over the paired Favilla app: session made, the phone is enrolled on its first sealed request (no QR)"); }
  // Auto-confirmed here and now → refresh idle-expiry clock. (When approval is
  // needed, the touch happens on approve, in sasResolve.)
  if (!needApprove) { phonesTouch(slot); fsecSyncPowerMode(); }

  if (needApprove) {
    // Transcript-bound code: commits to device static pub (g_qDevice) and the
    // phone static pub, so a MITM cannot produce a matching code without both
    // sides having seen the same two keys. deviceIdentityInit() ran above, so
    // g_qDevice is populated. For a reconnect the phone is already trusted and
    // the device key is pinned client-side, so the code compare is belt-and-
    // braces — the physical long-press is the point.
    sasCodeFromSk(s->sk, g_qDevice, phonePub, g_sasCode);
    memcpy(g_sasPub, phonePub, 32);
    strncpy(g_sasPairId, pairId, 16); g_sasPairId[16]=0;
    g_sasIsReconnect = (slot >= 0 && !isPending);   // trusted reconnect vs first-pair
    g_sasDeadlineMs = millis() + SAS_TTL_MS;
    g_sasState = SAS_WAITING;          // main loop renders the confirm modal
    Serial.println(g_sasIsReconnect
      ? "[PAIR] trusted reconnect — approval armed, awaiting on-device long-press"
      : "[PAIR] handshake OK for PENDING pubkey — SAS armed, awaiting on-device confirm");
  }
  memset(sk, 0, 32);

  char devEphHex[65]; toHex(devEphPub, 32, devEphHex);
  // sealed confirmation: device proves it holds sk (the es-term authenticates
  // the device; for a just-promoted pending pair this is also the phone's
  // proof that it paired with the REAL device, not a rogue AP).
  char aad[80]; size_t aadLen = snprintf(aad,sizeof(aad),"POST /api/session");
  String confirm = String("{\"ok\":true,\"pair_id\":\"")+s->pairId+"\"}";
  String sealed = sealBody(s->sk, aad, aadLen, confirm);
  httpIo.send(200,"application/json",
    String("{\"device_eph\":\"")+devEphHex+
    "\",\"pair_id\":\""+s->pairId+
    "\",\"sas\":"+ (needApprove ? "true" : "false") +
    // reconnect:true lets the PWA show "approve on your KEY" instead of the
    // first-pair 6-digit code compare screen. The two flows need distinct UI.
    (g_sasIsReconnect ? ",\"reconnect\":true" : "") +
    ",\"sealed\":"+ (sealed.length()? sealed : String("null")) +"}");
}

// ── Option B: SAS status poll ────────────────────────────────────────────────
// GET /api/pair/sas?pair_id=<16hex> → {"state":"waiting|confirmed|rejected|unknown"}
// Deliberately UNAUTHENTICATED: the caller is mid-pairing and by construction
// has no confirmed session yet. It reveals only the confirmation state of one
// specific pair_id — a 64-bit random value known only to the browser that ran
// the handshake and to this device; unguessable, non-secret, single-use.
// Expiry is NOT resolved here (Core 0) — the main-loop modal (Core 1) owns
// timeout via sasResolve(false), keeping resolution single-writer.
void handleApiPairSas() {
  apiAddCORS();
  String pid = httpIo.arg("pair_id");
  const char* st = "unknown";
  if (pid.length() == 16 && strncmp(pid.c_str(), g_sasPairId, 16) == 0) {
    if      (g_sasState == SAS_WAITING)   st = "waiting";
    else if (g_sasState == SAS_CONFIRMED) st = (int32_t)(millis()-g_sasResultExpiryMs) < 0 ? "confirmed" : "unknown";
    else if (g_sasState == SAS_REJECTED)  st = (int32_t)(millis()-g_sasResultExpiryMs) < 0 ? "rejected"  : "unknown";
  }
  httpIo.send(200,"application/json",String("{\"state\":\"")+st+"\"}");
}

// ════════════════════════════════════════════════════════════════════════
// Auth + body chokepoint for every SEALED endpoint.
//
// Call sequence inside a sealed handler:
//   apiAddCORS();
//   if(!apiCheckAuth2()){ ... 401 ... return; }   // resolves session, opens body
//   String body = apiReadBody();                  // plaintext inner JSON
//   ... existing handler logic, unchanged ...
//   apiSend(200, jsonString);                     // seals if request was sealed
// ════════════════════════════════════════════════════════════════════════

// Resolve session from X-Favilla-Session header, open+verify the body, run the
// replay check. On success g_req is populated and the opened plaintext stashed.
static String g_openedBody;   // plaintext inner JSON for this request

// 28 Sep 2026: every request that passes this chokepoint is REAL session
// traffic (sign, decrypt, unlock...), as opposed to the PWA link heartbeat,
// /api/info, or a phone's captive-portal probe. The hotspot idle-off reads
// this stamp so genuine use holds the AP up while idle polling does not.
static bool apiCheckAuth2Impl();
bool apiCheckAuth2() {
  bool ok = apiCheckAuth2Impl();
  if (ok && g_req.sess) g_req.sess->proven = true;   // 11bv (issue #47 item 5): it opened under sk
  // 9l (issue #8): this request opened under the session's sk, which proves the
  // caller holds phone_pub's private key: enrol it now, owned by its app client.
  if (ok && g_req.sess && g_req.sess->appEnrol) {
    Session* s = g_req.sess;
    int slot = phonesFind(s->enrolPub);
    if (slot < 0) slot = phonesEnrol(s->enrolPub);
    phonesSetApp(slot, s->enrolApp);
    phonesTouch(slot);
    s->phoneSlot = slot; s->appEnrol = false;
    memset(s->enrolPub, 0, 32); memset(s->enrolApp, 0, 8);
    fsecSyncPowerMode();
    Serial.printf("[PAIR] PWA enrolled over the paired Favilla app (slot %d): possession proven by its first sealed request\n", slot);
  }
  if (ok) { ::g_sessionApiMs = millis(); ::wifiApplyPs(false); }   // globals in main.cpp (this header sits inside namespace fsec)
  // 3 Nov 2026 (bench): wake the radio NOW, before the handler answers. The
  // loop only re-applied the policy after the handler returned, so with the
  // screen dark a vault list reply went out in MAX_MODEM and took 10.6 s.
  return ok;
}
static bool apiCheckAuth2Impl() {
  memset(&g_req, 0, sizeof(g_req));
  g_openedBody = "";
  if (!apiCheckOrigin()) { Serial.println("[AUTH2] REJECT: bad origin"); return false; }

  String pairId = httpIo.header("X-Favilla-Session");
  if (pairId.length() == 0) { Serial.println("[AUTH2] REJECT: no X-Favilla-Session header"); return false; }
  Session* s = sessionByPairId(pairId.c_str());
  if (!s) { Serial.printf("[AUTH2] REJECT: pairId not found (%s)\n", pairId.c_str()); return false; }
  // Option B: a session born from a first-pair handshake authorises NOTHING
  // until the user compares the confirmation code and presses Confirm on the
  // device. The sk is real; the trust is not yet.
  if (!s->confirmed) { Serial.println("[AUTH2] REJECT: session awaiting SAS confirmation"); return false; }

  if (!buildAad(g_req)) { Serial.println("[AUTH2] REJECT: path and query too long to bind"); return false; }

  // ── GET path: no body to seal. Auth = a MAC over (aad ‖ counter) carried in
  // the X-Favilla-Auth header. Counter still enforces replay. Response is
  // sealed normally on the way out (apiSend). ──────────────────────────────
  if (httpIo.method() == HTTP_GET) {
    String authHex = httpIo.header("X-Favilla-Auth");
    String ctrStr  = httpIo.header("X-Favilla-Ctr");
    if (authHex.length() != 64 || ctrStr.length() == 0) { Serial.println("[AUTH2] REJECT(GET): missing/malformed auth headers"); return false; }
    uint32_t ctr = (uint32_t)strtoul(ctrStr.c_str(), nullptr, 10);
    if (ctr <= s->lastCounter) { Serial.printf("[AUTH2] REJECT(GET): replay ctr=%lu <= last=%lu\n", (unsigned long)ctr, (unsigned long)s->lastCounter); return false; }     // REPLAY → reject
    uint8_t authRecv[32];
    if (!fromHex(authHex.c_str(), authRecv, 32)) { Serial.println("[AUTH2] REJECT(GET): auth header not valid hex"); return false; }
    // expected = HMAC(sk, aad ‖ ":" ‖ ctr)
    char macMsg[sizeof(g_req.aad) + 16];
    int mm = snprintf(macMsg, sizeof(macMsg), "%s:%lu", g_req.aad, (unsigned long)ctr);
    if (mm <= 0 || mm >= (int)sizeof(macMsg)) { Serial.println("[AUTH2] REJECT(GET): auth message too long"); return false; }
    uint8_t expect[32];
    hmac_sha256(s->sk, 32, (const uint8_t*)macMsg, mm, expect);
    uint8_t diff = 0; for (int i=0;i<32;i++) diff |= (uint8_t)(expect[i]^authRecv[i]);
    memset(expect,0,32);
    if (diff) { Serial.println("[AUTH2] REJECT(GET): MAC mismatch"); return false; }                       // bad MAC → reject
    s->lastCounter = ctr;
    s->lastSeenMs  = millis();
    g_req.sealed  = true;
    g_req.sess    = s;
    g_req.counter = ctr;
    g_openedBody  = "";   // GETs carry params in query string, not body
    Serial.printf("[AUTH2] OK(GET) ctr=%lu\n", (unsigned long)ctr);
    return true;
  }

  // ── POST path: sealed body { n, ct } ─────────────────────────────────────
  JsonDocument env;
  if (deserializeJson(env, httpIo.arg("plain"))) { Serial.println("[AUTH2] REJECT(POST): outer JSON parse failed"); return false; }
  const char* nHex  = env["n"]  | "";
  const char* ctB64 = env["ct"] | "";
  if (!*nHex || !*ctB64) { Serial.println("[AUTH2] REJECT(POST): missing n/ct fields"); return false; }

  String plain = openBody(s->sk, g_req.aad, g_req.aadLen, String(nHex), String(ctB64));
  if (plain.length() == 0) { Serial.println("[AUTH2] REJECT(POST): openBody failed (bad tag / wrong sk / malformed)"); return false; }   // bad tag / malformed → reject

  // plaintext envelope: { "c": <counter>, "d": <real json> }
  JsonDocument pj;
  if (deserializeJson(pj, plain)) { Serial.println("[AUTH2] REJECT(POST): inner JSON parse failed"); return false; }
  uint32_t ctr = pj["c"] | 0;
  if (ctr <= s->lastCounter) { Serial.printf("[AUTH2] REJECT(POST): replay ctr=%lu <= last=%lu\n", (unsigned long)ctr, (unsigned long)s->lastCounter); return false; } // REPLAY → reject
  s->lastCounter = ctr;
  s->lastSeenMs = millis();

  // extract the real inner JSON ("d") back into a string for the handler
  String inner;
  serializeJson(pj["d"], inner);

  g_req.sealed  = true;
  g_req.sess    = s;
  g_req.counter = ctr;
  g_openedBody  = inner;
  Serial.printf("[AUTH2] OK(POST) ctr=%lu\n", (unsigned long)ctr);
  return true;
}

// Body the handler reads instead of httpIo.arg("plain").
String apiReadBody() {
  return g_openedBody;
}

// True iff the CURRENT request arrived over the encrypted (sealed) channel —
// i.e. authenticated under a live session key sk. Since the legacy cleartext
// bearer path has been removed, apiCheckAuth2() now only ever succeeds on a
// sealed request, so this is effectively an invariant after a passing auth
// check. Retained as an explicit guard for handlers carrying secrets that must
// never traverse the wire in cleartext (PIN unlock above all): a sealed body is
// AEAD-encrypted to sk, which a phone only derives against the PINNED device
// pairing key, so an active LAN MITM cannot read or forge it.
bool apiReqSealed() {
  return g_req.sealed && g_req.sess != nullptr;
}

// Response sender the handler uses instead of httpIo.send(code,"application/json",json)
void apiSend(int code, const String& json) {
  if (g_req.sealed && g_req.sess) {
    String out = sealBody(g_req.sess->sk, g_req.aad, g_req.aadLen, json);
    // 3 Nov 2026 (bench): the sealed-request awake window is 6 s from the request;
    // a reply still going out after that dropped to modem sleep mid-send. Hold
    // the radio awake for the whole send.
    if (out.length()) { if (::httpIo.tun) { httpIo.send(code, "application/json", out); return; }   // 9k: over Bluetooth, no Wi-Fi to keep awake
      ::g_bigSendUntil = millis() + 30000UL; ::wifiApplyPs(false); httpIo.send(code, "application/json", out); ::g_bigSendUntil = 0; return; }
    // FAIL CLOSED (SEC_1 finding 4). sealBody only fails on OOM — which is
    // exactly the kind of degraded state an attacker might try to induce.
    // A sealed request means the caller expects (and may be owed) an
    // encrypted response; the plaintext body could carry secrets. Never
    // fall back to cleartext: return a generic 500 with no payload data.
    Serial.println("[AUTH2] apiSend: sealBody FAILED — failing closed (500, no body data)");
    httpIo.send(500, "application/json", "{\"error\":\"encryption_failed\"}");
    return;
  }
  // Unsealed path: only reachable for requests that never authenticated a
  // sealed session (e.g. 401 rejections before auth) — no secret payloads.
  httpIo.send(code, "application/json", json);
}

} // namespace fsec
