#pragma once
// ============================================================================
// session_sec.h — Favilla KEY: encrypted PWA↔device transport (V3)
//
// Replaces the legacy cleartext 64-hex bearer-token session model with an
// identity-key, Noise-IK-style handshake that derives a fresh per-connection
// session key (sk) over plain HTTP, encrypts every API body under it, and
// authenticates BOTH sides without ever putting a long-term secret on the wire.
//
// THREAT MODEL (what this defends against):
//   - Passive sniffer on the LAN: sees only ephemeral pubkeys + ciphertext.
//     sk is never transmitted (derived independently on both ends via ECDH),
//     and every body (unlock PIN, PSBT, DM cache-key, sign requests) is sealed.
//   - Forged / replayed requests: auth IS "produce a valid AEAD tag under sk",
//     which is unforgeable without the shared secret. A monotonic counter +
//     method/path AAD blocks replay and cross-endpoint reuse.
//   - MITM at first pairing: the on-TFT PIN is bound into the confirm step
//     (HMAC under the provisional sk); a key swap fails the PIN check.
//   - Rogue AP impersonating the device on reconnect: the handshake mixes the
//     device's own static identity (es term), so only the real device can
//     derive a working sk.
//
// NOT defended (out of scope, documented honestly):
//   - An attacker already executing code on the phone or device (endpoint
//     compromise) can read sk from RAM — no transport scheme survives that.
//   - PIN brute-force: bounded by the SE051 hardware retry counter, not here.
//
// CRYPTO — all primitives reused from secp256k1.h, no new dependencies:
//   - ecdh_raw()        secp256k1 ECDH (x-only pubkey in, shared X out)
//   - hkdf_extract/expand, hmac_sha256   (mbedTLS-backed)
//   - cc20_xor + hmac_sha256   NIP-44-style ChaCha20 encrypt-then-MAC AEAD
//   - se_aes_wrap_block()  one-time, to root the device identity in the SE
//
// IDENTITIES:
//   d_phone  = HKDF(seed, "phone-identity")        — derived in the PWA,
//              domain-separated from Nostr/BTC, recoverable from seed.
//   d_device = HKDF(se_aes_wrap_block(const), ...)  — SE-bound, stable across
//              reboots, available WHILE LOCKED (wrap is not PIN-gated), so the
//              handshake works before unlock (the PWA needs the channel to send
//              the unlock PIN sealed).
//
// HANDSHAKE (per reconnect, no PIN after first pairing):
//   ee = ECDH(eph_phone, eph_device)   forward secrecy
//   se = ECDH(stat_phone, eph_device)  authenticates phone
//   es = ECDH(eph_phone, stat_device)  authenticates device
//   sk = HKDF(ee ‖ se ‖ es, info="favilla-session-v3")
// ============================================================================

#include "secp256k1.h"   // ecdh_raw, hkdf_*, hmac_sha256, cc20_xor, b64_*, sc_*, pt_mul_base
#include "se_signer.h"   // favilla::se_pair_wrap_block (cold identity), se_random
#include <Preferences.h>
#include <ArduinoJson.h>

namespace fsec {

// ── Tunables ───────────────────────────────────────────────────────────────
static constexpr int   MAX_TRUSTED_PHONES = 3;     // owner phone + tablet, etc.
static constexpr int   MAX_SESSIONS        = 3;     // concurrent live sessions
static constexpr char  DEVICE_ID_SALT[]    = "favilla-device-identity-v1";
static constexpr char  SESSION_INFO[]      = "favilla-session-v3";
static constexpr uint32_t PAIR_TTL_MS      = 120000; // 2 min PIN window

// ── Device static identity (SE-rooted, available while locked) ─────────────
// d_device is derived once (cached for the boot session) from the SE wrap key.
// We feed a FIXED constant through se_aes_wrap_block (AES-CBC under the SE's
// non-readable wrap key) → HKDF → scalar mod n. Same wrap key every boot ⇒
// same identity; unique per device; never leaves the chip.
static uint8_t  g_dDevice[32]   = {0};   // device static privkey (scalar)
static uint8_t  g_qDevice[32]   = {0};   // device static pubkey (x-only)
static bool     g_devIdReady    = false;

static bool deviceIdentityInit() {
  if (g_devIdReady) return true;
  // Fixed, public derivation constant + IV — secrecy comes from the SE pair-wrap
  // key, not from these. Domain string makes the wrap output purpose-specific.
  //
  // Path-A: derive from SE_OBJ_PAIR_WRAP (NO-AUTH policy) rather than the
  // PIN-bound SE_OBJ_AES_WRAP. This is what lets the device identity be
  // reconstructed on a COLD boot (locked), which is the precondition for
  // remote-unlock-while-locked: the /api/session handshake (ikDeriveSk) and
  // therefore apiCheckAuth2 now resolve without a PIN session.
  //
  // The "-v2" domain suffix below intentionally produces a DIFFERENT identity
  // scalar than the old wrap-key-derived "-v1" value. Moving the identity to a
  // dedicated key necessarily changes dev_pair_pub ONCE; every previously paired
  // phone must re-pair one time. After that the identity is stable forever
  // (the pair-wrap key is written once and never rotated by re-pairing).
  static const uint8_t kConstPt[32] = {
    'F','A','V','I','L','L','A','-','d','e','v','-','i','d','-','v','2',
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };
  static const uint8_t kConstIv[16] = {
    0xFA,0x71,0x11,0xA0,0xDE,0x71,0xCE,0x10,0x55,0x16,0x33,0x44,0x77,0x88,0x99,0xAB
  };
  uint8_t wrapped[32];
  // se_pair_wrap_block works WHILE LOCKED (no PIN session). If the pair-wrap key
  // is not yet provisioned (a pre-Path-A device that has not had its lazy
  // migration run), this returns false and the device falls back to requiring
  // an on-device unlock first — see the migration hook in the unlock path.
  if (!favilla::se_pair_wrap_block(kConstPt, kConstIv, wrapped)) return false;

  uint8_t prk[32];
  hkdf_extract((const uint8_t*)DEVICE_ID_SALT, sizeof(DEVICE_ID_SALT)-1,
               wrapped, 32, prk);
  uint8_t raw[32];
  hkdf_expand(prk, 32, (const uint8_t*)"device-pair", 11, raw, 32);
  memset(wrapped, 0, 32); memset(prk, 0, 32);

  // reduce mod n → valid scalar, then derive x-only pubkey
  sc d; sc_from_b32(&d, raw); sc_reduce_once(&d);
  if (sc_is_zero(&d)) { memset(raw,0,32); return false; }
  sc_to_b32(g_dDevice, &d);
  if (!bip340_make_key(g_dDevice, g_qDevice)) { memset(raw,0,32); return false; }
  memset(raw, 0, 32);
  g_devIdReady = true;
  return true;
}

// ── Trusted-phone store (public keys only — safe at rest) ──────────────────
// Stored in NVS namespace "fsec" as keys phone0..phone2 (64-hex x-only pubkeys).
struct TrustedPhones {
  uint8_t  pub[MAX_TRUSTED_PHONES][32];
  bool     used[MAX_TRUSTED_PHONES] = {false,false,false};
  // Last time (unix epoch) a session for this phone was CONFIRMED. 0 = unknown
  // (enrolled before this field existed, or while the clock was unsynced) —
  // such slots never auto-expire. Persisted in NVS as seen0..seen2.
  uint32_t seen[MAX_TRUSTED_PHONES] = {0,0,0};
  // 9l (issue #8): the Favilla app client (app channel id, 8 bytes) that enrolled
  // this phone over Bluetooth; all zero for one paired by the FK1 scan. Forgetting
  // that app client forgets the phones it enrolled. NVS aown0..aown2.
  uint8_t  app[MAX_TRUSTED_PHONES][8] = {};
};
static TrustedPhones g_phones;

// ── Idle-pairing expiry ─────────────────────────────────────────────────────
// A trusted phone that hasn't completed a confirmed session in this long is
// dropped from the allowlist, so a stolen kv_phone_id (from an old backup, a
// stale browser, leaked localStorage) stops working after the window even if
// it was never explicitly revoked. Owner just re-pairs. Tune to taste; shorter
// is safer but re-pairs more often.
static constexpr uint32_t PAIRING_IDLE_TTL_S = 30UL * 24 * 3600;  // 30 days

// True once the RTC holds a real wall clock (NTP synced). Mirrors main.cpp's
// timeIsSynced() but inlined so this header stays free of declaration-order
// dependencies. 1704067200 = 2024-01-01T00:00:00Z.
static inline bool fsecClockReady() {
  time_t now; time(&now);
  return (long)now > 1704067200L;
}
static inline uint32_t fsecNowEpoch() {
  time_t now; time(&now);
  return (uint32_t)now;
}

// When ON, a trusted-phone reconnect is treated like a first pairing: the
// session is created UNCONFIRMED and needs an on-device long-press approval
// before it authorises anything, and that approval evicts every other live
// session (single-session invariant). When OFF (default), behaviour is exactly
// as before — trusted reconnect goes live immediately. Kept OFF until the
// client half (background "approve on your Key" prompt) ships, so flashing the
// device code alone changes nothing. Persisted in NVS "fsec"/"rcConfirm".
static bool g_rcConfirm       = false;
static bool g_rcConfirmLoaded = false;
static bool requireReconnectConfirm() {
  if (!g_rcConfirmLoaded) {
    Preferences p;
    if (p.begin("fsec", true)) { g_rcConfirm = p.getBool("rcConfirm", false); p.end(); }
    g_rcConfirmLoaded = true;
  }
  return g_rcConfirm;
}
[[maybe_unused]] static void setRequireReconnectConfirm(bool on) {
  g_rcConfirm = on; g_rcConfirmLoaded = true;
  Preferences p;
  if (p.begin("fsec", false)) { p.putBool("rcConfirm", on); p.end(); }
}

static void phonesLoad() {
  Preferences p; p.begin("fsec", true);
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) {
    char key[8]; snprintf(key, sizeof(key), "phone%d", i);
    String h = p.getString(key, "");
    if (h.length() == 64 && fromHex(h.c_str(), g_phones.pub[i], 32)) {
      g_phones.used[i] = true;
      char sk[8]; snprintf(sk, sizeof(sk), "seen%d", i);
      g_phones.seen[i] = p.getUInt(sk, 0);   // 0 = unknown → never auto-expire
      char ak[8]; snprintf(ak, sizeof(ak), "aown%d", i);
      memset(g_phones.app[i], 0, 8);
      if (p.getBytesLength(ak) == 8) p.getBytes(ak, g_phones.app[i], 8);
    } else {
      g_phones.used[i] = false;
      g_phones.seen[i] = 0;
      memset(g_phones.app[i], 0, 8);
    }
  }
  p.end();
}
static bool phonesAny() {
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) if (g_phones.used[i]) return true;
  return false;
}
// Number of enrolled trusted phones (0 = fresh device → first-pair "open").
int phonesCount() {
  int n = 0;
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) if (g_phones.used[i]) n++;
  return n;
}
static int phonesFind(const uint8_t pub[32]) {
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++)
    if (g_phones.used[i] && memcmp(g_phones.pub[i], pub, 32) == 0) return i;
  return -1;
}
// Enrol a phone pubkey. If already present, no-op. If full, evicts slot 0
// (oldest) — simple ring; UI can expose explicit removal later.
static int phonesEnrol(const uint8_t pub[32]) {
  int existing = phonesFind(pub);
  if (existing >= 0) return existing;
  int slot = -1;
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) if (!g_phones.used[i]) { slot = i; break; }
  if (slot < 0) slot = 0; // evict oldest
  memcpy(g_phones.pub[slot], pub, 32);
  g_phones.used[slot] = true;
  g_phones.seen[slot] = fsecClockReady() ? fsecNowEpoch() : 0;
  memset(g_phones.app[slot], 0, 8);   // 9l: an evicted slot's owner goes with it
  Preferences p; p.begin("fsec", false);
  char key[8]; snprintf(key, sizeof(key), "phone%d", slot);
  char h[65]; toHex(pub, 32, h);
  p.putString(key, h);
  char sk[8]; snprintf(sk, sizeof(sk), "seen%d", slot);
  p.putUInt(sk, g_phones.seen[slot]);
  char ak[8]; snprintf(ak, sizeof(ak), "aown%d", slot); p.remove(ak);
  p.end();
  return slot;
}
// 9l (issue #8): note which app client enrolled a slot (over Bluetooth).
static void phonesSetApp(int slot, const uint8_t app[8]) {
  if (slot < 0 || slot >= MAX_TRUSTED_PHONES || !g_phones.used[slot]) return;
  memcpy(g_phones.app[slot], app, 8);
  Preferences p; p.begin("fsec", false);
  char ak[8]; snprintf(ak, sizeof(ak), "aown%d", slot); p.putBytes(ak, app, 8);
  p.end();
}
static bool appIdZero(const uint8_t a[8]) { uint8_t o = 0; for (int i = 0; i < 8; i++) o |= a[i]; return o == 0; }
// Forget the phones a given app client enrolled (app == nullptr: every phone any
// app client enrolled). Live sessions of those phones end too. Returns how many.
static void sessionsDropSlot(int slot);
static int phonesForgetApp(const uint8_t* app) {
  int n = 0; Preferences p; bool opened = false;
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) {
    if (!g_phones.used[i] || appIdZero(g_phones.app[i])) continue;
    if (app && memcmp(g_phones.app[i], app, 8) != 0) continue;
    if (!opened) { p.begin("fsec", false); opened = true; }
    char key[8]; snprintf(key, sizeof(key), "phone%d", i); p.remove(key);
    char sk[8];  snprintf(sk,  sizeof(sk),  "seen%d",  i); p.remove(sk);
    char ak[8];  snprintf(ak,  sizeof(ak),  "aown%d",  i); p.remove(ak);
    g_phones.used[i] = false; memset(g_phones.pub[i], 0, 32); g_phones.seen[i] = 0; memset(g_phones.app[i], 0, 8);
    sessionsDropSlot(i);
    n++;
  }
  if (opened) p.end();
  if (n) Serial.printf("[PAIR] forgot %d PWA pairing(s) the Favilla app had enrolled\n", n);
  return n;
}

// Refresh a slot's last-seen to now (call on every CONFIRMED session). Persists
// only when the clock is real and the stamp moved by more than an hour, to keep
// NVS wear low — the exact minute doesn't matter for a multi-day TTL.
static void phonesTouch(int slot) {
  if (slot < 0 || slot >= MAX_TRUSTED_PHONES || !g_phones.used[slot]) return;
  if (!fsecClockReady()) return;
  uint32_t now = fsecNowEpoch();
  if (g_phones.seen[slot] != 0 && now > g_phones.seen[slot] &&
      (now - g_phones.seen[slot]) < 3600) { g_phones.seen[slot] = now; return; }  // RAM-only bump
  g_phones.seen[slot] = now;
  Preferences p; p.begin("fsec", false);
  char sk[8]; snprintf(sk, sizeof(sk), "seen%d", slot);
  p.putUInt(sk, now);
  p.end();
}

// Drop any trusted phone idle longer than PAIRING_IDLE_TTL_S. Fail-safe: does
// nothing unless the clock is synced, and never touches a slot whose last-seen
// is unknown (0). Returns the number of slots dropped. Call before consulting
// the allowlist so an expired phone reads as "not paired" → must re-pair.
static int phonesExpireStale() {
  if (!fsecClockReady()) return 0;
  uint32_t now = fsecNowEpoch();
  int dropped = 0;
  Preferences p; bool opened = false;
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) {
    if (!g_phones.used[i] || g_phones.seen[i] == 0) continue;
    if (now <= g_phones.seen[i]) continue;                 // clock skew — leave it
    if ((now - g_phones.seen[i]) < PAIRING_IDLE_TTL_S) continue;
    if (!opened) { p.begin("fsec", false); opened = true; }
    char key[8]; snprintf(key, sizeof(key), "phone%d", i); p.remove(key);
    char sk[8];  snprintf(sk,  sizeof(sk),  "seen%d",  i); p.remove(sk);
    char ak[8];  snprintf(ak,  sizeof(ak),  "aown%d",  i); p.remove(ak);   // 9l
    g_phones.used[i] = false;
    memset(g_phones.pub[i], 0, 32);
    g_phones.seen[i] = 0;
    memset(g_phones.app[i], 0, 8);
    dropped++;
  }
  if (opened) p.end();
  if (dropped) Serial.printf("[PAIR] dropped %d idle pairing(s) > %lu days\n",
                             dropped, (unsigned long)(PAIRING_IDLE_TTL_S/86400));
  return dropped;
}
// ── Pending pairing (Option A: proof-of-possession gates enrolment) ─────────
//
// The FK1 scan flow used to call phonesEnrol() the instant the user pressed
// Confirm — i.e. it trusted a pubkey the device merely SCANNED, with no proof
// the browser actually holds the matching private key. A substituted QR that
// the user confirmed blindly was therefore fully enrolled.
//
// Option A splits enrolment in two:
//   1. Confirm on the device → pendingPairArm(scanned_pub): the pubkey is held
//      as PENDING (RAM only, short TTL), NOT trusted.
//   2. The browser's first /api/session runs the sealed IK handshake, whose
//      `se = ECDH(dev_eph, phone_static)` term SUCCEEDS ONLY IF the caller
//      holds phone_static's private key. On a successful handshake against the
//      pending pubkey we promote it PENDING → TRUSTED (phonesEnrol) and only
//      THEN report "paired" to the user.
//
// Net effect: the pubkey that becomes trusted is provably possession-checked,
// and the user's on-screen "Paired ✓" is shown after the crypto proof, not
// after a raw scan. A holder who cannot complete the handshake never gets
// promoted; the pending entry expires.
//
// RAM-only + single-slot by design: pairing is a deliberate, one-at-a-time
// physical action. Nothing about a pending entry is secret (it's a public
// pubkey), but keeping it out of NVS means an interrupted pair leaves no
// residue to clean up.
static uint8_t  g_pendPub[32]   = {0};
static bool     g_pendActive    = false;
static uint32_t g_pendExpiryMs  = 0;
static constexpr uint32_t PENDING_PAIR_TTL_MS = 120000;  // 2 min to complete the first connect

// Arm a pending enrolment for `pub`. Overwrites any prior pending entry (only
// one pair-in-flight at a time). Call this from ST_PAIR_CONFIRM on user Confirm
// INSTEAD OF phonesEnrol().
static void pendingPairArm(const uint8_t pub[32]) {
  memcpy(g_pendPub, pub, 32);
  g_pendActive   = true;
  g_pendExpiryMs = millis() + PENDING_PAIR_TTL_MS;
}

// Clear the pending entry (on success-promotion, expiry, cancel, or unpair).
static void pendingPairClear() {
  memset(g_pendPub, 0, 32);
  g_pendActive   = false;
  g_pendExpiryMs = 0;
}

// True iff `pub` is the live pending entry (and not expired). Expiry is checked
// lazily here so no timer task is needed.
static bool pendingPairMatches(const uint8_t pub[32]) {
  if (!g_pendActive) return false;
  if ((int32_t)(millis() - g_pendExpiryMs) >= 0) {  // expired
    pendingPairClear();
    return false;
  }
  return memcmp(g_pendPub, pub, 32) == 0;
}

// Is a pending pair currently armed (for UI: show "waiting for app to connect")?
// Optional hook — not required by the promotion flow; provided for a status
// indicator. maybe_unused so it doesn't warn if the UI doesn't call it.
[[maybe_unused]] static bool pendingPairArmed() {
  if (!g_pendActive) return false;
  if ((int32_t)(millis() - g_pendExpiryMs) >= 0) { pendingPairClear(); return false; }
  return true;
}


static void phonesClearAll() {
  Preferences p; p.begin("fsec", false);
  for (int i = 0; i < MAX_TRUSTED_PHONES; i++) {
    char key[8]; snprintf(key, sizeof(key), "phone%d", i);
    p.remove(key);
    char sk[8]; snprintf(sk, sizeof(sk), "seen%d", i);
    p.remove(sk);
    char ak[8]; snprintf(ak, sizeof(ak), "aown%d", i); p.remove(ak);   // 9l
    g_phones.used[i] = false;
    memset(g_phones.pub[i], 0, 32);
    g_phones.seen[i] = 0;
    memset(g_phones.app[i], 0, 8);
  }
  p.end();
  // Any half-finished pairing is also void once we forget everything.
  pendingPairClear();
}

// ── Live sessions (sk in RAM only — never persisted) ───────────────────────
struct Session {
  bool     active = false;
  // Option B (SAS): a session born from a PENDING (first-pair) handshake is
  // UNCONFIRMED until the user compares the 6-digit confirmation code on the
  // device against the one in the app and presses Confirm. apiCheckAuth2()
  // rejects unconfirmed sessions, so the sk exists but authorises nothing.
  // volatile: written by sasResolve() on loopTask (Core 1), read by
  // apiCheckAuth2() on the web-server task (Core 0).
  volatile bool confirmed = false;
  char     pairId[17] = {0};   // 8-byte hex id, non-secret, identifies the session
  uint8_t  sk[32] = {0};       // derived session key (RAM only)
  int      phoneSlot = -1;     // which trusted phone owns this session
  uint32_t lastCounter = 0;    // highest counter seen (replay defence)
  uint32_t lastSeenMs = 0;
  // 11bv (issue #47 item 5): a request has opened under sk, so the caller holds
  // the phone's key. A handshake alone proves nothing (phone_pub travels in
  // clear), so an unproven session never pushes a proven one out.
  bool     proven = false;
  // 9l (issue #8): born from a tunnelled /api/session of a paired app client for
  // an unknown phone_pub. The phone is enrolled on this session's FIRST request
  // that opens under sk (which only the holder of phone_pub's key can make).
  bool     appEnrol = false;
  uint8_t  enrolPub[32] = {0};
  uint8_t  enrolApp[8] = {0};
};
static Session g_sessions[MAX_SESSIONS];

// ── WiFi power mode: stay awake while a session is active ───────────────────────
// In STA/network mode the radio sleeps between DTIM beacons when WIFI_PS_MIN_MODEM
// is set. Every new TCP connection must wait up to one beacon interval (~100ms)
// before it's serviced. The PWA makes 5-10 API calls per user action — that
// latency compounds into a noticeably sluggish feel.
// Fix: WIFI_PS_NONE (radio always awake) while any confirmed session exists,
// MIN_MODEM when fully idle. The user is physically present when a session is
// live; power saving can wait. Reverts to MIN_MODEM automatically when the
// session expires or is evicted.
// NOTE: esp_wifi.h is in scope (included by main.cpp before these headers).
static bool fsecHasConfirmedSession() {
  for (int i = 0; i < MAX_SESSIONS; i++)
    if (g_sessions[i].active && g_sessions[i].confirmed) return true;
  return false;
}
static void fsecSyncPowerMode() {
  // WAKE ONLY. main.cpp's wifiApplyPs() is the single owner of the sleep
  // decision — it also keeps the radio awake for a window after ANY HTTP
  // request, which this function cannot see. If this dropped the radio back to
  // MIN_MODEM on session clear it would fight that policy, so it never sleeps.
  // 28 Sep 2026: NO-OP. Even the wake was fighting wifiApplyPs(): it only
  // re-calls esp_wifi_set_ps when its own view changes, so a PS_NONE set here
  // was never undone and the battery paid for it all day. Every session event
  // arrives as an HTTP request, and httpReqMark() already buys the awake
  // window for it. Kept as a hook so the call sites need not change.
}

static Session* sessionByPairId(const char* pairId) {
  if (!pairId || !*pairId) return nullptr;
  for (int i = 0; i < MAX_SESSIONS; i++)
    if (g_sessions[i].active && strncmp(g_sessions[i].pairId, pairId, 16) == 0)
      return &g_sessions[i];
  return nullptr;
}
// 9l: end every live session of a trusted slot (its phone was just forgotten).
static void sessionsDropSlot(int slot) {
  for (int i = 0; i < MAX_SESSIONS; i++)
    if (g_sessions[i].active && g_sessions[i].phoneSlot == slot) memset(&g_sessions[i], 0, sizeof(Session));
}
static Session* sessionAllocSlot() {
  for (int i = 0; i < MAX_SESSIONS; i++) if (!g_sessions[i].active) return &g_sessions[i];
  // all full — evict the least-recently-seen session that has not yet proven
  // its key (11bv, issue #47 item 5: a LAN host replaying a trusted phone_pub
  // could otherwise keep the real phone's session evicted). Only when every
  // slot is proven does the oldest proven one go.
  int oldest = -1; uint32_t best = 0xFFFFFFFF;
  for (int i = 0; i < MAX_SESSIONS; i++)
    if (!g_sessions[i].proven && g_sessions[i].lastSeenMs <= best) { best = g_sessions[i].lastSeenMs; oldest = i; }
  if (oldest < 0) {
    best = 0xFFFFFFFF; oldest = 0;
    for (int i = 0; i < MAX_SESSIONS; i++)
      if (g_sessions[i].lastSeenMs < best) { best = g_sessions[i].lastSeenMs; oldest = i; }
  }
  memset(&g_sessions[oldest], 0, sizeof(Session));
  return &g_sessions[oldest];
}
static void sessionsWipeAll() {
  for (int i = 0; i < MAX_SESSIONS; i++) { memset(&g_sessions[i], 0, sizeof(Session)); }
}

// ── HKDF the three-term IK shared secret into sk ───────────────────────────
// ee ‖ se ‖ es  →  HKDF  →  sk(32)
static bool deriveSk(const uint8_t ee[32], const uint8_t se[32], const uint8_t es[32],
                     const char* pairId, uint8_t sk_out[32]) {
  uint8_t ikm[96];
  memcpy(ikm,      ee, 32);
  memcpy(ikm + 32, se, 32);
  memcpy(ikm + 64, es, 32);
  uint8_t prk[32];
  // salt = pair_id (binds sk to this specific handshake instance)
  hkdf_extract((const uint8_t*)pairId, strlen(pairId), ikm, 96, prk);
  hkdf_expand(prk, 32, (const uint8_t*)SESSION_INFO, sizeof(SESSION_INFO)-1, sk_out, 32);
  memset(ikm, 0, 96); memset(prk, 0, 32);
  return true;
}

// ── AEAD: seal/open under sk (NIP-44-style ChaCha20 + HMAC-SHA256) ──────────
// Wire format (JSON): { "n": <24B nonce hex>, "ct": base64( ciphertext ‖ mac32 ) }
//   per-message keys = HKDF-expand(sk, info = aad ‖ nonce, 76B)
//                      → ckey(32) ‖ cnonce(12) ‖ hkey(32)
//   ct  = ChaCha20(ckey, cnonce, plaintext)
//   mac = HMAC-SHA256(hkey, aad ‖ nonce ‖ ct)
// AAD = "METHOD PATH" — binds the sealed body to its endpoint (anti cross-replay).
// The plaintext carries {"c":<counter>,"d":<real json>}; the caller checks c.
static const int AEAD_NONCE = 24;

static String sealBody(const uint8_t sk[32], const char* aad, size_t aadLen,
                       const String& plaintextJson) {
  uint8_t nonce[AEAD_NONCE];
  // F6: FAIL CLOSED. The nonce is mixed into the HKDF info string, so a
  // REPEATED nonce means a repeated per-message key AND a repeated ChaCha20
  // nonce — full keystream reuse, which recovers the XOR of two plaintexts.
  // Uniqueness here is load bearing, so an empty return is correct: apiSend
  // already fails closed on a sealing failure (SEC_1 finding 4) and sends
  // 500 encryption_failed with no payload rather than falling back to clear.
  if (!favilla::se_random(nonce, AEAD_NONCE)) {
    Serial.println("[AUTH2] se_random failed for AEAD nonce — refusing to seal");
    return "";
  }
  // derive per-message keys: info = aad ‖ nonce
  size_t infoLen = aadLen + AEAD_NONCE;
  uint8_t* info = (uint8_t*)malloc(infoLen);
  if (!info) return "";
  memcpy(info, aad, aadLen); memcpy(info + aadLen, nonce, AEAD_NONCE);
  uint8_t keys[76];
  hkdf_expand(sk, 32, info, infoLen, keys, 76);
  free(info);
  uint8_t* ckey = keys; uint8_t* cnonce = keys + 32; uint8_t* hkey = keys + 44;

  size_t pl = plaintextJson.length();
  uint8_t* ct = (uint8_t*)malloc(pl + 32);
  if (!ct) { memset(keys,0,76); return ""; }
  cc20_xor(ckey, cnonce, 0, (const uint8_t*)plaintextJson.c_str(), ct, pl);

  // mac over aad ‖ nonce ‖ ct
  size_t miLen = aadLen + AEAD_NONCE + pl;
  uint8_t* mi = (uint8_t*)malloc(miLen);
  if (!mi) { free(ct); memset(keys,0,76); return ""; }
  memcpy(mi, aad, aadLen);
  memcpy(mi + aadLen, nonce, AEAD_NONCE);
  memcpy(mi + aadLen + AEAD_NONCE, ct, pl);
  hmac_sha256(hkey, 32, mi, miLen, ct + pl); // append mac directly after ct
  free(mi);
  memset(keys, 0, 76);

  char nhex[AEAD_NONCE*2 + 1]; toHex(nonce, AEAD_NONCE, nhex);
  String b64 = b64_enc(ct, pl + 32);
  free(ct);
  return String("{\"n\":\"") + nhex + "\",\"ct\":\"" + b64 + "\"}";
}

// Returns "" on any failure (bad tag, malformed, OOM). On success returns the
// decrypted inner plaintext JSON.
static String openBody(const uint8_t sk[32], const char* aad, size_t aadLen,
                       const String& nHex, const String& ctB64) {
  if (nHex.length() != AEAD_NONCE*2) return "";
  uint8_t nonce[AEAD_NONCE];
  if (!fromHex(nHex.c_str(), nonce, AEAD_NONCE)) return "";

  size_t cap = ((ctB64.length() / 4) + 1) * 3;
  uint8_t* buf = (uint8_t*)malloc(cap);
  if (!buf) return "";
  size_t blobLen = b64_dec(ctB64, buf, cap);
  if (blobLen < 32) { free(buf); return ""; }   // must hold at least the mac
  size_t ctLen = blobLen - 32;
  uint8_t* ct = buf; uint8_t* macRecv = buf + ctLen;

  size_t infoLen = aadLen + AEAD_NONCE;
  uint8_t* info = (uint8_t*)malloc(infoLen);
  if (!info) { free(buf); return ""; }
  memcpy(info, aad, aadLen); memcpy(info + aadLen, nonce, AEAD_NONCE);
  uint8_t keys[76];
  hkdf_expand(sk, 32, info, infoLen, keys, 76);
  free(info);
  uint8_t* ckey = keys; uint8_t* cnonce = keys + 32; uint8_t* hkey = keys + 44;

  // verify mac (constant-time compare via mbedTLS-style accumulate)
  size_t miLen = aadLen + AEAD_NONCE + ctLen;
  uint8_t* mi = (uint8_t*)malloc(miLen);
  if (!mi) { free(buf); memset(keys,0,76); return ""; }
  memcpy(mi, aad, aadLen);
  memcpy(mi + aadLen, nonce, AEAD_NONCE);
  memcpy(mi + aadLen + AEAD_NONCE, ct, ctLen);
  uint8_t macCalc[32];
  hmac_sha256(hkey, 32, mi, miLen, macCalc);
  free(mi);
  uint8_t diff = 0;
  for (int i = 0; i < 32; i++) diff |= (uint8_t)(macCalc[i] ^ macRecv[i]);
  memset(macCalc, 0, 32);
  if (diff) { free(buf); memset(keys,0,76); return ""; }  // BAD TAG → reject

  uint8_t* plain = (uint8_t*)malloc(ctLen + 1);
  if (!plain) { free(buf); memset(keys,0,76); return ""; }
  cc20_xor(ckey, cnonce, 0, ct, plain, ctLen);
  plain[ctLen] = 0;
  free(buf); memset(keys, 0, 76);
  String res = (char*)plain;
  memset(plain, 0, ctLen); free(plain);
  return res;
}

} // namespace fsec
