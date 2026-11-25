// ============================================================================
// bitcoin_menu.ino — Favilla KEY Bitcoin app
// ============================================================================
//
// Menu > Bitcoin contains:
//   - Receive       : trusted-display receive address QR + tap-to-advance
//   - Wallet Info   : zpub QR for watch-only import (Sparrow, Nunchuk, ...)
//   - Back
//
// The PWA (and any other watch-only peer) handles UTXO scanning, fee
// estimation, coin selection, and broadcast. The device's job is to
//   (a) display trusted receive addresses
//   (b) sign PSBTs after on-screen confirmation
// This file covers (a). PSBT signing is the next build stage.
//
// SEED SOURCE (v3, 16 Sep 2026)
// ---------------------------
// There is NO seed on this processor. The wrapped seed blob lives in NVS;
// the SE051 strips its outer layer inside the G0's own session, the G0
// strips the inner layer, derives, signs and wipes (G0_CMD_BTCSIGN,
// psbtG0SignInput). The ESP32 only ever handles PUBLIC material: the
// persisted account xpub + fingerprint (btc_load_account_xpub) for receive
// addresses, change verification and PSBT input matching, and it
// cross-checks every G0 signature's pubkey + sighash against its own.
// wallet.seed is never populated (seed_unwrap_to_ram is disabled); the
// memset()s of it on the lock/sleep paths are belt-and-braces, not a wipe
// of anything that was there.

#include "bip84.h"
#include "bip143.h"
#include "secp256k1_ecdsa.h"
#include "psbt.h"
#include "psbt_sign.h"
#include "multisig.h"          // BIP-48 P2WSH sortedmulti cosigner core (Drop 1)
#include "btc_state.h"         // sealed Bitcoin state: AES-256-GCM under a seed-derived key (Drop 3)
#include "psbt_passthrough.h"  // cosigner return leg: add partial sigs, keep everything else
#include "bech32.h"
#include "mbedtls/platform_util.h"   // mbedtls_platform_zeroize (secret wiping)
#include <Preferences.h>
// #include <WiFiClientSecure.h>   // removed with the /api/btc proxy (11 Sep 2026)
#include "btc_roots.h"   // P0: root CA bundle for esplora TLS validation
// #include <HTTPClient.h>         // removed with the /api/btc proxy (11 Sep 2026)

// ── Bitcoin accent: Entropy Ember brass (same as the rest of the device) ──
#define C_BTC_ACCENT C_EB_BRASS

// ── Forward declarations ───────────────────────────────────────────────
// handleApiBtcProxy() (below) needs to reference these, but the rest of the
// PSBT signing state they belong with lives later in this file. C++ doesn't
// hoist like JS — these have to exist before first use, or the compile
// fails with "not declared in this scope" at the handleApiBtcProxy call
// site. g_psbt_relock_pending is a real variable, defined here (its one and
// only definition — a static variable can't be forward-declared separately
// from its definition the way a function can). psbtRelockAfterSpend() is a
// genuine forward declaration; its full definition/body is later in the
// file, alongside the rest of the PSBT state it operates on.
//
// Set instead of calling psbtRelockAfterSpend() immediately whenever a spend
// was attempted (any outcome). The reboot is deferred until the PWA has
// actually fetched the result via /api/btc/sign_psbt/result — rebooting
// right away (the old behavior) tore down the HTTP session before the PWA's
// next poll could land, which is what surfaced as "device session expired"
// on a transaction that had, in fact, already completed on-device.
static volatile bool g_psbt_relock_pending = false;
static void psbtRelockAfterSpend();

// ── Sub-menu structure ───────────────────────────────────────────────────

// ── Address book ─────────────────────────────────────────────────────────
// On-device, trusted list of known recipient addresses. Matching at signing
// time lets the confirm screen show "known contact" vs "new address", which
// catches recipient-substitution by a compromised companion app. The match
// key is the canonical address STRING (derived from the PSBT output's
// scriptPubKey via psbtSpkToAddr) — deterministic and exact, so no bech32
// decoder is needed. Stored in NVS namespace "addrbook" as a JSON array.
// CRITICAL: entries are added only through the device's trusted screen; the
// device never accepts a label/address asserted by the PWA.
#define ADDRBOOK_MAX        32
#define ADDRBOOK_LABEL_MAX  24      // chars incl. NUL -> 23 visible
#define ADDRBOOK_ADDR_MAX   100     // bech32 (P2TR/P2WSH ~62; headroom)

struct AddrBookEntry {
  char label[ADDRBOOK_LABEL_MAX];
  char addr[ADDRBOOK_ADDR_MAX];     // canonical address string (match key)
  uint32_t n_sent;                  // times sent (informational)
};
static PS_ARRAY(AddrBookEntry, g_addrbook, ADDRBOOK_MAX);   // 3 Nov 2026: PSRAM (see PS_ARRAY)
static int           g_addrbook_count = 0;

// ── Sealed Bitcoin state (Drop 3, 14 Sep 2026) ────────────────────────────
// Josh's ruling: everything Bitcoin that could be extracted or poisoned exists
// ONLY in RAM, ONLY inside a BTC life (true power cycle -> BITCOIN door ->
// spend PIN). At rest it is one AES-256-GCM blob in nvs_sec under a key
// derived from the seed at door entry (btc_state.h). The address book, the
// receive bookmark and the registered multisig wallets are all inside it.
// g_addrbook / g_btc_recv_index / g_ms stay the working copies the existing
// screens use; the load/save wrappers below marshal to and from g_bst.
static bst_state_t *g_bst           = nullptr;   // PSRAM, plaintext for this BTC life only
static uint8_t      g_bst_key[32];               // K = HMAC-SHA256(seed, label); zeroised on leave
static bool         g_bst_key_valid = false;
static bool         g_bst_loaded    = false;
static bool btcStateEnsure();   // load the sealed Bitcoin state once per BTC life (absent = empty, 11as)
static bool btcStateSave();     // re-seal with a fresh nonce and write
static void btcStateWipe();     // zeroise key + plaintext
static void cmRecord(const psbt_t* ps);   // 23 Nov 2026 (#57): coin memory, defined before beginPsbtConfirm
static void cmSleepWipe();


// Working copy <-> sealed state
static void addrbookFromState(){
  g_addrbook_count = 0;
  if (!g_bst) return;
  for (uint32_t i = 0; i < g_bst->addr_count && i < ADDRBOOK_MAX; i++) {
    AddrBookEntry* be = &g_addrbook[g_addrbook_count++];
    strncpy(be->label, g_bst->addrs[i].label, ADDRBOOK_LABEL_MAX-1); be->label[ADDRBOOK_LABEL_MAX-1]=0;
    strncpy(be->addr,  g_bst->addrs[i].addr,  ADDRBOOK_ADDR_MAX-1);  be->addr[ADDRBOOK_ADDR_MAX-1]=0;
    be->n_sent = g_bst->addrs[i].n_sent;
  }
}
static void addrbookToState(){
  if (!g_bst) return;
  memset(g_bst->addrs, 0, sizeof(g_bst->addrs));
  g_bst->addr_count = 0;
  for (int i = 0; i < g_addrbook_count && i < BST_ADDR_MAX; i++) {
    strncpy(g_bst->addrs[i].label, g_addrbook[i].label, BST_LABEL_MAX-1);
    strncpy(g_bst->addrs[i].addr,  g_addrbook[i].addr,  BST_ADDRSTR_MAX-1);
    g_bst->addrs[i].n_sent = g_addrbook[i].n_sent;
    g_bst->addr_count++;
  }
}
static void addrbookLoad(){ btcStateEnsure(); addrbookFromState(); }
static void addrbookSave(){ addrbookToState(); btcStateSave(); }

// Returns index of a matching entry by canonical address string, or -1.
static int addrbookFind(const char* addr){
  for(int i=0; i<g_addrbook_count; i++){
    if(strcmp(g_addrbook[i].addr, addr) == 0) return i;
  }
  return -1;
}

// Add (or no-op if already present). Returns the entry index, or -1 if full.
// Label may be NULL/empty -> a truncated-address placeholder is stored.
static int addrbookAdd(const char* addr, const char* label){
  int existing = addrbookFind(addr);
  if(existing >= 0) return existing;
  if(g_addrbook_count >= ADDRBOOK_MAX) return -1;
  AddrBookEntry* be = &g_addrbook[g_addrbook_count];
  strncpy(be->addr, addr, ADDRBOOK_ADDR_MAX-1); be->addr[ADDRBOOK_ADDR_MAX-1]=0;
  if(label && label[0]){
    strncpy(be->label, label, ADDRBOOK_LABEL_MAX-1); be->label[ADDRBOOK_LABEL_MAX-1]=0;
  } else {
    int n = strlen(addr);
    if(n > 12) snprintf(be->label, ADDRBOOK_LABEL_MAX, "%.6s...%.4s", addr, addr+n-4);
    else { strncpy(be->label, addr, ADDRBOOK_LABEL_MAX-1); be->label[ADDRBOOK_LABEL_MAX-1]=0; }
  }
  be->n_sent = 0;
  g_addrbook_count++;
  addrbookSave();
  return g_addrbook_count - 1;
}

static void addrbookDelete(int i){
  if(i < 0 || i >= g_addrbook_count) return;
  for(int j=i; j<g_addrbook_count-1; j++) g_addrbook[j] = g_addrbook[j+1];
  g_addrbook_count--;
  addrbookSave();
}

// Lazy one-time load — callable from any entry path (menu OR a PSBT confirm
// that arrives over the network without visiting the menu first).
static void addrbookEnsureLoaded(){
  static bool loaded = false;
  if(!loaded){ addrbookLoad(); loaded = true; }
}

// ── Cached account-level xprv (per-session) ──────────────────────────────
// Deriving the account xprv from seed costs ~250ms (3 hardened steps).
// Address derivation from there is 2 non-hardened steps (~70ms total).
// Caching the account xprv makes "tap to advance" feel instant after the
// first address. The xprv is sensitive — zeroised on power-off (it lives
// only in RAM) and on explicit invalidation (not needed in V1).
static bip32_xprv g_btc_account_xprv;
static uint8_t    g_btc_master_fp[4]   = {0};
static char       g_btc_zpub[128]      = {0};
static bool       g_btc_cache_valid    = false;

// ── Persisted account-level XPUB (seed-free, survives reboot) ─────────────
// The two-door design unlocks Door 1 (daily) WITHOUT loading the seed, so the
// watch-only side must derive addresses and verify change from PUBLIC data
// only. We persist the BIP-84 account public key (m/84'/0'/0') + the master
// fingerprint at onboarding, while the seed is briefly in RAM. From then on,
// receive-address derivation and PSBT change verification run from this xpub
// via CKD-pub (bip32_derive_child_pub) — no seed, no spend session.
//
// This is PUBLIC data (BIP-32 xpub): persisting it in plaintext NVS is safe by
// the standard's design. It does, however, reveal the wallet's full address
// space to anyone who can read the chip's flash — an accepted property of any
// watch-only export. It is wiped on Delete Key along with the rest of the
// wallet (see the btc namespace clear on the erase path).
static bip32_xpub g_btc_account_xpub;
static bool       g_btc_xpub_valid     = false;   // RAM mirror loaded?

void btc_invalidate_cache();  // fwd decl (defined below; used by erase helper)

// 15 Oct 2026: the account xpub and master fingerprint are NO LONGER stored
// on this chip. They live in RAM for one Bitcoin life only, filled from the
// G0's DOORKEYS answer at the door, and are gone at sleep / power-off. Until
// now they sat in plaintext NVS ("btc" namespace, default partition), so a
// compromised Nostr life (radio up) could read them and learn every address
// and the full balance/history of the single-sig wallet. A Nostr life now
// holds no Bitcoin information at all: the sealed BTC state (address book,
// receive index, multisig wallets) already needed the G0's state key, and
// the xpub was the last piece outside it. Nothing in a Nostr life used it.
static void btc_forget_legacy_xpub_nvs() {
  Preferences p;
  if (p.begin("btc", false)) { p.remove("acct_xpub"); p.remove("master_fp"); p.end(); }
}

// Onboarding hook (create AND restore). Kept for its callers: it now only
// removes any copy an older firmware left in NVS. Persists nothing.
bool btc_persist_account_xpub(const uint8_t seed[64]) {
  (void)seed;
  btc_forget_legacy_xpub_nvs();
  return true;
}

// The BTC life's account xpub comes from the G0's DOORKEYS answer, never from
// a seed on this processor. RAM only (see above).
bool btc_persist_account_xpub_from_g0(const g0_door_keys_t* k) {
  bip32_xpub xpub;
  memcpy(xpub.pubkey, k->xpub84_pub, 33);
  memcpy(xpub.chain_code, k->xpub84_cc, 32);
  xpub.depth = 3;
  xpub.child_number = 0x80000000UL;   // m/84'/0'/0' — last step is 0'
  memcpy(xpub.parent_fingerprint, k->xpub84_parent_fp, 4);
  g_btc_account_xpub = xpub;
  memcpy(g_btc_master_fp, k->master_fp, 4);
  g_btc_xpub_valid = true;
  btc_forget_legacy_xpub_nvs();   // an older firmware's plaintext copy must not outlive this
  return true;
}

// The account xpub for this Bitcoin life. true only after the door opened
// (btc_persist_account_xpub_from_g0). Never reads storage.
static bool btc_load_account_xpub() {
  return g_btc_xpub_valid;
}

// Receive address index (persisted in NVS). Declared here so btc_erase_persisted
// (below) can reset it. The PWA will eventually own this; for now the device
// manages it locally so Receive works standalone.
static uint32_t g_btc_recv_index = 0;

// Erase all persisted BTC watch-only state (account xpub, master fingerprint,
// receive index). Called from every wallet-erase path so a Delete Key removes
// the watch-only xpub too — otherwise the next person to onboard a different
// seed would briefly see the old wallet's address space. Also clears the RAM
// mirrors so nothing stale survives in-process.
// ── Multisig state (Drop 2) ───────────────────────────────────────────────
// The registered-wallet store lives in PSRAM (3.4KB) and is persisted in the
// "btc" NVS namespace. Drop 3 wraps this blob, the address book and the
// receive index in one seed-derived HMAC; until then a Nostr-life RCE can
// scribble it, which is why btcDoorUnlock() re-derives our BIP-48 xpub from
// the seed and ms_store_load() re-resolves membership from it every BTC life.
static ms_store_t *g_ms            = nullptr;
static bip32_xpub  g_ms_our_xpub;                 // our m/48'/0'/0'/2' account key
static bool        g_ms_our_valid  = false;
static uint8_t    *g_ms_scratch    = nullptr;     // wallet-config text buffer (UR payload)

static bool msEnsureMem() {
  if (!g_bst) {
    g_bst = (bst_state_t *)ps_malloc(sizeof(bst_state_t));
    if (!g_bst) g_bst = (bst_state_t *)malloc(sizeof(bst_state_t));
    if (g_bst) bst_init(g_bst);
  }
  if (g_bst && !g_ms) g_ms = &g_bst->ms;   // the wallet store IS a field of the sealed state
  if (!g_ms_scratch) {
    g_ms_scratch = (uint8_t *)ps_malloc(UR_MAX_MESSAGE);
    if (!g_ms_scratch) g_ms_scratch = (uint8_t *)malloc(UR_MAX_MESSAGE);
  }
  return g_ms && g_ms_scratch;
}

// Registered wallets are loaded/saved with the sealed state. These two keep
// the call sites in multisig_ui.inc unchanged.
static void ms_resolve_membership() {
  if (!g_ms) return;
  for (int i = 0; i < MS_MAX_WALLETS; i++) {
    if (!g_ms->w[i].valid) continue;
    if (g_ms_our_valid) ms_wallet_find_ours(&g_ms->w[i], g_btc_master_fp, &g_ms_our_xpub);
    else g_ms->w[i].our_index = 0xFF;
  }
}
static bool ms_store_load() { bool ok = btcStateEnsure(); ms_resolve_membership(); return ok; }
static bool ms_store_save() { return btcStateSave(); }

// ── Sealed state: load / migrate / save / wipe ────────────────────────────
// 11as (audit finding 5): the AEAD nonce comes from favillaRandom (SE051 TRNG
// and the ESP32 RNG hashed together, fail closed). bst_seal takes a void
// callback, so a failure is flagged here and the save is refused after it.
static bool g_bstRngFail = false;
static void bstRng(uint8_t *o, size_t n) { if (!favillaRandom(o, n)) { g_bstRngFail = true; memset(o, 0, n); } }
#define BST_NS   "btcstate"
#define BST_KEY  "blob"          // pre-v4 single blob; read as a fallback, never written again
// v4 (24 Sep 2026): one blob per wallet so a per-session passphrase wallet,
// its words-only wallet and any decoy each keep their own sealed state
// (address book, receive index, multisig registrations) and can never
// overwrite one another's.
// 16 Oct 2026: the NVS key is no longer the master fingerprint. That name
// sat in flash in plaintext in every life, so a Nostr-life RCE (or anyone
// with the flash) could read which wallet this KEY serves even though the
// blob itself was sealed. Now the name is derived from the sealed-state key
// (K = HMAC(seed, label), per wallet), which the ESP32 only holds in an
// unlocked Bitcoin life: outside one, the entry is an opaque "b_" + 8 hex
// with nothing to correlate it to. Legacy "b_<fp>" entries are migrated on
// first open and erased. NVS key = "b_" + 8 hex = 10 chars.
static const char* bstKeyName() {
  static char k[16];
  uint8_t h[32];
  const char* label = "favilla-bst-name-v5";
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, (const uint8_t*)label, strlen(label));
  mbedtls_sha256_update(&c, g_bst_key, 32);
  mbedtls_sha256_finish(&c, h); mbedtls_sha256_free(&c);
  snprintf(k, sizeof k, "b_%02x%02x%02x%02x", h[0], h[1], h[2], h[3]);
  return k;
}
// The pre-16-Oct name, read once for migration and then removed.
static const char* bstLegacyKeyName() {
  static char k[16];
  snprintf(k, sizeof k, "b_%02x%02x%02x%02x", g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3]);
  return k;
}

static bool btcStateSave() {
  if (!g_bst || !g_bst_key_valid || !g_bst_loaded) {
    LOG_BOOT("[bst] save refused (bst=%d key=%d loaded=%d)\n", g_bst != nullptr, g_bst_key_valid, g_bst_loaded);
    return false;
  }
  static uint8_t *scratch = nullptr, *out = nullptr;
  if (!scratch) { scratch = (uint8_t *)ps_malloc(BST_PLAIN_MAX); if (!scratch) scratch = (uint8_t *)malloc(BST_PLAIN_MAX); }
  if (!out)     { out     = (uint8_t *)ps_malloc(BST_SEALED_MAX); if (!out)   out     = (uint8_t *)malloc(BST_SEALED_MAX); }
  if (!scratch || !out) return false;
  g_bstRngFail = false;
  size_t n = bst_seal(g_bst_key, g_bst, bstRng, scratch, out, BST_SEALED_MAX);
  if (g_bstRngFail) { LOG_BOOT("[bst] seal refused: no randomness from the secure element\n"); mbedtls_platform_zeroize(out, BST_SEALED_MAX); return false; }
  if (!n) { LOG_BOOT("[bst] seal failed\n"); return false; }
  Preferences p;
  if (!p.begin(BST_NS, false, NVSPART_SEC)) return false;
  size_t w = p.putBytes(bstKeyName(), out, n);
  p.end();
  LOG_BOOT("[bst] sealed %u bytes (%u addr, %u wallet) -> nvs_sec %s\n",
           (unsigned)n, (unsigned)g_bst->addr_count, (unsigned)g_bst->ms.count, w == n ? "ok" : "WRITE FAILED");
  return w == n;
}

// No sealed blob yet: start EMPTY. Until 11as (audit finding 7) this point
// migrated pre-Drop-3 plaintext (default nvs: addrbook JSON, btc/recv_idx,
// btc/ms_wallets) into the sealed blob. That plaintext is untrusted by the
// Drop-3 rule (anything with code in a Nostr life could have written it), so
// an absent blob was a poison path: plant an address book, let the next BTC
// life seal it. No shipped unit predates Drop 3, so the migration is gone.
// Any leftover legacy keys are cleared so they cannot be read by anything.
static void btcStateStartEmpty() {
  bst_init(g_bst);
  g_bst_loaded = true;
  Preferences p;
  bool had = false;
  if (p.begin("addrbook", false)) { had |= p.isKey("entries"); p.clear(); p.end(); }
  if (p.begin("btc", false)) { had |= p.isKey("ms_wallets") || p.isKey("recv_idx"); p.remove("recv_idx"); p.remove("ms_wallets"); p.end(); }
  LOG_BOOT("[bst] no sealed state: starting empty%s\n", had ? " (legacy plaintext found and cleared, not imported)" : "");
}

static bool btcStateEnsure() {
  if (g_bst_loaded) return true;
  if (!msEnsureMem()) return false;
  bst_init(g_bst); g_ms = &g_bst->ms;
  if (!g_bst_key_valid) {
    // No seed this life (Nostr life, or door not opened): nothing is readable.
    // Callers get an EMPTY state, never the blob's contents.
    return false;
  }
  static uint8_t *scratch = nullptr, *in = nullptr;
  if (!scratch) { scratch = (uint8_t *)ps_malloc(BST_PLAIN_MAX); if (!scratch) scratch = (uint8_t *)malloc(BST_PLAIN_MAX); }
  if (!in)      { in      = (uint8_t *)ps_malloc(BST_SEALED_MAX); if (!in)    in      = (uint8_t *)malloc(BST_SEALED_MAX); }
  if (!scratch || !in) return false;
  size_t len = 0; bool fromLegacyName = false;
  { Preferences p;
    if (p.begin(BST_NS, true, NVSPART_SEC)) {
      const char* kn = bstKeyName();
      len = p.getBytesLength(kn); if (len > BST_SEALED_MAX) len = 0;
      if (len) p.getBytes(kn, in, len);
      else {
        // 16 Oct 2026: blob filed under the old fingerprint name? Open it,
        // then re-file it under the key-derived name and erase the old entry.
        const char* lk = bstLegacyKeyName();
        len = p.getBytesLength(lk); if (len > BST_SEALED_MAX) len = 0;
        if (len) { p.getBytes(lk, in, len); fromLegacyName = true; LOG_BOOT("[bst] blob under the legacy fingerprint name - migrating\n"); }
        else {   // pre-v4 blob: readable only by the wallet it was sealed for (the tag decides)
          len = p.getBytesLength(BST_KEY); if (len > BST_SEALED_MAX) len = 0;
          if (len) { p.getBytes(BST_KEY, in, len); LOG_BOOT("[bst] no per-wallet blob, trying the pre-v4 one\n"); }
        }
      }
      p.end(); } }
  if (len == 0) {
    btcStateStartEmpty();
    return true;
  }
  if (!bst_open(g_bst_key, in, len, scratch, g_bst)) {
    // Tag mismatch: the blob was rewritten by something that did not hold the
    // seed, or the seed changed. Say so loudly and start EMPTY. The blob is
    // left in place until the next save overwrites it, so the evidence is
    // still there if Josh wants to pull it.
    LOG_BOOT("[bst] SEALED STATE REFUSED (%u bytes) - tag mismatch, starting empty\n", (unsigned)len);
    bst_init(g_bst);
    dispError("Bitcoin data tampered - reset");
    errorPause();
    g_bst_loaded = true;
    return true;
  }
  g_bst_loaded = true;
  LOG_BOOT("[bst] opened %u bytes: %u address(es), recv_idx %u, %u wallet(s)\n",
           (unsigned)len, (unsigned)g_bst->addr_count, (unsigned)g_bst->recv_index, (unsigned)g_bst->ms.count);
  if (fromLegacyName && btcStateSave()) {
    Preferences p;
    if (p.begin(BST_NS, false, NVSPART_SEC)) { p.remove(bstLegacyKeyName()); p.end(); }
    LOG_BOOT("[bst] re-filed under the key-derived name; legacy fingerprint entry erased\n");
  }
  return true;
}

static void btcStateWipe() {
  if (g_bst) bst_init(g_bst);
  memset(g_bst_key, 0, sizeof(g_bst_key));
  g_bst_key_valid = false; g_bst_loaded = false;
  memset(g_addrbook, 0, sizeof(g_addrbook)); g_addrbook_count = 0;
  g_btc_recv_index = 0;
}

// Which registered wallet the in-flight PSBT belongs to (-1 = single-sig).
static int         g_psbt_ms_wallet = -1;
// The PSBT exactly as scanned. The cosigner return leg re-emits THESE bytes
// with our partial sigs spliced in; the parsed struct is lossy and must never
// be the source for a PSBT another signer will read.
static const uint8_t *g_psbt_raw      = nullptr;
static size_t         g_psbt_raw_len  = 0;

void btc_erase_persisted() {
  { Preferences p; if (p.begin("btc", false)) { p.clear(); p.end(); } }   // legacy keys
  { Preferences p; if (p.begin("addrbook", false)) { p.clear(); p.end(); } }
  { Preferences p; if (p.begin(BST_NS, false, NVSPART_SEC)) { p.clear(); p.end(); } }   // the sealed blob
  btcStateWipe();
  if (g_ms) ms_store_init(g_ms);
  g_ms_our_valid = false;
  memset(&g_ms_our_xpub, 0, sizeof(g_ms_our_xpub));
  memset(&g_btc_account_xpub, 0, sizeof(g_btc_account_xpub));
  memset(g_btc_master_fp, 0, sizeof(g_btc_master_fp));
  g_btc_xpub_valid = false;
  g_btc_recv_index = 0;
  btc_invalidate_cache();
}

static void btc_load_recv_index() {
  if (btcStateEnsure() && g_bst) g_btc_recv_index = g_bst->recv_index;
  else g_btc_recv_index = 0;
}

static void btc_save_recv_index() {
  if (!g_bst) return;
  g_bst->recv_index = g_btc_recv_index;
  btcStateSave();
}

// ── Seed loading (LEGACY - always false under v3) ───────────────────────
// Pre-v3 this returned the seed from wallet.seed. Nothing populates that
// buffer any more (see SEED SOURCE above), so this returns false on every
// path and btc_ensure_cache() below - the only caller - is unreachable in
// practice. Kept so the legacy zpub-export branch still compiles; both are
// candidates for removal once that view is rebuilt on the G0.
extern Wallet wallet;

static bool btc_load_seed(uint8_t seed_out[64]) {
  if (!wallet.exists) return false;
  if (!wallet.unlocked) return false;
  if (!wallet.hasSeed) return false;  // legacy or nsec-imported wallet
  // wallet.hasSeed means a seed EXISTS (wrapped), never that it is resident.
  // Refuse unless the buffer is non-zero - which under v3 it never is.
  bool resident = false;
  for (int i = 0; i < 64; i++) { if (wallet.seed[i] != 0) { resident = true; break; } }
  if (!resident) return false;
  memcpy(seed_out, wallet.seed, 64);
  return true;
}

// Invalidate the cached BIP-84 account xprv. Called from clearKeyCache()
// in main.cpp on every lock/sleep/unpair/delete path. Zeroises
// the in-RAM derived PRIVATE material so a lock truly clears spend-capable
// state. The next btc_ensure_cache() after a fresh unlock re-derives if a
// seed is available.
//
// The public account xpub mirror (g_btc_account_xpub) is deliberately NOT
// cleared here: it is watch-only public data, it must survive a lock so the
// daily door can still show balances/addresses with no seed, and it is
// reloaded from NVS on boot anyway. It is destroyed only on Delete Key (the
// btc-namespace clear on the wallet-erase path).
void btc_invalidate_cache() {
  memset(&g_btc_account_xprv, 0, sizeof(g_btc_account_xprv));
  memset(g_btc_zpub, 0, sizeof(g_btc_zpub));
  g_btc_cache_valid = false;
  // g_btc_master_fp and g_btc_account_xpub intentionally preserved (public).
}

// ── Derive a leaf pubkey from the account xpub (SEED-FREE, CKD-pub) ───────
// account xpub → /change → /index, both unhardened. This is the watch-only
// derivation path used by Receive and by PSBT change verification. No seed,
// no spend session. Requires the persisted account xpub (btc_load_account_xpub).
//
// Returns false if no xpub is available (pre-xpub wallet — caller may fall
// back to the seed path) or if either CKD-pub step fails.
static bool btc_derive_pubkey_pub(uint32_t change, uint32_t index,
                                  uint8_t pub33_out[33]) {
  if (change > 1) return false;
  if (!btc_load_account_xpub()) return false;   // no persisted xpub

  bip32_xpub chain;
  if (!bip32_derive_child_pub(&g_btc_account_xpub, change, &chain)) return false;
  bip32_xpub leaf;
  if (!bip32_derive_child_pub(&chain, index, &leaf)) return false;

  memcpy(pub33_out, leaf.pubkey, 33);
  return true;
}

// ── Build cache: account xprv, fingerprint, zpub ─────────────────────────
// SEED-REQUIRED, and therefore UNREACHABLE under v3 (btc_load_seed is always
// false - no seed on this processor). Retained for the legacy zpub-export
// branch only. The watch-only hot paths (receive address, change
// verification) use the seed-free xpub helpers above and must NOT call this.
static bool btc_ensure_cache() {
  if (g_btc_cache_valid) return true;

  uint8_t seed[64];
  if (!btc_load_seed(seed)) return false;

  uint8_t derived_fp[4];
  bool ok = bip84_derive_account_xprv(seed, BIP84_NETWORK_MAINNET,
                                       &g_btc_account_xprv, derived_fp);
  if (ok) {
    ok = bip84_serialise_account_xpub(seed, BIP84_NETWORK_MAINNET,
                                       g_btc_zpub, sizeof(g_btc_zpub));
  }

  if (ok) {
    // The freshly-derived master fingerprint is the SOURCE OF TRUTH. A value
    // loaded earlier by btc_load_account_xpub() from NVS may be STALE — older
    // firmware persisted a different fingerprint (e.g. the account-parent
    // fingerprint) into the "master_fp" key, and because unlock loads the
    // persisted pair rather than re-deriving, that stale value would otherwise
    // be displayed even though the seed (and the account xpub, and every
    // address) is correct. Overwrite the RAM mirror, and self-heal the NVS copy
    // if it disagrees so the stored fingerprint converges to the true value.
    if (memcmp(g_btc_master_fp, derived_fp, 4) != 0) {
      LOG_BOOT("[btc] master_fp mismatch (stored %02x%02x%02x%02x != derived "
               "%02x%02x%02x%02x) — healing\n",
               g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3],
               derived_fp[0], derived_fp[1], derived_fp[2], derived_fp[3]);
      memcpy(g_btc_master_fp, derived_fp, 4);
      // 15 Oct 2026: nothing is persisted any more (RAM only).
    } else {
      memcpy(g_btc_master_fp, derived_fp, 4);
    }
  }

  memset(seed, 0, sizeof(seed));
  g_btc_cache_valid = ok;
  return ok;
}

// ── Derive a receive address (SEED-FREE) ─────────────────────────────────
// Two non-hardened CKD-pub steps from the persisted account xpub: no seed,
// works on a daily-door unlock. Falls back to the legacy seed-based xprv walk
// only for wallets onboarded before the xpub was persisted (and only when the
// seed happens to be available, i.e. inside a spend session) — in normal V1
// operation the fall-back never runs.
// addr_out: caller-provided buffer, at least 64 bytes.
static bool btc_derive_receive_address(uint32_t index, char* addr_out, size_t cap) {
  if (cap < 64) return false;

  uint8_t pub[33];
  bool have_pub = btc_derive_pubkey_pub(0, index, pub);

  if (!have_pub) {
    // Legacy fallback: no persisted xpub. Derive from seed if one is loaded.
    if (!btc_ensure_cache()) return false;
    bip32_xprv chain, leaf;
    if (!bip32_derive_child(&g_btc_account_xprv, 0, &chain)) return false;
    bool ok = bip32_derive_child(&chain, index, &leaf);
    if (ok) ok = bip32_priv_to_pub_compressed(leaf.key, pub);
    memset(&leaf, 0, sizeof(leaf));
    memset(&chain, 0, sizeof(chain));
    if (!ok) return false;
  }

  uint8_t witness_program[20];
  hash160(pub, 33, witness_program);
  return segwit_addr_encode("bc", 0, witness_program, 20, addr_out);
}

// ── Address fingerprint (4-char anti-phishing checksum) ──────────────────
// First 4 hex chars of SHA256(address). Lets the user visually verify that
// the address shown by the PWA matches what the trusted device produced.
// 16 bits ≈ 1-in-65000 collision rate, sufficient for visual checking.
static void btc_address_fingerprint(const char* addr, char out[5]) {
  uint8_t h[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const uint8_t*)addr, strlen(addr));
  mbedtls_sha256_finish(&ctx, h);
  mbedtls_sha256_free(&ctx);
  static const char* HEXCHARS = "0123456789ABCDEF";
  out[0] = HEXCHARS[(h[0] >> 4) & 0xF];
  out[1] = HEXCHARS[h[0] & 0xF];
  out[2] = HEXCHARS[(h[1] >> 4) & 0xF];
  out[3] = HEXCHARS[h[1] & 0xF];
  out[4] = 0;
}

// ── Wallet Info screen ──────────────────────────────────────────────────

static void btc_draw_info_details() {
  spr.fillSprite(C_BG);
  uiHeader("WALLET INFO", C_BTC_ACCENT);

  fSet(F_BODY); spr.setTextColor(C_DIM);
  spr.drawString("Master fingerprint:", 10, 44); fEnd();

  char fp_hex[9];
  snprintf(fp_hex, sizeof(fp_hex), "%02x%02x%02x%02x",
           g_btc_master_fp[0], g_btc_master_fp[1],
           g_btc_master_fp[2], g_btc_master_fp[3]);
  fSet(F_MONO); spr.setTextColor(C_BTC_ACCENT);
  spr.drawString(fp_hex, 10, 60); fEnd();

  fSet(F_BODY); spr.setTextColor(C_DIM);
  spr.drawString("Derivation path:", 10, 92); fEnd();
  fSet(F_MONO); spr.setTextColor(C_TEXT2);
  spr.drawString("m/84'/0'/0'", 10, 108); fEnd();

  fSet(F_BODY); spr.setTextColor(C_DIM);
  spr.drawString("Address type:", 10, 132); fEnd();
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  spr.drawString("Native SegWit (bc1q)", 10, 148); fEnd();

  fSet(F_BODY); spr.setTextColor(C_DIM);
  spr.drawString("Network:", 10, 172); fEnd();
  fSet(F_BODY); spr.setTextColor(C_GREEN);
  spr.drawString("MAINNET", 10, 188); fEnd();

  DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
}

static void btc_show_wallet_info() {
  // The master fingerprint is derived ONCE at onboarding (the only time the seed
  // is in hand) and stored in NVS. This screen — and the PWA — simply DISPLAY
  // that stored value. We must NEVER try to re-derive it here: on a daily-door
  // unlock the seed is not resident (it's spend-bound), so a "re-derive" would
  // run against a zero seed and produce garbage. Just load the persisted xpub +
  // fingerprint (seed-free) and show them.
  btc_load_account_xpub();   // RAM only: valid after the Bitcoin door opened this life

  bool showing_qr = false;
  btc_draw_info_details();

  while (true) {
    // Background btnPollTask polls all buttons; don't poll here (races it).
    esp_task_wdt_reset();
    if (wsStarted) { webSocket.loop(); webSocket2.loop(); }
    delay(5);

    if (btn4.isPressed()) return;   // BACK -> exit

    if (btn2.isPressed()) {
      showing_qr = !showing_qr;
      if (showing_qr) {
        // Serialise the zpub SEED-FREE from the persisted xpub (g_btc_zpub is
        // only populated by the seed-based cache, which isn't built on a daily
        // unlock). Falls back to g_btc_zpub for legacy wallets where it was set.
        char zpub_buf[128];
        const char* zpub_to_show = g_btc_zpub;
        if (g_btc_xpub_valid &&
            bip84_serialise_xpub_struct(&g_btc_account_xpub, BIP84_NETWORK_MAINNET,
                                        zpub_buf, sizeof(zpub_buf))) {
          zpub_to_show = zpub_buf;
        }
        showQR(zpub_to_show, "Account zpub", "scan into your wallet app");
      } else {
        btc_draw_info_details();
      }
    }

    // 29 Oct 2026: removed a hold-DOWN exit labelled "HOLD BACK" (DOWN is not
    // BACK). BACK exits, above.
  }
}

// ── Receive screen ──────────────────────────────────────────────────────
//
// Full-screen QR with:
//   - Top strip: "Receive #N" left, "FP:XXXX" right
//   - QR centred (version 3 = 29x29 modules, scaled 6x)
//   - Bottom strip: truncated address + control hint
//
// Controls:
//   btn2 tap      → next address (advance, persists)
//   btn1 tap      → previous address (decrement, clamped at 0)
//   btn1 hold     → back to Bitcoin sub-menu

static void btc_draw_receive(const char* addr, uint32_t index, const char* fp) {
  spr.fillSprite(C_BG);

  // Top strip
  spr.fillRect(0, 0, 240, 20, 0x0000);
  spr.fillRect(0, 0, 3, 20, C_BTC_ACCENT);

  fSet(F_BODY);
  char idx_str[20];
  snprintf(idx_str, sizeof(idx_str), "Receive #%u", (unsigned)index);
  spr.setTextColor(C_BTC_ACCENT);
  spr.drawString(idx_str, 8, 4);
  fEnd();

  fSet(F_MONO);
  char fp_label[12];
  snprintf(fp_label, sizeof(fp_label), "FP:%s", fp);
  spr.setTextColor(C_DIM);
  int fpw = spr.textWidth(fp_label);
  spr.drawString(fp_label, 240 - fpw - 8, 4);
  fEnd();

  // QR — version 3 fits 42-char bech32 with ECC_LOW comfortably.
  QRCode qr;
  uint8_t qrBuf[qrcode_getBufferSize(3)];
  if (qrcode_initText(&qr, qrBuf, 3, ECC_LOW, addr) == 0) {
    int dim = qr.size;
    int avail = 180;
    int sc = avail / dim;
    if (sc < 1) sc = 1;
    int px = dim * sc;
    int ox = (240 - px) / 2;
    int oy = 28 + (180 - px) / 2;
    spr.fillRoundRect(ox - 6, oy - 6, px + 12, px + 12, 6, C_QR_WHITE);
    for (int y = 0; y < dim; y++) {
      for (int x = 0; x < dim; x++) {
        if (qrcode_getModule(&qr, x, y)) {
          spr.fillRect(ox + x * sc, oy + y * sc, sc, sc, C_BG);
        }
      }
    }
  } else {
    fSet(F_BODY); spr.setTextColor(C_RED);
    fDrawCentre("QR error", 120, 110); fEnd();
  }

  // Bottom: truncated address (first 8 ... last 8) for human recognition
  fSet(F_MONO); spr.setTextColor(C_TEXT2);
  char short_addr[32];
  int alen = strlen(addr);
  if (alen > 20) {
    snprintf(short_addr, sizeof(short_addr), "%.8s...%s", addr, addr + alen - 8);
  } else {
    snprintf(short_addr, sizeof(short_addr), "%s", addr);
  }
  int saw = spr.textWidth(short_addr);
  spr.drawString(short_addr, (240 - saw) / 2, 216);
  fEnd();
  // 29 Oct 2026: the old hint here ("btn1=prev btn2=next hold=back") named the
  // wrong buttons. No footer hint (Josh's rule): DOWN next, UP previous, BACK leaves.

  DISP_LOCK(); spr.pushSprite(0, 0); DISP_UNLOCK();
}

// ── Address Book UI ──────────────────────────────────────────────────────
// Forward decl — psbtDrawAddrWrapped is defined later (near the PSBT confirm
// screen) but the address-book screens above it render addresses too.
static int psbtDrawAddrWrapped(const char *addr, int x, int y, uint16_t col);

// Strip a BIP-21 "bitcoin:" URI down to the bare address (drop scheme and any
// ?amount=/&label= query params). Returns true if a plausible address remains.
static bool ab_parse_scanned(const char* in, char* out, size_t outsz){
  String s = String(in); s.trim();
  if(s.startsWith("bitcoin:") || s.startsWith("BITCOIN:")) s = s.substring(8);
  int q = s.indexOf('?'); if(q >= 0) s = s.substring(0, q);
  s.trim();
  if(s.length() < 8 || s.length() >= (int)outsz) return false;
  // Must look like a bech32 mainnet address (bc1...). We only match what the
  // device can also produce from a scriptPubKey, so restrict to bc1.
  if(!(s.startsWith("bc1") || s.startsWith("BC1"))) return false;
  s.toLowerCase();
  strncpy(out, s.c_str(), outsz-1); out[outsz-1]=0;
  return true;
}

// Scan a QR to capture a new recipient address. Mirrors the PROVEN nsec/seed
// scan loop in the main ino EXACTLY (camera start once, poll cancel button
// manually, single triggerQRScan cadence, cameraStop on exit/find, no
// re-cameraStart inside the loop) — the camera path is heap/bus-sensitive and
// must not deviate from the known-good structure. Only the parse/save differs.
static void ab_scan_to_add(){
  spr.fillSprite(C_BG);
  uiHeader("ADD ADDRESS", C_BTC_ACCENT);
  fSet(F_BODY); spr.setTextColor(C_VDIM);
  fDrawCentre("Show the address QR on your phone", 120, 104);
  fDrawCentre("BACK to cancel", 120, 200); fEnd();
  uiFooter(); dispPush(); delay(800);

  pwrBoost();              // full speed for camera + QR decode
  autoNetCancel();         // V22: cancel any in-flight AUTO network transition
                           // so the camera's contiguous-RAM init doesn't collide
                           // with WiFi stack churn (promote/fallback) → crash.
  g_airgapLivePreview = true;   // draw the live camera feed via qrScanOnce so
  g_airgapUrGot = 0; g_airgapUrTotal = 0;  // the user can AIM (no preview =
                                // scanning blind = QR never framed = identified=0)
  cameraStart(); qrFound = false;
  unsigned long ns = millis(), lastQR = 0;
  char captured[ADDRBOOK_ADDR_MAX] = {0};
  bool got = false, gotFrame = false;

  // Use qrScanOnce() — the SYNCHRONOUS main-loop scanner used by the airgap
  // path. The old triggerQRScan()/qrScanTask BACKGROUND-task path hits the
  // "FB-SIZE: 0" wall (cross-core fb_get race) and corrupts the heap.
  // qrScanOnce() owns the camera in the one context where fb_get is proven to
  // work, discards torn frames, reuses one quirc, draws the live preview when
  // g_airgapLivePreview is set, and feeds the watchdog.
  while(millis() - ns < 30000){
    esp_task_wdt_reset();
    btn4.poll();
    if(btn4.isPressed()){ g_airgapLivePreview=false; cameraStop(); pwrIdle(); return; }  // BACK = cancel
    if(!qrFound && (millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS)){
      lastQR = millis();
      qrScanOnce();   // sets qrFound + fills qrResultBuf on a successful decode
    }
    if(qrFound){
      gotFrame = true;
      qrFound = false; g_airgapLivePreview=false; cameraStop();
      if(ab_parse_scanned(qrResultBuf, captured, sizeof(captured))) got = true;
      break;
    }
  }
  g_airgapLivePreview = false;
  pwrIdle();
  if(!got){
    cameraStop();   // idempotent — safe if already stopped above
    if(gotFrame){ dispError("Not a BTC address"); errorPause(); }
    return;
  }

  // Confirm the decoded address on the trusted screen, then save.
  spr.fillSprite(C_BG);
  uiHeader("CONFIRM ADDRESS", C_BTC_ACCENT);
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  spr.drawString("Save this address?", 10, 40); fEnd();
  psbtDrawAddrWrapped(captured, 10, 64, C_FG);
  uiPill(16, 168, 100, 34, C_BG, C_DIM, "Cancel", true, C_BORDER);
  uiPill(124, 168, 100, 34, C_GREEN, C_BG, "Save");
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  fDrawCentre("BACK cancel    ENTER save", 120, 218); fEnd();
  DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
  drainButtonsAfterTransition();
  while(true){
    esp_task_wdt_reset(); delay(5);
    if(btn4.isPressed()) return;
    if(btn2.isPressed()){
      int i = addrbookAdd(captured, nullptr);
      if(i < 0) dispError("Book full");
      else      dispSuccess("Saved", "Address added", C_GREEN);
      errorPause();
      return;
    }
  }
}

// Smart-scan entry: the universal scan router already has a decoded QR string
// (a bc1.../bitcoin: address). Parse it and run the same confirm+save screen
// as the address-book scan. Non-static: called from the main ino's scan
// router across the translation unit.
void scanSaveBtcAddress(const char* qr){
  addrbookEnsureLoaded();
  char addr[ADDRBOOK_ADDR_MAX] = {0};
  if(!ab_parse_scanned(qr, addr, sizeof(addr))){
    dispError("Not a BTC address"); errorPause(); return;
  }
  // Already in the book?
  if(addrbookFind(addr) >= 0){
    dispSuccess("Known", "Already saved", C_GREEN); errorPause(); return;
  }
  // Confirm + save on the trusted screen.
  spr.fillSprite(C_BG);
  uiHeader("SAVE ADDRESS", C_BTC_ACCENT);
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  spr.drawString("Save to address book?", 10, 40); fEnd();
  psbtDrawAddrWrapped(addr, 10, 64, C_FG);
  uiPill(16, 168, 100, 34, C_BG, C_DIM, "Cancel", true, C_BORDER);
  uiPill(124, 168, 100, 34, C_GREEN, C_BG, "Save");
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  fDrawCentre("BACK cancel    ENTER save", 120, 218); fEnd();
  DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
  drainButtonsAfterTransition();
  while(true){
    esp_task_wdt_reset(); delay(5);
    if(btn4.isPressed()) return;
    if(btn2.isPressed()){
      int i = addrbookAdd(addr, nullptr);
      if(i < 0) dispError("Book full");
      else      dispSuccess("Saved", "Address added", C_GREEN);
      errorPause();
      return;
    }
  }
}

// Delete confirmation — mirrors the Delete Key flow (ENTER confirms, BACK cancels).
// Returns true if the entry was deleted.
static bool ab_confirm_delete(int i){
  spr.fillSprite(C_BG);
  uiHeader("DELETE CONTACT", C_RED);
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  fDrawCentre("Remove this address from", 120, 56);
  fDrawCentre("the address book?", 120, 72); fEnd();
  psbtDrawAddrWrapped(g_addrbook[i].addr, 10, 100, C_MUTED);
  uiPill(16, 168, 100, 34, C_BG, C_DIM, "Cancel", true, C_BORDER);
  uiPill(124, 168, 100, 34, C_RED, C_FG, "Delete");
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  fDrawCentre("BACK cancel    ENTER delete", 120, 218); fEnd();
  DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
  drainButtonsAfterTransition();
  while(true){
    esp_task_wdt_reset(); delay(5);
    if(btn4.isPressed()) return false;            // BACK = cancel
    if(btn2.isPressed()){                          // ENTER = delete
      addrbookDelete(i);
      dispSuccess("Deleted", "Contact removed", C_RED);
      errorPause();
      return true;
    }
  }
}

// Detail view for one entry: shows the address + send count, plus a scrollable
// action menu (Show QR / Delete / Back). Navigation matches the device grammar:
// SCROLL UP/DOWN move the selection, ENTER activates, BACK exits.
static void ab_show_entry(int i){
  if(i < 0 || i >= g_addrbook_count) return;
  const char* actions[] = { "Show QR", "Delete", "Back" };
  const int N_ACT = 3;
  int sel = 0;
  bool showing_qr = false;

  auto draw = [&](){
    spr.fillSprite(C_BG);
    uiHeader("CONTACT", C_BTC_ACCENT);
    if(showing_qr){
      QRCode qr;
      uint8_t qrBuf[qrcode_getBufferSize(3)];
      if (qrcode_initText(&qr, qrBuf, 3, ECC_LOW, g_addrbook[i].addr) == 0) {
        int dim = qr.size, sc = 180 / dim; if(sc < 1) sc = 1;
        int px = dim * sc, ox = (240 - px) / 2, oy = 34 + (180 - px) / 2;
        spr.fillRoundRect(ox - 6, oy - 6, px + 12, px + 12, 6, C_QR_WHITE);
        for(int yy=0; yy<dim; yy++) for(int xx=0; xx<dim; xx++)
          if(qrcode_getModule(&qr, xx, yy))
            spr.fillRect(ox + xx*sc, oy + yy*sc, sc, sc, C_BG);
      }
      fSet(F_BODY); spr.setTextColor(C_MUTED);
      fDrawCentre("BACK to return", 120, 224); fEnd();
      DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
      return;
    }
    // Address + stats
    psbtDrawAddrWrapped(g_addrbook[i].addr, 10, 40, C_TEXT2);
    char st[40]; snprintf(st, sizeof(st), "sent %u time%s",
                          (unsigned)g_addrbook[i].n_sent,
                          g_addrbook[i].n_sent==1?"":"s");
    fSet(F_BODY); spr.setTextColor(C_MUTED);
    spr.drawString(st, 10, 96); fEnd();
    // Action menu — selected = filled accent pill, others = ghost outline.
    for(int a=0; a<N_ACT; a++){
      int py = 120 + a * 32;
      uint16_t fill = (a==1) ? C_RED : C_BTC_ACCENT;   // Delete is red
      if(a==sel) uiPill(16, py, 208, 28, fill, C_BG, actions[a]);
      else       uiPill(16, py, 208, 28, C_BG, C_DIM, actions[a], true, C_BORDER);
    }
    DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
  };
  draw();
  drainButtonsAfterTransition();
  while(true){
    esp_task_wdt_reset(); delay(5);
    if(showing_qr){
      if(btn4.isPressed()){ showing_qr=false; draw(); }
      continue;
    }
    if(btn4.isPressed()) return;                        // BACK = exit
    else if(btn1.isPressed()){ sel=(sel+1)%N_ACT; draw(); }      // SCROLL DOWN
    else if(btn3.isPressed()){ sel=(sel-1+N_ACT)%N_ACT; draw(); } // SCROLL UP
    else if(btn2.isPressed()){                          // ENTER = activate
      if(sel==0){ showing_qr=true; draw(); }
      else if(sel==1){ if(ab_confirm_delete(i)) return; else { draw(); drainButtonsAfterTransition(); } }
      else return;                                      // "Back"
    }
  }
}

static void btc_show_addrbook(){
  addrbookEnsureLoaded();
  // Row 0 is always "+ Add address"; contacts follow. So total rows =
  // count + 1, and a contact's book index is (row - 1).
  int sel = 0, top = 0;
  const int ROWS = 4;   // visible rows
  auto draw = [&](){
    int total = g_addrbook_count + 1;   // +1 for the Add row
    if(sel < top) top = sel;
    if(sel >= top + ROWS) top = sel - ROWS + 1;
    spr.fillSprite(C_BG);
    uiHeader("ADDRESS BOOK", C_BTC_ACCENT);
    for(int r=0; r<ROWS && (top+r)<total; r++){
      int row = top + r;
      int yy = 44 + r * 38;
      bool cur = (row == sel);
      if(cur) spr.fillRoundRect(6, yy-4, 228, 34, 5, C_BORDER);
      if(row == 0){
        // The Add action row
        fSet(F_BODY); spr.setTextColor(cur ? C_BTC_ACCENT : C_TEXT2);
        spr.drawString("+ Add address", 14, yy + 4); fEnd();
      } else {
        int i = row - 1;
        fSet(F_BODY); spr.setTextColor(cur ? C_FG : C_TEXT2);
        spr.drawString(g_addrbook[i].label, 14, yy); fEnd();
        char sa[24]; int n=strlen(g_addrbook[i].addr);
        snprintf(sa, sizeof(sa), "%.10s...%.4s", g_addrbook[i].addr, g_addrbook[i].addr+n-4);
        fSet(F_BODY); spr.setTextColor(C_MUTED);
        spr.drawString(sa, 14, yy+16); fEnd();
      }
    }
    fSet(F_BODY); spr.setTextColor(C_MUTED);
    fDrawCentre("ENTER select    BACK exit", 120, 224); fEnd();
    DISP_LOCK(); spr.pushSprite(0,0); DISP_UNLOCK();
  };
  draw();
  drainButtonsAfterTransition();
  while(true){
    esp_task_wdt_reset();
    if (wsStarted) { webSocket.loop(); webSocket2.loop(); }
    delay(5);
    int total = g_addrbook_count + 1;
    if(btn4.isPressed()) return;                              // BACK = exit
    else if(btn1.isPressed()){ sel=(sel+1)%total; draw(); }   // SCROLL DOWN
    else if(btn3.isPressed()){ sel=(sel-1+total)%total; draw(); } // SCROLL UP
    else if(btn2.isPressed()){                                // ENTER = activate
      if(sel == 0){
        ab_scan_to_add();
      } else {
        ab_show_entry(sel - 1);
      }
      // clamp selection (a delete may have shrunk the list) and redraw
      total = g_addrbook_count + 1;
      if(sel >= total) sel = total - 1;
      draw(); drainButtonsAfterTransition();
    }
  }
}

static void btc_show_receive() {
  char addr[64];
  char fp[5];
  uint32_t idx = g_btc_recv_index;

  // Seed-free by design: btc_derive_receive_address() tries the CKD-pub path
  // (persisted account xpub, no seed) first and only falls back to the
  // seed-based btc_ensure_cache() for pre-xpub legacy wallets. Receive must
  // work on a plain daily-door unlock — it must NOT require a spend session,
  // so there is no upfront btc_ensure_cache() gate here (that gate used to
  // block Receive entirely under the two-door model, since the seed isn't
  // resident on a daily unlock — see btc_show_wallet_info() above for the
  // same seed-free pattern already applied there).
  if (!btc_derive_receive_address(idx, addr, sizeof(addr))) {
    dispError("Address derive failed");
    errorPause();
    return;
  }
  btc_address_fingerprint(addr, fp);
  btc_draw_receive(addr, idx, fp);

  while (true) {
    // Background btnPollTask polls all buttons; don't poll here (races it).
    esp_task_wdt_reset();
    if (wsStarted) { webSocket.loop(); webSocket2.loop(); }
    delay(5);

    if (btn4.isPressed()) {   // BACK -> exit Receive
      g_btc_recv_index = (idx > g_btc_recv_index) ? idx : g_btc_recv_index;
      btc_save_recv_index();
      return;
    }

    if (btn1.isPressed()) {              // SCROLL DOWN (phys BTN3) = next address
      // Cap unbounded advance to prevent NVS pollution / weird states.
      // 100 unused addresses is well past the BIP-44 gap limit (20); if
      // a user has wandered this far without funding any, they should be
      // prompted to sync with the PWA which knows what's actually on-chain.
      if (idx >= 99) {
        dispError("Too many unused");
        errorPause();
        btc_draw_receive(addr, idx, fp);
        continue;
      }

      idx++;
      g_btc_recv_index = idx;
      btc_save_recv_index();

      uint32_t t0 = millis();
      if (!btc_derive_receive_address(idx, addr, sizeof(addr))) {
        dispError("Address derive failed");
        errorPause();
        return;
      }
      uint32_t t_derive = millis() - t0;
      btc_address_fingerprint(addr, fp);
      uint32_t t1 = millis();
      btc_draw_receive(addr, idx, fp);
      uint32_t t_render = millis() - t1;
      Serial.printf("[btc/recv] #%u derive=%lums render=%lums\n",
                    (unsigned)idx, t_derive, t_render);
    }

    if (btn3.isPressed()) {              // SCROLL UP (phys BTN4) = previous address
      // Previous address. Clamp at 0 — no negative indices.
      if (idx == 0) {
        // No-op: bump the screen so the user knows the tap was seen but
        // we're already at #0. Cheap visual ack rather than total silence.
        btc_draw_receive(addr, idx, fp);
      } else {
        idx--;
        // Do NOT persist a backwards step. The persisted index is the
        // "highest we've reached" — backing up to verify a prior address
        // shouldn't lose track of forward progress. When the user re-enters
        // Receive, they resume at the highest reached index, not at idx-N.
        // (If we did persist backwards steps, advancing past the old high
        // water mark would re-derive addresses they already showed someone.)
        uint32_t t0 = millis();
        if (!btc_derive_receive_address(idx, addr, sizeof(addr))) {
          dispError("Address derive failed");
          errorPause();
          return;
        }
        uint32_t t_derive = millis() - t0;
        btc_address_fingerprint(addr, fp);
        uint32_t t1 = millis();
        btc_draw_receive(addr, idx, fp);
        uint32_t t_render = millis() - t1;
        Serial.printf("[btc/recv] #%u derive=%lums render=%lums\n",
                      (unsigned)idx, t_derive, t_render);
      }
    }

    // 29 Oct 2026: the hold-DOWN exit is gone. Holding DOWN to step through
    // addresses quickly used to drop you out of Receive; BACK is the way out.
  }
}

// 29 Oct 2026: runBitcoinMenu() removed - unreachable since the doors replaced it (23 Sep 2026).

// (removed 11 Sep 2026: the PWA no longer carries any Bitcoin surface —
//  every /api/btc/* endpoint and the mempool proxy were deleted with it.
//  Bitcoin exists only behind the BITCOIN door, offline, on the device.)
// (removed 11 Sep 2026: the PWA no longer carries any Bitcoin surface —
//  every /api/btc/* endpoint and the mempool proxy were deleted with it.
//  Bitcoin exists only behind the BITCOIN door, offline, on the device.)

//
// /api/btc/sign_psbt receives a PSBT (base64), parses it, displays the
// transaction summary on the device's screen, waits for user confirmation
// via BTN1 (reject) or BTN2 (approve), then signs each input the user
// owns and returns the partial signatures as JSON.
//
// The on-screen confirmation is the trust boundary — the device extracts
// amount/recipient/fee directly from the PSBT bytes and shows the user.
// A compromised PWA cannot lie to the user about what's being signed
// because the device draws its display data from the same bytes it signs.

// ── Static state for the confirmation screen ────────────────────────────
// We avoid passing massive structs through ESPAsyncWebServer's handler
// chain by keeping the parsed PSBT + summary as file-static globals. The
// confirmation function reads them, the API handler populates them. Only
// one PSBT can be in flight at a time (single-user device).
// PSBT parse buffer. Multisig grew psbt_t from ~2.2KB to ~15KB (7 derivation
// records + a 256-byte witness script per input/output), which is far too much
// INTERNAL .bss for a structure only ever used in an offline ceremony boot —
// the same reasoning that moved the UR decoder to PSRAM. Allocated on first
// use, never freed, and reached through the macro below so every existing
// `g_pending_psbt` / `&g_pending_psbt` / `sizeof(g_pending_psbt)` still works.
static psbt_t          *g_psbt_buf = nullptr;
#define g_pending_psbt (*g_psbt_buf)
static bool psbtBufEnsure() {
  if (!g_psbt_buf) {
    g_psbt_buf = (psbt_t *)ps_malloc(sizeof(psbt_t));
    if (!g_psbt_buf) g_psbt_buf = (psbt_t *)malloc(sizeof(psbt_t));
    if (g_psbt_buf) memset(g_psbt_buf, 0, sizeof(psbt_t));
  }
  return g_psbt_buf != nullptr;
}
static psbt_summary_t   g_pending_summary;
static int              g_psbt_scroll = 0;     // vertical scroll offset (px)
static int              g_psbt_content_h = 0;  // total content height (px), set by draw

// Helper: format a uint64 with thousand separator commas into `out`
// (caller-supplied buffer, must be ≥24 bytes for 64-bit max + commas).
static void formatSats(uint64_t v, char *out) {
  char tmp[24];
  int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
  int outp = 0;
  for (int i = 0; i < n; i++) {
    out[outp++] = tmp[i];
    int remaining = n - 1 - i;
    if (remaining > 0 && remaining % 3 == 0) out[outp++] = ',';
  }
  out[outp] = 0;
}

// Encode a scriptPubKey to a bech32/bech32m address string. Returns true and
// fills `addr` (≥100 bytes) on success; false for unsupported scripts.
static bool psbtSpkToAddr(const uint8_t *spk, uint8_t spk_len, char *addr) {
  addr[0] = 0;
  if (spk_len == 22 && spk[0] == 0x00 && spk[1] == 0x14)
    return segwit_addr_encode("bc", 0, spk + 2, 20, addr);   // P2WPKH
  if (spk_len == 34 && spk[0] == 0x00 && spk[1] == 0x20)
    return segwit_addr_encode("bc", 0, spk + 2, 32, addr);   // P2WSH
  if (spk_len == 34 && spk[0] == 0x51 && spk[1] == 0x20)
    return segwit_addr_encode("bc", 1, spk + 2, 32, addr);   // P2TR
  return false;
}

// Draw an address across wrapped monospace lines at (x, y) in the given
// colour. Returns the y AFTER the last line (so the caller can flow content).
// `yw` writes happen into the sprite already offset for scroll by the caller.
static int psbtDrawAddrWrapped(const char *addr, int x, int y, uint16_t col) {
  fSet(F_MONO); spr.setTextColor(col);
  const int CPL = 21;                 // chars per line at F_MONO within ~210px
  int alen = (int)strlen(addr);
  int line = 0;
  for (int i = 0; i < alen; i += CPL, line++) {
    char piece[CPL + 1] = {0};
    int copy = (alen - i < CPL) ? alen - i : CPL;
    memcpy(piece, addr + i, copy);
    spr.drawString(piece, x, y + line * 13);
  }
  fEnd();
  return y + line * 13;
}

// Small anti-aliased checkmark. Apex (the bottom corner) sits at (cx,cy):
// a short stroke down-right into the corner, then a longer stroke up-right.
// Sized for inline use next to a label. Uses drawWideLine (anti-aliased).
static void drawTick(int cx, int cy, uint16_t col){
  spr.drawWideLine(cx - 4, cy - 3, cx - 1, cy + 1, 2, col);  // short down-stroke
  spr.drawWideLine(cx - 1, cy + 1, cx + 5, cy - 6, 2, col);  // long up-stroke
}

// Draw text with faux-bold weight (the vlw fonts have no bold variant, so we
// over-print with a 1px horizontal offset). Caller sets the font; this sets
// the colour and draws twice. Returns pixel width of the string.
static int drawBold(const char *s, int x, int y, uint16_t col){
  spr.setTextColor(col);
  spr.drawString(s, x, y);
  spr.drawString(s, x + 1, y);   // over-print → heavier stroke
  return spr.textWidth(s);
}

// Render the PSBT confirmation. Content is laid out top-to-bottom into a
// virtual canvas taller than the screen; `scroll` shifts what's visible.
// Sections: SENDING (hero) · TO (each recipient) · CHANGE (verified own,
// or "None") · FEE · TOTAL. A scrollbar appears when content overflows.
//
// Hierarchy follows the device's restraint language: one dominant number
// (the amount leaving), everything else quiet and supporting. Change is
// shown explicitly because a hardware wallet's job is to prove where funds
// go — change returning to a verified own-address is a security signal, and
// change to an *unexpected* address is exactly what this screen exists to
// surface.
#define PSBT_HEADER_H   30      // header band (kept fixed, not scrolled)
#define PSBT_FOOTER_H   44      // footer band: pill buttons at screen bottom
                                // (no status bar on this modal screen)
#define PSBT_VIEW_TOP   PSBT_HEADER_H
#define PSBT_VIEW_BOT   (240 - PSBT_FOOTER_H)
#define PSBT_VIEW_H     (PSBT_VIEW_BOT - PSBT_VIEW_TOP)

static void psbtDrawConfirm(const psbt_summary_t *sum, int scroll) {
  addrbookEnsureLoaded();   // match recipients against known contacts
  spr.fillSprite(C_BG);

  // ── Scrolled content: render into the view window, offset by `scroll`.
  // We draw everything relative to a content-origin y0 that moves up as the
  // user scrolls. Items fully outside the window are cheap (off-canvas).
  // Labels use C_TEXT2 (readable grey) not C_VDIM — in real light VDIM labels
  // vanish. Hierarchy comes from white values vs grey labels, not from making
  // labels faint. Hairline separators give each section a distinct block.
  const int x = 10;
  const int rule_w = 240 - 2 * x;
  int y = PSBT_VIEW_TOP + 8 - scroll;   // running content cursor
  char buf[28];

  // ── Hero (29 Oct 2026, board S2): the first screen answers "how much, to
  // whom, at what cost" before any detail. Amount centred in Archivo Bold 44
  // (28 if it is too wide), SATS in tracked brass, the single recipient's
  // address in full (mono), then one fee / change line. DOWN scrolls on into
  // the full breakdown below, which is unchanged.
  formatSats(sum->total_recipients, buf);
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_44_num); spr.setTextColor(C_EB_INK);
  if (spr.textWidth(buf) <= 224) { spr.drawString(buf, 120 - spr.textWidth(buf) / 2, y); y += 50; }
  else { fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
         spr.drawString(buf, 120 - spr.textWidth(buf) / 2, y + 8); y += 44; }
  fEndHard();
  uiTrackLabel("SATS", 120, y, C_EB_BRASS);
  y += 22;
  if (sum->n_recipients == 1) {
    char a1[100];
    if (psbtSpkToAddr(sum->recipients[0].script_pubkey, sum->recipients[0].script_pubkey_len, a1)) {
      // Centre the wrapped address block: 21 mono chars a line.
      int len = (int)strlen(a1), lines = (len + 20) / 21;
      fSet(F_MONO); spr.setTextColor(C_EB_INK);
      for (int i = 0; i < lines; i++) {
        char piece[22] = {0}; int c = (len - i * 21 < 21) ? len - i * 21 : 21;
        memcpy(piece, a1 + i * 21, c);
        spr.drawString(piece, 120 - spr.textWidth(piece) / 2, y + i * 14);
      }
      y += lines * 14 + 8;
    }
  } else if (sum->n_recipients > 1) {
    char l[32]; snprintf(l, sizeof(l), "to %d recipients", sum->n_recipients);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_INK);
    spr.drawString(l, 120 - spr.textWidth(l) / 2, y); fEndHard(); y += 22;
  }
  {
    char f[20], l[64]; formatSats(sum->fee, f);
    const char* ch = sum->n_changes_unverified > 0 ? "change NOT verified"
                   : sum->n_changes > 0 ? "change is yours" : "no change";
    snprintf(l, sizeof(l), "Fee %s sats, %s", f, ch);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13);
    spr.setTextColor(sum->n_changes_unverified > 0 ? C_RED : C_EB_GREY);
    if (spr.textWidth(l) > 220) { snprintf(l, sizeof(l), "Fee %s sats", f); }
    spr.drawString(l, 120 - spr.textWidth(l) / 2, y);
    fEndHard();
    y += 30;
  }

  // ── separator ──
  spr.drawFastHLine(x, y, rule_w, C_BORDER); y += 12;

  // TO — recipients (each shown in full; multiple stack vertically)
  fSet(F_HEAD_SM); spr.setTextColor(C_TEXT2);
  spr.drawString(sum->n_recipients > 1 ? "RECIPIENTS" : "TO", x, y); fEnd();
  y += 18;
  if (sum->n_recipients == 0) {
    fSet(F_BODY); spr.setTextColor(C_RED);
    spr.drawString("(no recipients)", x, y); fEnd();
    y += 18;
  } else {
    for (int r = 0; r < sum->n_recipients; r++) {
      if (sum->n_recipients > 1) {
        char lbl[16]; snprintf(lbl, sizeof(lbl), "%d/%d", r + 1, sum->n_recipients);
        fSet(F_BODY); spr.setTextColor(C_MUTED);
        spr.drawString(lbl, x, y); fEnd();
        formatSats(sum->recipients[r].value, buf);
        fSet(F_BODY); spr.setTextColor(C_FG);
        spr.drawString(buf, x + 36, y); fEnd();
        y += 18;
      }
      char addr[100];
      if (psbtSpkToAddr(sum->recipients[r].script_pubkey,
                        sum->recipients[r].script_pubkey_len, addr)) {
        // Address-book lookup — known contact vs first-time recipient. A
        // matched contact gets a green tick + label; an unknown address is
        // shown amber as "New address" so a substituted recipient can't pose
        // as someone you trust. Match is on the canonical address string.
        int abi = addrbookFind(addr);
        if (abi >= 0) {
          drawTick(x + 4, y + 8, C_GREEN);
          fSet(F_BODY); drawBold(g_addrbook[abi].label, x + 16, y, C_GREEN); fEnd();
          y += 19;
          y = psbtDrawAddrWrapped(addr, x, y, C_TEXT2) + 13;
        } else {
          spr.fillCircle(x + 3, y + 7, 3, C_BTC_ACCENT);  // amber dot = unknown
          fSet(F_BODY); spr.setTextColor(C_BTC_ACCENT);
          spr.drawString("New address", x + 14, y); fEnd();
          y += 19;
          y = psbtDrawAddrWrapped(addr, x, y, C_BTC_ACCENT) + 13;
        }
      } else {
        fSet(F_BODY); spr.setTextColor(C_RED);
        spr.drawString("(unsupported script)", x, y); fEnd();
        y += 15;
      }
      y += 4;
    }
  }

  // ── separator ──
  y += 2;
  spr.drawFastHLine(x, y, rule_w, C_BORDER); y += 12;

  // CHANGE — verified to return to our own wallet, or none. Shown distinctly
  // so the user can confirm change isn't being diverted.
  fSet(F_HEAD_SM); spr.setTextColor(C_TEXT2);
  spr.drawString("CHANGE", x, y); fEnd();
  if (sum->n_changes == 0) {
    fSet(F_BODY); spr.setTextColor(C_MUTED);
    spr.drawString("none", x + 80, y - 2); fEnd();
    y += 18;
  } else {
    formatSats(sum->total_change, buf);
    fSet(F_HEAD); spr.setTextColor(C_FG);
    spr.drawString(buf, x + 80, y - 4); fEnd();
    y += 22;
    // Each change output with its own verification verdict.
    for (int c = 0; c < sum->n_changes; c++) {
      char addr[100];
      bool have_addr = psbtSpkToAddr(sum->changes[c].script_pubkey,
                                     sum->changes[c].script_pubkey_len, addr);
      if (sum->changes[c].verified) {
        // Green tick + bold "Verified" — instantly scannable security state.
        drawTick(x + 4, y + 8, C_GREEN);
        fSet(F_BODY);
        drawBold("Verified", x + 16, y, C_GREEN); fEnd();
        y += 19;
        fSet(F_BODY); spr.setTextColor(C_MUTED);
        spr.drawString("returns to your wallet", x, y); fEnd();
        y += 17;
        if (have_addr) y = psbtDrawAddrWrapped(addr, x, y, C_TEXT2) + 13;
      } else {
        // Red X + bold warning — the attack-surface case, equally scannable.
        spr.drawWideLine(x, y + 1, x + 8, y + 9, 2, C_RED);   // ╲
        spr.drawWideLine(x + 8, y + 1, x, y + 9, 2, C_RED);   // ╱
        fSet(F_BODY);
        drawBold("UNVERIFIED", x + 16, y, C_RED); fEnd();
        y += 19;
        fSet(F_BODY); spr.setTextColor(C_RED);
        spr.drawString("address not yours - check!", x, y); fEnd();
        y += 17;
        if (have_addr) y = psbtDrawAddrWrapped(addr, x, y, C_RED) + 13;
      }
      y += 4;
    }
  }

  // ── separator ──
  y += 2;
  spr.drawFastHLine(x, y, rule_w, C_BORDER); y += 12;

  // FEE
  fSet(F_HEAD_SM); spr.setTextColor(C_TEXT2);
  spr.drawString("FEE", x, y + 2); fEnd();
  formatSats(sum->fee, buf);
  fSet(F_HEAD); spr.setTextColor(C_FG);
  spr.drawString(buf, x + 80, y - 2);
  int feew = spr.textWidth(buf); fEnd();
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  spr.drawString("sat", x + 80 + feew + 4, y + 3); fEnd();
  y += 26;

  // TOTAL — what actually leaves the wallet (recipients + fee)
  fSet(F_HEAD_SM); spr.setTextColor(C_TEXT2);
  spr.drawString("TOTAL", x, y + 2); fEnd();
  formatSats(sum->total_recipients + sum->fee, buf);
  fSet(F_HEAD); spr.setTextColor(C_FG);
  spr.drawString(buf, x + 80, y - 2);
  int totw = spr.textWidth(buf); fEnd();
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  spr.drawString("sat", x + 80 + totw + 4, y + 3); fEnd();
  y += 28;

  // Record total content height (for scroll clamping). y is in screen coords
  // shifted by -scroll, so content height = (y + scroll) - view_top.
  g_psbt_content_h = (y + scroll) - PSBT_VIEW_TOP;

  // ── Fixed bands drawn on top (mask any content that scrolled under them) ──
  bool danger = (sum->n_changes_unverified > 0) || (sum->n_recipients == 0);
  spr.fillRect(0, 0, 240, PSBT_HEADER_H, C_BG);
  if (danger) {
    uiHeader("CHECK TX", C_RED);
  } else if (g_psbt_ms_wallet >= 0 && g_ms) {
    // Multisig: the header names the wallet and its policy, so the user can
    // see WHICH quorum is being spent from before reading a single amount.
    const ms_wallet_t *w = &g_ms->w[g_psbt_ms_wallet];
    char h[32]; snprintf(h, sizeof(h), "%u OF %u - %s", (unsigned)w->m, (unsigned)w->n, w->name);
    uiHeader(h, C_EB_BRASS);
  } else {
    uiHeader("CONFIRM TX", C_EB_BRASS);
  }

  spr.fillRect(0, PSBT_VIEW_BOT, 240, PSBT_FOOTER_H, C_BG);

  // ── Scrollbar (only if content overflows the viewport) ──
  // 3px wide to read as a deliberate element (matches the old accent stripe
  // weight we removed). Rounded ends for a cleaner look.
  bool overflow = g_psbt_content_h > PSBT_VIEW_H;
  if (overflow) {
    int trackX = 240 - 5, trackY = PSBT_VIEW_TOP + 2, trackH = PSBT_VIEW_H - 4;
    spr.fillRoundRect(trackX, trackY, 3, trackH, 1, C_BORDER);
    int maxScroll = g_psbt_content_h - PSBT_VIEW_H;
    if (maxScroll < 1) maxScroll = 1;
    int thumbH = trackH * PSBT_VIEW_H / g_psbt_content_h;
    if (thumbH < 14) thumbH = 14;
    int thumbY = trackY + (trackH - thumbH) * scroll / maxScroll;
    spr.fillRoundRect(trackX, thumbY, 3, thumbH, 1, C_BTC_ACCENT);
  }

  // ── Footer (29 Oct 2026): HOLD ENTER TO SIGN, BACK declines ──
  // Was a red DECLINE pill (wired to a hidden hold of DOWN) and a green ACCEPT
  // pill (a tap). Now one rule for every serious action on the KEY: hold ENTER
  // to act, BACK to decline. Unverified change keeps its red danger prompt.
  {
    bool needHold = (sum->n_changes_unverified > 0);
    uiHoldFooter(needHold ? "HOLD ENTER IF SURE" : "HOLD ENTER TO SIGN",
                 overflow ? "BACK declines   DOWN for more" : "BACK declines",
                 0.0f, needHold ? C_RED : C_EB_BRASS);
  }

  dispPush();
}

// ── Async PSBT confirmation flow ────────────────────────────────────────
//
// The HTTP handler cannot block waiting for button presses — the
// WebServer task and the main loop are the same task, so blocking the
// handler starves the screen rendering and button polling. Instead we
// use the same pattern as `pendingApproval` / iOS sign:
//
//   1. Handler parses PSBT, builds summary, stores state, returns 202
//      with an id. Sets `g_psbt_pending = true`.
//   2. Main loop sees `g_psbt_pending` at its top, draws the confirmation
//      screen, polls buttons. On press, sets approved/rejected flag and
//      clears `g_psbt_pending`.
//   3. PWA polls /api/btc/sign_psbt/result. Returns:
//        {status:"pending"}       — still waiting on user
//        {status:"approved", signatures:[...], summary:{...}}
//        {status:"rejected"}      — BTN1 long-press or timeout
//
// The PWA shows "Confirm on device…" between the 202 and the final
// result, polling every ~500ms.

// State machine for the in-flight PSBT
enum {
  PSBT_STATE_IDLE = 0,
  PSBT_STATE_PENDING,    // displayed, waiting on user
  PSBT_STATE_SPEND_PIN,  // user approved; entering spend PIN on-device (Task 3)
  PSBT_STATE_APPROVED,   // signatures computed
  PSBT_STATE_REJECTED,   // user pressed BTN1-long, OR timeout, OR error
};
static volatile uint8_t g_psbt_state = PSBT_STATE_IDLE;
static char             g_psbt_id[33]    = {0};     // 32-hex random
static int              g_psbt_recipient_page = 0;
static unsigned long    g_psbt_start_ms  = 0;
static bool             g_psbt_drawn     = false;
static unsigned long    g_psbt_drawn_ms  = 0;   // 29 Oct 2026: when the confirm screen appeared (hold-to-sign must start after it)
static psbt_partial_sig_t g_psbt_sigs[PSBT_MAX_SIGNABLE_INPUTS];
static int              g_psbt_n_sigs    = 0;
static char             g_psbt_error[64] = {0};

// Spend-PIN entry state (Task 3). Spending is gated by the spend PIN, ALWAYS
// typed on the device (even for PWA-initiated sends) so the PIN never leaves
// the trusted display. These mirror the onboarding PIN-entry vars but are
// local to the PSBT flow so they never collide with onboarding's pinBuf.
static char  g_psbt_pin[9]      = {0};   // entered spend PIN (PIN_NEW_LEN digits)
static int   g_psbt_pin_digit   = 0;     // cursor 0..PIN_NEW_LEN-1
static bool  g_psbt_pin_confirm = false; // armed-to-submit (all digits entered)
static bool  g_psbt_pin_drawn   = false; // screen painted this entry?

// Whether main loop should yield/draw the PSBT confirmation. Sub-menus
// poll this same way they poll pendingApproval. Includes the spend-PIN
// sub-state so the PSBT flow keeps ownership of the screen through signing,
// and the relock-pending window after signing completes — the main loop
// must keep calling psbtTickPoll() during that window too, or its fallback
// timeout (in case the PWA never fetches the result) would never run.
bool psbtConfirmActive() {
  return g_psbt_state == PSBT_STATE_PENDING ||
         g_psbt_state == PSBT_STATE_SPEND_PIN ||
         g_psbt_relock_pending;
}

// Called by main loop when entering the PSBT confirmation screen for
// the first time, and on each recipient page change. Lives in the main
// task so it can safely touch the TFT.
void psbtTickDraw() {
  // Don't paint the confirm screen while the spend-PIN sub-state owns the
  // display — psbtPollSpendPin draws its own screen. Same for the
  // relock-pending window: the "Tx signed" success screen (or the on-device
  // error screen for a failed/wrong-PIN attempt) is already showing at this
  // point, and g_pending_summary describes a transaction that's already
  // done — redrawing the confirm screen here would incorrectly paint over
  // that with stale data.
  if (g_psbt_state == PSBT_STATE_SPEND_PIN) return;
  if (g_psbt_relock_pending) return;
  if (!g_psbt_drawn) {
    g_psbt_scroll = 0;
    psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
    g_psbt_drawn = true;
    g_psbt_drawn_ms = millis();
    // Drain any in-flight button presses from before the screen appeared
    btn1.resetHold(); btn2.resetHold();
  }
}

// ── Spend-PIN entry screen (Task 3) ──────────────────────────────────────
// Reuses the dot-row + hero-digit idiom of the onboarding PIN screen, but
// reads the PSBT-local entry vars so it never collides with onboarding state.
// Always drawn on the device — the spend PIN is never accepted from the PWA.
static void psbtDrawSpendPin() {
  // Entropy Ember (5 Oct 2026): the BTC PIN screen is the Nostr unlock
  // screen's chrome (pinDrawChrome in main.cpp — ember mark, tracked label,
  // position squares, no footer) with the label "BTC PIN", so the user always
  // reads which door they are opening. Same hero-digit metrics as dispPin.
  g_pinMark = { 1.0f, 0.0f, (uint8_t)(g_psbt_pin_confirm ? 150 : 255), false, 0 };
  pinDrawChrome("BTC PIN", C_EB_BRASS,
                g_psbt_pin_confirm ? PIN_NEW_LEN : g_psbt_pin_digit,
                g_psbt_pin_confirm ? -1 : g_psbt_pin_digit, PIN_NEW_LEN);
  if (g_psbt_pin_confirm) {
    fSet(F_HEAD); spr.setTextColor(C_EB_BRASS);
    fDrawCentre("PRESS TO CONFIRM", 120, 170);
    fEnd();
  } else {
    const int DIGIT_IN_BOX = 15;                       // see dispPin for the derivation
    fSet(F_TITLE); spr.setTextColor(C_EB_INK);
    char ch[2] = { g_psbt_pin[g_psbt_pin_digit], 0 };
    fDrawCentre(ch, 120, PIN_INK_CY - DIGIT_IN_BOX);
    fEnd();
  }
  dispPush();
}

// ── Gated sign ───────────────────────────────────────────────────────────
// Called once the spend PIN is fully entered. Verifies the PIN with the SE,
// has the G0 witness the latch, then hands every input to the G0 to sign
// (psbtG0SignInput) and cross-checks each returned pubkey + sighash. No seed
// is ever unwrapped on this processor - see SEED SOURCE at the top.
// Returns: >0 sig count on success, 0 on wrong-PIN (caller may let the user
// retry; the SE enforces the 10-attempt lockout), <0 on unwrap/sign failure.
// Reset the device after a spend excursion via a clean reboot. The SE has a
// single session slot, so the spend tore down the DAILY session that Nostr
// signing depends on, and the user must re-unlock regardless. Rather than an
// in-place relock (which was slow — ~7-8s of session/relay teardown — and left
// the heap fragmented after the unwrap/sign/PSBT allocations), we do a clean
// reboot:
//   - BTC spends are rare, so a reboot's cost is paid infrequently.
//   - Spends can't happen during an active bunker session, so there's no live
//     relay/bunker connection to lose.
//   - The reboot returns a pristine heap, which directly helps our recurring
//     RAM pressure after the signing path's transient allocations.
//   - The user re-enters the daily PIN on the post-boot lock screen — the same
//     re-unlock the in-place relock required, just from a clean boot.
// secureRestart() already wipes session credentials (clearKeyCache) and shows a
// deliberate-restart screen before esp_restart().
static void psbtRelockAfterSpend() {
  mbedtls_platform_zeroize(wallet.seed, 64);   // belt-and-suspenders before the restart screen delay
  wallet.hasSeed = false;
  LOG_BOOT("[psbt] spend complete → secure restart (clean heap, re-unlock on boot)\n");
  secureRestart("Signed", "Transaction signed. Enter your PIN again to continue.");
}

// ── Spend-time cache integrity check ─────────────────────────────────────
// The seed-free paths (receive addresses, PSBT change verification, the PWA
// fingerprint) all trust the persisted account xpub + master fingerprint cached
// at onboarding. If that cache ever drifts from the actual seed — older firmware
// that stored a wrong fingerprint, a botched migration, a half-completed
// re-onboard, NVS corruption — the device would derive addresses / verify change
// against a wallet the seed does not control. That is the same class of footgun
// as receiving to a stale wallet, but device-side.
//
// A spend is the one post-onboarding moment the seed is available, so it's where
// we VERIFY the cache against ground truth. Re-derive the account xpub + master
// fingerprint from the live seed and compare to the cache:
//   - everything matches            → proceed (no-op).
//   - xpub matches, only fp differs → benign stale metadata (e.g. a legacy
//                                      fingerprint). Heal silently: correct the
//                                      RAM mirror + re-persist, then proceed.
//   - xpub itself differs           → DANGER: the cached watch-only wallet does
//                                      not belong to this seed. Receive addresses
//                                      may have been wrong. Refuse to sign.
// Returns: 0 ok (matched or healed), -1 on xpub mismatch (caller must abort).
// (psbtVerifyCacheAgainstSeed removed in v3: the cached xpub is rewritten from
// the G0's DOORKEYS answer at every door entry, so it cannot disagree with the
// seed the G0 holds; there is no seed on this processor to compare against.)

// ── Witnessed spend session (16 Sep 2026, v3) ────────────────────────────
// Open the spend session with g_psbt_pin and get MODE_PCR to BTC by way of
// the G0. Every signature goes through this; the G0 then strips the seed's
// layers in ITS session, signs, and burns the latch (BTC -> SPENT), so BTC
// never persists: power-off, crash or a pulled G0 leaves SPENT, which no key
// gate matches. Sequence:
//   open spend session -> read latch
//     BTC     (crash inside the unwrap window) -> proceed
//     NEUTRAL / SPENT -> close session, g0_mode_btc() (the G0 reads the latch
//                        over ITS session and re-extends only from those two),
//                        reopen spend session, verify == BTC
//     NOSTR / other   -> refuse
// Returns 1 with the session OPEN and the latch at BTC; 0 = wrong PIN (caller
// may retry); -1 = refused (message already shown / logged). Always clears
// g_psbt_pin before returning.
static void psbtClearSpendPin();   // defined below (declaration-order rule — see favilla-build-traps)
// v3 (16 Sep 2026): the witness no longer ends with an open spend session,
// because this processor never unwraps anything any more. Sequence:
//   open spend session (SE verifies the PIN) -> read latch (refuse NOSTR) ->
//   ARM (extend "FAVILLA-MODE-ARM", a PIN-session WRITE) -> close ->
//   g0_mode_btc() (G0 accepts only an ARMed latch; resets, extends S) ->
//   reopen -> verify latch == BTC -> close.
// v5 (15 Oct 2026): inner_pkt_out != nullptr -> while the reopened spend
// session is still open and the latch reads BTC, the SE strips its own layer
// of the seed blob (the seed key's DEC right belongs to the SPEND PIN, gated
// on BTC) and this processor packs the result, which is still the G0's inner
// layer, into the SEED_IN/ENT_IN packet. The G0 command that follows
// (DOORKEYS / BTCSIGN) re-reads the latch over ITS session, refuses unless it
// is BTC, burns it to SPENT, and only then strips the inner layer. So opening
// the seed now needs the SE to have verified the spend PIN itself; before v5
// anyone holding the G0's secrets could skip the PIN.
// Returns 1 ok, 0 wrong PIN, -1 refused.
// keepPin: leave g_psbt_pin in place for the next input of the same PSBT.
// BRICK GUARD for the SPEND PIN (24 Sep 2026). The spend object has the same
// SE counter (10) and until now no software counter at all - every wrong
// entry went straight to the SE. Same rule as the daily PIN: never send the
// tenth. A locked spend object is not a brick (the daily session can still
// wipe), but it is a Bitcoin door closed until wipe + restore, so it gets the
// same escalating delays and the same hard stop at 9. Buttons only: there is
// no remote path to the spend PIN.
static int g_spendFails = -1;   // -1 = not loaded yet
static void btcSpendFailsLoad() {
  if (g_spendFails >= 0) return;
  Preferences p; g_spendFails = 0;
  if (p.begin("device", true, NVSPART_SEC)) { g_spendFails = p.getInt("spFails", 0); p.end(); }
  if (g_spendFails < 0) g_spendFails = 0;
}
static void btcSpendFailsSave() {
  Preferences p;
  if (p.begin("device", false, NVSPART_SEC)) { p.putInt("spFails", g_spendFails); p.end(); }
}
static bool btcSpendBudgetSpent() { btcSpendFailsLoad(); return g_spendFails >= PIN_SEND_MAX; }
// 31 Oct 2026: COUNT BEFORE SEND, as the daily and passkey PINs. Counted and
// saved before the spend PIN reaches the SE, so a power cut between the SE's
// decrement and our save can never leave the SE an attempt ahead of the guard.
static void btcSpendPinCountBeforeSend() {
  btcSpendFailsLoad();
  if (g_spendFails < PIN_ATTEMPT_MAX) g_spendFails++;
  btcSpendFailsSave();
  Serial.printf("[PIN] spend PIN attempt counted and saved before the SE check: %d of %d\n", g_spendFails, PIN_SEND_MAX);
}
// The SE refused it: already counted by btcSpendPinCountBeforeSend().
static void btcSpendPinFailed() {
  btcSpendFailsLoad();
  uint32_t lk = (g_spendFails <= PIN_ATTEMPT_MAX) ? PIN_LOCKOUT_SECS[g_spendFails] : 0;
  if (g_spendFails >= PIN_SEND_MAX) { dispPinBudgetSpentForever(); }   // never returns
  if (lk == 0) return;
  // Escalating wait, same table as the daily PIN. Blocking is fine here: this
  // is a ceremony boot, nothing else needs the loop.
  uint32_t t0 = millis();
  while (true) {
    uint32_t el = (millis() - t0) / 1000UL; if (el >= lk) break;
    uint32_t r = lk - el;
    spr.fillSprite(C_BG); uiHeader("WRONG BTC PIN", C_RED);
    fSet(F_HEAD); spr.setTextColor(C_FG); fDrawCentre("Wait before trying again", 120, 70); fEnd();
    char t[24];
    if (r >= 3600) snprintf(t, sizeof t, "%lu h %lu min", (unsigned long)(r / 3600), (unsigned long)((r % 3600) / 60));
    else if (r >= 60) snprintf(t, sizeof t, "%lu min %lu s", (unsigned long)(r / 60), (unsigned long)(r % 60));
    else snprintf(t, sizeof t, "%lu s", (unsigned long)r);
    fSet(F_TITLE); spr.setTextColor(C_BTC_ACCENT); fDrawCentre(t, 120, 104); fEnd();
    char a[32]; snprintf(a, sizeof a, "%d attempts left", PIN_SEND_MAX - g_spendFails);
    fSet(F_BODY); spr.setTextColor(C_RED); fDrawCentre(a, 120, 160); fEnd();
    dispPush();
    esp_task_wdt_reset(); delay(250);
  }
  clearButtonPending();
}
static void btcSpendPinOk() {
  btcSpendFailsLoad();
  if (g_spendFails) { g_spendFails = 0; btcSpendFailsSave(); }
}

static int btcWitnessedSpendOpen(bool showUi, bool keepPin = false, uint8_t* inner_pkt_out = nullptr, uint8_t* kind_out = nullptr) {
  if (btcSpendBudgetSpent()) { psbtClearSpendPin(); dispPinBudgetSpentForever(); }   // never returns
  btcSpendPinCountBeforeSend();
  if (!favilla::se_pin_session_open_obj(favilla::SE_OBJ_PIN_SPEND, g_psbt_pin)) { psbtClearSpendPin(); btcSpendPinFailed(); return 0; }
  btcSpendPinOk();
  int st = favilla::mode_pcr_btc_state_in_open_session();
  if (st < 0) {
    favilla::se_pin_session_close(); psbtClearSpendPin();
    if (showUi) { dispError("Door closed - power cycle"); errorPause(); }
    return -1;
  }
  if (st != 3) {   // 3 = already ARMed (soft reset between arm and mint)
    if (!favilla::mode_pcr_arm_in_open_session()) {
      favilla::se_pin_session_close(); psbtClearSpendPin();
      if (showUi) { dispError("Arm failed"); errorPause(); }
      return -1;
    }
  }
  favilla::se_pin_session_close();   // one SE session at a time: the G0 needs the slot
  if (showUi && !bgSpinnerRunning) pinAnimWorking();   // stay on the ember noise frame — the G0 witness is not a user-facing step (already animating when called from btcDoorUnlock)
  bool witnessed = g0_mode_btc();
  if (!witnessed) {
    psbtClearSpendPin();
    if (showUi) { dispError("Signer did not open door"); errorPause(); }
    return -1;
  }
  if (!favilla::se_pin_session_open_obj(favilla::SE_OBJ_PIN_SPEND, g_psbt_pin)) {
    psbtClearSpendPin();
    if (showUi) { dispError("Session reopen failed"); errorPause(); }
    return -1;
  }
  bool verified = favilla::mode_pcr_verify_btc_in_open_session();
  bool inner_ok = true;
  if (verified && inner_pkt_out) {
    // v5: the SE strips its layer HERE, in the spend session it verified.
    // v5.1: the blob, its kind and the inner-layer hash all come from the G0
    // (one SEEDGET; no SE traffic, so it is fine inside this session). The
    // hash check here only turns a mismatch into a clear message: the G0
    // makes the same check itself before it touches the latch (0xEA).
    uint8_t blob[G0_SEED_IN_LEN], inner[64], ih[32], ihc[32], kind = 0;
    inner_ok = favilla::seed_blob_read(blob, &kind, ih);
    if (inner_ok && kind_out) *kind_out = kind;
    if (inner_ok) inner_ok = favilla::seed_inner_from_blob_in_open_session(blob, inner);
    if (inner_ok) {
      mbedtls_sha256(inner, 64, ihc, 0);
      if (memcmp(ih, ihc, 32) != 0) { inner_ok = false; LOG_BOOT("[btc] v5.1: SE layer opened but the inner layer is not the G0's stored seed - refusing\n"); }
    }
    if (inner_ok) g0_pack_inner_packet(inner, inner_pkt_out);
    else mbedtls_platform_zeroize(inner_pkt_out, G0_SEED_IN_LEN);
    mbedtls_platform_zeroize(blob, sizeof(blob)); mbedtls_platform_zeroize(inner, sizeof(inner));
  }
  favilla::se_pin_session_close();   // nothing key-bearing stays open; the G0 takes it from here
  if (!keepPin) psbtClearSpendPin();
  if (!verified) {
    psbtClearSpendPin();
    if (showUi) { dispError("Door verify failed"); errorPause(); }
    return -1;
  }
  if (!inner_ok) {
    psbtClearSpendPin();
    LOG_BOOT("[btc] v5.1 seed unwrap refused - no seed on the G0, or a KEY onboarded before v5.1: wipe and re-onboard\n");
    if (showUi) { dispError("Re-onboard needed (v5.1)"); errorPause(); }
    return -1;
  }
  return 1;
}

// v3: the signer callback handed to psbt_sign_all / ms_sign_all. One input =
// one spend-PIN-armed G0 mint + one G0 fetch/burn/sign. g_psbt_pin is held
// for the whole PSBT (PIN once per transaction, as before) and cleared by
// psbtGatedSign afterwards.
static int  g_psbt_last_witness = 1;   // 0 = wrong spend PIN on the last input, so the caller can offer a retry
static bool psbtG0SignInput(const uint8_t req[416], uint8_t pub33_out[33],
                            uint8_t der_out[72], uint8_t* der_len_out, uint8_t sighash_out[32]) {
  uint8_t pkt[G0_SEED_IN_LEN]; uint8_t kind = 0;
  int w = btcWitnessedSpendOpen(false, /*keepPin=*/true, pkt, &kind);   // v5: spend session strips the SE layer
  g_psbt_last_witness = w;
  if (w != 1) { mbedtls_platform_zeroize(pkt, sizeof(pkt)); LOG_BOOT("[psbt] input: witnessed arm/mint/unwrap failed (%d)\n", w); return false; }
  bool ok = g0_btc_sign(pkt, req, pub33_out, der_out, der_len_out, sighash_out, kind);   // v4: entropy wallets derive on the G0 with the passphrase it holds
  mbedtls_platform_zeroize(pkt, sizeof(pkt));
  if (!ok && g0_antiexfil_faulted()) dispAntiExfilFaultForever();   // 27 Oct 2026: never returns, never retries
  return ok;
}

static bool psbt_derive_pub_adapter(uint32_t change, uint32_t index, uint8_t pub33_out[33]);   // defined below (declaration-order rule)

static int psbtGatedSign() {
  // ── CEREMONY ENFORCEMENT (fail-closed core, V23) ────────────────────────
  // A PSBT signature can be produced ONLY in a ceremony boot — a boot in
  // which the radio stacks were never initialized. Every signing path
  // funnels through this function (scan router, airgap collector, any
  // future caller), so this single check IS the airgap-only TX doctrine.
  // Returns -100 — deliberately far outside the sign engine's code space so
  // it can never be confused with an engine failure. Caller renders it.
  if (!g_ceremonyBoot) {
    LOG_BOOT("[psbt] sign refused: not a ceremony boot\n");
    return -100;
  }
  // v3 (16 Sep 2026): no seed on this processor. Every input is signed by
  // the G0 (psbtG0SignInput): spend PIN verified by the SE + ARM, G0 mints
  // BTC, G0 has the SE strip the seed's outer layer in ITS session, burns the
  // latch, strips its inner layer, derives, signs, wipes. The spend PIN is
  // entered once per PSBT and reused for each input's arm; it is cleared here
  // on every path. This processor cross-checks the G0's pubkey and sighash
  // against its own for every input before accepting a signature.
  if (!g_btc_xpub_valid) { psbtClearSpendPin(); LOG_BOOT("[psbt] no account xpub for this BTC life - door not opened\n"); return -1; }
  int result;
  g_psbt_last_witness = 1;
  if (g_psbt_ms_wallet >= 0) {
    // Multisig: sign with the m/48'/0'/0'/2' leaf key for the registered
    // wallet. ms_sign_all re-verifies every input against the REGISTERED
    // xpubs (never the PSBT's claims) and refuses the G0's signature unless
    // its leaf pubkey equals the registered cosigner key, so a wallet
    // belonging to a different seed cannot be signed for.
    result = ms_sign_all(&g_ms->w[g_psbt_ms_wallet], &g_pending_psbt, psbtG0SignInput,
                         true, g_psbt_sigs, PSBT_MAX_SIGNABLE_INPUTS);
  } else {
    result = psbt_sign_all(&g_pending_psbt, psbtG0SignInput, psbt_derive_pub_adapter,
                           g_btc_master_fp, true, g_psbt_sigs, PSBT_MAX_SIGNABLE_INPUTS);
  }
  psbtClearSpendPin();
  if (result < 0 && g_psbt_last_witness == 0) { LOG_BOOT("[psbt] spend session open FAILED (wrong PIN or lockout)\n"); return 0; }   // same contract as before: 0 = retry PIN
  if (result < 0) LOG_BOOT("[psbt] G0 signing FAILED (%d)\n", result);
  else LOG_BOOT("[psbt] G0 signed %d input(s)\n", result);
  if (result > 0) { cmRecord(&g_pending_psbt); LOG_BOOT("[psbt] coin memory: amounts of %u input(s) remembered\n", (unsigned)g_pending_psbt.tx.n_inputs); }   // 23 Nov 2026 (#57)
  return result;
}

// Clear the spend-PIN entry buffer + cursor. Call on every exit from the
// spend-PIN sub-state (submit, cancel, timeout) so a typed PIN never lingers.
static void psbtClearSpendPin() {
  mbedtls_platform_zeroize(g_psbt_pin, sizeof(g_psbt_pin));
  g_psbt_pin_digit = 0;
  g_psbt_pin_confirm = false;
  g_psbt_pin_drawn = false;
}

// Called by main loop while in PSBT confirmation. Polls buttons,
// advances state. Returns true if state changed (caller should switch
// screen or repaint).
static bool psbtPollSpendPin();   // fwd decl (defined after psbtTickPoll)
bool psbtTickPoll() {
  // ── Spend-PIN sub-state (Task 3) ────────────────────────────────────────
  if (g_psbt_state == PSBT_STATE_SPEND_PIN) {
    return psbtPollSpendPin();
  }
  // A result is ready and waiting for the PWA (g_psbt_relock_pending is only
  // ever set alongside REJECTED/APPROVED after an actual spend attempt). For
  // an approved spend this now stays true through TWO PWA round-trips —
  // fetching the signature, then broadcasting it (see handleApiBtcProxy,
  // which clears it on a confirmed broadcast) — not just the first fetch, so
  // the timeout needs to comfortably cover both plus the client-side PSBT
  // finalization in between. If nothing ever completes that — crashed tab,
  // dropped network — don't wait forever with a session that's already
  // unusable for Nostr signing anyway; reboot after 45s so the device
  // recovers on its own regardless.
  if (g_psbt_relock_pending && (millis() - g_psbt_start_ms > 45000UL)) {
    LOG_BOOT("[psbt] spend never completed after 45s — rebooting anyway\n");
    g_psbt_relock_pending = false;
    psbtRelockAfterSpend();
    return true;
  }
  if (g_psbt_state != PSBT_STATE_PENDING) return false;
  if (millis() - g_psbt_start_ms > 90000UL) {
    LOG_BOOT("[psbt] poll: TIMEOUT after 90s\n");
    snprintf(g_psbt_error, sizeof(g_psbt_error), "Timeout");
    g_psbt_state = PSBT_STATE_REJECTED;
    g_psbt_drawn = false;
    nextState = ST_MENU;
    dispMenu();
    return true;
  }

  // BACK = decline (29 Oct 2026: was a hidden 1.5 s hold of DOWN, which also
  // fired when someone held DOWN to scroll a long transaction).
  if (btn4.isPressed()) {
    LOG_BOOT("[psbt] poll: BACK -> REJECT\n");
    snprintf(g_psbt_error, sizeof(g_psbt_error), "User rejected");
    g_psbt_state = PSBT_STATE_REJECTED;
    g_psbt_drawn = false;
    btn1.resetHold(); btn2.resetHold();
    drainButtonsAfterTransition();
    nextState = ST_MENU;
    dispMenu();
    return true;
  }

  // Scroll: a paged step that's a large fraction of the viewport, so a few
  // presses traverse a long tx. Clamp to content. BTN1 short = down,
  // BTN3 = up. (BTN1 *hold* is reject, handled above.)
  int maxScroll = g_psbt_content_h - PSBT_VIEW_H;
  if (maxScroll < 0) maxScroll = 0;
  const int STEP = PSBT_VIEW_H * 3 / 4;

  // DOWN = scroll down
  if (btn1.isPressed()) {
    if (maxScroll > 0) {
      g_psbt_scroll += STEP;
      if (g_psbt_scroll > maxScroll) g_psbt_scroll = maxScroll;
      psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
    }
    return false;
  }

  // BTN3 = scroll up
  if (btn3.isPressed()) {
    if (g_psbt_scroll > 0) {
      g_psbt_scroll -= STEP;
      if (g_psbt_scroll < 0) g_psbt_scroll = 0;
      psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
    }
    return false;
  }

  // APPROVE → sign. Two tiers of friction:
  //  - Normal tx (all change verified): a BTN2 tap signs.
  //  - Unverified change present: a tap is NOT enough. The user must HOLD
  //    BTN2 (1.5s) past a DANGER prompt — deliberate friction so a redirected-
  //    change transaction cannot be approved by a reflexive tap. There is
  //    rarely a legitimate reason for a fingerprint-matching output to fail
  //    address re-derivation, so we make approving one a conscious act.
  bool unsafe = (g_pending_summary.n_changes_unverified > 0);
  bool do_sign = false;
  // 29 Oct 2026: every signature is a HOLD of ENTER (1.5 s); a tap does
  // nothing. The press must start after this screen was drawn.
  btn2.isPressed();   // swallow taps so a stale one can't leak to the next screen
  {
    static float lastHp = 0.0f;
    float hp = holdSince(btn2, g_psbt_drawn_ms, 1500);
    if (unsafe && hp > 0.0f && hp < 1.0f) {
      spr.fillSprite(C_BG);
      uiHeader("CHECK TX", C_RED);
      fSet(F_HEAD); spr.setTextColor(C_RED);
      fDrawCentre("UNVERIFIED CHANGE", 120, 64); fEnd();
      fSet(F_BODY); spr.setTextColor(C_TEXT2);
      fDrawCentre("Change address could not", 120, 94);
      fDrawCentre("be confirmed as yours.", 120, 112); fEnd();
      uiHoldFooter("KEEP HOLDING TO SIGN", "Let go to stop", hp, C_RED);
      dispPush(); lastHp = hp;
      return false;
    }
    if (!unsafe && hp > 0.0f && hp < 1.0f) {
      uiHoldFooter("HOLD ENTER TO SIGN", "Let go to stop", hp);
      dispPushRegion(0, 196, 240, 44); lastHp = hp;
      return false;
    }
    if (hp >= 1.0f) { do_sign = true; btn2.resetHold(); lastHp = 0.0f; }
    else if (lastHp > 0.0f) { lastHp = 0.0f; psbtDrawConfirm(&g_pending_summary, g_psbt_scroll); }
  }

  if (do_sign) {
    LOG_BOOT("[psbt] poll: APPROVE (unsafe=%d) → spend-PIN entry\n", (int)unsafe);
    // Task 3: approval no longer signs directly. Spending requires the spend
    // PIN, entered ON THE DEVICE. Transition to the spend-PIN sub-state; the
    // actual sign happens in psbtPollSpendPin once the PIN is entered and a
    // SPEND session is opened. The seed is never resident until then.
    psbtClearSpendPin();
    for (int i = 0; i < PIN_NEW_LEN; i++) g_psbt_pin[i] = '0';
    g_psbt_pin[PIN_NEW_LEN] = 0;
    btn1.resetHold(); btn2.resetHold();
    drainButtonsAfterTransition();
    g_psbt_state = PSBT_STATE_SPEND_PIN;
    g_psbt_start_ms = millis();   // reset the 90s window for PIN entry
    return true;
  }

  return false;
}

// ── Spend-PIN sub-state poll (Task 3) ────────────────────────────────────
// Non-blocking digit entry mirroring the onboarding PIN scheme:
//   BTN4 (btn3) scroll up, BTN3 (btn1) scroll down, BTN1 (btn2) enter/advance,
//   BTN2 (btn4) back / cancel. Submitting opens a SPEND session and signs.
static bool psbtPollSpendPin() {
  if (!g_psbt_pin_drawn) {
    psbtDrawSpendPin();
    g_psbt_pin_drawn = true;
    btn1.resetHold(); btn2.resetHold();
    return false;
  }

  // 90s timeout (reset on entry) — abandon and clear the typed PIN.
  if (millis() - g_psbt_start_ms > 90000UL) {
    LOG_BOOT("[psbt] spend-PIN: TIMEOUT\n");
    psbtClearSpendPin();
    snprintf(g_psbt_error, sizeof(g_psbt_error), "Timeout");
    g_psbt_state = PSBT_STATE_REJECTED;
    g_psbt_drawn = false;
    nextState = ST_MENU; dispMenu();
    return true;
  }

  // Cancel (29 Oct 2026): BACK on the first digit. Was a hidden 1.5 s hold of
  // DOWN, the same button that lowers the digit.
  if (!pinChordDefer() && g_psbt_pin_digit == 0 && !g_psbt_pin_confirm && btn4.isPressed()) {
    LOG_BOOT("[psbt] spend-PIN: cancelled\n");
    psbtClearSpendPin();
    snprintf(g_psbt_error, sizeof(g_psbt_error), "User cancelled");
    g_psbt_state = PSBT_STATE_REJECTED;
    g_psbt_drawn = false;
    btn1.resetHold(); btn2.resetHold();
    drainButtonsAfterTransition();
    nextState = ST_MENU; dispMenu();
    return true;
  }

  // ENTER+BACK together: verify the device before typing the PIN.
  if (pinVerifyChord()) { g_psbt_pin_drawn = false; g_psbt_start_ms = millis(); return false; }
  const bool chDefer = pinChordDefer();
  if (btn3.isPressed()) {                 // scroll digit up
    if (!g_psbt_pin_confirm) {
      g_psbt_pin[g_psbt_pin_digit] = ((g_psbt_pin[g_psbt_pin_digit]-'0'+1)%10)+'0';
      psbtDrawSpendPin();
    }
    return false;
  }
  if (btn1.isPressed()) {                 // scroll digit down (short press)
    if (!g_psbt_pin_confirm) {
      g_psbt_pin[g_psbt_pin_digit] = ((g_psbt_pin[g_psbt_pin_digit]-'0'+9)%10)+'0';
      psbtDrawSpendPin();
    }
    return false;
  }
  if (!chDefer && btn4.isPressed()) {     // back / un-arm
    if (g_psbt_pin_confirm) {
      g_psbt_pin_confirm = false; g_psbt_pin_digit = PIN_NEW_LEN-1; psbtDrawSpendPin();
    } else if (g_psbt_pin_digit > 0) {
      g_psbt_pin_digit--; psbtDrawSpendPin();
    }
    return false;
  }
  if (!chDefer && btn2.isPressed()) {     // enter / advance / submit
    if (!g_psbt_pin_confirm) {
      if (++g_psbt_pin_digit == PIN_NEW_LEN) { g_psbt_pin_digit = PIN_NEW_LEN-1; g_psbt_pin_confirm = true; }
      psbtDrawSpendPin();
      return false;
    }
    // Submit: ember noise frame while the spend door opens and the sig computes.
    pinAnimSetup("BTC PIN", PIN_NEW_LEN, "SIGNING", "SIGNED", false);
    pinAnimWorking();

    int n;
    { BgSpin _signSpin(C_EB_BRASS); n = psbtGatedSign(); }   // 5 Oct 2026: the ember keeps moving through every input's G0 mint + sign
    psbtClearSpendPin();   // wipe the typed PIN immediately after use
    if (n > 0) pinAnimSuccess();

    if (n == 0) {
      // Wrong PIN (or SE lockout). The spend-open attempt already tore down the
      // daily session (single SE slot), so we can't cleanly retry in place —
      // relock and let the user re-unlock, then re-attempt the spend. BTC is
      // spent rarely, so this is acceptable friction. The SE enforces the
      // 10-attempt lockout on the spend PIN itself.
      LOG_BOOT("[psbt] spend-PIN: wrong PIN → relock\n");
      pinAnimFail("WRONG BTC PIN");
      snprintf(g_psbt_error, sizeof(g_psbt_error), "Wrong BTC PIN");
      g_psbt_state = PSBT_STATE_REJECTED;
      g_psbt_drawn = false;
      g_psbt_relock_pending = true;
      g_psbt_start_ms = millis();   // reset: now timing "unfetched result" instead
      return true;
    }

    if (n == -100) {
      // Not a ceremony boot (V23). Shouldn't be reachable — the router and
      // collector gate PSBTs into the ceremony long before the PIN screen —
      // but if any path slips through, refuse loudly rather than sign.
      LOG_BOOT("[psbt] non-ceremony sign attempt blocked\n");
      dispError("Airgap ceremony required"); errorPause();
      snprintf(g_psbt_error, sizeof(g_psbt_error), "Ceremony required");
      g_psbt_state = PSBT_STATE_REJECTED;
      g_psbt_drawn = false;
      g_psbt_start_ms = millis();
      return true;
    }

    if (n == -2) {
      // Cache integrity check failed: the persisted watch-only wallet does not
      // match the seed. Refuse to sign and warn clearly — this is a wrong-wallet
      // condition, not a transient error. Re-onboarding (or Delete Key + restore)
      // re-syncs the cache to the seed.
      LOG_BOOT("[psbt] cache/seed mismatch → refusing to sign\n");
      dispError("Wallet mismatch - re-onboard"); errorPause();
      snprintf(g_psbt_error, sizeof(g_psbt_error), "Wallet cache mismatch");
      g_psbt_state = PSBT_STATE_REJECTED;
      g_psbt_drawn = false;
      g_psbt_relock_pending = true;
      g_psbt_start_ms = millis();
      return true;
    }

    if (n < 0) {
      snprintf(g_psbt_error, sizeof(g_psbt_error), "Signing failed");
      __sync_synchronize();
      g_psbt_state = PSBT_STATE_REJECTED;
    } else {
      g_psbt_n_sigs = n;
      __sync_synchronize();
      g_psbt_state = PSBT_STATE_APPROVED;
      // 5 Oct 2026: pinAnimSuccess already played SIGNED (burst + dissolve);
      // the ring-and-tick screen that followed it was a duplicate.
      delay(200);
      btn1.resetHold(); btn2.resetHold();
      drainButtonsAfterTransition();
    }
    g_psbt_drawn = false;
    // Spend complete (success or sign-failure): the daily session was torn
    // down by the spend, so a relock+reboot is needed to restore Door 1
    // (Nostr + watch-only) on re-unlock. Deferred rather than fired here —
    // see handleApiBtcSignPsbtResult(), which triggers it once the PWA has
    // actually read this result. Rebooting immediately (the old behavior)
    // routinely won the race against the PWA's next poll, tearing down the
    // HTTP session before the result could ever be fetched.
    g_psbt_relock_pending = true;
    g_psbt_start_ms = millis();
    return true;
  }

  return false;
}

// ── Shared PSBT confirm entry — the single join point ───────────────────
//
// V22: the airgap (UR/QR) path and the network (PWA/HTTP) path both arrive
// here with RAW PSBT BYTES. This factors the parse → summary → ownership
// check → queue-for-confirmation logic out of handleApiBtcSignPsbt so both
// callers share one confirm/sign flow (the on-screen trust boundary is the
// same regardless of how the PSBT reached the device).
//
// Returns a status code; on PSBT_BEGIN_OK the PSBT is queued (g_psbt_state
// = PENDING) and the main loop drives the confirmation UI. On error, writes
// a short reason into err (caller-supplied, >=48 bytes) for the HTTP body /
// device error screen. Does NOT send any HTTP response or draw any screen.
//
// Preconditions the CALLER must have already checked: wallet exists +
// unlocked + hasSeed, and g_psbt_state == IDLE (no PSBT in flight).
enum {
  PSBT_BEGIN_OK = 0,
  PSBT_BEGIN_PARSE_FAIL,     // not a valid PSBT
  PSBT_BEGIN_SUMMARY_FAIL,   // missing witness UTXO data
  PSBT_BEGIN_NO_INPUTS,      // no inputs match this wallet
  PSBT_BEGIN_CACHE_FAIL,     // BIP-84 cache init failed
  PSBT_BEGIN_MS_UNKNOWN,     // P2WSH inputs from a quorum we have not registered
  PSBT_BEGIN_MS_MIXED,       // single-sig AND multisig inputs in one PSBT (refused by policy)
  PSBT_BEGIN_MS_NOT_OURS,    // multisig PSBT this device is not a cosigner of
};

// Adapter matching psbt_derive_pubkey_fn: seed-free leaf-pubkey derivation
// from the cached account xpub. This is the function the PSBT verification
// path uses, so the whole preview/verify flow runs with no seed resident.
static bool psbt_derive_pub_adapter(uint32_t change, uint32_t index,
                                    uint8_t pub33_out[33]) {
  return btc_derive_pubkey_pub(change, index, pub33_out);
}

// ── Coin memory (23 Nov 2026, #57) ─────────────────────────────────────────
// The BIP-143 fee attack (CVE-2020-14199) needs the same transaction signed
// twice with a different coin understated each time. Sparrow leaves the full
// previous transactions out of its QR for segwit wallets, so the KEY cannot
// always check amounts itself. Instead, like Coldcard (3.1.4) and Keystone, it
// remembers the amount each coin was signed with: a later PSBT that claims a
// different amount for a coin the KEY has signed is refused.
//
// Privacy: nothing here says which coins, how many or how much. The store is
// CM_SLOTS fixed slots of two 8-byte keyed fingerprints, filled with random
// bytes from the start, overwritten at random (no counter). The key is the
// SE051 pair-wrap of a constant (needs the SE, never in flash) mixed with the
// active wallet's account xpub, so each passphrase wallet has its own key and
// its entries cannot be linked or tested without that passphrase.
#define CM_NS     "coinmem"
#define CM_SLOTS  256
#define CM_TAG    8
static uint8_t* g_cmBlob = nullptr;      // CM_SLOTS * 2 * CM_TAG, PSRAM, loaded on first use per life
static bool     g_cmKeyOk = false;
static uint8_t  g_cmKey[32];

static bool cmHmac(const uint8_t* key, const uint8_t* msg, size_t n, uint8_t out[32]) {
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, msg, n, out) == 0;
}
static bool cmKeyGet() {
  if (g_cmKeyOk) return true;
  if (!g_btc_xpub_valid) return false;
  static const uint8_t kPt[32] = { 'F','A','V','I','L','L','A','-','C','O','I','N','-','M','E','M',
                                   'O','R','Y','-','K','E','Y','-','V','1',0,0,0,0,0,0 };
  static const uint8_t kIv[16] = { 'c','o','i','n','m','e','m','-','i','v','-','v','1',0,0,0 };
  uint8_t w[32];
  if (!favilla::se_pair_wrap_block(kPt, kIv, w)) return false;
  uint8_t wid[65];
  memcpy(wid, g_btc_account_xpub.pubkey, 33); memcpy(wid + 33, g_btc_account_xpub.chain_code, 32);
  bool ok = cmHmac(w, wid, sizeof wid, g_cmKey);
  mbedtls_platform_zeroize(w, sizeof w);
  g_cmKeyOk = ok;
  return ok;
}
static bool cmLoad() {
  if (g_cmBlob) return true;
  const size_t n = CM_SLOTS * 2 * CM_TAG;
  g_cmBlob = (uint8_t*)heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!g_cmBlob) return false;
  Preferences p; size_t got = 0;
  if (p.begin(CM_NS, true, NVSPART_SEC)) { if (p.getBytesLength("b") == n) got = p.getBytes("b", g_cmBlob, n); p.end(); }
  if (got != n) esp_fill_random(g_cmBlob, n);   // first use, or wiped: all random, nothing to learn
  return true;
}
static bool cmSave() {
  Preferences p;
  if (!g_cmBlob || !p.begin(CM_NS, false, NVSPART_SEC)) return false;
  bool ok = p.putBytes("b", g_cmBlob, CM_SLOTS * 2 * CM_TAG) == (size_t)(CM_SLOTS * 2 * CM_TAG);
  p.end(); return ok;
}
static void cmTags(const psbt_t* ps, uint8_t i, uint8_t coin[CM_TAG], uint8_t amt[CM_TAG]) {
  uint8_t m[1 + 32 + 4 + 8 + 1 + PSBT_MAX_SCRIPT_LEN], h[32]; size_t k = 0;
  m[k++] = 'c'; memcpy(m + k, ps->tx.inputs[i].prev_txid, 32); k += 32;
  for (int b = 0; b < 4; b++) m[k++] = (uint8_t)(ps->tx.inputs[i].prev_vout >> (8 * b));
  cmHmac(g_cmKey, m, k, h); memcpy(coin, h, CM_TAG);
  m[0] = 'a';
  for (int b = 0; b < 8; b++) m[k++] = (uint8_t)(ps->inputs[i].witness_utxo_value >> (8 * b));
  m[k++] = ps->inputs[i].witness_utxo_script_len;
  memcpy(m + k, ps->inputs[i].witness_utxo_script, ps->inputs[i].witness_utxo_script_len); k += ps->inputs[i].witness_utxo_script_len;
  cmHmac(g_cmKey, m, k, h); memcpy(amt, h, CM_TAG);
  mbedtls_platform_zeroize(m, sizeof m); mbedtls_platform_zeroize(h, sizeof h);
}
static int cmFind(const uint8_t coin[CM_TAG]) {
  for (int s = 0; s < CM_SLOTS; s++) if (!memcmp(g_cmBlob + s * 2 * CM_TAG, coin, CM_TAG)) return s;
  return -1;
}
// Intake: the first input whose claimed amount differs from the one this KEY
// signed it with (and that is not proven by its previous transaction), or -1.
// -2: the memory is not available (no SE answer): refuse, fail closed.
static int cmCheck(const psbt_t* ps) {
  if (!cmKeyGet() || !cmLoad()) return -2;
  for (uint8_t i = 0; i < ps->tx.n_inputs; i++) {
    if (!ps->inputs[i].witness_utxo_present || ps->inputs[i].nwu_verified) continue;
    uint8_t c[CM_TAG], a[CM_TAG]; cmTags(ps, i, c, a);
    int s = cmFind(c);
    if (s >= 0 && memcmp(g_cmBlob + s * 2 * CM_TAG + CM_TAG, a, CM_TAG)) return i;
  }
  return -1;
}
// After a successful sign: remember every input's amount. A slot this PSBT
// wrote is never reused by it (PSBT_MAX_INPUTS < CM_SLOTS); other slots are
// picked at random, so the store has no order and no count.
static void cmRecord(const psbt_t* ps) {
  if (!cmKeyGet() || !cmLoad()) return;
  int used[PSBT_MAX_INPUTS]; int nu = 0;
  for (uint8_t i = 0; i < ps->tx.n_inputs; i++) {
    if (!ps->inputs[i].witness_utxo_present) continue;
    uint8_t c[CM_TAG], a[CM_TAG]; cmTags(ps, i, c, a);
    int s = cmFind(c);
    if (s < 0) {
      for (int tries = 0; tries < 64; tries++) {
        int r = (int)(esp_random() % CM_SLOTS); bool mine = false;
        for (int u = 0; u < nu; u++) if (used[u] == r) mine = true;
        if (!mine) { s = r; break; }
      }
      if (s < 0) continue;
    }
    memcpy(g_cmBlob + s * 2 * CM_TAG, c, CM_TAG);
    memcpy(g_cmBlob + s * 2 * CM_TAG + CM_TAG, a, CM_TAG);
    used[nu++] = s;
  }
  if (!cmSave()) LOG_BOOT("[psbt] coin memory: save failed\n");
}
// Forget coin history / wipe: every slot back to random.
void cmForgetAll() {
  if (g_cmBlob) esp_fill_random(g_cmBlob, CM_SLOTS * 2 * CM_TAG);
  Preferences p; if (p.begin(CM_NS, false, NVSPART_SEC)) { p.clear(); p.end(); }
}
static void cmSleepWipe() {
  mbedtls_platform_zeroize(g_cmKey, sizeof g_cmKey); g_cmKeyOk = false;
  if (g_cmBlob) { mbedtls_platform_zeroize(g_cmBlob, CM_SLOTS * 2 * CM_TAG); heap_caps_free(g_cmBlob); g_cmBlob = nullptr; }
}

static int beginPsbtConfirm(const uint8_t *psbt_bytes, size_t psbt_len, char *err) {
  // Boost FIRST: change/input verification below runs CKD-pub point math and
  // is the trust-critical step, so it should be at 240MHz. The boost then
  // holds through user confirmation (confirm states are in the loop()
  // safety-net keep-boosted list). If we bail early, the safety net drops the
  // clock back to 80MHz on the next loop iteration.
  pwrBoost();

  // Seed-free watch-only: we need the persisted account xpub, NOT the seed.
  // On a daily-door unlock the seed is not resident; verification derives from
  // the xpub via CKD-pub. If no xpub is persisted (pre-Task-1 wallet), fail
  // clearly rather than silently falling back to a seed that isn't there.
  if (!btc_load_account_xpub()) {
    if (err) snprintf(err, 48, "Watch-only key not provisioned");
    return PSBT_BEGIN_CACHE_FAIL;
  }
  if (!psbtBufEnsure()) {
    if (err) snprintf(err, 48, "No memory for PSBT");
    return PSBT_BEGIN_CACHE_FAIL;
  }
  if (!psbt_parse(psbt_bytes, psbt_len, &g_pending_psbt)) {
    // 23 Nov 2026 (#57): say when a previous transaction does not back the amounts.
    if (err) snprintf(err, 48, (psbt_last_err == 19 || psbt_last_err == 20) ? "Input amount does not match" : "PSBT parse failed");
    return PSBT_BEGIN_PARSE_FAIL;
  }
  // 23 Nov 2026 (#57, CVE-2020-14199): amounts. A previous transaction in the
  // PSBT proves its input (checked in psbt_parse). The rest are checked
  // against the coin memory: a coin this KEY signed with another amount is
  // refused. One input cannot be attacked this way, so it is not checked.
#ifdef FAVILLA_BENCH_PROBES
  if (g_cmLieInput >= 0) {   // 23 Nov 2026 (#57, bench): play a lying wallet once ("cm lie N")
    if (g_cmLieInput < g_pending_psbt.tx.n_inputs && g_pending_psbt.inputs[g_cmLieInput].witness_utxo_value > g_cmLieSats) {
      g_pending_psbt.inputs[g_cmLieInput].witness_utxo_value -= g_cmLieSats;
      g_pending_psbt.inputs[g_cmLieInput].nwu_verified = false;
      LOG_BOOT("[CM-BENCH] input %d now claims %lu sats less (lying wallet)\n", g_cmLieInput, (unsigned long)g_cmLieSats);
    }
    g_cmLieInput = -1;
  }
#endif
  if (g_pending_psbt.tx.n_inputs >= 2) {
    int bad = cmCheck(&g_pending_psbt);
    if (bad == -1) LOG_BOOT("[psbt] coin memory: no input's amount differs from a past sign\n");
    if (bad == -2) { if (err) snprintf(err, 48, "Coin memory unavailable"); return PSBT_BEGIN_SUMMARY_FAIL; }
    if (bad >= 0) {
      LOG_BOOT("[psbt] input %d: amount differs from the one this KEY signed it with - refused\n", bad);
      if (err) snprintf(err, 48, "Coin amount changed since last sign");
      return PSBT_BEGIN_SUMMARY_FAIL;
    }
  }
  // Keep the raw bytes for the return leg (see g_psbt_raw).
  g_psbt_raw = psbt_bytes; g_psbt_raw_len = psbt_len;

  // ── Which wallet is this? Decided BEFORE anything is drawn. ─────────────
  g_psbt_ms_wallet = -1;
  int signable = 0;
  ms_class_t cls = MS_CLASS_SINGLESIG;
  if (g_ms) cls = ms_classify_psbt(g_ms, &g_pending_psbt, g_btc_master_fp, &g_psbt_ms_wallet);
  switch (cls) {
    case MS_CLASS_MIXED:
      if (err) snprintf(err, 48, "Mixed wallets - not supported");
      return PSBT_BEGIN_MS_MIXED;
    case MS_CLASS_NO_WALLET:
      if (err) snprintf(err, 48, "Register this wallet first");
      return PSBT_BEGIN_MS_UNKNOWN;
    case MS_CLASS_NONE_OURS:
      if (err) snprintf(err, 48, "Not a cosigner of this tx");
      return PSBT_BEGIN_MS_NOT_OURS;
    default: break;
  }

  if (cls == MS_CLASS_MULTISIG) {
    const ms_wallet_t *w = &g_ms->w[g_psbt_ms_wallet];
    if (!ms_build_summary(w, &g_pending_psbt, g_btc_master_fp, &g_pending_summary)) {
      if (err) snprintf(err, 48, "PSBT missing witness UTXO");
      return PSBT_BEGIN_SUMMARY_FAIL;
    }
    for (uint8_t i = 0; i < g_pending_psbt.tx.n_inputs; i++) {
      uint32_t c, x; uint8_t pub[33];
      if (ms_verify_input(w, &g_pending_psbt.inputs[i], &c, &x, pub)) signable++;
    }
    if (signable == 0) {
      if (err) snprintf(err, 48, "No inputs match this wallet");
      return PSBT_BEGIN_NO_INPUTS;
    }
  } else {
    if (!psbt_build_summary(&g_pending_psbt, g_btc_master_fp,
                            psbt_derive_pub_adapter, &g_pending_summary)) {
      LOG_BOOT("[psbt] summary refused: an input has no witness UTXO, or the outputs add up to more than the inputs\n");
      if (err) snprintf(err, 48, "PSBT missing witness UTXO");
      return PSBT_BEGIN_SUMMARY_FAIL;
    }
    // Count signable inputs upfront — fail fast on PSBTs we can't sign. Seed-free
    // ownership check (the actual signing re-verifies under the seed).
    for (uint8_t i = 0; i < g_pending_psbt.tx.n_inputs; i++) {
      uint32_t change, index;
      if (psbt_verify_input_ownership_pub(&g_pending_psbt.inputs[i],
                                           &g_pending_psbt.tx.inputs[i],
                                           psbt_derive_pub_adapter, g_btc_master_fp,
                                           &change, &index)) {
        signable++;
      }
    }
    if (signable == 0) {
      if (err) snprintf(err, 48, "No inputs match this wallet");
      return PSBT_BEGIN_NO_INPUTS;
    }
  }

  // Generate a request id (used by the network /result poller; harmless for
  // the airgap path which ignores it).
  for (int i = 0; i < 16; i++) {
    uint8_t b = esp_random() & 0xFF;
    sprintf(g_psbt_id + i*2, "%02x", b);
  }
  g_psbt_id[32] = 0;

  g_psbt_recipient_page = 0;
  g_psbt_drawn = false;
  g_psbt_n_sigs = 0;
  g_psbt_error[0] = 0;
  g_psbt_start_ms = millis();
  lastActivity = millis();
  buzzerSignRequest();
  __sync_synchronize();
  g_psbt_state = PSBT_STATE_PENDING;
  LOG_BOOT("[psbt] queued %d input(s), id=%s\n", signable, g_psbt_id);
  return PSBT_BEGIN_OK;
}

// (removed 11 Sep 2026: the PWA no longer carries any Bitcoin surface —
//  every /api/btc/* endpoint and the mempool proxy were deleted with it.
//  Bitcoin exists only behind the BITCOIN door, offline, on the device.)

// ── AIRGAP PSBT confirm + sign + finalize (synchronous) ─────────────────
//
// V22: the offline QR path. Unlike the network handler (async: queue, main
// loop draws, PWA polls /result), the airgap flow has no remote poller — the
// device drives the whole confirmation inline on the main task, then FINALIZES
// the signed inputs into a complete PSBT for the coordinator to scan back.
//
// Reuses the EXACT confirmation UI the network path uses (psbtDrawConfirm),
// so the trust boundary — amount/recipient/fee drawn from the same bytes we
// sign — is identical regardless of transport.
//
// Returns: finalized PSBT length written to out (>=0), or
//   -1  parse/summary/ownership failure (errmsg set)
//   -2  user rejected / timed out
//   -3  signing failed
//   -4  not all inputs ours (can't finalize single-sig — foreign input)
//   -5  finalize/serialize overflow
//
// `errmsg` (>=48 bytes) gets a short reason for the on-screen error.
// Caller (ST_AIRGAP_BTC) must have verified wallet exists+unlocked+hasSeed.
int airgapPsbtConfirmAndSign(const uint8_t *psbt_bytes, size_t psbt_len,
                             uint8_t *out, size_t out_cap, char *errmsg) {
  // Must start from a clean state — airgap is exclusive (camera path stopped
  // WiFi, no network PSBT can be racing).
  if (g_psbt_state != PSBT_STATE_IDLE) {
    if (errmsg) snprintf(errmsg, 48, "Busy — try again");
    return -1;
  }

  int rc = beginPsbtConfirm(psbt_bytes, psbt_len, errmsg);
  if (rc != PSBT_BEGIN_OK) {
    // beginPsbtConfirm wrote errmsg; ensure state is clean
    g_psbt_state = PSBT_STATE_IDLE;
    return -1;
  }

  // Confirmation loop — draw once, poll buttons. Mirrors psbtTickPoll's
  // button semantics (BTN1 long = reject, BTN1 short = scroll down,
  // BTN3 = scroll up, BTN2 = approve, BTN4 = cancel) but runs synchronously.
  g_psbt_scroll = 0;
  psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
  btn1.resetHold(); btn2.resetHold(); btn4.resetHold();
  bool approved = false, decided = false;
  unsigned long start = millis();
  drainButtonsAfterTransition();   // drop any press latched during the scan
  while (!decided) {
    // Background btnPollTask polls all buttons; don't poll here (races it).
    esp_task_wdt_reset();
    if (millis() - start > 90000UL) { if (errmsg) snprintf(errmsg,48,"Timeout"); break; }
    if (btn4.isPressed()) { if (errmsg) snprintf(errmsg,48,"Cancelled"); break; } // BACK = cancel
    int maxScroll = g_psbt_content_h - PSBT_VIEW_H; if (maxScroll < 0) maxScroll = 0;
    const int STEP = PSBT_VIEW_H * 3 / 4;
    if (btn1.isPressed()) {                                   // scroll down
      if (maxScroll > 0) {
        g_psbt_scroll += STEP; if (g_psbt_scroll > maxScroll) g_psbt_scroll = maxScroll;
        psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
      }
    } else if (btn3.isPressed()) {                            // scroll up
      if (g_psbt_scroll > 0) {
        g_psbt_scroll -= STEP; if (g_psbt_scroll < 0) g_psbt_scroll = 0;
        psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
      }
    }
    // SIGN: a HOLD of ENTER (1.5 s), begun on this screen (29 Oct 2026; a tap
    // used to sign a normal tx). Unverified change shows the red prompt.
    {
      static float lastHp = 0.0f;
      btn2.isPressed();
      float hp = holdSince(btn2, start, 1500);
      bool unsafe = g_pending_summary.n_changes_unverified > 0;
      if (hp > 0.0f && hp < 1.0f) {
        if (unsafe) {
          spr.fillSprite(C_BG);
          uiHeader("CHECK TX", C_RED);
          fSet(F_HEAD); spr.setTextColor(C_RED);
          fDrawCentre("UNVERIFIED CHANGE", 120, 64); fEnd();
          fSet(F_BODY); spr.setTextColor(C_TEXT2);
          fDrawCentre("Change address could not", 120, 94);
          fDrawCentre("be confirmed as yours.", 120, 112); fEnd();
          uiHoldFooter("KEEP HOLDING TO SIGN", "Let go to stop", hp, C_RED);
          dispPush();
        } else {
          uiHoldFooter("HOLD ENTER TO SIGN", "Let go to stop", hp);
          dispPushRegion(0, 196, 240, 44);
        }
        lastHp = hp;
      } else if (hp >= 1.0f) {
        approved = true; decided = true; btn2.resetHold(); lastHp = 0.0f;
      } else if (lastHp > 0.0f) {
        lastHp = 0.0f; psbtDrawConfirm(&g_pending_summary, g_psbt_scroll);
      }
    }
    delay(15);
  }

  if (!approved) {
    g_psbt_state = PSBT_STATE_IDLE;
    memset(&g_pending_psbt, 0, sizeof(g_pending_psbt));
    memset(&g_pending_summary, 0, sizeof(g_pending_summary));
    pwrIdle();
    return -2;
  }

  // Sign all our inputs — gated by the spend PIN (Task 3). The airgap path is
  // blocking, so we capture the PIN in a synchronous sub-loop (mirroring the
  // confirm loop's button semantics), then sign under a transient SPEND
  // session via psbtGatedSign. Cancel/timeout/lockout all bail cleanly.
  {
    psbtClearSpendPin();
    for (int i = 0; i < PIN_NEW_LEN; i++) g_psbt_pin[i] = '0';
    g_psbt_pin[PIN_NEW_LEN] = 0;
    g_psbt_pin_drawn = false;
    btn1.resetHold(); btn2.resetHold(); btn4.resetHold();
    drainButtonsAfterTransition();

    int sign_rc = 0;                 // >0 ok, 0 keep-entering, sentinel via flags
    bool pin_done = false, pin_abort = false, spend_attempted = false;
    unsigned long pstart = millis();
    while (!pin_done && !pin_abort) {
      esp_task_wdt_reset();
      if (!g_psbt_pin_drawn) { psbtDrawSpendPin(); g_psbt_pin_drawn = true; }
      if (millis() - pstart > 90000UL) { if (errmsg) snprintf(errmsg,48,"Timeout"); pin_abort = true; break; }
      if (pinVerifyChord()) { g_psbt_pin_drawn = false; pstart = millis(); continue; }   // ENTER+BACK: verify the device first
      const bool chDefer = pinChordDefer();
      if (btn3.isPressed()) { if(!g_psbt_pin_confirm){ g_psbt_pin[g_psbt_pin_digit]=((g_psbt_pin[g_psbt_pin_digit]-'0'+1)%10)+'0'; psbtDrawSpendPin(); } }
      else if (btn1.isPressed()) { if(!g_psbt_pin_confirm){ g_psbt_pin[g_psbt_pin_digit]=((g_psbt_pin[g_psbt_pin_digit]-'0'+9)%10)+'0'; psbtDrawSpendPin(); } }
      else if (!chDefer && btn4.isPressed()) {
        if (g_psbt_pin_confirm){ g_psbt_pin_confirm=false; g_psbt_pin_digit=PIN_NEW_LEN-1; psbtDrawSpendPin(); }
        else if (g_psbt_pin_digit>0){ g_psbt_pin_digit--; psbtDrawSpendPin(); }
        else { if (errmsg) snprintf(errmsg,48,"Cancelled"); pin_abort = true; break; }   // BACK on the first digit cancels
      }
      else if (!chDefer && btn2.isPressed()) {
        if (!g_psbt_pin_confirm) {
          if (++g_psbt_pin_digit==PIN_NEW_LEN){ g_psbt_pin_digit=PIN_NEW_LEN-1; g_psbt_pin_confirm=true; }
          psbtDrawSpendPin();
        } else {
          pinAnimSetup("BTC PIN", PIN_NEW_LEN, "SIGNING", "SIGNED", false);
          pinAnimWorking();
          spend_attempted = true;   // spend-open ran → daily session torn down
          int n;
          { BgSpin _signSpin(C_EB_BRASS); n = psbtGatedSign(); }   // 5 Oct 2026: animated through the signing
          if (n > 0) pinAnimSuccess();
          if (n == 0) {
            pinAnimFail("WRONG BTC PIN");
            // Wrong PIN: the spend-open already tore down the daily session, so
            // we can't cleanly retry in place — abort and relock. (Matches the
            // network path.) The SE enforces the 10-attempt lockout itself.
            if (errmsg) snprintf(errmsg,48,"Wrong BTC PIN");
            pin_abort = true;
          } else if (n == -2) {
            // Cache integrity check failed — the cached watch-only wallet does
            // not match the seed. Refuse to sign; re-onboard to re-sync.
            if (errmsg) snprintf(errmsg,48,"Wallet mismatch - re-onboard");
            pin_abort = true;
          } else {
            sign_rc = n; pin_done = true;
          }
        }
      }
      delay(15);
    }
    psbtClearSpendPin();   // wipe typed PIN on every exit

    if (pin_abort) {
      g_psbt_state = PSBT_STATE_IDLE;
      memset(&g_pending_psbt, 0, sizeof(g_pending_psbt));
      memset(&g_pending_summary, 0, sizeof(g_pending_summary));
      // If a spend was attempted, the daily session is gone — relock so the
      // caller lands on a clean lock screen and the user re-unlocks Door 1.
      // (Pure cancel/timeout with no spend attempt leaves Door 1 intact, so
      // only relock when spend_attempted.)
      if (spend_attempted) psbtRelockAfterSpend();
      pwrIdle();
      return -2;
    }
    g_psbt_n_sigs = sign_rc;
  }
  // A spend was performed above (we only reach here via pin_done, i.e. a real
  // sign). The spend tore down the daily session. We must NOT secureRestart()
  // here: on the airgap path the finalized PSBT QR is displayed on-device by
  // the CALLER after this function returns, and that is the ONLY channel to
  // get the signed tx out. Rebooting now (the old psbtRelockAfterSpend() does
  // exactly that) kills the function before ur_build_finalized_psbt() runs and
  // before the caller ever sees the result — the device just reboots after PIN
  // entry with no QR. Instead do a SOFT relock here: wipe the seed so no key
  // material survives the QR display, mark the wallet locked, and let the
  // CALLER trigger secureRestart() after the QR view exits. (The network/PWA
  // path still reboots via its own psbtRelockAfterSpend() call, which is fine
  // there because the result is fetched from the hosted endpoint, not shown
  // on-device.)
  mbedtls_platform_zeroize(wallet.seed, 64);
  wallet.hasSeed = false;
  wallet.unlocked = false;
  LOG_BOOT("[psbt] airgap spend complete → soft relock (seed wiped, QR shown, reboot deferred to caller)\n");
  if (g_psbt_n_sigs <= 0) {
    if (errmsg) snprintf(errmsg, 48, "Signing failed");
    g_psbt_state = PSBT_STATE_IDLE;
    memset(&g_pending_psbt, 0, sizeof(g_pending_psbt));
    memset(g_psbt_sigs, 0, sizeof(g_psbt_sigs));
    pwrIdle();
    return -3;
  }

  // Return leg. Two cases:
  //   every input ours AND single-sig -> FINALIZE on-device (unchanged: the
  //     coordinator gets a ready-to-broadcast tx).
  //   multisig, or any input not ours -> return the ORIGINAL PSBT with our
  //     partial signatures added and everything else byte-identical, for the
  //     coordinator to combine and finalize. This is what a cosigner owes the
  //     quorum, and it also retires the old "Foreign input - can't finalize"
  //     refusal on the single-sig path.
  int flen;
  bool finalize = (g_psbt_ms_wallet < 0) && (g_psbt_n_sigs == g_pending_psbt.tx.n_inputs);
  if (finalize) {
    flen = ur_build_finalized_psbt(&g_pending_psbt, g_psbt_sigs,
                                   g_psbt_n_sigs, out, out_cap);
  } else {
    flen = psbt_add_partial_sigs(g_psbt_raw, g_psbt_raw_len, &g_pending_psbt,
                                 g_psbt_sigs, g_psbt_n_sigs, out, out_cap);
    LOG_BOOT("[psbt] cosigner return: %d/%u input(s) signed, %d bytes\n",
             g_psbt_n_sigs, (unsigned)g_pending_psbt.tx.n_inputs, flen);
  }
  // Wipe sensitive context regardless of outcome.
  g_psbt_state = PSBT_STATE_IDLE;
  memset(&g_pending_psbt, 0, sizeof(g_pending_psbt));
  memset(&g_pending_summary, 0, sizeof(g_pending_summary));
  memset(g_psbt_sigs, 0, sizeof(g_psbt_sigs));
  g_psbt_n_sigs = 0;
  pwrIdle();

  if (flen < 0) {
    if (errmsg) snprintf(errmsg, 48, "Finalize overflow");
    return -5;
  }
  return flen;
}


// ══════════════════════════════════════════════════════════════════════════
// THE BITCOIN DOOR (11 Sep 2026)
//
// A ceremony boot IS the Bitcoin door: power cycle -> BITCOIN -> this menu,
// offline, radios never initialised, the RCE evicted. Everything Bitcoin
// lives here and nowhere else (the Nostr life has no Bitcoin surface).
//
//   Entry : spend PIN once -> spend session -> ARM -> G0 witnesses the
//           latch -> MODE_PCR == BTC verified -> session CLOSED. The menu
//           runs on public data only (persisted account xpub + fingerprint).
//   Send  : ST_AIRGAP_SIGN. psbtGatedSign() asks for the spend PIN again
//           for EVERY signature; the G0 signs each input in its own session.
//   Exit  : BACK -> confirm -> BITCOIN DONE halt. The latch stays BTC until
//           the battery is pulled; only a power cycle re-opens either door.
// ══════════════════════════════════════════════════════════════════════════
// 23 Sep 2026 (mockup A): the door is three task cards — SIGN / RECEIVE /
// WALLETS — in the Nostr-menu card geometry, not a six-word list. Signing is
// wallet-agnostic (the PSBT names its wallet), so the single-sig / multisig
// split lives under RECEIVE and WALLETS, not at the top. The two sub-menus
// are in multisig_ui.inc (included below) because they call its statics.
void btcReceiveMenu();     // multisig_ui.inc: Single-sig / each multisig wallet / Verify address
void btcWalletsMenu();     // multisig_ui.inc: Single-sig / each multisig wallet / Import / Export cosigner key
void btcExportSingleSig(); // multisig_ui.inc: 3-page single-sig key export (replaces btc_show_export)
void drawScanLogo(int cx, int cy, uint16_t col, uint16_t bg);   // main.cpp, baked mask (defined earlier)

// Number of registered multisig wallets (0 when the store is unavailable).
static int btcMsCount() {
  if (!g_ms) return 0;
  int n = 0;
  for (int i = 0; i < MS_MAX_WALLETS; i++) if (g_ms->w[i].valid) n++;
  return n;
}
// Name of the only registered multisig wallet, or NULL if not exactly one.
static const char* btcMsSoleName() {
  if (!g_ms) return nullptr;
  const char* nm = nullptr; int n = 0;
  for (int i = 0; i < MS_MAX_WALLETS; i++) if (g_ms->w[i].valid) { nm = g_ms->w[i].name; n++; }
  return (n == 1) ? nm : nullptr;
}

// ── Door-menu glyphs: same 3px stroke as the main-menu icon family ────────
// RECEIVE — an arrow dropping into an open tray.
static void drawIconReceive(int cx, int cy, uint16_t col) {
  const int t = ICON_STROKE;
  spr.drawWideLine(cx - 15, cy + 2,  cx - 15, cy + 14, t, col);   // tray left
  spr.drawWideLine(cx - 15, cy + 14, cx + 15, cy + 14, t, col);   // tray floor
  spr.drawWideLine(cx + 15, cy + 14, cx + 15, cy + 2,  t, col);   // tray right
  spr.drawWideLine(cx, cy - 16, cx, cy + 5, t, col);              // shaft
  spr.drawWideLine(cx - 8, cy - 3, cx, cy + 6, t, col);           // head L
  spr.drawWideLine(cx + 8, cy - 3, cx, cy + 6, t, col);           // head R
}
// WALLETS — three stacked cards with a clasp on the front one.
static void drawIconWallets(int cx, int cy, uint16_t col) {
  const int t = ICON_STROKE;
  spr.drawRoundRect(cx - 16, cy - 2, 32, 18, 4, col);
  spr.drawRoundRect(cx - 15, cy - 1, 30, 16, 3, col);             // 2px-ish outline without a second colour
  spr.drawWideLine(cx - 12, cy - 8,  cx + 12, cy - 8,  t, col);   // second card
  spr.drawWideLine(cx - 8,  cy - 14, cx + 8,  cy - 14, t, col);   // third card
  spr.fillRect(cx + 6, cy + 4, 7, 6, col);                        // clasp
}

// Draw the three-card door. sel = highlighted card.
static void btcDoorDraw(int sel) {
  const int CARD_X = 12, CARD_W = 216, CARD_H = 68, CARD_TOP = 10, CARD_GAP = 8;
  spr.fillSprite(C_BG);
  // Live descriptions: RECEIVE and WALLETS say what they will open onto.
  int ms = btcMsCount(); const char* sole = btcMsSoleName();
  char dRecv[40], dWal[40];
  if (ms == 0)        snprintf(dRecv, sizeof dRecv, "Next address");
  else if (sole && strlen(sole) <= 10) snprintf(dRecv, sizeof dRecv, "Single-sig or %s", sole);   // longer names would run off the card
  else                snprintf(dRecv, sizeof dRecv, "Single-sig or multisig");
  if (ms == 0)        snprintf(dWal, sizeof dWal, "Single-sig only");
  else                snprintf(dWal, sizeof dWal, "1 single-sig, %d multisig", ms);
  const char* title[4] = { "SIGN", "RECEIVE", "WALLETS", "EMBERWILL" };
  const char* desc[4]  = { "Transaction or message", dRecv, dWal, "Inheritance plan, BETA" };
  // 28 Oct 2026 (bench): a fourth card, EMBERWILL. Three cards fill the panel,
  // so the list scrolls: the window of three slides once the selection is
  // below it.
  int first = sel > 2 ? sel - 2 : 0;
  for (int r = 0; r < 3; r++) {
    int i = first + r;
    int y = CARD_TOP + r * (CARD_H + CARD_GAP);
    bool s = (i == sel);
    // 7 Oct 2026 (Entropy Ember): the shared list card, same as the passphrase
    // and onboarding choices. Icon grey until selected, then the BTC accent.
    uint16_t cardBg = uiListCard(CARD_X, y, CARD_W, CARD_H, s, C_BTC_ACCENT, title[i], desc[i], CARD_X + 64);
    int icx = CARD_X + 34, icy = y + CARD_H / 2;
    uint16_t icol = s ? C_BTC_ACCENT : C_EB_GREY;
    if (i == 0)      drawScanLogo(icx, icy, icol, cardBg);
    else if (i == 1) drawIconReceive(icx, icy, icol);
    else if (i == 2) drawIconWallets(icx, icy, icol);
    else             ebMarkSmall(icx - 12, icy - 12, 4, 1);          // the ember, 24 px
  }
  dispPush();
}
#ifdef FAVILLA_EMBERWILL   // 11cd: Emberwill BETA, its own switch
static const int BTC_DOOR_SIZE = 4;
static bool emwDoorScreen();   // ember_mvp.inc
#else
static const int BTC_DOOR_SIZE = 3;
#endif

// Collect the spend PIN on-device (same screen and button grammar as the
// signing sub-loop). true = PIN confirmed in g_psbt_pin; false = cancelled or
// timed out. Caller MUST psbtClearSpendPin() after using the PIN.
// 10m: the spend PIN pad's first frame, for the door hand-off (main.cpp). The
// same state btcCollectSpendPin starts from, so its first draw is identical.
void btcSpendPinPreview() {
  psbtClearSpendPin();
  for (int i = 0; i < PIN_NEW_LEN; i++) g_psbt_pin[i] = '0';
  g_psbt_pin[PIN_NEW_LEN] = 0;
  psbtDrawSpendPin();
}
// 11w: the pad in the door hand-off gap draws through the same state and frame.
static void prePinDrawBtc(const char* pin, int digit, bool armed) {
  memcpy(g_psbt_pin, pin, PIN_NEW_LEN); g_psbt_pin[PIN_NEW_LEN] = 0; g_psbt_pin_digit = digit; g_psbt_pin_confirm = armed;
  psbtDrawSpendPin();
}
static bool btcCollectSpendPin() {
  psbtClearSpendPin();
  for (int i = 0; i < PIN_NEW_LEN; i++) g_psbt_pin[i] = '0';
  g_psbt_pin[PIN_NEW_LEN] = 0;
  {   // 11w: what was pressed on the pad while the boot finished
    char pp[9]; int pd = 0; bool pa = false, ps = false;
    if (prePinStop(pp, &pd, &pa, &ps)) {
      memcpy(g_psbt_pin, pp, PIN_NEW_LEN); g_psbt_pin[PIN_NEW_LEN] = 0; g_psbt_pin_digit = pd; g_psbt_pin_confirm = pa;
      mbedtls_platform_zeroize(pp, sizeof pp);
      if (ps) return true;   // entered and submitted in the gap
    }
  }
  g_psbt_pin_drawn = false;
  btn1.resetHold(); btn2.resetHold(); btn4.resetHold();
  drainButtonsAfterTransition();
  unsigned long pstart = millis();
  while (true) {
    esp_task_wdt_reset();
    if (!g_psbt_pin_drawn) { psbtDrawSpendPin(); g_psbt_pin_drawn = true; }
    if (millis() - pstart > 90000UL) { psbtClearSpendPin(); return false; }
    if (pinVerifyChord()) { g_psbt_pin_drawn = false; pstart = millis(); continue; }   // ENTER+BACK: verify the device first
    const bool chDefer = pinChordDefer();
    if (btn3.isPressed()) { if(!g_psbt_pin_confirm){ g_psbt_pin[g_psbt_pin_digit]=((g_psbt_pin[g_psbt_pin_digit]-'0'+1)%10)+'0'; psbtDrawSpendPin(); } }
    else if (btn1.isPressed()) { if(!g_psbt_pin_confirm){ g_psbt_pin[g_psbt_pin_digit]=((g_psbt_pin[g_psbt_pin_digit]-'0'+9)%10)+'0'; psbtDrawSpendPin(); } }
    else if (!chDefer && btn4.isPressed()) {
      if (g_psbt_pin_confirm){ g_psbt_pin_confirm=false; g_psbt_pin_digit=PIN_NEW_LEN-1; psbtDrawSpendPin(); }
      else if (g_psbt_pin_digit>0){ g_psbt_pin_digit--; psbtDrawSpendPin(); }
      else { psbtClearSpendPin(); return false; }   // 29 Oct 2026: BACK on the first digit cancels (was a hidden hold of DOWN)
    }
    else if (!chDefer && btn2.isPressed()) {
      if (!g_psbt_pin_confirm) {
        if (++g_psbt_pin_digit==PIN_NEW_LEN){ g_psbt_pin_digit=PIN_NEW_LEN-1; g_psbt_pin_confirm=true; }
        psbtDrawSpendPin();
      } else {
        return true;
      }
    }
    delay(15);
  }
}

// Door entry. Returns false only when the user cancels or the door cannot be
// opened this power cycle (latch not neutral); a wrong PIN just re-prompts —
// the SE's own attempt counter on the spend object is the lockout.
bool btcDoorUnlock() {
  while (true) {
    if (!btcCollectSpendPin()) return false;
    pinAnimSetup("BTC PIN", PIN_NEW_LEN, "OPENING", "OPEN", false);
    pinAnimWorking();   // ember noise while the SE/G0 open the door
    uint8_t blob[G0_SEED_IN_LEN] = {0};   // v5: receives the inner packet (G0's layer only)
    uint8_t kind = 0;
    {
      int w;
      { BgSpin _doorSpin(C_EB_BRASS); w = btcWitnessedSpendOpen(true, false, blob, &kind); }   // 5 Oct 2026: the noise keeps moving through the SE/G0 round trips. v5: also strips the SE layer in the spend session
      if (w == 0) { mbedtls_platform_zeroize(blob, sizeof(blob)); pinAnimFail("WRONG BTC PIN"); continue; }
      if (w < 0)  { mbedtls_platform_zeroize(blob, sizeof(blob)); return false; }
    }
    pinAnimSuccess();   // resolve + burst: the door is open
    // v5 (15 Oct 2026): no seed on this processor. The spend session above had
    // the SE strip its outer layer (blob now holds the G0's inner packet); the
    // G0 re-checks the latch, burns it to SPENT and strips the inner layer,
    // and hands back only public or one-way material: master fp, the two
    // account xpubs, the sealed-state key.
    g0_door_keys_t dk;
    // 5 Oct 2026: the derivation is a G0 round trip the user has to wait for -
    // it gets the ember working screen (noise animated by core 1), not a
    // static line. The screen fades in from the unlock dissolve.
    dispEmberWorking("Bitcoin", "DERIVING WALLET", nullptr);
    bool ok = true;
    uint8_t rc = 0xFF;
    {
      BgSpin _deriveSpin(C_EB_BRASS);
      if (ok) {
        if (kind != favilla::SEED_KIND_ENTROPY) {
          ok = g0_door_keys(blob, &dk);
        } else {
          // v4 (24 Sep 2026): per-session passphrase wallet. First try with no
          // passphrase delivered: the G0 holds one for the whole power-on life
          // (across sleep/wake), so a re-entry needs no prompt. Only 0xE3 ("no
          // passphrase held") brings up the prompt; NONE is the words-only
          // wallet, any other answer opens whatever wallet it produces. Every
          // answer is a valid wallet - nothing here can distinguish a decoy.
          // The G0 accepts five passphrases per battery pull (0xE4 after that).
          ok = g0_door_keys_kind(blob, kind, nullptr, 0, &dk, &rc);
        }
      }
    }
    if (!ok && kind == favilla::SEED_KIND_ENTROPY && rc == G0_RC_NO_PASS) {
      char pass[PP_MAX + 1] = {0};
      int pr = ppCollectDoor(pass, sizeof pass);
      if (pr < 0) { mbedtls_platform_zeroize(blob, sizeof(blob)); return false; }
      dispEmberWorking("Bitcoin", "DERIVING WALLET", nullptr);
      // The latch is still BTC: the refused call answered 0xE3 before any
      // SE traffic (the passphrase check comes first on the G0), so nothing
      // was burned and the minted latch is intact. Retry directly.
      { BgSpin _deriveSpin2(C_EB_BRASS); ok = g0_door_keys_kind(blob, kind, pass, strlen(pass), &dk, &rc); }
      mbedtls_platform_zeroize(pass, sizeof(pass));
      if (!ok && rc == G0_RC_PASS_BUDGET) { dispError("Passphrase tries used - restart"); errorPause(); }
    }
    mbedtls_platform_zeroize(blob, sizeof(blob));
    btcStateWipe();
    if (ok) { memcpy(g_bst_key, dk.state_key, 32); g_bst_key_valid = true; }
    if (!g_bst_key_valid) LOG_BOOT("[bst] state key not available\n");
    // The account xpub + fingerprint for THIS Bitcoin life, from the G0's
    // answer, held in RAM only (15 Oct 2026: never written to flash, so a
    // Nostr life has nothing to read or poison).
    if (ok) ok = btc_persist_account_xpub_from_g0(&dk);
    // Multisig: our BIP-48 account key, PUBLIC image only, for this BTC life.
    if (ok) {
      memcpy(g_ms_our_xpub.pubkey, dk.xpub48_pub, 33);
      memcpy(g_ms_our_xpub.chain_code, dk.xpub48_cc, 32);
      g_ms_our_xpub.depth = 4;
      g_ms_our_xpub.child_number = 0x80000002UL;   // m/48'/0'/0'/2'
      memcpy(g_ms_our_xpub.parent_fingerprint, dk.xpub48_parent_fp, 4);
      g_ms_our_valid = true;
      LOG_BOOT("[ms] BIP-48 key ready (fp %02x%02x%02x%02x)\n",
               g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3]);
    }
    mbedtls_platform_zeroize(&dk, sizeof(dk));
    if (!ok) { dispError("Seed unavailable"); errorPause(); return false; }
    btc_load_recv_index();
    msEnsureMem();
    ms_store_load();   // re-resolves our slot in every registered wallet
    // 5 Oct 2026: the wait ends on the mark - noise resolves to the lit ember,
    // WALLET READY, then dissolves into the door menu (no burst: the door's
    // own unlock already had it).
    dispEmberResolve("Bitcoin", "WALLET READY", nullptr, false);
    return true;
  }
}

#include <mbedtls/base64.h>
// ── BIP-137 message signing (15 Oct 2026) ──────────────────────────────────
// Input: a QR with the Coldcard text format
//     signmessage m/84'/0'/0'/<change>/<index> ascii:<message>
// ("h" or "H" may replace "'", the leading "m/" is optional). Single-sig
// native segwit only. Output: the 65-byte BIP-137 signature, base64, as a QR
// (verify in Sparrow / Electrum / Coldcard with the address and message shown).
// Every message costs one spend PIN and one G0 latch burn, like a transaction
// input. The G0 builds the digest from the message bytes itself.
static bool btcMsgIsRequest(const char* q) {
  while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
  return strncasecmp(q, "signmessage", 11) == 0 && (q[11] == ' ' || q[11] == '\t');
}

// Parse "84'/0'/0'/c/i" (after an optional "m/"). true on the one shape we sign.
static bool btcMsgParsePath(const char* p, size_t n, uint32_t* change, uint32_t* index) {
  char b[48]; if (n == 0 || n >= sizeof b) return false;
  memcpy(b, p, n); b[n] = 0;
  const char* s = b;
  if ((s[0] == 'm' || s[0] == 'M') && s[1] == '/') s += 2;
  uint32_t v[5]; bool hard[5]; int k = 0;
  while (*s && k < 5) {
    if (*s < '0' || *s > '9') return false;
    uint64_t x = 0; while (*s >= '0' && *s <= '9') { x = x * 10 + (uint64_t)(*s - '0'); if (x > 0x7FFFFFFFull) return false; s++; }
    bool h = false; if (*s == '\'' || *s == 'h' || *s == 'H') { h = true; s++; }
    v[k] = (uint32_t)x; hard[k] = h; k++;
    if (*s == '/') { s++; if (!*s) return false; } else if (*s) return false;
  }
  if (*s || k != 5) return false;
  if (!(v[0] == 84 && hard[0] && v[1] == 0 && hard[1] && v[2] == 0 && hard[2])) return false;
  if (hard[3] || hard[4] || v[3] > 1) return false;
  *change = v[3]; *index = v[4];
  return true;
}

// Split the QR text. msg_out gets the message (NUL-terminated). err names the
// problem for the user.
static bool btcMsgParse(const char* q, uint32_t* change, uint32_t* index, char* msg_out, size_t cap, const char** err) {
  while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
  q += 11;                                              // "signmessage"
  while (*q == ' ' || *q == '\t') q++;
  const char* ps = q; while (*q && *q != ' ' && *q != '\t') q++;
  if (!btcMsgParsePath(ps, (size_t)(q - ps), change, index)) { *err = "Path must be m/84'/0'/0'/0|1/n"; return false; }
  while (*q == ' ' || *q == '\t') q++;
  if (strncasecmp(q, "ascii:", 6) != 0) { *err = "Message must start ascii:"; return false; }
  q += 6;
  size_t n = strlen(q);
  while (n && (q[n-1] == ' ' || q[n-1] == '\t' || q[n-1] == '\r' || q[n-1] == '\n')) n--;   // a scanner may add a newline
  if (n == 0) { *err = "Empty message"; return false; }
  if (n > G0_MSG_MAX || n >= cap) { *err = "Message too long (240 max)"; return false; }
  for (size_t i = 0; i < n; i++) if ((uint8_t)q[i] < 0x20 || (uint8_t)q[i] > 0x7E) { *err = "Message must be plain ASCII"; return false; }
  memcpy(msg_out, q, n); msg_out[n] = 0;
  return true;
}

static void btcMsgDigest(const char* msg, size_t n, uint8_t out[32]) {
  static const char PREFIX[] = "\x18" "Bitcoin Signed Message:\n";
  uint8_t t[32], vl = (uint8_t)n;
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, (const uint8_t*)PREFIX, sizeof(PREFIX) - 1);
  mbedtls_sha256_update(&c, &vl, 1);
  mbedtls_sha256_update(&c, (const uint8_t*)msg, n);
  mbedtls_sha256_finish(&c, t); mbedtls_sha256_free(&c);
  mbedtls_sha256(t, 32, out, 0);
}

static void btcSignMessageCore(uint32_t change, uint32_t index, const char* msg);   // defined below (declaration-order rule)

// Plain-text message (what exchanges and "verify address" pages show as a QR):
// printable ASCII, 1..240 bytes after trimming, and not itself an address.
static bool btcMsgPlainOk(const char* q, char* out, size_t cap) {
  while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
  size_t n = strlen(q);
  while (n && (q[n-1] == ' ' || q[n-1] == '\t' || q[n-1] == '\r' || q[n-1] == '\n')) n--;
  if (n == 0 || n > G0_MSG_MAX || n >= cap) return false;
  for (size_t i = 0; i < n; i++) if ((uint8_t)q[i] < 0x20 || (uint8_t)q[i] > 0x7E) return false;
  memcpy(out, q, n); out[n] = 0;
  return true;
}

// Which of our single-sig addresses is this? Walks receive then change from
// the account xpub (seed-free). true + change/index on a hit.
static bool btcFindOwnAddress(const char* want, uint32_t* change_out, uint32_t* index_out) {
  if (!btc_load_account_xpub()) return false;
  const uint32_t limit[2] = { (g_btc_recv_index + 200 > 500) ? g_btc_recv_index + 200 : 500, 500 };
  for (uint32_t ch = 0; ch < 2; ch++) {
    bip32_xpub chain;
    if (!bip32_derive_child_pub(&g_btc_account_xpub, ch, &chain)) return false;
    for (uint32_t i = 0; i < limit[ch]; i++) {
      if ((i % 25) == 0) esp_task_wdt_reset();
      bip32_xpub leaf; uint8_t wp[20]; char a[96];
      if (!bip32_derive_child_pub(&chain, i, &leaf)) continue;
      hash160(leaf.pubkey, 33, wp);
      if (!segwit_addr_encode("bc", 0, wp, 20, a)) continue;
      if (strcmp(a, want) == 0) { *change_out = ch; *index_out = i; return true; }
    }
  }
  return false;
}

// Scan the address to sign with (same proven loop as the address-book scan).
// true + bare lowercase bc1 address in out.
static bool btcMsgScanAddress(const char* msg, char* out, size_t cap) {
  spr.fillSprite(C_BG);
  uiHeader("SIGN WITH", C_BTC_ACCENT);
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  { char pv[28]; snprintf(pv, sizeof pv, strlen(msg) > 24 ? "%.22s.." : "%s", msg); fDrawCentre(pv, 120, 64); }
  spr.setTextColor(C_VDIM);
  fDrawCentre("Now scan the address", 120, 104);
  fDrawCentre("to sign this message with", 120, 124);
  fDrawCentre("BACK to cancel", 120, 200); fEnd();
  uiFooter(); dispPush(); delay(800);
  pwrBoost();
  g_airgapLivePreview = true; g_airgapUrGot = 0; g_airgapUrTotal = 0;
  cameraStart(); qrFound = false;
  unsigned long ns = millis(), lastQR = 0;
  bool got = false, gotFrame = false;
  while (millis() - ns < 60000) {
    esp_task_wdt_reset();
    btn4.poll();
    if (btn4.isPressed()) break;
    if (!qrFound && (millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS)) { lastQR = millis(); qrScanOnce(); }
    if (qrFound) {
      gotFrame = true; qrFound = false;
      got = ab_parse_scanned(qrResultBuf, out, cap);
      break;
    }
  }
  g_airgapLivePreview = false; cameraStop(); pwrIdle();
  if (!got && gotFrame) { dispError("Not a bc1 address"); errorPause(); }
  return got;
}

bool btcMsgIsRequestPublic(const char* q) {
  if (btcMsgIsRequest(q)) return true;
  char tmp[G0_MSG_MAX + 1], a[96];
  if (ab_parse_scanned(q, a, sizeof a)) return false;          // an address on its own is not a message
  return btcMsgPlainOk(q, tmp, sizeof tmp);
}

// Called from the Bitcoin-session scan (main.cpp) with the decoded QR text.
//   "signmessage <path> ascii:<msg>"  -> sign with that path
//   any other short plain-ASCII text  -> it is the message; then scan the
//                                        address, find it in this wallet
// Returns when the user is done; the caller goes back to the door menu.
void btcSignMessageFromQr(const char* qr) {
  static char msg[G0_MSG_MAX + 1];
  uint32_t change = 0, index = 0; const char* err = nullptr;
  if (btcMsgIsRequest(qr)) {
    if (!btcMsgParse(qr, &change, &index, msg, sizeof msg, &err)) { dispError(err ? err : "Bad message QR"); errorPause(); return; }
    btcSignMessageCore(change, index, msg);
    return;
  }
  if (!btcMsgPlainOk(qr, msg, sizeof msg)) { dispError("Message must be plain text, 240 max"); errorPause(); return; }
  char addr[96];
  if (!btcMsgScanAddress(msg, addr, sizeof addr)) return;
  bool found;
  dispEmberWorking("Bitcoin", "FINDING ADDRESS", nullptr);
  { BgSpin _s(C_EB_BRASS); found = btcFindOwnAddress(addr, &change, &index); }
  if (!found) { dispError("Not a single-sig address of this wallet"); errorPause(); return; }
  btcSignMessageCore(change, index, msg);
}

// Sign msg with m/84'/0'/0'/change/index: confirm, spend PIN, G0, QR.
static void btcSignMessageCore(uint32_t change, uint32_t index, const char* msg) {
  const size_t mlen = strlen(msg);

  // The address comes from the account xpub the G0 handed over at the door.
  uint8_t pub[33], wp[20]; char addr[96] = {0};
  if (!btc_derive_pubkey_pub(change, index, pub)) { dispError("Open the Bitcoin door first"); errorPause(); return; }
  hash160(pub, 33, wp);
  if (!segwit_addr_encode("bc", 0, wp, 20, addr)) { dispError("Address error"); errorPause(); return; }

  // Confirm: the same scrollable sign screen as a Nostr event, so the whole
  // message can be read before anything is signed.
  snprintf(approvalLine1, sizeof approvalLine1, "Bitcoin message");
  approvalBody[0] = 0;
  strncat(approvalBody, msg, APPROVAL_BODY_SZ - 1);
  {
    char tail[200];
    snprintf(tail, sizeof tail, "\n\nADDRESS\n%s\n\nPATH\nm/84'/0'/0'/%lu/%lu", addr, (unsigned long)change, (unsigned long)index);
    strncat(approvalBody, tail, APPROVAL_BODY_SZ - 1 - strlen(approvalBody));
  }
  g_approval_scroll = 0;
  dispApprovalScroll(g_approval_scroll);
  const unsigned long shownAt = millis();
  drainButtonsAfterTransition();
  bool go = false;
  while (true) {
    esp_task_wdt_reset(); delay(20);
    int maxScroll = g_approval_content_h - APV_VIEW_H; if (maxScroll < 0) maxScroll = 0;
    const int STEP = APV_VIEW_H * 3 / 4;
    if (btn3.isPressed()) { if (g_approval_scroll > 0) { g_approval_scroll -= STEP; if (g_approval_scroll < 0) g_approval_scroll = 0; dispApprovalScroll(g_approval_scroll); } continue; }
    if (btn1.isPressed()) { if (maxScroll > 0) { g_approval_scroll += STEP; if (g_approval_scroll > maxScroll) g_approval_scroll = maxScroll; dispApprovalScroll(g_approval_scroll); } continue; }
    if (btn2.isPressedFresh(shownAt)) { go = true; break; }
    if (btn4.isPressed()) break;
    g_ceremonyStart = millis();
  }
  approvalBody[0] = 0;
  if (!go) { dispError("Cancelled"); delay(800); return; }

  // Spend PIN -> SE strips its layer in the spend session -> the G0 checks
  // the latch, burns it, strips its layer, signs. One PIN per message.
  uint8_t pkt[G0_SEED_IN_LEN] = {0}; uint8_t kind = 0;
  while (true) {
    if (!btcCollectSpendPin()) { mbedtls_platform_zeroize(pkt, sizeof pkt); return; }
    pinAnimSetup("BTC PIN", PIN_NEW_LEN, "SIGNING", "SIGNED", false);
    pinAnimWorking();
    int w;
    { BgSpin _s(C_EB_BRASS); w = btcWitnessedSpendOpen(true, false, pkt, &kind); }
    if (w == 0) { mbedtls_platform_zeroize(pkt, sizeof pkt); pinAnimFail("WRONG BTC PIN"); continue; }
    if (w < 0)  { mbedtls_platform_zeroize(pkt, sizeof pkt); return; }
    break;
  }
  uint8_t gpub[33], sig[65], gdg[32], dg[32];
  bool ok;
  // The PIN screen's ember is still up: re-arm it so the next BgSpin keeps
  // animating it (the arm is one-shot and the spend-open BgSpin used it),
  // rather than falling back to the plain spinner over the ember frame.
  emberWorkingArm(32);
  { BgSpin _s(C_EB_BRASS); ok = g0_msg_sign(pkt, kind, change, index, msg, mlen, gpub, sig, gdg); }
  if (!ok && g0_antiexfil_faulted()) dispAntiExfilFaultForever();   // 27 Oct 2026
  mbedtls_platform_zeroize(pkt, sizeof pkt);
  // Cross-checks: the key the G0 used is the one behind the address the user
  // just approved, and the digest is the one this side computes for the text.
  btcMsgDigest(msg, mlen, dg);
  if (ok && memcmp(gpub, pub, 33) != 0) { ok = false; LOG_BOOT("[msg] G0 signed with a different key than the shown address - refused\n"); }
  if (ok && memcmp(gdg, dg, 32) != 0)  { ok = false; LOG_BOOT("[msg] G0 digest differs from ours - refused\n"); }
  if (!ok) { dispError("Message not signed"); errorPause(); return; }
  pinAnimSuccess();

  unsigned char b64[100]; size_t olen = 0;
  if (mbedtls_base64_encode(b64, sizeof b64, &olen, sig, 65) != 0 || olen != 88) { dispError("Encode failed"); errorPause(); return; }
  b64[olen] = 0;
  LOG_BOOT("[msg] signed m/84'/0'/0'/%lu/%lu %s sig %s\n", (unsigned long)change, (unsigned long)index, addr, (const char*)b64);
  char bot[24]; snprintf(bot, sizeof bot, "%.8s...%.6s", addr, addr + strlen(addr) - 6);
  delay(120);
  showQR((const char*)b64, "Signed message", bot);
  clearButtonPending();
  btn1.resetHold(); btn2.resetHold(); btn3.resetHold(); btn4.resetHold();
  const unsigned long qrAt = millis();
  while (true) {
    if (btn1.isPressedFresh(qrAt) || btn2.isPressedFresh(qrAt) || btn4.isPressedFresh(qrAt)) break;
    esp_task_wdt_reset(); delay(15);
  }
}

// Leaving the door is final for this power cycle — make it a deliberate act.
// (btcDoorBurnOnLeave removed in v2, 16 Sep 2026: every unwrap burns the
// latch itself, so there is nothing left to burn on the way out.)

// 23 Sep 2026: BACK on the door now SLEEPS rather than halting for a battery
// pull. Bitcoin stays the door for this power-on life — waking lands on the
// BITCOIN SESSION screen and ENTER re-opens the menu (spend PIN again).
static bool btcDoorConfirmLeave() {
  drainButtonsAfterTransition();
  spr.fillSprite(C_BG); uiHeader("SLEEP?", C_EB_BRASS);
  fSet(F_HEAD); spr.setTextColor(C_FG);
  fDrawCentre("Bitcoin stays open.", 120, 76);
  fDrawCentre("Wake to sign again.", 120, 98); fEnd();
  fSet(F_BODY); spr.setTextColor(C_DIM);
  fDrawCentre("Two LEFT buttons together:", 120, 134);
  fDrawCentre("restart to use Nostr", 120, 152); fEnd();
  uiCornerAnswers("STAY", "SLEEP");   // 11cw: the answers in the corners
  dispPush();
  unsigned long shownAt = millis();
  while (true) {
    esp_task_wdt_reset(); delay(15);
    if (btn2.isPressed()) return true;
    if (btn4.isPressed()) return false;
    if (millis() - shownAt > 30000UL) return false;
  }
}

// Called by goSleep() when sleeping inside a Bitcoin life: nothing plaintext
// or key-like from the sealed state may sit in the RAM image across a wake.
void btcSleepWipe() {
  cmSleepWipe();   // 23 Nov 2026 (#57)
  btcStateWipe();
  psbtClearSpendPin();
}

// The Bitcoin door menu. Returns with nextState = ST_AIRGAP_SIGN for Send;
// never returns on exit (BACK -> confirm -> deep sleep; wake = BITCOIN SESSION).
#ifdef FAVILLA_BENCH_PROBES
// 28 Oct 2026: the door menu below is a blocking loop, so the main loop's
// handleSerialInput() never runs in the Bitcoin life. The Emberwill bench
// (em feed / em ceremony / em clear) needs serial here; nothing else is read.
static bool emberBenchDoorPoll() {
  static String buf; bool ran = false;
  while (CON_AVAILABLE()) {
    char c = (char)CON_READ();
    if (c == '\n' || c == '\r') {
      buf.trim();
      if (buf == "em" || buf.startsWith("em ")) { emberBenchSerial(buf); ran = true; }
      else if (buf.startsWith("cm ")) { cmBenchSerial(buf); ran = true; }   // 23 Nov 2026 (#57): coin memory proof
      buf = "";
    } else if (buf.length() < 512) buf += c;
  }
  return ran;
}
#endif

void runBtcDoorMenu() {
  int idx = 0;
  drainButtonsAfterTransition();
  btcDoorDraw(idx);
  while (true) {
    esp_task_wdt_reset();
    delay(5);
#ifdef FAVILLA_BENCH_PROBES
    if (emberBenchDoorPoll()) { g_ceremonyStart = millis(); btcDoorDraw(idx); }   // bench: keep the idle ceiling and the screen honest
#endif
    if (tickSleepGesture()) continue;   // hold both scroll buttons -> deep sleep (never returns)
    if (btn1.isPressed()) {
      idx = (idx + 1) % BTC_DOOR_SIZE; g_ceremonyStart = millis();
      btcDoorDraw(idx);
    } else if (btn3.isPressed()) {
      idx = (idx - 1 + BTC_DOOR_SIZE) % BTC_DOOR_SIZE; g_ceremonyStart = millis();
      btcDoorDraw(idx);
    } else if (btn4.isPressed()) {
      g_ceremonyStart = millis();
      if (btcDoorConfirmLeave()) { goSleep(); }   // never returns; goSleep wipes BTC state (v2: latch is already SPENT after every unwrap)
      btcDoorDraw(idx);
    } else if (btn2.isPressed()) {
      g_ceremonyStart = millis();
      switch (idx) {
        case 0: nextState = ST_AIRGAP_SIGN; return;   // spend PIN again inside psbtGatedSign
        case 1: btcReceiveMenu(); break;
        case 2: btcWalletsMenu(); break;
#ifdef FAVILLA_EMBERWILL
        case 3: if (emwDoorScreen()) { nextState = ST_AIRGAP_SIGN; return; } break;   // scan the plan (PSBT), same scanner as SIGN
#endif
      }
      drainButtonsAfterTransition();
      btcDoorDraw(idx);
    }
  }
}

// ── Multisig screens ──────────────────────────────────────────────────────
// Included LAST: it uses psbtDrawAddrWrapped, drawTick, uiPill, dispSubMenu,
// the camera helpers and the g_ms globals above.
#include "multisig_ui.inc"
