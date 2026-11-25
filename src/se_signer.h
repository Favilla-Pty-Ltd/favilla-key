#ifndef FAVILLA_SE_SIGNER_H
#define FAVILLA_SE_SIGNER_H

// ============================================================
// se_signer — Favilla KEY V22.1 SE051 driver
//
// Public interface for all SE051 operations the V1 firmware needs.
// Replaces the ATECC608B-based crypto chain entirely once M7
// Steps 1–5 are complete.
//
// Memory model (Strategy A — see security architecture §8.5):
//   - Nostr scalar lives as a wrapped 32-byte blob in SE persistent
//     storage at SE_OBJ_NOSTR_SCALAR. Never exported in cleartext;
//     unwrapped to RAM only for the duration of a signing call.
//   - BIP-39 seed lives in ESP32 NVS as two AES-CBC-wrapped 32-byte
//     halves, encrypted with the SE-stored AES key at SE_OBJ_AES_WRAP.
//     Seed is unwrapped to RAM only for the duration of a Bitcoin
//     derivation, then zeroed.
//
// Threading model: all SE operations are blocking and must run on
// a single task. Calling concurrently from multiple FreeRTOS tasks
// will corrupt the T=1 transport state machine. The V22 firmware
// runs all signing on loopTask, which satisfies this naturally.
//
// Error model: every public function returns bool. False means the
// operation failed at some level (I²C, T=1 framing, APDU SW != 9000,
// TLV malformed, output length mismatch). On failure, no output
// buffer is modified. Detailed error reporting is via Serial.print
// inside the implementation — caller decides whether to retry or
// surface the failure to the user.
//
// M7 step gating:
//   Step 1 (this commit):    se_init, se_object_exists
//   Step 3 (Nostr swap):     se_schnorr_sign  (will add)
//   Step 4 (ECDH swap):      se_ecdh          (will add)
//   Step 6 (onboarding):     se_provision_nostr_scalar,
//                            se_provision_seed_wrap_key
//
// Functions defined later are forward-declared here for the public
// surface but live behind `SE_SIGNER_STUB_LATER_STEPS` in the .cpp
// until their step lands.
// ============================================================

#include <Arduino.h>
#include <stdint.h>

namespace favilla {

// ── SE object identifiers ────────────────────────────────────
//
// These are part of the device's lifetime contract — once shipped,
// they cannot change without breaking factory-reset / migration.
// Kept as constexpr (not #define) for type safety: any function
// expecting a SE object id wants a uint32_t, and these provide it
// without polluting the preprocessor namespace of every TU that
// includes this header.
// ── v5.1 (15 Oct 2026): SE object GENERATIONS ───────────────────────────────
// Every object a policy names (PINs, the G0 and RECOVER auth objects, both
// PCRs) and every wallet secret lives at  legacy_base + (gen << 8),
// gen 1..SE_GEN_MAX, picked fresh at each onboarding (se_begin_new_generation)
// and stored on the G0 (SETKEYS), which reports it at boot (g0_peek_generation
// -> se_set_generation). WHY: an object that someone other than itself may
// DELETE can be recreated at the same id with values of the deleter's choice,
// and every policy naming that id accepts the impostor. For a PIN object that
// is a PIN reset. So from v5.1 nobody but a PIN may delete a PIN (no
// anonymous delete, no RECOVER delete) and nobody may delete the G0's auth
// object; a recovery wipe destroys the secrets only, and the next onboarding
// moves to the next generation. Dead objects of old generations guard nothing.
// gen 0 = the pre-v5.1 ids. SE_OBJ_PAIR_WRAP and SE_OBJ_ATTEST_KEY are device
// identity and stay fixed. These are variables now: read them, never cache
// them across a se_set_generation().
constexpr uint8_t SE_GEN_MAX  = 63;
constexpr uint8_t SE_GEN_NONE = 0xFF;   // no wallet: ids point at an unused range
void    se_set_generation(uint8_t gen);
uint8_t se_generation();
// Onboarding: pick the lowest generation >= 1 with NONE of its objects present,
// and switch to it. false if all are used (SE full of dead generations).
bool    se_begin_new_generation();
#ifdef FAVILLA_BENCH_PROBES
bool    se_bench_anon_delete(uint32_t id);   // v5.1 bench probe, bench env only
// RCE sim probes (19 Oct 2026, bench env only): see se_signer.cpp / rce_sim.h
bool     se_bench_mode_exists();
bool     se_bench_daily_session_open();
uint8_t  se_bench_mode_class();          // 1 NEUTRAL 2 NOSTR 3 BTC 4 SPENT 5 other, 0xFE absent, 0xFF unreadable
uint16_t se_bench_mode_delete_daily();   // SW; 0 = no daily session
uint16_t se_bench_mode_recreate_btc();   // SW; 0 = id still live, not attempted
uint16_t se_bench_seed_dec_spend(const char* spendPin);   // SW; 0xFFFE = spend PIN refused. Leaves no session open.
#endif
extern uint32_t SE_OBJ_AES_WRAP;  // v5.1: per generation, legacy base 0x20000020  // AES-256 wrap key (two-door: SEED only, spend-bound)
// Two-door (V1.x): SE_OBJ_AES_WRAP_SEED is the spec-vocabulary alias for the
// existing wrap key — post-split it wraps ONLY the BIP-39 seed and its ENC/DEC
// binds to the SPEND PIN. SE_OBJ_AES_WRAP_DAILY is a NEW key that wraps ONLY
// the Nostr scalar (and imported nsec), bound to the DAILY PIN, so Nostr
// signing works under Door 1 without ever touching the spend door. This split
// is the crux of two-door: one AES key per door, because a single key cannot
// be bound to two different PIN sessions. (Pre-split, ONE key wrapped both
// secrets — which would have forced the spend PIN for Nostr signing.)
extern uint32_t SE_OBJ_AES_WRAP_SEED;  // v5.1: per generation, legacy base SE_OBJ_AES_WRAP  // seed key (alias, spend-bound)
extern uint32_t SE_OBJ_AES_WRAP_DAILY;  // v5.1: per generation, legacy base 0x20000022  // AES-256 wrap key for Nostr scalar (daily-bound)
// SE_OBJ_PAIR_WRAP — device-IDENTITY wrap key (Path-A, remote cold unlock).
// AES-256 key whose CipherOneShot policy is NO-AUTH (usable while LOCKED). Its
// ONLY purpose is to deterministically derive the device pairing scalar
// (g_dDevice) by wrapping a fixed constant — exactly as SE_OBJ_AES_WRAP does for
// the identity today, but WITHOUT the SE_OBJ_USER_PIN binding so deviceIdentityInit()
// works on a cold boot. It NEVER touches the Nostr scalar or BIP-39 seed (those stay
// strictly PIN-bound on SE_OBJ_AES_WRAP). Compromise of this key yields only the
// ability to decrypt an ECDH/session envelope addressed to the device identity —
// it cannot sign, spend, or unwrap the seed. See HANDOVER remote-unlock design.
constexpr uint32_t SE_OBJ_PAIR_WRAP       = 0x20000021;  // AES-256 device-identity wrap key (NO-AUTH policy, cold-capable)
extern uint32_t SE_OBJ_NOSTR_SCALAR;  // v5.1: per generation, legacy base 0x20000002  // Wrapped 32-byte Nostr scalar (Schnorr)
// ── Isolated signer (STM32G0) objects ─────────────────────────────────────
// SE_AUTH_OBJ_G0: AES-128 AESKey auth object. The G0 opens ITS OWN SCP03
//   session against it (AN12543 3.6.3.2) — the ESP32 relays the frames blind.
//   Policy: DELETE|WRITE to the daily PIN only. No ENC/DEC bits, so nobody can
//   cipher with it; its only use is session authentication, which is not
//   policy-gated.
// SE_OBJ_PCR_UNLOCK: TRANSIENT PCR — the Door-1 AND-gate. At rest (locked) it
//   holds SHA256(zeros); PIN entry extends it to the "unlocked" value; lock /
//   timeout / spend-switch resets it; and being transient it is simply GONE
//   after an SE power cycle, which is "locked after power loss" for free.
//   Policy: READ|WRITE|DELETE to the daily PIN only (reset is a DELETE right).
// The scalar's policy then names the G0 auth object with
//   ALLOW_READ | REQUIRE_PCR_VALUE + (PCR id, unlocked value)
// which the July 2026 silicon tests confirmed is a true AND. See g0-signer
// record / TEST_NOTES for the five tests behind this.
extern uint32_t SE_AUTH_OBJ_G0;  // v5.1: per generation, legacy base 0x20000030  // AES-128 auth object for the G0's session
extern uint32_t SE_AUTH_OBJ_RECOVER;  // v5.1: per generation, legacy base 0x20000035  // 14 Oct 2026: moved from 0x20000034 (orphaned on bench unit by N21; see doc). v4.1 (24 Sep 2026): AES-128 recovery auth object (K_RECOVER = SHA256(K_SE||"favilla-recover-key")[0:16]); DELETE on the wallet secrets and MODE_PCR only (v5.1: no right on PINs, the G0 auth object or the Door-1 PCR), unlimited attempts, used solely by G0 WIPEALL
extern uint32_t SE_OBJ_PCR_UNLOCK;  // v5.1: per generation, legacy base 0x20000031  // transient PCR, Door-1 gate
extern uint32_t SE_OBJ_DOOR1_SECRET;  // v5.1: per generation, legacy base 0x20000036  // v5.1: 48 B binary, READ by the daily PIN only; X = SHA256(label||it) is the Door-1 unlock extend
extern uint32_t SE_OBJ_NSEC_IMPORT;  // v5.1: per generation, legacy base 0x20000003  // Wrapped 32-byte imported nsec (restore-from-nsec onboarding path)
extern uint32_t SE_OBJ_USER_PIN;  // v5.1: per generation, legacy base 0x70000003  // M5 user-PIN UserID auth object (arch §10.2)
// Two-door (V1.x): SE_OBJ_PIN_DAILY is the spec's name for the Door-1 PIN.
// It IS today's SE_OBJ_USER_PIN slot (0x70000003) — same object, reused, so
// existing single-PIN wallets need no migration. The alias lets two-door code
// read in the spec's vocabulary (DAILY vs SPEND) without a mass rename.
extern uint32_t SE_OBJ_PIN_DAILY;  // v5.1: per generation, legacy base SE_OBJ_USER_PIN  // Door 1 (alias)

// ── RESERVED slot IDs — NOT YET PROVISIONED (declaration only) ───────────────
// These are reserved so future features land in known-empty, collision-free
// slots and so deleteSlot() / factory-reset logic can reference them explicitly.
// Reserving an ID writes NOTHING to the SE; no provisioning code targets these
// until their features are implemented (post single-PIN V1).
//
// SE_OBJ_PIN_SPEND — Two-Door PIN (V1.x). Second UserID auth object (the "spend
//   PIN"). When implemented: the seed wrap key's ENC/DEC binding moves to THIS
//   object, and deleteSlot() must delete it (it is a USER key — wiped on reset).
extern uint32_t SE_OBJ_PIN_SPEND;  // v5.1: per generation, legacy base 0x70000005  // RESERVED (two-door spend PIN)
// SE_OBJ_PIN_PASSKEY — the passkey door's PIN (30 Oct 2026, passkey door spec
//   v1.0 section 5). Third UserID, base 0x70000007, per generation. Created at
//   onboarding only on FAVILLA_PASSKEY_DOOR builds; MODE_PCR's policy then gives
//   it READ|WRITE (arm + burn) and each credential key gives it SIGN while
//   MODE_PCR == V_3. Like the other PINs it is never deleted (a wipe leaves it
//   as dead weight; the next onboarding takes a fresh generation).
extern uint32_t SE_OBJ_PIN_PASSKEY;
// Restorable passkeys (30 Oct 2026, spec v0.7). MUST match the G0's se_objects.h.
extern uint32_t SE_OBJ_PK_SCRATCH;   // 0x20000037 + gen: P-256 private-only key; the G0 creates it (G0 SIGN|WRITE|DELETE, RECOVER DELETE)
extern uint32_t SE_OBJ_PK_MASTER;    // 0x20000038 + gen: the NOSTR copy of S_pk (2b: under K_PKN; present = the NOSTR gate open)
// 2 Nov 2026, Vault spec v0.25 section 1b (phase 2b). MUST match the G0's se_objects.h.
extern uint32_t SE_OBJ_K_PK;         // 0x20000039 + gen: AES, outer key of the PASSKEY copy
extern uint32_t SE_OBJ_K_PKN;        // 0x2000003A + gen: AES, outer key of the NOSTR copy
extern uint32_t SE_OBJ_PK_MASTER_P;  // 0x2000003B + gen: the PASSKEY copy of S_pk
extern uint32_t SE_OBJ_VPUB;         // 0x2000003C + gen: IV || AES(K_PKN, AES(K_G0, k_pub)), the vault backup publishing key (phase 3)
// 3 Nov 2026 (Vault spec P4-10): the NOSTR life's wrap key for the site index key. Passkey PIN ENC|WRITE|DELETE
// at V_3; daily PIN DEC|DELETE; RECOVER DELETE. Made when the gate opens, deleted when it closes. ESP32 only (not in the G0's list).
extern uint32_t SE_OBJ_K_IXN;        // 0x2000003D + gen
#ifdef FAVILLA_PK_RESTORABLE
bool se_pkr_ready();                              // NOSTR copy present (the gate is open)
bool se_pkr_ready_passkey();                      // PASSKEY copy present
bool se_pk2b_keys_present();                      // K_PK exists (a 2b setup)
bool se_pk_old_generation();                      // v19: K_PKN or the NOSTR copy exists (set up before v19: set the KEY up again)
bool se_pk2b_create_keys();                       // onboarding: K_PK with its v19 policy (needs passkey PIN, MODE_PCR)
// Inside an open passkey window with the session kept (se_pk_window_open(pin, true)).
bool se_pk2b_write_copies(const uint8_t pkm64[64]);   // first PASSKEY login: PK_MASTER_P = IV || AES(K_PK, inner || tag), 80 B
bool se_pk_master_read(uint8_t out64[64]);            // each window: inner || tag for the G0's PKM_IN
bool se_vpub_present();                          // phase 3: the publishing key copy exists
bool se_vpub_write(const uint8_t sealed32[32]);  // v19: NOSTR life, daily session open (daily layer over K_G0)
// P4-10 (3 Nov 2026): the site index key K_IDX, wrapped as IV(16) || AES(key, K_IDX)(32). Session-bound:
// K_PK needs the passkey session at V_3 (a window with the session kept); K_IXN ENC likewise, DEC the daily session.
bool se_idx_kixn_present();
bool se_idx_kixn_delete_in_session();             // gate closing: passkey session at V_3, or the daily session
bool se_idx_wrap(uint32_t keyId, const uint8_t k[32], uint8_t out48[48]);
bool se_idx_unwrap(uint32_t keyId, const uint8_t in48[48], uint8_t k[32]);
#endif
//
// SE_OBJ_ATTEST_KEY — Favilla device-attestation key (V1.x). On-chip ECDSA key,
//   Favilla-injected at MANUFACTURE, proves device authenticity + signs CIPHER
//   scores. DEVICE-IDENTITY, not user data:
//     • deleteSlot()/factory-reset MUST NOT delete it (must survive user wipe).
//     • Provisioning policy (no-DELETE permanent vs Favilla-rotatable) is an
//       OPEN decision for implementation time.
//   ID below is PROVISIONAL — confirm a valid EC-key-object ID range against
//   AN12543 object-ID conventions before implementing (EC key objects may have
//   different range constraints than the 0x20.. binary-blob slots used today).
constexpr uint32_t SE_OBJ_ATTEST_KEY      = 0x40000001;  // RESERVED, PROVISIONAL (device attestation ECDSA key)
// ─────────────────────────────────────────────────────────────────────────────
// Historical note: slots 0x70000001 and 0x70000002 are bench-only
// orphans from earlier bringups. 0x70000001 carries a Favilla-auth
// policy from M5 bench work; 0x70000002 carries the default-restrictive
// policy that resulted from passing empty policySet to WriteUserID
// before the self-delete policy fix. Production-fresh SE units are
// unaffected and use 0x70000003 from first onboarding.

// ── PIN policy ───────────────────────────────────────────────
// Max attempts before the PIN object locks out. Locked-out PIN objects
// cannot be unlocked; the device requires seed-restore to recover.
// V1 ships with 10 attempts (M5-verified value).
constexpr uint16_t PIN_MAX_ATTEMPTS = 10;

// ── Sizes ────────────────────────────────────────────────────
//
// Wrapped scalar layout: IV(16) || CT(32) = 48 bytes
constexpr size_t SE_BLOB_IV_LEN    = 16;
constexpr size_t SE_BLOB_CT_LEN    = 32;
constexpr size_t SE_BLOB_TOTAL_LEN = SE_BLOB_IV_LEN + SE_BLOB_CT_LEN;

// Schnorr signature is always 64 bytes (BIP-340).
constexpr size_t SCHNORR_SIG_LEN = 64;

// ECDH shared secret is the X-coordinate of the shared point.
constexpr size_t ECDH_SHARED_LEN = 32;

// ── Initialisation ───────────────────────────────────────────
//
// Initialises the I²C bus, brings the SE up via T=1' resync, and
// selects the IoT applet. Must be called once during boot, before
// any other se_* function. Safe to call multiple times — second
// and subsequent calls re-run the select but skip Wire.begin.
//
// Returns true on success. On failure, the caller MUST NOT use
// any other se_* function — they will all fail and may stall the
// task on I²C timeouts.
//
// Logs to Serial: applet version, AppletConfig, and "OK" / "FAIL".
// The boot log line is the audit trail for whether the SE came
// up cleanly.
//
// Parameters:
//   sda_pin    — ESP32 GPIO for SDA (5 on V22 bench)
//   scl_pin    — ESP32 GPIO for SCL (6 on V22 bench)
//   freq_hz    — I²C clock (100000 for V1, 400000 candidate for V1.1)
bool se_init(int sda_pin, int scl_pin, uint32_t freq_hz);

// ── Shared-I2C-bus lock hook ────────────────────────────────────────────────
// The SE051 shares the I2C bus with the MAX17048, DRV2605L, TCA9554 and BMA400.
// Those peripherals take a global mutex (I2C_LOCK) before touching the bus, but
// the SE driver historically did NOT — so a battery/haptic read firing mid-APDU
// could interrupt the SE's multi-frame T=1 exchange, desyncing it and producing
// "SW err ... (n=-1)" then "6D00" on every following INS until reboot. To close
// that race, main.cpp registers its I2C_LOCK/UNLOCK here; the SE driver holds
// the lock for the WHOLE APDU round-trip. If unset, calls are no-ops (bench use).
void se_set_bus_lock(void (*lock_fn)(), void (*unlock_fn)());

// Returns true if init has completed successfully and the SE is
// known to be responsive. Used by the boot-status log and any
// guard code that wants to fail fast before queuing a sign.
bool se_is_ready();

// ── se_power_down ────────────────────────────────────────────
// Put the SE into Power-down mode (~450 uA typ, state retained) before the
// host deep-sleeps. Sends the T=1 "End of APDU session request" S-block.
// The SE wakes automatically on the next I2C activity (falling SDA edge),
// so no explicit wake call is needed — and after deep sleep the device
// reboots and se_init() re-runs anyway.
//
// Marks the SE not-ready internally, so anything called afterwards must
// re-init rather than assume a live session.
//
// Returns true if the SE acknowledged. Fail-soft: callers should proceed to
// sleep regardless of the return value.
//
// NOTE: Deep Power-down (<5 uA) requires the ENA pad and the Vin/Vout supply
// arrangement — a board change, not reachable from firmware.
bool se_power_down();

// ── Object existence check ───────────────────────────────────
//
// Probes whether a given SE object id is provisioned (i.e., a
// ReadObject APDU returns 9000 with a non-empty body). Cheap —
// one round-trip. Used at boot to verify the wallet has been
// provisioned (Nostr scalar present means onboarding completed).
//
// Note this does NOT distinguish "object exists" from "object
// exists and has the expected size". Callers needing the latter
// should attempt a read and check the returned length.
//
// IMPORTANT LIMITATION: this probe uses ReadObject, which only
// returns 9000 for BinaryFile-type objects (e.g. the wrapped
// scalar at SE_OBJ_NOSTR_SCALAR). For AES key, EC key, or other
// non-readable object types — including SE_OBJ_AES_WRAP — this
// function returns false even when the object exists. Such keys
// must be tested by attempting a no-op operation against them
// (e.g. se_aes_wrap_block with a throwaway plaintext) and
// checking the result. For boot-time provisioning checks, prefer
// probing only the BinaryFile slots.
bool se_object_exists(uint32_t obj_id);

// ── se_transceive_raw — opaque APDU passthrough for the G0 blind relay ──
//
// Writes an APDU to the SE and returns the response verbatim, with no TLV
// parsing and no status-word interpretation. Used ONLY by g0_signer.cpp to
// carry AESKey-session (SCP03) frames between the STM32G0 and the SE. This
// processor holds no session keys and cannot read what it is carrying.
//
// Caller must hold the I2C bus lock for the whole relay sequence.
bool se_transceive_raw(const uint8_t *apdu, size_t apdu_len,
                       uint8_t *resp, size_t resp_cap, size_t *resp_len);

// ── Two-door mode latch (NOSTR/BTC) selftest — see TWO_DOOR_MODE_SPEC.md ──
// Bench/bring-up: provisions SE_OBJ_PCR_MODE (persistent, 2-PIN policy) if
// absent, then proves on silicon: create OK, daily-session set->NOSTR OK, and
// anonymous write REFUSED. Returns true only if all three pass. dailyPin is
// needed to open the gated session; pass nullptr to skip the P2 in-session set.
bool mode_pcr_selftest(const char *dailyPin);
// Set MODE_PCR -> NOSTR using an ALREADY-OPEN daily session (call right after a
// successful on-device daily unlock, session still live). Returns true on set+verify.
bool mode_pcr_set_nostr_in_open_session();
// Set MODE_PCR -> BTC using an ALREADY-OPEN spend session (onboarding calls
// this in the spend session right before the seed wrap key is created, so the
// MODE==BTC-gated key is usable for the seed wrap that immediately follows).
// 16 Sep 2026: the ESP32 cannot set BTC any more (see mode_pcr.inc). The door
// asks the latch's state, hands off to g0_mode_btc(), then verifies.
int  mode_pcr_btc_state_in_open_session();     // 0 neutral/SPENT/leftover-BTC (arm + ask the G0) | 3 already ARMed | -1 refuse
bool mode_pcr_arm_in_open_session();           // v3: extend "FAVILLA-MODE-ARM" from the open spend session, before g0_mode_btc()
bool mode_pcr_verify_btc_in_open_session();
bool mode_btc_secret_begin();                  // onboarding, daily session, BEFORE the seed wrap key
void mode_btc_value_erase();                   // wipe
bool mode_pcr_burn_after_spend_in_open_session();   // one signing session per power cycle
// Create MODE_PCR if absent, without setting a mode. Onboarding must call this
// (in a PIN session) BEFORE provisioning wrap keys whose policies reference it.
bool mode_pcr_ensure_exists();
// Read current mode from MODE_PCR via an open PIN session: 0=neutral,1=NOSTR,2=BTC.
int mode_pcr_current_in_open_session();

// ── PIN-GATE PROBE (bench, remove after) ────────────────────────────────────
// Answers: does REQUIRE_PCR_VALUE on a PIN object gate the UNLOCK itself?
// Call right after a successful daily unlock (needs MODE_PCR readable and a
// known mode). Creates two throwaway gated PINs (0x70000090/91), tries to open
// each, prints the verdict, deletes them. NOTE: it opens/closes sessions, so
// the caller's session is gone afterwards — call it late in the unlock path.
void mode_pcr_pingate_probe();

// ── Step 3 forward declaration (Nostr Schnorr sign) ──────────
//
// Will be implemented in M7 Step 3. Signs `msg32` under the
// SE-stored Nostr scalar at SE_OBJ_NOSTR_SCALAR. Internally:
//   1. ReadObject(SE_OBJ_NOSTR_SCALAR) → wrapped blob
//   2. CipherOneShot(decrypt, blob) → scalar in RAM
//   3. schnorr_sign(scalar, msg32, sig_out)  [secp256k1.h, in RAM]
//   4. mbedtls_platform_zeroize(scalar)
//
// Returns true on success. Caller does not need to zero sig_out;
// it's a public value.
//
// NOTE: declared here for the public surface but not implemented
// in M7 Step 1. Calling it now returns false and logs an error.
bool se_schnorr_sign(const uint8_t msg32[32], uint8_t sig_out[SCHNORR_SIG_LEN]);

// ── Direct scalar access (M7 Step 6 — replaces getUnmaskedKey) ──
//
// Reads the wrapped Nostr scalar from SE_OBJ_NOSTR_SCALAR, AES-unwraps
// it to RAM, returns. Caller is responsible for using the scalar
// quickly and zeroing it with mbedtls_platform_zeroize immediately
// after use. The RAM-exposure window is the caller's responsibility.
//
// Used by ECDH paths (NIP-04, NIP-44) where the scalar genuinely
// needs to be in firmware RAM (see security architecture §8.3 —
// SE-native ECDH was rejected for V1 to avoid storage drift). These
// paths previously used getUnmaskedKey (ATECC); they now use this
// function and ATECC code can be deleted entirely.
//
// Fail-closed on PIN session, same invariant as seed_unwrap_to_ram
// and se_schnorr_sign. Returns false if no session, SE not ready,
// or any APDU/unwrap failure.
//
// Cost (projected from M6.5 SE numbers): ~50ms p95 (22ms SE read +
// 28ms AES unwrap + sub-ms copy out).
//
// *** DISABLED (isolated-signer build). Always returns false and zeroes `out`. ***
//
// The scalar is stored double-wrapped, AES(K_DAILY, AES(K_G0, scalar)), and the
// inner key K_G0 exists only inside the STM32G0 behind RDP-2. There is no path
// that returns the plaintext scalar to this processor. Use:
//   signing        -> se_schnorr_sign()  (G0 SIGN)
//   NIP-04/44 DMs  -> nostr_ecdh()       (G0 ECDH, via the hook in secp256k1.h)
//   public key     -> g0_get_pubkey()
//   PWA cache key  -> g0_get_cache_key() (HKDF, one-way)
// Retained only so a forgotten caller fails closed rather than silently using
// uninitialised memory.
bool se_get_nostr_scalar(uint8_t out[32]);

// ── Step 4 forward declaration (NIP-04 / NIP-44 ECDH) ────────
//
// Will be implemented in M7 Step 4. Computes the X-coordinate of
// d * peer_pubkey, where d is the SE-stored Nostr scalar and
// peer_pubkey is the 33-byte compressed pubkey of the other party.
//
// For NIP-44 v2, caller applies HKDF-SHA256 to shared_x with
// salt="nip44-v2" to derive the conversation key. For NIP-04,
// caller uses shared_x directly as the AES key (legacy).
//
// NOTE: not implemented in M7 Step 1. Calling it now returns false.
bool se_ecdh(const uint8_t peer_pubkey33[33], uint8_t shared_x_out[ECDH_SHARED_LEN]);

// ── AES wrap / unwrap (used by seed storage layer) ───────────
//
// Encrypts/decrypts a 32-byte plaintext under the SE-stored AES-256
// key at SE_OBJ_AES_WRAP using AES-CBC with no padding. The seed
// storage code in V22.1 calls these directly to wrap/unwrap each
// 32-byte half of the BIP-39 seed.
//
// IV must be 16 bytes; caller is responsible for generating fresh
// IVs (use esp_random) and storing them alongside the ciphertext.
bool se_aes_wrap_block  (const uint8_t plaintext[32], const uint8_t iv[16], uint8_t ct_out[32]);
bool se_aes_unwrap_block(const uint8_t ciphertext[32], const uint8_t iv[16], uint8_t pt_out[32]);

// Two-door (V1.x): keyed variants. wrap/unwrap a 32-byte block under an
// explicit AES wrap-key object:
//   - SE_OBJ_AES_WRAP_SEED  (spend-bound) → BIP-39 seed halves.
//   - SE_OBJ_AES_WRAP_DAILY (daily-bound) → Nostr scalar / imported nsec.
// The SE enforces the binding: the seed key's DEC only succeeds inside a SPEND
// session; the daily key's DEC only inside a DAILY session. The legacy
// se_aes_wrap_block/se_aes_unwrap_block above default to SE_OBJ_AES_WRAP_SEED.
bool se_aes_wrap_block_keyed  (uint32_t keyObjId, const uint8_t plaintext[32], const uint8_t iv[16], uint8_t ct_out[32]);
bool se_aes_unwrap_block_keyed(uint32_t keyObjId, const uint8_t ciphertext[32], const uint8_t iv[16], uint8_t pt_out[32]);

// ── Pair-wrap (Path-A device identity, cold-capable) ─────────
//
// Identical primitive to se_aes_wrap_block, but keyed by SE_OBJ_PAIR_WRAP
// (NO-AUTH policy) and sent as an ANONYMOUS CipherOneShot — i.e. NOT routed
// through a PIN session. These therefore WORK WHILE THE DEVICE IS LOCKED.
// Used by deviceIdentityInit() to derive the device pairing scalar on a cold
// boot. Do NOT use these for the Nostr scalar or BIP-39 seed — those must stay
// on the PIN-bound se_aes_wrap_block path.
//
// Returns false if SE not ready or the pair-wrap key is not provisioned.
bool se_pair_wrap_block  (const uint8_t plaintext[32], const uint8_t iv[16], uint8_t ct_out[32]);
bool se_pair_unwrap_block(const uint8_t ciphertext[32], const uint8_t iv[16], uint8_t pt_out[32]);

// Provisions the NO-AUTH AES-256 device-identity wrap key at SE_OBJ_PAIR_WRAP.
// Unlike se_provision_aes_wrap_key, this does NOT require an open PIN session —
// the key's policy references no auth object. It is, however, called from
// contexts where a PIN session already exists (onboarding; lazy migration on
// first on-device unlock) purely so it is created at a moment the user is
// authenticated at the device. Idempotent: deletes any prior key first.
// Returns true on success (or if already present, see se_pair_wrap_exists).
bool se_provision_pair_wrap_key();

// True if SE_OBJ_PAIR_WRAP exists on the chip. Used by the lazy-migration hook
// to decide whether an already-provisioned (pre-Path-A) device needs the new
// key created on this unlock.
bool se_pair_wrap_exists();


// ── PIN session (M5 — real hardware PIN check) ───────────────
//
// Opens a session against SE_OBJ_USER_PIN by sending the user's
// entered PIN. The SE compares against the provisioned PIN value
// internally; on match returns 9000 and an 8-byte session handle.
// On mismatch returns 6985 — the SE's hardware retry counter
// decrements toward PIN_MAX_ATTEMPTS, after which the PIN object
// is permanently locked and seed-restore is the only recovery.
//
// Calling se_pin_session_open(pin) is REQUIRED before any
// seed_unwrap_to_ram, se_schnorr_sign, se_get_nostr_scalar, or
// provisioning operation. These fail-closed when no session is
// open.
//
// pin should be ASCII bytes (e.g. "1234" for a 4-digit PIN).
// pin_len is the byte length. Caller must zero pin after the call.
//
// Returns true if the PIN matched and the session was created.
// Returns false on wrong PIN, locked-out PIN object, or SE failure.
// The session ID is held internally — callers don't see it.
bool se_pin_session_open(const char *pin);

// Two-door (V1.x): object-ID-aware variant. Opens a session against an
// arbitrary PIN auth object (SE_OBJ_PIN_DAILY or SE_OBJ_PIN_SPEND).
//   - SE_OBJ_PIN_DAILY → daily unlock (Nostr + watch-only BTC).
//   - SE_OBJ_PIN_SPEND → transient spend session (unwrap seed, sign one TX).
// IMPORTANT: unlike the legacy single-object open, this does NOT silently
// succeed when a session for a DIFFERENT object is already open. The spend
// path requires a genuine SE_OBJ_PIN_SPEND session; if a daily session is
// open it is closed first, so the wrap key's spend-bound policy is satisfied
// by the live session and seed_unwrap_to_ram succeeds. Re-opening the SAME
// object that is already open is still a no-op success (idempotent).
// The legacy se_pin_session_open(pin) is now a thin wrapper that targets
// SE_OBJ_PIN_DAILY, so existing daily-unlock callers are unchanged.
bool se_pin_session_open_obj(uint32_t pinObjId, const char *pin);
// Status word of the most recent CreateSession. On this SE a LOCKED PIN
// object answers 6986 at CreateSession (a wrong PIN fails later, at the
// verify, with 6985) - so 6986 here means the object is gone for good and
// only the recovery wipe can help (bench, 24 Sep 2026).
extern uint16_t g_lastCreateSessionSW;
static inline bool se_pin_object_locked() { return g_lastCreateSessionSW == 0x6986; }

void se_pin_session_close();
bool se_pin_session_is_open();
// Two-door: which PIN object the currently-open session authenticates
// against (0 if none open). Lets callers assert they hold the right door.
uint32_t se_pin_session_obj();

// ── Seed storage (Step 2 — Strategy A: SE wrap, NVS persist) ───────
//
// The BIP-39 seed (64 bytes) is stored as:
//   IV_lo(16) || CT_lo(32) || IV_hi(16) || CT_hi(32)  = 96 bytes
// in ESP32 NVS under namespace "favilla_se", key "seed_blob".
// Each 32-byte half is independently AES-CBC encrypted under the
// SE-stored wrap key at SE_OBJ_AES_WRAP with a fresh per-half IV.
//
// The seed is exposed in cleartext RAM only:
//   - During seed_store, between caller derivation and SE wrap call
//   - During seed_unwrap_to_ram + caller's subsequent use, until
//     caller zeroes the buffer with mbedtls_platform_zeroize
//
// Callers MUST:
//   1. Open a PIN session via se_pin_session_open() before unwrap
//   2. Zero the seed buffer immediately after deriving the signing
//      scalar — do NOT hold the seed for the duration of a session.
//      Target RAM exposure window: <500ms per signing operation.

// Wraps the seed and writes the blob to NVS. The input buffer is
// NOT zeroed by this function — caller decides when to zero (after
// also using the seed to derive any other long-lived keys, e.g.
// the Nostr scalar that goes into se_provision_nostr_scalar).
//
// v5.1: the 96-byte blob is handed to the G0 (SEEDSTORE, write-once) and
// never written to this chip's flash. Returns false on SE failure or if the
// G0 refuses (a seed already stored, no seal this life, flash failure).
bool seed_store(const uint8_t seed[64]);

// v4 (24 Sep 2026): per-session passphrase wallets seal the ENTROPY (16 or
// 32 bytes, wc = 12 or 24) instead of a derived seed. Same 96-byte blob in
// the same NVS slot (G0 ENTSEAL inner layer + SE outer layer), tagged with
// seed_kind = 1 so the door delivers it to the G0's ENT_IN register and asks
// for the passphrase. The tag is a hint only: the G0 verifies the container
// magic under its own key, so a flipped tag fails closed.
bool seed_store_entropy(const uint8_t* entropy, int word_count);
constexpr uint8_t SEED_KIND_SEED    = 0;
constexpr uint8_t SEED_KIND_ENTROPY = 1;
uint8_t seed_blob_kind();   // v5.1: SEED_KIND_* from the G0's seed record; SEED_KIND_SEED when absent

// Reads the blob from NVS and unwraps both halves to RAM.
// Fail-closed if no PIN session is open. Caller must zero seed_out
// with mbedtls_platform_zeroize after use.
//
// Returns false if: no PIN session, no blob in NVS, NVS read error,
// SE unwrap error, or blob malformed (wrong length).
bool seed_unwrap_to_ram(uint8_t seed_out[64]);   // v3: DISABLED, always false — see se_signer.cpp

// v3: the 96-byte seed blob (ciphertext) for delivery to the G0's DOORKEYS /
// BTCSIGN commands. No session needed; the bytes open nothing on this chip.
bool seed_blob_read(uint8_t blob[96], uint8_t* kind = nullptr, uint8_t ihash[32] = nullptr);   // v5.1: from the G0 (SEEDGET)
// v5 (15 Oct 2026): strip the SE layer inside an open SPEND PIN session (latch
// must read BTC). Output = the G0's inner layer, for g0_pack_inner_packet().
bool seed_inner_from_blob_in_open_session(const uint8_t blob[96], uint8_t inner_out[64]);

// v5.1: true if the G0 holds a seed record (one SEEDGET over I2C, no SE).
bool seed_is_provisioned();

// v5.1: removes a LEGACY (pre-v5.1) seed blob from NVS. The live seed is on
// the G0 and is cleared only by g0_wipe_keys() (WIPEKEYS, gated). Idempotent.
bool seed_erase_from_nvs();

// ── Object provisioning (onboarding paths) ───────────────────
//
// Will be implemented in M7 Step 6. Three onboarding paths converge
// here:
//
//   - New BIP-39:    generate 256-bit entropy → derive seed → derive
//                    Nostr scalar via NIP-06 → se_provision_nostr_scalar
//                    with the derived scalar.
//
//   - Restore seed:  user enters BIP-39 words → derive seed → derive
//                    Nostr scalar via NIP-06 → se_provision_nostr_scalar.
//
//   - Restore nsec:  user scans bech32/hex nsec → 32-byte scalar →
//                    se_provision_imported_nsec. The Bitcoin seed
//                    is NOT provisioned in this path (Nostr-only wallet).
//
// Both functions are idempotent: they delete any existing object at
// the target slot before writing. Caller must zero `scalar` after
// the call.
bool se_provision_aes_wrap_key();                                 // first-boot only

// Two-door (V1.x): bind the wrap key's ENC/DEC to a chosen PIN object.
//   bindObjId = SE_OBJ_PIN_SPEND → seed is unwrappable ONLY under a Door-2
//   spend session (the security promise). DELETE is additionally granted to
//   SE_OBJ_PIN_DAILY so a wipe from the daily session can destroy the key.
//   PRECONDITION: a session against bindObjId must be open (its WRITE policy
//   is satisfied by that session). The legacy se_provision_aes_wrap_key()
//   binds to SE_OBJ_PIN_DAILY (single-PIN behaviour, unchanged).
bool se_provision_aes_wrap_key_bound(uint32_t bindObjId);

// Two-door (V1.x): provision each wrap key explicitly.
//   se_provision_aes_wrap_key_seed()  — SEED key, ENC/DEC bound to SPEND,
//       DELETE also granted to daily (for "either PIN wipes both"). Requires
//       an open SPEND session. Wraps ONLY the BIP-39 seed.
//   se_provision_aes_wrap_key_daily() — DAILY key, ENC/DEC bound to DAILY.
//       Requires an open DAILY session. Wraps ONLY the Nostr scalar / nsec.
bool se_provision_aes_wrap_key_seed();
bool se_provision_aes_wrap_key_daily();
bool se_provision_nostr_scalar(const uint8_t scalar[32]);

// ── Isolated-signer provisioning (onboarding, air-gapped) ─────────────────
//
// se_provision_g0_identity() — call ONCE per onboarding, with the DAILY PIN
// session open, BEFORE se_provision_aes_wrap_key_daily() (whose policy names
// the G0 auth object and the PCR, so both must exist first). It:
//   1. draws K_SE (16 B) and K_G0 (32 B) from the SE TRNG,
//   2. writes K_SE to the SE as the G0's AESKey auth object (SE_AUTH_OBJ_G0),
//   3. makes sure the transient PCR exists (locked) and extends it (the daily
//      session is open, so the device is unlocked),
//   4. hands both keys to the G0 and requires its acknowledgement,
//   5. zeroizes both keys.
// If step 4 fails the SE auth object is deleted again so the SE never holds an
// auth key that nothing can use. Refuses if the G0 is not present.
bool se_provision_g0_identity();

// v4.1 (24 Sep 2026) — BRICK GUARD, SE side. Must run FIRST in every onboarding
// path, before the daily PIN object is written: every later object names
// SE_AUTH_OBJ_RECOVER in its policy (DELETE only), and a policy may not name
// an auth object that does not exist yet. Generates K_SE here (parked for
// se_provision_g0_identity), derives K_RECOVER, creates the auth object
// anonymously with a self-only policy. Refuses if the object already exists
// (a leftover recovery object is removed only by G0 WIPEALL).
bool se_provision_recovery_auth();
bool se_recovery_auth_exists();

// True when both isolated-signer objects exist on the SE (boot diagnostics).
bool se_g0_objects_present();

// The Door-1 PCR. se_init() creates it locked if it is absent (transient
// objects vanish on SE power-up). Reading its state back is a diagnostic —
// the SE enforces the gate, the ESP32 merely observes it.
bool se_pcr_ensure_exists();
bool se_pcr_is_unlocked();         // new BIP-39 + restore seed paths
bool se_provision_imported_nsec(const uint8_t scalar[32]);        // restore-nsec path

// ── PIN provisioning (M5 — user PIN object) ──────────────────
//
// Creates the user PIN as a UserID auth object at SE_OBJ_USER_PIN with
// max_attempts = PIN_MAX_ATTEMPTS. Called once during onboarding when
// the user picks their PIN.
//
// PIN bytes are ASCII; V22 onboarding uses 4-digit numeric PINs but
// the SE supports up to 32-byte values, so longer PINs are a future
// V1.x feature without an APDU change. Caller must zero `pin` after
// the call.
//
// Idempotent: any existing PIN object at SE_OBJ_USER_PIN is deleted
// first. This means "change PIN" reuses this function with the new
// value; locked-out PIN objects can also be cleared this way only
// if the firmware authenticates via Favilla auth first (V1 cannot —
// recovery requires seed restore, which provisions a new PIN as
// part of the onboarding flow).
//
// Returns true on success. Does not open a session — caller must
// se_pin_session_open(pin) after provisioning to actually unlock
// SE operations.
bool se_pin_provision(const uint8_t *pin, size_t pin_len);

// Two-door (V1.x): object-ID-aware provisioning. Writes a PIN UserID auth
// object at an arbitrary slot.
//   - SE_OBJ_PIN_DAILY → self-policy (R/W/D to its own session), as today.
//   - SE_OBJ_PIN_SPEND → ANONYMOUS-delete policy in ADDITION to self R/W, so
//     a wallet wipe driven from a DAILY session (the only door open at
//     Delete-Key time) can still destroy it. This is the deliberate, benign
//     weakening agreed for "either PIN wipes both": deleting the spend PIN
//     only strands the seed (same as lockout) — it never exposes spend
//     authority. The legacy 2-arg se_pin_provision targets SE_OBJ_PIN_DAILY.
bool se_pin_provision_obj(uint32_t pinObjId, const uint8_t *pin, size_t pin_len);

// ── se_pin_destroy (M5 — authenticated PIN deletion) ─────────────
//
// Deletes the PIN object at SE_OBJ_USER_PIN by opening a session
// with the current PIN, then issuing DeleteSecureObject from inside
// that session. The session has the auth required to delete the
// object (anonymous delete is refused due to PIN object policy).
//
// Use cases:
//   - PIN change flow: destroy old PIN → provision new PIN
//   - Cleanup of bench-test residue (smoke test PIN objects)
//
// Returns true if the object is gone after the call (success path)
// or if it was never there. Returns false if authentication failed
// (wrong PIN — SE retry counter decremented) or any APDU error.
bool se_pin_destroy(const char *current_pin);

// ── se_factory_reset (nuclear — wipes the entire SE namespace) ─────
//
// Issues the SE051 IoT applet's DeleteAll command (AN12543 §4.x).
// This destroys EVERY object in the SE — AES keys, PIN objects,
// BinaryFiles, EC key pairs, the lot. Only the applet itself
// survives.
//
// Use cases:
//   - Bench debugging: recovering from objects stuck behind policies
//     we can't authenticate against
//   - User-initiated factory reset (V1 will expose this through a
//     "Wipe device" menu option, paired with the existing ATECC wipe)
//
// Side effects: also clears the favilla_se/wrapkey_done NVS flag, so
// the next se_first_boot_setup() call will regenerate the AES wrap
// key from scratch.
//
// Returns true on SE acknowledgement. After this returns, the SE is
// in a virgin state and the device must be re-onboarded.
bool se_factory_reset();
// Probe: does RESERVED_ID_FACTORY_RESET exist? (decides if DeleteAll is possible)
bool se_factory_reset_probe();

// ── se_random (TRNG → host) ──────────────────────────────────────
//
// Reads `len` bytes from the SE's hardware-backed RNG. The SE051
// RNG is an AIS31 PTG.2 TRNG feeding an AIS20 DRG.4 PRNG, evaluated
// under Common Criteria EAL 6+. Use this as a second entropy source
// alongside ESP32's esp_fill_random for defense-in-depth — XOR the
// two sources so a compromise of either preserves entropy.
//
// `len` must be ≥ 1 and ≤ 256. Larger requests need multiple calls.
// Does NOT require an open PIN session (per AN12543 GetRandom does
// not check session auth).
//
// Cost: ~5-10ms typical. Single APDU round-trip.
//
// Returns true on success and fills `out`. Returns false on any SE
// error; `out` is zeroed in that case so callers can fail closed.
bool se_random(uint8_t *out, size_t len);

// ── First-boot setup ─────────────────────────────────────────
//
// Generates the AES wrap key on the very first boot of a virgin
// device. Uses a NVS-stored flag ("favilla_se" / "wrapkey_done")
// to know whether this has run before. The wrap key is the
// precondition for every subsequent SE crypto operation, so this
// MUST succeed before onboarding starts.
//
// Idempotent: calling multiple times is a no-op after the first
// successful run.
//
// Returns true if (a) the flag was already set, or (b) the key
// was just provisioned. Returns false if provisioning failed —
// caller should treat this as a hard error and refuse to onboard.
bool se_first_boot_setup();

#ifdef FAVILLA_PASSKEY_DOOR
// ── Passkey door (30 Oct 2026, step 3b) — passkey_door.inc ────────────────
// The real door: passkey PIN (SE_OBJ_PIN_PASSKEY), MODE_PCR at V_3 minted by
// the G0's MODEDOOR, credential keys that sign only there. Callers hold the
// I2C lock. Every call closes any PIN session that was open.
bool se_passkey_ready();                                         // passkey PIN + V_3 + MODE_PCR present
bool se_passkey_pin_provision(const uint8_t* pin, size_t len);   // onboarding only (fresh generation)
int  se_passkey_pin_check(const char* pin);                      // 1 accepted, 0 refused (costs an SE attempt)
bool se_passkey_keygen(uint32_t obj, uint8_t pub65[65], uint16_t* sw);
bool se_passkey_sign(uint32_t obj, const char* pin, const uint8_t hash32[32], uint8_t* der, size_t* derN, uint16_t* sw);
#ifdef FAVILLA_BENCH_PROBES
int  se_pkprobe(const char* pin);   // 2 Nov 2026: `bench pkprobe`, the Vault spec 1b policy probe
#endif
void se_passkey_delete(uint32_t obj);
int  se_passkey_free();
void se_passkey_wipe_credentials();                              // called from se_pin_destroy
bool se_passkey_wedged();                                        // a burn was not confirmed this boot: no more logins
// 2 Nov 2026 (2b): a passkey window - ARM, G0 mints V_3, [op], burn. Caller holds the I2C lock.
bool se_pk_window_open(const char* pin, bool keepSession);
bool se_pk_window_close(const char* pin);
#endif

} // namespace favilla

#endif // FAVILLA_SE_SIGNER_H
