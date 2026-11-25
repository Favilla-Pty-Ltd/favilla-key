// =============================================================================
// g0_signer.h — ESP32 side of the isolated Nostr signer (STM32G0)
// =============================================================================
//
// WHY THIS EXISTS
// ---------------
// Before this module, se_schnorr_sign() unwrapped the Nostr scalar into ESP32
// RAM and signed there. That put a long-lived identity key in the address space
// of the processor that runs the radios and every parser (JSON, UR, PSBT, QR).
// A memory-safety flaw in any of those paths could yield RCE and a permanent,
// unrecoverable key theft.
//
// The scalar now lives on a dedicated STM32G0 that has no radios, no network
// stack, and no parser. This file is the ESP32's half of that split.
//
// WHAT THE ESP32 HOLDS AFTER THIS CHANGE
// --------------------------------------
//   - the 32-byte event hash          (public)
//   - the 64-byte signature           (public)
//   - opaque session frames it relays (ciphertext; no keys to open them)
//   - NOTHING else. No scalar, no session auth key, no K_G0.
//
// If you grep this firmware image and find key material for the Nostr path,
// something has gone wrong.
//
// THE BLIND RELAY
// ---------------
// The ESP32 has no spare GPIO, so the G0 and the SE share the existing I2C bus
// with the ESP32 as sole master. Because the G0 is an I2C *target* it cannot
// initiate transactions to the SE. The ESP32 therefore relays the G0<->SE
// exchange frame by frame. Those frames belong to an AESKey *applet session*
// (AN12543 3.6.3.2) — SCP03 crypto (AES-CBC + CMAC) end to end between the G0
// and the SE — so the ESP32 carries sealed traffic it can neither read nor
// forge.
//
// This is an applet session, NOT Platform SCP. The distinction matters:
// Platform SCP is platform-wide, and mandating it (SCP_REQUIRED) would make the
// SE refuse every plain APDU — locking THIS processor out of the SE entirely
// and breaking all Bitcoin operations. An applet session is scoped by session
// ID, so the ESP32 keeps its own concurrent PIN session for Bitcoin, unchanged.
//
//     *** SCP_REQUIRED MUST NOT BE SET DURING PROVISIONING. ***
//
// The relay is sound because the session is addressed by a session ID carried
// inside the APDU payload (AN12543 4.5.1.3), not by the transport — the applet
// neither knows nor cares that a third party moved the bytes.
//
// DEFENCE IN DEPTH: THE SECOND WRAP
// ---------------------------------
// The session channel alone would be a single point of failure for the most
// important secret
// on the device. So the scalar is stored double-wrapped:
//
//     SE object  =  AES(K_DAILY, AES(K_G0, scalar))       (48 bytes: IV||CT)
//                        ^                ^
//                        |                +-- key exists ONLY in G0 flash,
//                        |                    sealed behind RDP Level 2
//                        +------------------- SE-held, PIN-gated, non-extractable
//
// The SE unwraps its own layer and emits the still-K_G0-encrypted blob. The SE
// therefore never outputs a plaintext scalar. Even with the channel absent or
// broken,
// what crosses the bus is ciphertext only the G0 can open.
//
// THREAT MODEL
// ------------
// In scope:     remote software compromise of the ESP32.
// Out of scope: physical attack on an opened, powered, unlocked device.
// Residual:     a compromised ESP32 can still REQUEST signatures (an oracle).
//               That is forged authorship, not key theft, and does not survive
//               a reboot into Secure-Boot-verified firmware.
// =============================================================================

#pragma once
// 11cd (20 Nov 2026, issue #40 C11): Emberwill ships in v1 as BETA. Its code
// was fenced by FAVILLA_BENCH_PROBES, which a release build refuses; it now has
// its own switch, on in release builds and in every bench build.
#if (defined(FAVILLA_RELEASE) || defined(FAVILLA_BENCH_PROBES)) && !defined(FAVILLA_EMBERWILL) && !defined(FAVILLA_NO_EMBERWILL)
#define FAVILLA_EMBERWILL 1
#endif
#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

// -----------------------------------------------------------------------------
// Wire protocol — must match g0/include/g0_proto.h byte for byte.
// -----------------------------------------------------------------------------
constexpr uint8_t  G0_I2C_ADDR      = 0x42;

// Registers
constexpr uint8_t  G0_REG_CMD       = 0x00;  // W, 1 byte
constexpr uint8_t  G0_REG_STATUS    = 0x01;  // R, 1 byte
constexpr uint8_t  G0_REG_HASH_IN   = 0x10;  // W, exactly 32 bytes
constexpr uint8_t  G0_REG_SIG_OUT   = 0x11;  // R, exactly 64 bytes
constexpr uint8_t  G0_REG_RELAY_OUT = 0x20;  // R, [len_hi][len_lo][payload] — every read
                                             //    streams from byte 0 (see g0_pump_relay)
constexpr uint8_t  G0_REG_RELAY_IN  = 0x21;  // W, [len_hi][len_lo][payload]
constexpr uint8_t  G0_REG_SELFTEST  = 0x7F;  // R, 16 bytes: 'G0ST',ver,npass,ntotal,flags,
                                             //    sign_ms u16, verify_ms u16, ecdh_ms u16, 0,0

// Commands
constexpr uint8_t  G0_CMD_SIGN      = 0x01;  // RETIRED 27 Oct 2026 (anti-exfil): the G0 no longer accepts it. Kept so the id is never reused.
constexpr uint8_t  G0_CMD_RESET     = 0x02;  // abort, zeroize, return to IDLE
constexpr uint8_t  G0_CMD_PROVISION = 0x03;  // onboarding only; see g0_seal_scalar()
constexpr uint8_t  G0_CMD_ECDH      = 0x04;  // NIP-04/44 shared secret
constexpr uint8_t  G0_CMD_PUBKEY    = 0x05;  // x-only public key
constexpr uint8_t  G0_CMD_CACHEKEY  = 0x06;  // HKDF PWA cache key
constexpr uint8_t  G0_CMD_SETKEYS   = 0x07;  // onboarding only; see g0_set_keys()
constexpr uint8_t  G0_CMD_WIPEKEYS  = 0x08;  // wallet delete; see g0_wipe_keys()
constexpr uint8_t  G0_CMD_SESSIONTEST = 0x09; // step-3 bring-up: G0 opens its SE session, fetches the scalar, reports
constexpr uint8_t  G0_CMD_MODERESET   = 0x0A; // two-door: reset MODE_PCR->NEUTRAL, one-shot per physical boot
constexpr uint8_t  G0_CMD_MODEDEL     = 0x0C; // RETIRED 19 Oct 2026: the G0 no longer accepts it (finding 3). Kept only so the id is never reused.
constexpr uint8_t  G0_CMD_MODEBTC     = 0x0B; // two-door (16 Sep 2026): extend MODE_PCR with the G0's secret S
                                              // -> BTC = SHA256(NEUTRAL || S). One-shot per physical boot,
                                              // separate arm from MODERESET. The ESP32 knows the VALUE (it
                                              // is in the seed key's policy) but never S, so it cannot
                                              // produce BTC itself — nor can an RCE. SE-enforced.
// v3 (16 Sep 2026): Bitcoin signing inside the G0. The seed is plaintext only
// on the G0. See g0/ (witness tree) main.c header and G0_V3_HANDOVER.md.
constexpr uint8_t  G0_CMD_SEEDSEAL    = 0x0D; // onboarding: SEED_IN[0..63] = seed -> SIG_OUT = 64-byte inner CT
constexpr uint8_t  G0_CMD_DOORKEYS    = 0x0E; // SEED_IN = NVS blob -> BTC_OUT = fp, xpub84, xpub48, state key
constexpr uint8_t  G0_CMD_BTCSIGN     = 0x0F; // RETIRED 27 Oct 2026 (anti-exfil): replaced by BTCSIGN_INIT + AE_FINISH
constexpr uint8_t  G0_CMD_SLEEP       = 0x10; // power: G0 enters Stop mode, wakes on next I2C address match
constexpr uint8_t  G0_CMD_DOORNOSTR   = 0x11; // door memory (24 Sep 2026): declare this physical boot a NOSTR life
constexpr uint8_t  G0_CMD_DOORBTC     = 0x12; // door memory (24 Sep 2026): declare this physical boot a BITCOIN life
constexpr uint8_t  G0_CMD_ENTSEAL     = 0x13;
constexpr uint8_t  G0_CMD_WIPEALL     = 0x14; // v4.1 (24 Sep 2026): recovery wipe over K_RECOVER (SE_AUTH_OBJ_RECOVER), fixed order, PIN objects last // v4 (24 Sep 2026): ENT_IN[0]=wc, [1..32]=entropy -> SIG_OUT = 64-byte inner CT of the entropy container

// ── SE051 deep power-down over ENA (13 Oct 2026, ENA-wired boards) ───────────
// SE051 ENA is driven by G0 PB2 (pin 17; 1 M pull-up = SE on when the G0 is in reset).
// SEPWR_ON/OFF are applied in the G0's ISR with NO status change, so SEPWR_ON
// is safe as the very first word after a wake. SLEEPDEEP = Stop mode with ENA
// low; EVERY Stop exit raises ENA again, so the ESP32's boot probe of 0x42 is
// also the SE's power-on. Plain SLEEP (idle dim) leaves the SE powered.
constexpr uint8_t  G0_CMD_SEPWR_OFF   = 0x15;
constexpr uint8_t  G0_CMD_SEPWR_ON    = 0x16;
constexpr uint8_t  G0_CMD_SLEEPDEEP   = 0x17;
// v5.1 (15 Oct 2026): the seed blob lives on the G0, and Door 1 is locked at boot.
constexpr uint8_t  G0_CMD_SEEDSTORE   = 0x18; // STORE_IN = kind || outer(96) -> write-once seed page on the G0
constexpr uint8_t  G0_CMD_SEEDGET     = 0x19; // BTC_OUT <- "SGET" + kind + outer(96) + inner hash(32)
constexpr uint8_t  G0_CMD_DOOR1LOCK   = 0x1A; // G0 extends SE_OBJ_PCR_UNLOCK off the unlocked value over its own session
constexpr uint8_t  G0_CMD_MSGSIGN     = 0x1B; // RETIRED 27 Oct 2026 (anti-exfil): replaced by MSGSIGN_INIT + AE_FINISH
// ── Anti-exfil signing (27 Oct 2026) ────────────────────────────────────────
// Every signature is two round trips: INIT carries the message (or request)
// plus h = TAGGED(t) for a t this processor drew, and answers R0 (the G0's
// nonce commitment); AE_FINISH carries t and answers the signature made with
// k = k0 + TAGGED(R0 || t). This processor then checks x(R0 + TAGGED(R0||t)G)
// == r and verifies the signature (antiexfil_host.h). Any mismatch is an
// ANTI-EXFIL FAULT: the signature is zeroised, never used, and signing is
// latched off until reboot (g0_antiexfil_faulted). There is no one-shot
// signing command left on the G0, so there is no way to ask it for an
// uncommitted nonce.
constexpr uint8_t  G0_CMD_SIGN_INIT    = 0x1C; // AE_IN = event id(32) || h(32)            -> SIG_OUT = R0(33) + zeros
constexpr uint8_t  G0_CMD_AE_FINISH    = 0x1D; // AE_T = t                                  -> SIG_OUT = sig64 | BTC_OUT "BSIG"/"MSIG"
constexpr uint8_t  G0_CMD_BTCSIGN_INIT = 0x1E; // SEED/ENT_IN, BTC_IN, AE_IN = zeros(32)||h -> BTC_OUT "BSIG" v3: pub33, R0, sighash
constexpr uint8_t  G0_CMD_MSGSIGN_INIT = 0x1F; // same registers                           -> BTC_OUT "MSIG" v2: pub33, R0, digest
// Generic doors (30 Oct 2026, G0 image with SELFTEST[25] = 1)
constexpr uint8_t  G0_CMD_DOORPASSKEY = 0x20; // declare this physical boot a PASSKEY life (first-wins, like the other doors)
constexpr uint8_t  G0_CMD_PKSIGN      = 0x22; // restorable passkeys (30 Oct 2026): PK_IN -> BTC_OUT "PKSG"
constexpr uint8_t  G0_CMD_PKSCRUB     = 0x23; // junk over the scratch key; SIG_OUT "PKSC"
constexpr uint8_t  G0_CMD_PKMASTER    = 0x24; // HASH_IN = S_pk -> SIG_OUT = inner32 || tag32 (v19); onboarding seal window only, once
constexpr uint8_t  G0_REG_PKM_IN      = 0x25; // v19: W, exactly 64: the master's inner || tag from the passkey session, before each PKSIGN / VAULT
constexpr size_t   G0_PKM_LEN         = 64;
constexpr uint8_t  G0_SELFTEST_VER_DOORPIN = 19;   // SELFTEST v19 (13 Nov 2026): one door one PIN (the master only from the passkey session), byte 26 = RDP level
constexpr uint8_t  G0_REG_PK_IN       = 0x22; // W, exactly G0_PK_IN_LEN (0x1B is Emberwill EM_HDR)
constexpr size_t   G0_PK_IN_LEN       = 97;   // op || nonce16 || tag16 || rpIdHash32 || hash32
constexpr uint8_t  G0_SELFTEST_VER_PK = 10;   // SELFTEST v10: PKSIGN / PKSCRUB present
constexpr uint8_t  G0_SELFTEST_VER_UV = 11;   // SELFTEST v11: UVSET / UVCHECK / UVCLEAR present
constexpr uint8_t  G0_SELFTEST_VER_VAULT = 12;   // SELFTEST v12: VAULT (SEAL / OPEN / TAG) present, 2 Nov 2026
constexpr uint8_t  G0_SELFTEST_VER_VPUB  = 14;   // SELFTEST v14: VAULT op PUBSEAL + VSIGN_INIT (vault backup publishing key, 2 Nov 2026)
constexpr uint8_t  G0_SELFTEST_VER_V15   = 15;   // SELFTEST v15: VAULT op IMPORT (window) and op LABEL (3 Nov 2026, Vault spec 7f)
constexpr uint8_t  G0_SELFTEST_VER_V18   = 18;   // SELFTEST v18: hedged nonces for passkey and Bitcoin signatures (fault hardening), 7 Nov 2026
constexpr uint8_t  G0_SELFTEST_VER_LIMIT = 24;   // SELFTEST v24 (25 Nov 2026): VAULT ops LIMIT / SETLIM, the owner's vault limit (default none)
constexpr uint8_t  G0_SELFTEST_VER_V17   = 17;   // SELFTEST v17: VAULT op TOTP (a code from a kind 3 record; the secret never leaves the G0), 7 Nov 2026
constexpr uint8_t  G0_SELFTEST_VER_V16   = 16;   // SELFTEST v16: passkeys signed P-256 by the G0 (the SE051 never sees a site key), PKSIGN budget (7 Nov 2026)
constexpr uint8_t  G0_SELFTEST_VER_PK2B  = 13;   // SELFTEST v13: PKSIGN / VAULT in a PASSKEY life, K_PK / K_PKN copies, budget C+ (2 Nov 2026)
constexpr uint8_t  G0_CMD_VAULT       = 0x28;
constexpr uint8_t  G0_REG_VAULT_IN    = 0x23;   // W, exactly G0_VAULT_IN_LEN: op || len16 || data[511]
constexpr uint8_t  G0_REG_VAULT_OUT   = 0x24;   // R, G0_VAULT_OUT_LEN, SIG_READY only
constexpr size_t   G0_VAULT_IN_LEN    = 514;
constexpr size_t   G0_VAULT_DATA_MAX  = 511;
constexpr size_t   G0_VAULT_OUT_LEN   = 12 + 511;
constexpr uint8_t  G0_VAULT_SEAL = 1, G0_VAULT_OPEN = 2, G0_VAULT_TAG = 3, G0_VAULT_PUBSEAL = 4;   // 4: v14, out = sealed32 || xonly32 || check8
constexpr uint8_t  G0_VAULT_LIMIT = 8, G0_VAULT_SETLIM = 9;   // v24: LIMIT out = now || next || OPENs left || TAGs left (0xFF none) || refills used || refills max; SETLIM in = 0/8/16/32/64/128, only straight after a right UVCHECK
constexpr uint8_t  G0_VAULT_TOTP = 7;   // v17: in = unix time (8, BE) || sealed kind 3 record; out = code (4, BE) || digits (1) || period (1)
constexpr uint8_t  G0_VAULT_IMPORT = 5, G0_VAULT_LABEL = 6;   // v15: IMPORT out = SEALs left16 || TAGs left16; LABEL out = left16 || hdr13 || [sLen][site] || [uLen][user]
constexpr uint8_t  G0_CMD_VSIGN_INIT = 0x29;   // v14: AE_IN = event id || h -> R0; AE_FINISH -> sig (vault backup)
constexpr uint8_t  G0_CMD_UVSET = 0x25, G0_CMD_UVCHECK = 0x26, G0_CMD_UVCLEAR = 0x27;
constexpr uint8_t  G0_CMD_MODEDOOR    = 0x21; // mint V_d for the door the G0 holds (BTC or PASSKEY), from an ARMed latch
constexpr uint8_t  G0_REG_AE_IN        = 0x19; // W, exactly 64 bytes
constexpr uint8_t  G0_REG_AE_T         = 0x1A; // W, exactly 32 bytes
constexpr uint8_t  G0_SELFTEST_VER_AE  = 8;    // SELFTEST v8: byte 23 = anti-exfil present
constexpr size_t   G0_MSG_MAX         = 240;  // printable ASCII bytes per message (the G0 refuses anything else)
constexpr uint8_t  G0_REG_STORE_IN    = 0x18; // W, exactly G0_STORE_IN_LEN
constexpr size_t   G0_STORE_IN_LEN    = 97;
constexpr uint8_t  G0_REG_ENT_IN      = 0x16; // v4: W, exactly G0_SEED_IN_LEN — the NVS blob of an ENTROPY wallet (seed_kind 1)
constexpr uint8_t  G0_REG_PASS_IN     = 0x17; // v4: W, exactly G0_PASS_IN_LEN — [len][100 bytes]; consumed by the next DOORKEYS/BTCSIGN, one of 5 per power-on life
constexpr size_t   G0_PASS_IN_LEN     = 101;
constexpr uint8_t  G0_REG_SEED_IN     = 0x13; // W, exactly G0_SEED_IN_LEN
constexpr uint8_t  G0_REG_BTC_IN      = 0x14; // W, exactly G0_BTC_REQ_LEN
constexpr uint8_t  G0_REG_BTC_OUT     = 0x15; // R, G0_BTC_OUT_LEN, only in SIG_READY
constexpr size_t   G0_SEED_IN_LEN     = 96;   // v5: inner CT(64) || "FVI5" || zero(28) — see g0_pack_inner_packet (v3 sent the raw NVS blob)
constexpr uint8_t  G0_BTC_OUT_VER_MIN = 2;    // v5: DOORKEYS/BTCSIGN answer version 2 = G0 takes the inner packet + checks the latch
constexpr size_t   G0_BTC_REQ_LEN     = 416;  // fixed-length signing request, layout in g0 btc.h / g0_btc_build_request
constexpr size_t   G0_BTC_OUT_LEN     = 192;
constexpr uint32_t G0_BTC_POLL_TIMEOUT_MS = 8000;  // relay (~7 steps) + up to ~8 EC ops on an M0+
constexpr uint32_t G0_ENT_POLL_TIMEOUT_MS = 20000; // v4: the above plus PBKDF2-HMAC-SHA512 x2048 on an M0+ (measured on the bench, see DOORKEYS ms field)
constexpr int      G0_BTC_MAX_RELAY_STEPS = 12;    // fetch = open(3) + DEC x2 + burn + close = 7

// Onboarding key delivery. Written once, air-gapped, before the scalar is
// sealed. The G0 stores both in flash (behind RDP-2 in production) and
// acknowledges with SHA256(K_SE || K_G0) on SIG_OUT so the ESP32 can prove the
// G0 actually took them before the matching SE auth object is relied upon.
constexpr uint8_t  G0_REG_KEYS_IN   = 0x12;  // W, exactly G0_KEYS_LEN bytes
constexpr size_t   G0_KSE_LEN       = 16;    // SE05x AESKey auth object (AES-128)
constexpr size_t   G0_KG0_LEN       = 32;    // inner scalar wrap key
constexpr size_t   G0_KMODE_LEN     = 32;    // S: the BTC-door secret (16 Sep 2026); only the G0 ever holds it after onboarding
constexpr size_t   G0_KEYS_LEN      = G0_KSE_LEN + G0_KG0_LEN + G0_KMODE_LEN + 1;   // v5.1: 81 = + SE object generation byte
constexpr uint8_t  G0_GEN_MAX       = 63;    // v5.1: SE object generations 1..63 (see se_signer.h)

// Status
constexpr uint8_t  G0_ST_IDLE       = 0x00;
constexpr uint8_t  G0_ST_NEED_RELAY = 0x01;
constexpr uint8_t  G0_ST_BUSY       = 0x02;
constexpr uint8_t  G0_ST_SIG_READY  = 0x03;
constexpr uint8_t  G0_ST_ERROR      = 0xE0;

// Sizes
constexpr size_t   G0_HASH_LEN      = 32;
constexpr size_t   G0_SIG_LEN       = 64;
constexpr size_t   G0_RELAY_MAX     = 512;   // largest session frame we will carry
constexpr size_t   G0_ECDH_LEN      = 32;   // shared secret X

// Bounds. A complete session handshake plus one unwrap is a small, known number of
// round trips. If the G0 keeps asking beyond this, treat it as a fault rather
// than looping forever — a wedged relay must fail, not hang the UI.
constexpr int      G0_MAX_RELAY_STEPS = 8;
// Wire rx/tx buffer needed for the largest transaction: reg byte + 2-byte
// length + G0_RELAY_MAX payload, rounded up. Applied in g0_init().
constexpr size_t   G0_WIRE_BUF      = 2 + 2 + G0_RELAY_MAX + 28;   // 544
constexpr uint32_t G0_POLL_TIMEOUT_MS = 3000;

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

// Probe the G0 and confirm it answers with a sane status byte.
// Call once after se_init(). Shares the same I2C bus and the same bus lock.
bool g0_init();

// True if the G0 responded to g0_init() and is present on the bus.
bool g0_present();
bool g0_bus_ack();   // 23 Nov 2026 (#60): raw ACK probe at the G0 address (caller holds the bus lock)

// Install the same lock/unlock pair used by se_set_bus_lock(). The ENTIRE sign
// sequence (hash out, N relay round trips, signature back) must be held under
// one lock: an asynchronous battery-gauge or accelerometer read landing between
// relay steps will desync both the SE's T=1 state and the G0's state machine.
void g0_set_bus_lock(void (*lock_fn)(), void (*unlock_fn)());
// 2 Nov 2026 (Vault phase 2b): set in a PASSKEY life; every PKSIGN and VAULT then runs in a passkey window.
void g0_set_window_hooks(bool (*openFn)(), void (*closeFn)());
// One window for several G0 ops (one FIDO request). No-ops outside the PASSKEY
// life. Holds the bus lock from begin to end: no user waits in between.
void g0_window_batch_begin();
void g0_window_batch_end();
bool g0_pk2b_present();   // SELFTEST v13
bool g0_vpub_present();
bool g0_caps_known();   // 11 Nov 2026: the self-test register was read this boot (false = capabilities unknown, not old)   // SELFTEST v14: the vault backup publishing key ops
bool g0_limit_present();  // SELFTEST v24: the owner's vault limit (VAULT ops 8 and 9)
bool g0_v17_present();    // SELFTEST v17: VAULT TOTP
bool g0_v15_present();    // SELFTEST v15: VAULT IMPORT and LABEL
// Phase 3 (2 Nov 2026): sign a vault backup event id with k_pub (anti-exfil, as
// g0_schnorr_sign). NOSTR life, KEY unlocked. pub32 = the x-only key the
// signature must verify against (stored when the copy was made).
bool g0_vault_sign(const uint8_t msg32[32], const uint8_t pub32[32], uint8_t sig_out[64]);

// -----------------------------------------------------------------------------
// Signing
// -----------------------------------------------------------------------------

// Produce a BIP-340 Schnorr signature over msg32 using the Nostr scalar that
// lives on the G0. Drop-in replacement for the old in-RAM schnorr_sign() path.
//
// The scalar is never exposed to this processor at any point. Returns false on
// timeout, relay fault, session failure, or if the G0 refuses (no PIN session).
//
// PRECONDITION: a daily (Door 1) PIN session must be open. The G0 verifies this
// itself against the SE over its own session — not a flag the ESP32 can assert.
bool g0_schnorr_sign(const uint8_t msg32[32], uint8_t sig_out[G0_SIG_LEN]);
// 27 Oct 2026: anti-exfil state. faulted = a signature failed the host check
// this boot (signing is latched off; the event/PSBT was not signed; see the
// [G0] ANTI-EXFIL FAULT log line). present = the G0 reported SELFTEST v8
// byte 23 at init; a G0 without it cannot sign at all with this build.
bool    g0_antiexfil_faulted();
uint8_t g0_antiexfil_present();   // 1 present, 0 absent, 0xFF unknown (no G0)

// -----------------------------------------------------------------------------
// Onboarding
// -----------------------------------------------------------------------------

// Hand a freshly derived scalar to the G0 so it can seal it under K_G0 and
// return the blob for storage in the SE.
//
// CALL THIS ONLY WHILE AIR-GAPPED. The scalar is briefly in ESP32 RAM here
// because onboarding derives it from the BIP-39 seed via NIP-06 on this
// processor. That is acceptable only because onboarding runs with the radios
// down, so no remote attacker can be resident. The caller MUST zeroize the
// scalar immediately after this returns.
//
// out_blob receives AES(K_G0, scalar) — exactly 32 bytes of ciphertext, which
// the SE then wraps under its own daily key. The G0 derives its IV internally
// from K_G0, so no IV needs storing and the existing 32-byte SE wrap path is
// unchanged. (Deterministic IV is safe: exactly one value is ever sealed under
// K_G0, and IV reuse only matters across multiple messages sharing a key.)
constexpr size_t G0_SEALED_BLOB_LEN = 32;
bool g0_seal_scalar(const uint8_t scalar[32],
                    uint8_t out_blob[G0_SEALED_BLOB_LEN]);

// -----------------------------------------------------------------------------
// g0_set_keys — ONBOARDING ONLY. Deliver the two long-lived keys to the G0.
//
//   k_se : 16-byte AES-128 key. The SAME bytes are written to the SE05x as the
//          G0's AESKey auth object (SE_AUTH_OBJ_G0). The G0 uses it to open its
//          own SCP03 session to the SE. The ESP32 never holds it again.
//   k_g0 : 32-byte inner wrap key for the scalar (AES(K_G0, scalar)).
//
// Both come from the SE051's TRNG (se_random) because the G0B1 has no TRNG.
// The plaintext keys are in ESP32 RAM only inside the air-gapped onboarding
// ceremony — the same window in which the scalar itself is in RAM — and the
// caller MUST zeroize them on every path.
//
// The G0 acknowledges with SHA256(k_se || k_g0); this returns false unless the
// acknowledgement matches, so a G0 that did not store the keys (or a bring-up
// stub) cannot leave the SE holding an auth key nobody can use.
// -----------------------------------------------------------------------------
bool g0_set_keys(const uint8_t k_se[G0_KSE_LEN], const uint8_t k_g0[G0_KG0_LEN], const uint8_t k_mode[G0_KMODE_LEN], uint8_t gen);
uint8_t g0_peek_generation();   // v5.1: G0's SE object generation; 0xFF no keys, 0xFE unknown

// Wallet delete: instruct the G0 to erase K_SE and K_G0 from its flash. Best
// effort — the SE-side objects are the ones that must be gone; this stops a
// stale K_G0 from surviving a re-onboard.
bool g0_wipe_keys();

// -----------------------------------------------------------------------------
// ECDH — encrypted DMs (NIP-04 / NIP-44)
// -----------------------------------------------------------------------------

// Compute the ECDH shared secret between our Nostr key and a peer's x-only
// public key. The scalar stays on the G0; only the 32-byte shared X comes back.
//
// The peer pubkey is attacker-controlled (it arrives from a relay). The G0
// validates it is a real curve point before use — see the invalid-curve note
// in g0/src/main.c. A malformed point is rejected there, not here.
//
// WHAT THIS DOES AND DOES NOT PROTECT
// The identity scalar is never exposed to this processor. A compromised ESP32
// can still ASK for shared secrets for arbitrary peers, and so can read and
// forge DMs while it retains access. That is the same oracle property as
// signing: bad, bounded, survivable by reboot — and categorically different
// from losing the identity key itself, which is permanent.
bool g0_ecdh(const uint8_t peer_xonly32[32], uint8_t shared_out[G0_ECDH_LEN]);

// -----------------------------------------------------------------------------
// Derived values — safe to return, do not expose the scalar
// -----------------------------------------------------------------------------

// Our x-only Nostr public key. Public by definition; returning it exposes
// nothing. Exists so this processor never needs the scalar just to learn the
// matching pubkey.
bool g0_get_pubkey(uint8_t xonly_out[32]);

// HKDF-derived key the PWA uses to encrypt its local DM cache. HKDF is one-way,
// so this does not expose the scalar — a derived secret leaves, not the key.
bool g0_get_cache_key(uint8_t key_out[32]);

// Abort any in-flight operation and zeroize G0-side transient state.
bool g0_reset();
bool g0_sleep();   // tell the G0 to enter Stop mode: before ESP32 deep sleep, and (2 Oct 2026) on idle dim
// 2 Oct 2026: idle-dim sleep. The G0 wakes on the first I2C address match, and
// every g0_* command handles that transparently (retried STATUS ping first).
bool     g0_is_asleep();   // true between g0_sleep() and the next command
uint32_t g0_idle_ms();     // ms since the last register access (for the re-sleep timer)
bool g0_sleep_if_idle(uint32_t quietMs);   // SLEEP only if quiet that long, judged under the bus lock (31 Oct 2026)
bool     g0_wake();        // optional explicit wake (e.g. on screen wake, so the first sign is not delayed)
// 11cf (power): a wake for another device's frame (counted, not logged), and the
// matching re-sleep: back to Stop at once if no G0 command came since that wake.
bool     g0_wake_quiet();
bool     g0_resleep_if_untouched();
uint32_t g0_stop_ms();             // total ms in Stop since boot (census)
uint32_t g0_wakes();               // wakes from Stop since boot (census)
uint32_t g0_courtesy_resleeps();   // re-sleeps after a courtesy wake (census)
// 13 Oct 2026, ENA-wired boards (-DFAVILLA_SE_ENA): Stop mode with the SE051
// cut (ENA low) for the whole sleep. ONLY from goSleep(), after
// se_pin_session_close(); the SE is unpowered from here until the next boot
// probe wakes the G0. Returns false if the G0 is absent (caller falls back to
// the T=1 power-down). Never use on the idle-dim path.
bool     g0_sleep_deep();
// Explicit SE power (bench / recovery). on=false is only legal when nothing
// will talk to the SE until on=true again; se_init() must follow on=true.
bool     g0_se_power(bool on);
// Boot: FIRST bus transaction after a wake. Wakes a Stop-mode G0 (which raises
// ENA), sends SEPWR_ON for the G0-awake-but-SE-dark case, then waits for the
// SE051 to ACK its I2C address (DPD exit + boot, polled up to ~300 ms).
// Idempotent on a cold boot (SE already up: returns on the first ACK). Needs
// Wire started. Returns true once the SE answers; *ms receives the wait.
bool     g0_se_power_on_early(uint32_t* ms);
bool     g0_se_power_cycle_early(uint32_t* ms);   // 16 Oct 2026: ENA off/on reset of a wedged SE051, pre-g0_init
// SE ENA level as the G0 last reported it (SELFTEST v6 byte 20): 1 on, 0 off,
// 0xFF unknown / pre-v6 G0.
uint8_t  g0_se_ena();

// -----------------------------------------------------------------------------
// Step-3 bring-up: G0 <-> SE session over the blind relay
// -----------------------------------------------------------------------------
// Ask the G0 to open its own AESKey (SCP03) session to the SE through the relay,
// read the sealed scalar (PCR-gated), strip the SE's wrap with the daily key
// inside that session, close the session and unwrap the rest locally — then
// report a 64-byte diagnostic (never the scalar). Prints one decoded line.
//
// PRECONDITION: the daily PIN session is open and the Door-1 PCR is extended,
// otherwise the ReadObject is refused (step 5, SW 6986) — which is itself a
// useful result. Runs automatically after each daily unlock while
// G0_SESSION_TEST_ON_UNLOCK is 1; set it to 0 once step 4 is in.
#ifndef G0_SESSION_TEST_ON_UNLOCK
#define G0_SESSION_TEST_ON_UNLOCK 1
#endif
bool g0_session_test();

// ── Two-door power-cycle witness ────────────────────────────────────────────
// Ask the G0 to reset the SE mode latch to NEUTRAL. Succeeds at most ONCE per
// physical power cycle (the G0's one-shot is armed only by its own boot, and
// the ESP32 cannot reset the G0). Call early in setup(), before any PIN entry.
// Returns true only if the latch was actually reset by this call.
bool g0_mode_reset();
// g0_mode_btc — the BTC door. Asks the G0 to extend MODE_PCR with its secret S
// inside its own SCP03 session, producing the BTC value the seed key's policy
// requires. Fires at most ONCE per physical boot (G0-side one-shot). Returns
// true only if the G0 reports the extend succeeded THIS call; the caller must
// then read the latch back under its own spend session and compare it to the
// provisioned BTC value before trusting anything. Call with NO PIN session open.
bool g0_mode_btc();
// g0_mode_door — the generic mint (30 Oct 2026). The G0 mints V_d for the door
// IT holds for this power-on life: V_3 in a PASSKEY life, BTC (byte-identical
// to MODEBTC) in a BTC life, refused otherwise. Same rules as g0_mode_btc: from
// an ARMed latch only, one mint from ARM_N per door per physical boot. Call
// with NO PIN session open (the G0 opens its own SE session through the relay).
bool g0_mode_door();
// g0_mode_delete() retired 19 Oct 2026 (finding 3): MODE_PCR is deleted only
// by WIPEALL, and only after the seed wrap key is gone.
// v4.1 BRICK GUARD recovery. The G0 opens a session as SE_AUTH_OBJ_RECOVER
// (a credential no PIN lock can touch and that holds DELETE only) and deletes
// every wallet object in ITS fixed order - keys and gates first, the PIN
// objects last, itself at the end. Needs no PIN. Call with no SE session open.
// done/missing: bit i = object i in the G0's WIPE_ORDER deleted / not present.
bool g0_wipe_all(uint16_t* done, uint16_t* missing, uint8_t* rc_out = nullptr);   // rc_out: WALL diag[5]; 0xD1 = stopped, seed wrap key still present
// BENCH ONLY (strip before ship): write one raw command byte to the G0 and
// poll its status for waitMs WITHOUT pumping the relay - plays an RCE that
// sends a command and refuses to cooperate. Returns the last status byte.
uint8_t g0_bench_raw_cmd(uint8_t cmd, uint32_t waitMs);

// ── v3: Bitcoin inside the G0 ────────────────────────────────────────────────
// Onboarding only: apply the G0's inner seed wrap. seed (64 B plaintext, the
// air-gapped ceremony's trust window) -> inner (64 B ciphertext under a key
// derived from K_G0 that never leaves the G0). se_signer's seed_store() then
// SE-wraps each 32-byte half exactly as before. Requires SETKEYS to have run.
bool g0_seed_seal(const uint8_t seed[64], uint8_t inner_out[64]);
// v4: same, for a per-session passphrase wallet. entropy = 16 (wc 12) or 32
// (wc 24) bytes; the G0 builds the "FENT" container and seals it under its
// entropy key domain. The inner_out ciphertext goes through seed_blob_store
// exactly like a seed's.
bool g0_ent_seal(const uint8_t* entropy, int word_count, uint8_t inner_out[64]);

// ── v5.1 (15 Oct 2026): the seed blob lives on the G0 ───────────────────────
// SEEDSTORE: hand the SE-wrapped 96-byte blob to the G0, which writes it to its
// own write-once flash page together with the hash of the inner layer it
// sealed earlier in this power-on life (SEEDSEAL/ENTSEAL). Refused if a seed is
// already stored (only a wipe clears it), if no seal ran this life, or if the
// kind differs. ihash_out (optional) = the hash the G0 stored. rc_out gets the
// G0's code (0 ok, 0xE7 already stored, 0xE8 no seal this life, 0xE9 kind,
// 0xEA flash, 0xE0 no keys, 0xE1 no input; 0xFF = no answer / old G0).
bool g0_seed_store(uint8_t kind, const uint8_t outer[96], uint8_t ihash_out[32] = nullptr, uint8_t* rc_out = nullptr);
// SEEDGET: read the stored blob back. Returns true and fills kind/outer/ihash
// (any may be nullptr) when a seed is stored on the G0; false when none is or
// the G0 cannot answer (present_known_out says which: true = the G0 answered).
bool g0_seed_get(uint8_t* kind, uint8_t outer[96], uint8_t ihash[32], bool* present_known_out = nullptr);
// DOOR1LOCK: the G0 pushes the Door-1 PCR off the unlocked value. Must run with
// NO ESP32 SE session open. The G0 refuses every Nostr scalar fetch until one
// of these succeeds in its power-on life. Returns true when the G0 reports the
// PCR locked (or authenticated-absent).
// BIP-137 message signing. The G0 builds the digest from the message bytes
// itself (SHA256d of "\x18Bitcoin Signed Message:\n" || len || msg), so it can
// never be made to sign a transaction hash. Path m/84'/0'/0'/change/index.
// sig65 = header (39..42, P2WPKH) || r || s. Caller MUST compare pub33 with the
// pubkey it derived for that address, and digest with its own computation.
bool g0_msg_sign(const uint8_t blob[G0_SEED_IN_LEN], uint8_t kind,
                 uint32_t change, uint32_t index, const char* msg, size_t msg_len,
                 uint8_t pub33_out[33], uint8_t sig65_out[65], uint8_t digest_out[32]);
bool g0_door1_lock();
bool g0_door1_locked_this_boot();   // this ESP32 boot has seen a successful g0_door1_lock()

// What the G0 hands back at BTC-door entry. Everything here is PUBLIC or a
// one-way product of the seed; none of it can recover the seed or sign.
struct g0_door_keys_t {
  uint8_t master_fp[4];
  uint8_t xpub84_pub[33], xpub84_cc[32], xpub84_parent_fp[4];   // m/84'/0'/0'
  uint8_t xpub48_pub[33], xpub48_cc[32], xpub48_parent_fp[4];   // m/48'/0'/0'/2'
  uint8_t state_key[32];                                        // HMAC-SHA256(seed, "FAVILLA-BTC-STATE-v1")
};
// blob = the 96-byte NVS seed blob (se_signer seed_blob_read). The G0 opens
// its own SE session, has the SE strip the outer layer (allowed only while
// MODE_PCR == BTC, which only the G0 can have minted), BURNS the latch to
// SPENT in the same session, closes, strips its inner layer, derives, and
// wipes the seed. Call with NO PIN session open (one SE session at a time).
// v5 (15 Oct 2026): build the SEED_IN/ENT_IN packet from the 64-byte inner
// layer that seed_inner_from_blob_in_open_session() produced inside the spend
// session. The marker lets the G0 refuse a v3 ESP32's raw blob.
void g0_pack_inner_packet(const uint8_t inner[64], uint8_t pkt[G0_SEED_IN_LEN]);
bool g0_door_keys(const uint8_t blob[G0_SEED_IN_LEN], g0_door_keys_t* out);
// v4: kind = se_signer SEED_KIND_* (0 seed blob -> SEED_IN, 1 entropy container
// -> ENT_IN). For an entropy wallet the G0 needs a passphrase for this power-on
// life: pass/pass_len deliver one (costs one of the G0's 5 per-life tries);
// pass == nullptr means "use the one already held". rc_out (optional) gets the
// G0's byte-5 code so the caller can tell 0xE3 (no passphrase held yet: prompt
// and retry) from a real failure. NONE is a zero-length passphrase, not nullptr.
constexpr uint8_t G0_RC_NO_PASS     = 0xE3;
constexpr uint8_t G0_RC_PASS_BUDGET = 0xE4;
constexpr uint8_t G0_RC_NOT_ENTROPY = 0xE5;
bool g0_door_keys_kind(const uint8_t blob[G0_SEED_IN_LEN], uint8_t kind,
                       const char* pass, size_t pass_len,
                       g0_door_keys_t* out, uint8_t* rc_out = nullptr);

// Sign ONE input. req = G0_BTC_REQ_LEN bytes built by g0_btc_build_request().
// Same fetch + burn as g0_door_keys. Returns the compressed pubkey the G0
// derived (caller MUST compare it with the pubkey it expected for that
// input), the DER signature and the sighash the G0 signed (caller MUST
// compare it with its own BIP-143 computation — a field KAT of both sides).
bool g0_btc_sign(const uint8_t blob[G0_SEED_IN_LEN], const uint8_t req[G0_BTC_REQ_LEN],
                 uint8_t pub33_out[33], uint8_t der_out[72], uint8_t* der_len_out,
                 uint8_t sighash_out[32], uint8_t kind = 0);   // v4: kind as g0_door_keys_kind; the passphrase is the one the G0 holds

// Build the fixed-length request. kind 1 = BIP-84 P2WPKH, 2 = BIP-48 P2WSH
// (witness_script required, <= 252 bytes). All ints little-endian on the wire.
bool g0_btc_build_request(uint8_t req[G0_BTC_REQ_LEN], uint8_t kind,
                          uint32_t version, uint32_t locktime,
                          const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                          const uint8_t hashOutputs[32], const uint8_t outpoint[36],
                          uint32_t nSequence, uint64_t amount,
                          uint32_t change, uint32_t index,
                          const uint8_t* witness_script, size_t witness_script_len);

// 17 Sep 2026: latch class the G0 read when it REFUSED the last mode reset
// (one-shot spent): 1 NEUTRAL 2 NOSTR 3 BTC 4 SPENT 5 ARMed 0 wedged/unknown,
// 0xFF = not available (reset succeeded, G0 could not read, or old firmware).
// Lets boot tell "soft reboot in the same life" from "wrong door, power cycle".
uint8_t g0_last_latch_class();
const char* g0_latch_class_name(uint8_t cls);

// 23 Sep 2026: state of the G0's MODERESET one-shot as read at g0_init()
// (SELFTEST v4). 1 = armed (the G0 saw a real power cycle and no reset has
// consumed it yet), 0 = spent (soft reboot — onboarding CANNOT succeed until
// the battery is pulled), 0xFF = unknown (G0 absent or pre-v4 firmware).
// Reading it does not consume it.
uint8_t g0_reset_armed();

// ── Door memory (24 Sep 2026) ────────────────────────────────────────────────
// The G0 keeps its OWN record of which door this physical boot is, so a lying
// SE can no longer talk it into minting the BTC latch value in a Nostr life.
// g0_door_commit(door) sends DOORNOSTR/DOORBTC (door = 1 / 2). Returns true if
// the G0 now holds that door (set now, or already held); false if the G0 holds
// the OTHER door (only a real power cycle clears it) or is unreachable. *held
// receives the door the G0 holds after the call (0 unset, 1 NOSTR, 2 BTC,
// 0xFF unknown). Re-sending the same door is harmless (soft reboots do it).
bool    g0_door_commit(uint8_t door, uint8_t* held);
// Last door reported by the G0 (SELFTEST v5 byte 19 at init, or the last
// commit). 0 unset, 1 NOSTR, 2 BTC, 0xFF unknown / pre-v5 firmware.
uint8_t g0_door();
// Early peek for the boot fork, BEFORE g0_init(): reads SELFTEST byte 19 over
// the bus as it is. Returns 1/2 if the G0 already holds a door for this
// power-on life, 0 if unset, 0xFF if unreachable, still self-testing (BUSY,
// register not yet valid) or pre-v5 firmware. Never sets the presence flag.
// Caller must have started Wire.
uint8_t g0_peek_door();

// Human-readable status for logs.
const char* g0_status_name(uint8_t st);

// SELFTEST v19 (13 Nov 2026), every build: the boot log and the DEV UNIT banner
// read the G0's lock state (15 Nov: moved out of the bench-only block below).
bool g0_doorpin_present();   // SELFTEST v19
uint8_t g0_rdp_level();      // SELFTEST v19 byte 26: 0xAA none, 0xCC level 2, else level 1; 0 = unknown (older G0)

// -----------------------------------------------------------------------------
// Emberwill driver (28 Oct 2026). 11cd: its own switch, FAVILLA_EMBERWILL, on
// in release and bench builds (Emberwill ships as BETA). See the end of
// g0_signer.cpp and the G0's src/ember_glue.inc for the register map.
// -----------------------------------------------------------------------------
#ifdef FAVILLA_EMBERWILL
bool g0_em_cmd(uint8_t cmd, int8_t* rc, uint8_t* payload, size_t cap, size_t* len, uint32_t tmo_ms);
bool g0_em_write(uint8_t reg, const uint8_t* d, size_t n);
bool g0_em_stage(const uint8_t* d, size_t n);
bool g0_em_header(const uint8_t hdr80[80], bool quorum, int8_t* rc, uint8_t status96[96]);
// 11cd (G0 v20, issue #40 A1): the ESP32's own check of every transaction the
// G0 signs at the ceremony (src/ember_check.h). onSet gets the ceremony tip;
// onSig gets, before each signature, the digest about to be signed and, on a
// transaction's first input, the UNSIGNED transaction; onDone is asked before
// EM_COMMIT. Any false ends the ceremony (the G0 is reset, nothing committed).
struct EmCerHooks {
  bool (*onSet)(uint32_t tip0);
  bool (*onSig)(unsigned k, unsigned input, const uint8_t sh[32], const uint8_t* tx, size_t txlen);
  bool (*onDone)();
};
bool g0_em_ceremony(const uint8_t set430[430], const uint8_t seedpkt[G0_SEED_IN_LEN], uint8_t kind,
                    bool (*sink)(uint16_t k, const uint8_t* blob, size_t n),
                    void (*progress)(unsigned s, unsigned nsig),   // screen: "signature s of nsig" (28 Oct 2026)
                    const EmCerHooks* hooks);                      // 11cd: required; a G0 older than v20 is refused
bool g0_em_pulse(char* json_out, size_t cap, uint8_t id_out[32] = nullptr, uint8_t sig_out[64] = nullptr);   // serialized array out; id/sig for the full event (MVP, 28 Oct 2026)

// Restorable passkeys (30 Oct 2026). g0_pk_sign: true = the G0 ran it and out
// holds the "PKSG" diagnostic (out[5] = 0 ok, else the G0's PK_E_* code).
// g0_pk_scrub: true = ran; *res 0 ok, *sw the SE's answer to the junk write.
bool g0_pk_present();
bool g0_pk_sign(const uint8_t in97[G0_PK_IN_LEN], uint8_t out[G0_BTC_OUT_LEN]);
bool g0_pk_scrub(uint8_t* res, uint16_t* sw);
// Onboarding only (before the seed store closes the G0's seal window): seal
// S_pk under K_G0 with the master IV. sealed32 then goes to se_pkr_provision.
bool g0_pk_master(const uint8_t spk[32], uint8_t sealed64[G0_PKM_LEN]);   // v19: inner || tag
// v19 (13 Nov 2026, one door one PIN): the passkey master's inner || tag, read by the
// passkey-PIN session at V_3 (se_pk_master_read). Set by the window's open hook and
// written to the G0 before every PKSIGN and VAULT; cleared by its close hook.
void g0_pkm_set(const uint8_t pkm[G0_PKM_LEN]);
void g0_pkm_clear();
// User verification (31 Oct 2026). The G0 keeps HMAC(K_G0, label || PIN) in its
// RAM after a PIN entered on the KEY (UVSET), checks a later PIN against it
// (UVCHECK: 1 right, 0 wrong, -1 no reference / G0 error; *left = tries left,
// the G0 wipes the reference at 0), and forgets it on every lock (UVCLEAR).
bool g0_uv_present();
// Vault records (2 Nov 2026, Vault spec section 3). One G0 session per call.
// true = the G0 ran it; *res = its result (0 ok, 0xE1 input, 0xE2 keys, 0xE3
// master, 0xE5 session, 0xE6 MAC/padding, 0xE7 OPEN budget spent); *left =
// the OPENs left this power-on life. out gets *outN bytes (up to 511).
bool g0_vault_present();
bool g0_vault(uint8_t op, const uint8_t* data, size_t n, uint8_t* out, size_t* outN, uint8_t* res, uint8_t* left);
bool g0_uv_set(const char* pin);
int  g0_uv_check(const char* pin, uint8_t* left);
void g0_uv_clear();

#endif
