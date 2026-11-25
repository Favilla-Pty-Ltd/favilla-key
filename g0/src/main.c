/* =============================================================================
 * Favilla KEY — STM32G0B1KBU6 isolated Nostr signer
 * STEP 5 of the build order: K_SE/K_G0 persist in flash (last 2 KB page), so a
 * reboot no longer wipes them — onboard once, then reboot/sign freely. RDP-2
 * (step 6) seals the page against readout; until then a bench flash is readable.
 * =============================================================================
 *
 * New in step 3:
 *   RELAY_OUT / RELAY_IN  the blind relay. A command that needs the SE parks a
 *                         complete C-APDU in RELAY_OUT, sets STATUS=NEED_RELAY and
 *                         sleeps; the ESP32 reads it, transceives it with the SE
 *                         verbatim, writes the R-APDU to RELAY_IN. Frames are
 *                         SCP03-protected (lib/scp03) so the ESP32 can neither read
 *                         nor forge them. Six round trips fetch the scalar:
 *                         CreateSession, INITIALIZE UPDATE, EXTERNAL AUTHENTICATE,
 *                         ReadObject(scalar blob), CipherOneShot(daily wrap key, DEC),
 *                         CloseSession.
 *   SESSIONTEST (0x09)    runs the full fetch and reports a 64-byte diagnostic on
 *                         SIG_OUT (layout below) — this is how step 3 is proven on
 *                         silicon WITHOUT switching signing over to it.
 *   fetch_scalar_se()     the real fetch. STEP 4 (committed): fetch_scalar() now
 *                         calls it unconditionally; the step-2 RAM stub is gone,
 *                         so a session/PCR/relay fault fails the op closed.
 *
 * What works after this drop, end to end from the ESP32:
 *   SETKEYS   store K_SE || K_G0, ack SHA256(K_SE||K_G0)        (RAM only — step 5 moves to flash)
 *   PROVISION seal the scalar under K_G0, return 32-byte CT      (and keep the plaintext — see STEP-2 STUB)
 *   PUBKEY    x-only public key of the scalar
 *   SIGN      BIP-340 signature of the 32-byte hash
 *   ECDH      x-coordinate of scalar * peer, peer given x-only
 *   CACHEKEY  HKDF(salt "favilla-dm-cache", ikm scalar, info "favilla-dm-cache-v2")
 *   WIPEKEYS  zeroize everything
 *   RESET     abort, zeroize transient state, IDLE
 *   SESSIONTEST open the G0's own SE session, fetch + unwrap the scalar, report
 *   The boot self-test from step 1 still runs and still reports on 0x7F.
 *
 * (HISTORICAL) STEP-2 STUB — removed in step 4. fetch_scalar() talks to the SE. It
 * returns the scalar that PROVISION sealed in THIS power cycle, held in RAM.
 * That makes onboarding -> sign -> DMs work today, and it means the scalar
 * evaporates on power loss (so signing fails closed until you re-onboard).
 * Step 3/4 replace fetch_scalar() with the PCR-gated SE read over the blind
 * relay, at which point the RAM copy is deleted from this file. Nothing else
 * in this file changes for that.
 *
 * The three invariants, enforced here:
 *   1. every input is fixed-length; a write of the wrong length is dropped
 *   2. the signing nonce is derived in-chip (BIP-340 with key-bound aux) and,
 *      since 27 Oct 2026, tweaked by a host-committed value the chip learns
 *      only after it has committed to its nonce point (anti-exfil, antiexfil.h)
 *   3. nothing but STATUS, SIG_OUT, SELFTEST and (later) session ciphertext
 *      is ever readable; the key registers are write-only
 *
 * Commands NEVER execute inside the I2C interrupt. The ISR latches the
 * command and main() runs it; STATUS reads BUSY meanwhile.
 *
 * v3 (16 Sep 2026): BITCOIN SIGNING MOVES INTO THIS CHIP. The seed is now
 * plaintext ONLY here. It is stored the same way as the Nostr scalar — two
 * layers, SE outside, this chip inside:
 *     NVS blob (96 B) = IV_lo || AES(K_SEED_SE, AES(K_SEEDWRAP, seed)[0:32])
 *                    || IV_hi || AES(K_SEED_SE, AES(K_SEEDWRAP, seed)[32:64])
 *     K_SEEDWRAP = SHA256(K_G0 || "favilla-g0-seedwrap-key")   (never leaves)
 * v5 (15 Oct 2026): the SE's DEC right on K_SEED_SE (0x20000020) belongs to
 * the SPEND PIN, gated on MODE_PCR == BTC = SHA256(NEUTRAL||S) — a value only
 * this chip can mint (MODEBTC). Before v5 it belonged to THIS chip's auth
 * object, which meant anyone holding K_SE + S + K_G0 (a readout of this chip,
 * or an I2C tap during SETKEYS) could reset the latch, extend S, have the SE
 * strip its layer and strip ours: the whole seed with NO PIN, because the
 * "a PIN armed the door" rule lived only in this firmware. Now the SE itself
 * demands a verified spend PIN for the only operation that opens the seed.
 * The ESP32 does that DEC inside its spend session and receives only the
 * INNER layer (useless without K_SEEDWRAP), and hands it here as SEED_IN.
 * Every fetch (fetch_blob_se) is: own SCP03 session -> READ the latch and
 * require it == BTC (so a cached inner packet is worthless without a fresh,
 * PIN-armed door this boot) -> BURN the latch to SPENT -> close -> strip
 * K_SEEDWRAP locally. The burn still sits before any result is released.
 *   SEEDSEAL  (0x0D) onboarding: 64-byte seed on SEED_IN -> 64-byte inner CT on SIG_OUT
 *   DOORKEYS  (0x0E) BTC-door entry: SEED_IN = NVS blob -> BTC_OUT = master fp,
 *                    BIP-84 + BIP-48 account xpubs, sealed-state key
 *   BTCSIGN   (0x0F) one input: SEED_IN = NVS blob, BTC_IN = 416-byte fixed
 *                    request (btc.h) -> BTC_OUT = pubkey, DER sig, sighash
 * MODEBTC now requires a PIN session to have ARMed the latch first
 * (SHA256(x || "FAVILLA-MODE-ARM"), x in NEUTRAL/SPENT/BTC): the SE verified a
 * PIN since the last burn, so "one spend PIN per signature" is SE-enforced
 * even though this chip does the unwrap.
 * ========================================================================== */

#include "stm32g0xx_hal.h"
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_preallocated.h"
#include "sha256.h"
#include "aes.h"
#include "bip340_vectors.h"
#include "scp03.h"
#include "se_objects.h"
#include "key_store.h"   /* STEP 5: K_SE/K_G0 persist in the last flash page */
/* Emberwill (28 Oct 2026): src/ember_glue.inc, included below commit_write's helpers */
static void em_glue_tier1(int nostr);
static void em_glue_wipe_transient(void);
#include "btc.h"
#include "bip39_words.h"
#include "pbkdf2.h"         /* v3: BIP-32 / BIP-143 / ECDSA inside the G0 */
#include "antiexfil.h"      /* 27 Oct 2026: host-contributed nonce on every signature */
#include "antiexfil_vectors.h"

/* STEP 4 (committed): every scalar op fetches from the SE over the blind relay.
 * The step-2 RAM stub is gone. A session fault now fails the operation closed —
 * which is correct: no key in RAM means no fallback to a key in RAM. */
#define FETCH_SCALAR_FROM_SE 1

/* ---- wire protocol: must match FKIO/src/g0_signer.h byte for byte -------- */
#define G0_I2C_ADDR        0x42
#define G0_REG_CMD         0x00
#define G0_REG_STATUS      0x01
#define G0_REG_HASH_IN     0x10
#define G0_REG_SIG_OUT     0x11
#define G0_REG_KEYS_IN     0x12
#define G0_REG_SEED_IN     0x13   /* v3: W, exactly SEED_IN_LEN (96) — SE-layer ciphertext, or the plaintext seed for SEEDSEAL */
#define G0_REG_BTC_IN      0x14   /* v3: W, exactly BTC_REQ_LEN (416) — fixed-length signing request */
#define G0_REG_BTC_OUT     0x15   /* v3: R, BTC_OUT_LEN (192), readable only in SIG_READY */
#define G0_REG_RELAY_OUT   0x20
#define G0_REG_RELAY_IN    0x21
#define G0_REG_SELFTEST    0x7F

#define G0_CMD_SIGN        0x01   /* RETIRED 27 Oct 2026 (anti-exfil): replaced by SIGN_INIT + AE_FINISH. Not accepted by commit_write, no handler. Id never reused. */
#define G0_CMD_RESET       0x02
#define G0_CMD_PROVISION   0x03
#define G0_CMD_ECDH        0x04
#define G0_CMD_PUBKEY      0x05
#define G0_CMD_CACHEKEY    0x06
#define G0_CMD_SETKEYS     0x07
#define G0_CMD_WIPEKEYS    0x08
#define G0_CMD_SESSIONTEST 0x09
#define G0_CMD_MODERESET   0x0A   /* two-door: reset MODE_PCR->NEUTRAL, one-shot per physical boot */
#define G0_CMD_MODEBTC     0x0B   /* two-door (16 Sep 2026): extend MODE_PCR with S -> BTC, one-shot per physical boot */
#define G0_CMD_MODEDEL     0x0C   /* RETIRED 19 Oct 2026 (finding 3): not accepted by commit_write, no handler. Id kept so it is never reused. */
#define G0_CMD_SEEDSEAL    0x0D   /* v3: apply the inner K_SEEDWRAP layer to a 64-byte seed (onboarding) */
#define G0_CMD_DOORKEYS    0x0E   /* v3: fetch seed, burn, return account xpubs + state key */
#define G0_CMD_BTCSIGN     0x0F   /* RETIRED 27 Oct 2026 (anti-exfil): replaced by BTCSIGN_INIT + AE_FINISH. Id never reused. */
#define G0_CMD_SLEEP       0x10   /* power (18 Sep 2026): enter Stop mode, wake on I2C address match. Sent by the ESP32 only just before it deep-sleeps; NEVER self-initiated, so no command is ever interrupted. */
#define G0_CMD_DOORNOSTR   0x11   /* door memory (24 Sep 2026): this physical boot is a NOSTR life */
#define G0_CMD_DOORBTC     0x12   /* door memory (24 Sep 2026): this physical boot is a BITCOIN life */
#define G0_CMD_WIPEALL     0x14   /* v4.1 (24 Sep 2026): recovery wipe over K_RECOVER, fixed order, PIN objects last */
#define G0_CMD_ENTSEAL     0x13   /* v4 (24 Sep 2026): apply the inner K_ENTWRAP layer to an ENTROPY container (per-session passphrase wallets) */
/* ── SE051 deep power-down over ENA (13 Oct 2026, ENA-wired boards) ──────────
 * SE051 ENA (pin 11, net SE051_WAKE) is driven by PB2 (pin 17) with a 1 M pull-up, so a
 * G0 in reset / unprogrammed / hi-Z leaves the SE ON (fail-safe). ENA low =
 * SE Deep Power-down (<5 uA, VOUT->VCC cut; persistent objects untouched,
 * volatile sessions lost). Rules:
 *   SEPWR_OFF / SEPWR_ON are applied IN THE ISR (like RESET) and never touch
 *     g_status, so the ESP32 can send SEPWR_ON as its very first bus
 *     transaction after a wake without creating a stale SIG_READY to clear.
 *     SEPWR_ON is always accepted; SEPWR_OFF only when accepting() (never
 *     mid-command - the relay would be talking to a dead SE).
 *   SLEEPDEEP = SLEEP + ENA low for the whole Stop interval. EVERY Stop exit
 *     raises ENA again (whatever dropped it), so a G0 that wakes for any
 *     reason brings the SE back with it and the ESP32 can never strand the
 *     SE dark by crashing. Plain SLEEP (idle dim) leaves the SE powered: the
 *     ESP32 is awake with a PIN session open and expects it. */
#define G0_CMD_SEPWR_OFF   0x15   /* ENA low now (bench / explicit) */
#define G0_CMD_SEPWR_ON    0x16   /* ENA high now (idempotent; ESP32 boot poke) */
#define G0_CMD_SLEEPDEEP   0x17   /* Stop mode with the SE cut; SE restored on wake */
/* v5.1 (15 Oct 2026). The seed blob moves from the ESP32's NVS into this chip
 * (src/key_store.h, SEED STORE), and Door 1 is locked at every boot. */
#define G0_CMD_SEEDSTORE   0x18   /* STORE_IN -> write-once seed page; needs a SEEDSEAL/ENTSEAL earlier this life */
#define G0_CMD_SEEDGET     0x19   /* BTC_OUT <- "SGET" + kind + outer blob + inner hash (all ciphertext / public) */
#define G0_CMD_DOOR1LOCK   0x1A
#define G0_CMD_MSGSIGN     0x1B   /* RETIRED 27 Oct 2026 (anti-exfil): replaced by MSGSIGN_INIT + AE_FINISH. Id never reused. */
/* ── Generic doors (30 Oct 2026, passkey door spec v1.0 section 4) ──────────
 * A third door, PASSKEY (3), in the same 2-bit field, with the same first-wins
 * rule. MODEDOOR mints V_d for the door THIS chip already holds (never a door
 * the caller names): d = 2 is byte-identical to MODEBTC, d = 3 uses
 * S_3 = SHA256(S || "FAVILLA-DOOR" || 0x03). Door ids above 3 do not exist. */
#define G0_CMD_DOORPASSKEY 0x20   /* this physical boot is a PASSKEY life (radios never start; FIDO only) */
#define G0_CMD_MODEDOOR    0x21   /* mint V_d for the held door d (2 or 3), from an ARMed latch; one-shot per door per physical boot from ARM_N */
/* ── Anti-exfil signing (27 Oct 2026, src/antiexfil.c) ──────────────────────
 * Every signature is now two commands. INIT takes the message (or the signing
 * request) plus the host's 32-byte commitment h and answers the nonce point
 * R0; AE_FINISH takes the host's revealed t and answers the signature made
 * with k = k0 + H(R0 || t). One operation may be pending at a time; see
 * g_ae and ae_* below for the rules. There is NO one-shot signing command
 * left, so there is no way to ask this chip for an uncommitted nonce. */
#define G0_CMD_SIGN_INIT    0x1C   /* Nostr: AE_IN = event id (32) || h (32); SIG_OUT = R0 (33) + zeros */
#define G0_CMD_AE_FINISH    0x1D   /* any pending kind: AE_T = t; SIG_OUT = sig64 (Nostr) or BTC_OUT (Bitcoin) */
#define G0_CMD_BTCSIGN_INIT 0x1E   /* BIP-143 input: BTC_IN = request, SEED_IN/ENT_IN = inner packet, AE_IN = zeros(32) || h; BTC_OUT "BSIG" v3 with R0 */
#define G0_CMD_MSGSIGN_INIT 0x1F   /* BIP-137 message: same registers; BTC_OUT "MSIG" v2 with R0 */
#define G0_CMD_VSIGN_INIT   0x29   /* v14 vault backup (vpub_glue.inc): AE_IN = event id || h; SIG_OUT = R0 (33); AE_FINISH as Nostr */
#define MSGSIGN_VER        1   /* extend SE_OBJ_PCR_UNLOCK with junk over this chip's session: Door 1 locked */
#define G0_REG_STORE_IN    0x18   /* v5.1: W, exactly STORE_IN_LEN (97) = kind(1) || outer blob(96) */
#define G0_REG_AE_IN       0x19   /* anti-exfil: W, exactly AE_IN_LEN (64) = msg32 || h32 (msg32 is zero for the Bitcoin kinds) */
#define G0_REG_AE_T        0x1A   /* anti-exfil: W, exactly 32 = the host's revealed t */
#define AE_IN_LEN 64
#define AE_TIMEOUT_MS 10000      /* a pending INIT with no FINISH is wiped after this (uptime tick; Stop entry wipes it anyway) */
#define STORE_IN_LEN       97
#define SE_ENA_PORT        GPIOB      /* SE051_WAKE net: G0 PB2 = UFQFPN32 pin 17 (Josh, 13 Oct 2026, from the schematic) */
#define SE_ENA_PIN         GPIO_PIN_2
#define G0_REG_ENT_IN      0x16   /* v4: W, exactly SEED_IN_LEN (96) — SE-layer ciphertext of an entropy container, or the plaintext container for ENTSEAL */
#define G0_REG_PASS_IN     0x17   /* v4: W, exactly PASS_IN_LEN (101) — [len][100 passphrase bytes, zero padded]; opaque to this chip */

#define G0_ST_IDLE         0x00
#define G0_ST_NEED_RELAY   0x01
#define G0_ST_BUSY         0x02
#define G0_ST_SIG_READY    0x03
#define G0_ST_ERROR        0xE0

#define KSE_LEN 16
#define KG0_LEN 32
#define KMODE_LEN 32                                /* S — the BTC-door secret (16 Sep 2026) */
#define KEYS_LEN (KSE_LEN + KG0_LEN + KMODE_LEN + 1)   /* v5.1: 81 = K_SE || K_G0 || S || gen over REG 0x12 */
#define SELFTEST_VER 24  /* v24 (25 Nov 2026, KEY 11ep): the vault limit is the owner's (Settings > Vault > Open limit): VAULT op 8 LIMIT reads it, op 9 SETLIM sets it straight after a right UVCHECK, kept in the key page's tail, default no limit (OPEN/TAG uncounted, VAULT_OUT byte 7 = 0xFF), stricter at once, looser from the next power-on, error 0xED; v23 (23 Nov 2026, KEY 11dr): v23 (23 Nov 2026, KEY 11dr): RK_MAX 400 - LABEL 800 per power-on life (kept in pairs in BKP1R), import window 450 SEALs, no new bytes; v22 (23 Nov 2026): SETKEYS refused in the life that ran WIPEKEYS (BKP1R bit 10, audit #60), no new bytes; v21 (22 Nov 2026): SETKEYS only while the door is UNSET (audit #53), no new bytes; v20 (20 Nov 2026): Emberwill ceremony check - EM_CER_INIT also returns the sighash and, on a transaction's first input, the unsigned transaction; EM_SET returns the ceremony tip; no signature leaves before release; v19 (13 Nov 2026, one door one PIN): the passkey master opens only from the passkey session (PKM_IN 0x25, PKMASTER returns inner || tag), PKSIGN and VAULT in a PASSKEY life only, VSIGN reads VPUB under the daily wrap, byte 26 = RDP level; v18: hedged nonces for the passkey (P-256) and Bitcoin (ECDSA, including Ember) signatures, 7 Nov 2026, no new bytes; v17: v17: VAULT op TOTP (a code from a kind 3 record; OPEN refuses kind 3, the secret never leaves), 7 Nov 2026, no new bytes; v16: PKSIGN signs P-256 in the G0 (p256-m, RFC 6979), the SE051 never sees a site key; PKSIGN budget per sitting; word list front-coded; LTO (7 Nov 2026), no new bytes; v15: VAULT op IMPORT (the import window, Vault spec 7f P4-4) and op LABEL (P4-8), life token word 2 in BKP1R, 3 Nov 2026, no new bytes; v14: VAULT op PUBSEAL + VSIGN_INIT 0x29 (vault backup publishing key, 2 Nov 2026), WIPEALL 15 objects (+VPUB); v13: PKSIGN and VAULT also in a PASSKEY life (K_PK / K_PKN copies), vault budget C+ (2 Nov 2026), no new bytes; v12: VAULT (2 Nov 2026), no new bytes; v11: UVSET / UVCHECK / UVCLEAR (31 Oct 2026); v10: PKSIGN / PKSCRUB present (restorable passkeys, 30 Oct 2026), no new bytes;  v9: bytes 24..25 = PASSKEY one-shot + generic doors present, byte 19 may read 3 (30 Oct 2026); v8: byte 23 = anti-exfil present (27 Oct 2026); v4: bytes 16..18 = live one-shot arms + keys_valid (23 Sep 2026); v5: byte 19 = door (24 Sep 2026); v6: byte 20 = SE ENA level, byte 21 = deep-sleep (SE-cut) entries (13 Oct 2026) */
#define SESSIONTEST_VER 1
#define RELAY_MAX 512
#define SEED_IN_LEN 96                 /* v5: inner CT(64) || "FVI5" || zero(28). (v3 was the SE blob IV_lo|CT_lo|IV_hi|CT_hi.) */
#define BTC_OUT_LEN 192
#define DOORKEYS_VER 2                 /* v5 (15 Oct 2026): SEED_IN/ENT_IN carry the INNER packet; the SE layer is stripped by the spend PIN */
#define BTCSIGN_VER 3                  /* v3 (27 Oct 2026): anti-exfil; INIT answers R0 at 41..73, FINISH the DER + R0 echo at 152..184 */
#define MSGSIGN_VER_AE 2              /* MSIG v2 (27 Oct 2026): anti-exfil, same split */
/* v5 inner-packet marker at SEED_IN/ENT_IN[64..67]. A v3 ESP32 sends the raw SE
 * blob, whose bytes 64..67 are ciphertext: they will not read "FVI5", so an old
 * ESP32 is refused (0xE6) instead of having its ciphertext treated as the inner
 * layer and silently deriving a wrong wallet. */
static const uint8_t INNER_PKT_MAGIC[4] = { 'F', 'V', 'I', '5' };
#define PASS_MAX 100                   /* v4: BIP-39 passphrase cap (Coldcard/Ledger/Jade) */
#define PASS_IN_LEN (1 + PASS_MAX)     /* v4: length byte + 100 */
#define PASS_BUDGET_PER_LIFE 5         /* v4: passphrases this chip will accept per physical boot (an RCE's guessing oracle) */
#define ENT_MAGIC0 'F'
#define ENT_MAGIC1 'E'
#define ENT_MAGIC2 'N'
#define ENT_MAGIC3 'T'
#define RELAY_TIMEOUT_MS 2500          /* ESP32 gives up at 3000 for the whole op */

/* ---------------------------------------------------------------------------
 * libsecp256k1 hooks — trap; there is nothing to print to.
 * ------------------------------------------------------------------------- */
void secp256k1_default_illegal_callback_fn(const char *m, void *d) { (void)m; (void)d; __disable_irq(); for (;;) __BKPT(0); }
void secp256k1_default_error_callback_fn  (const char *m, void *d) { (void)m; (void)d; __disable_irq(); for (;;) __BKPT(0); }

static uint8_t g_ctx_buf[512] __attribute__((aligned(16)));
static secp256k1_context *g_ctx;

static void secure_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}
static void kg0_iv(uint8_t iv[16]);
static void entropy_mix(const uint8_t *d, size_t n);
static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

/* ---------------------------------------------------------------------------
 * Long-lived key material. STEP 5: the working copy is in RAM (fast path for
 * the SCP03 host challenge and the K_G0 unwrap), but it is LOADED from flash at
 * boot and WRITTEN to flash by SETKEYS, so it survives a power cycle. RDP-2
 * (step 6) makes the flash page unreadable over SWD.
 * ------------------------------------------------------------------------- */
static uint8_t g_kse[KSE_LEN];
static uint8_t g_kg0[KG0_LEN];
static uint8_t g_kmode[KMODE_LEN];   /* S: extends MODE_PCR to BTC = SHA256(NEUTRAL || S). Never output. */
static uint8_t g_keys_valid = 0;
/* v5.1: SE object generation (include/se_objects.h). 0xFF = no keys. Every
 * object id this chip names is base + g_gen_off. */
static uint8_t g_gen = 0xFF;
uint32_t g_gen_off = 0;
static void gen_set(uint8_t g) { g_gen = g; g_gen_off = (g == 0xFF) ? 0 : ((uint32_t)g << 8); }
/* 14 Oct 2026: set ONLY inside do_wipeall() when the delete of
 * SE_AUTH_OBJ_RECOVER came back 9000 under a verified R-MAC. The WIPEKEYS
 * gate accepts it so that a second WIPEALL in the same power-on life (the
 * ESP32's se_pin_destroy runs one itself before sending WIPEKEYS) is not
 * needed - by then the G0 auth object is gone too and nothing could be
 * proven again. Cleared whenever the key record changes; zeroed at every
 * boot by ram_scrub_at_boot(). */
static uint8_t g_recover_gone = 0;

/* ---------------------------------------------------------------------------
 * Two-door power-cycle witness (MODE_RESET).
 * g_mode_reset_arm is set ONCE, in main(), which runs only on a physical G0
 * reset (NRST -> TC2030, un-triggerable by the ESP32). It is burned on the
 * first MODE_RESET and never re-armed by any command, so the ESP32 can obtain
 * at most one MODE_PCR->NEUTRAL per real battery cycle. This is the ONLY thing
 * on the board that can neutralise the mode latch, and it cannot be faked by a
 * compromised ESP32. Does NOT touch the sign/scalar path.
 * ------------------------------------------------------------------------- */
static uint8_t g_mode_reset_arm = 0;
/* BTC-door one-shot (16 Sep 2026). Same rules as g_mode_reset_arm: set ONLY in
 * main() (physical boot), burned on first use, never re-armed by any command,
 * untouched by wipe_transient() and RESET. The SE's seed key is gated on
 * MODE_PCR == SHA256(NEUTRAL || S); S lives only here, so the ESP32 — RCE or
 * not, PIN or not — cannot produce that value. One BTC door per battery cycle,
 * enforced by the SE policy plus this arm. */
static uint8_t g_mode_btc_arm = 0;
/* ── Door memory (24 Sep 2026) ──────────────────────────────────────────────
 * Why: until now the G0 decided whether to mint the BTC latch value by
 * READING the latch from the SE. A malicious SE could lie ("neutral, go
 * ahead") and, with an ESP32 RCE driving it, Bitcoin could be signed while
 * the device was online — in a NOSTR life the MODEBTC one-shot is never
 * consumed, so it was still armed. The G0 is the only chip that strips the
 * seed's inner layer and signs, so it must keep its OWN answer.
 *
 * g_door is RAM only. It is set ONCE per physical boot by the first
 * DOORNOSTR / DOORBTC the ESP32 sends (the select-mode screen, before any
 * radio comes up), re-sends of the SAME door are accepted (soft reboots),
 * the OTHER door is refused, and nothing but power loss clears it:
 * wipe_transient() and CMD_RESET do not touch it, Stop mode retains RAM,
 * ram_scrub_at_boot() zeroes it only on a real reset.
 *   NOSTR (1): MODEBTC / DOORKEYS / BTCSIGN are refused whatever the SE says
 *   BTC   (2): SIGN / ECDH / PUBKEY / CACHEKEY / PROVISION / SESSIONTEST refused
 *   unset (0): Bitcoin-side commands refused (fail closed); Nostr-side allowed
 *              so first-ever onboarding (no door chosen yet) can run
 * Persistence-in-flash on the ESP32 (an RCE that survives to the next cold
 * boot and sends DOORBTC itself) is NOT covered here — that is secure boot. */
#define DOOR_UNSET   0
#define DOOR_NOSTR   1
#define DOOR_BTC     2
#define DOOR_PASSKEY 3   /* 30 Oct 2026: generic doors. PASSKEY: MODEDOOR mints V_3; every Nostr- and Bitcoin-side command is refused */
static uint8_t g_door = DOOR_UNSET;
/* PASSKEY-door one-shot (30 Oct 2026). Same rules as g_mode_btc_arm, its own
 * bit: one mint from ARM_N per physical boot. Life token bit 12. */
static uint8_t g_mode_pk_arm = 0;
/* Reset-cause snapshot (16 Sep 2026 bench): RCC->CSR flags captured in main()
 * before they are cleared, so the MRST/MBTC diagnostics can prove whether this
 * chip actually rebooted (PWRRSTF/BORRSTF = power, PINRSTF = NRST) and how long
 * ago (HAL_GetTick). Un-fakeable by the ESP32. */
static uint32_t g_boot_rcc_csr = 0;

/* ── Life token (16 Oct 2026) ────────────────────────────────────────────────
 * Until now main() re-armed the one-shots and cleared the door on ANY reset:
 * the "fresh power cycle" signal was "main() ran", and main() runs on a
 * brown-out, a NRST pulse or a software reset just as it does on a battery
 * insertion. NRST and software resets are unreachable from the ESP32, but a
 * brown-out is a supply event, and a compromised ESP32 does control most of
 * the board's current draw. Close it: the life state (door, one-shot arms,
 * passphrase budget) is mirrored into TAMP backup register 0, which the
 * backup domain keeps through every system reset (NRST, software, watchdog,
 * BOR) and loses only when VDD actually goes away. Rule (see main()): on a
 * NON-power reset a valid token means "same life": restore it, do not re-arm.
 * On a POWER reset (PWRRSTF) the life is fresh regardless of the token, so a
 * normal battery pull always offers the door screen; the token only closes
 * NRST / software / watchdog resets, none of which the ESP32 can trigger.
 * Layout: [31:16] magic  [12] passkey-arm spent  [11] btc-arm spent
 *         [10] mode-reset spent  [9:8] door (0..3)  [7:0] passphrase budget.
 * (30 Oct 2026: door 3 = PASSKEY and bit 12 added.)
 * (2 Nov 2026: [15:13] vault budget refills used this life, 0..4, Vault P5 = C+.)
 * BKP0R is full. Second word, BKP1R (v15, 3 Nov 2026; the G0B1 has BKP0R..BKP4R):
 *         [31:16] magic 0xA5F2  [10] keys wiped this life (v22)  [9] import window used  [8:0] LABELs used (0..400).
 * Read only when BKP0R restored; a valid BKP0R with no valid BKP1R (a token
 * from before v15) fails closed: window used, LABELs spent, until a power cycle. */
#define LIFE2_MAGIC 0xA5F2u
#define LIFE_MAGIC 0xA5F1u
static uint8_t g_life_resumed = 0;   /* 1 = this boot restored a token (not a power cycle) */
static void life_save(void);

/* ---------------------------------------------------------------------------
 * Register file. Everything the ESP32 can write lands in a fixed-size slot
 * and is only accepted at exactly its expected length (invariant 1).
 * ------------------------------------------------------------------------- */
static uint8_t g_hash_in[32];       static volatile uint8_t g_hash_in_valid = 0;
static uint8_t g_keys_in[KEYS_LEN]; static volatile uint8_t g_keys_in_valid = 0;
static uint8_t g_sig_out[64];       /* SIG_OUT: 64 bytes, readable only in SIG_READY */
static uint8_t g_seed_in[SEED_IN_LEN]; static volatile uint8_t g_seed_in_valid = 0;   /* v3 */
static uint8_t g_btc_in[BTC_REQ_LEN];  static volatile uint8_t g_btc_in_valid = 0;    /* v3 */
static uint8_t g_btc_out[BTC_OUT_LEN]; /* v3: BTC_OUT, readable only in SIG_READY */
/* v4 — per-session passphrase wallets. ENT_IN carries the SE-layer ciphertext
 * of an ENTROPY container (same 96-byte shape as SEED_IN, different inner
 * key); PASS_IN is a staging buffer consumed by the next DOORKEYS/BTCSIGN;
 * g_pass is the passphrase this chip will use for the rest of the power-on
 * life. Nothing derived from it is ever cached: every signature still fetches
 * the container from the SE (PIN + latch + burn) and runs PBKDF2 again. */
static uint8_t g_ent_in[SEED_IN_LEN]; static volatile uint8_t g_ent_in_valid = 0;
static uint8_t g_pass_in[PASS_IN_LEN]; static volatile uint8_t g_pass_in_valid = 0;
static uint8_t g_pass[PASS_MAX]; static uint8_t g_pass_len = 0; static uint8_t g_pass_valid = 0;
static uint8_t g_pass_budget = 0;   /* set in main() only; never re-armed; survives wipe_transient/RESET/Stop like the one-shots */
/* 2 Nov 2026 (Vault P5 = C+): vault budget refills used this power-on life, 0..VLT_REFILLS_MAX. Kept in the life token. */
#define VLT_REFILLS_MAX 4u
static uint8_t g_vlt_refills = 0;
/* v15 (3 Nov 2026, Vault spec 7f P4-4 and P4-8): kept in BKP1R so a reset that keeps the life keeps them too. */
#define VLT_LABEL_PER_LIFE 800u   /* 2 x RK_MAX: two full listings per power-on life (v23: RK_MAX 400; was 400) */
static uint16_t g_lbl_used = 0;   /* LABELs used this life */
static uint8_t g_imp_used = 0;    /* this life's import window has been opened */
/* v22 (23 Nov 2026, audit #60): set by a WIPEKEYS that forgot the keys; kept in
 * BKP1R bit 10, so only power loss clears it. SETKEYS refuses while it is set:
 * code on the ESP32 cannot cut the power, so it cannot wipe and re-key in one
 * life. Every honest re-onboard already sits behind a power cycle (Delete Key
 * then a battery pull; the recovery wipe holds the restart screen). */
static uint8_t g_wiped_life = 0;
static void life_bkp_enable(void) {
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_RCC_RTCAPB_CLK_ENABLE();      /* TAMP registers sit behind the RTC APB clock on the G0 */
    HAL_PWR_EnableBkUpAccess();
}
static void life_save(void) {
    uint32_t v = ((uint32_t)LIFE_MAGIC << 16)
               | ((uint32_t)(g_door & 3u) << 8)
               | ((g_mode_reset_arm ? 0u : 1u) << 10)
               | ((g_mode_btc_arm   ? 0u : 1u) << 11)
               | ((g_mode_pk_arm    ? 0u : 1u) << 12)
               | ((uint32_t)(g_vlt_refills & 7u) << 13)
               | ((uint32_t)g_pass_budget & 0xFFu);
    TAMP->BKP0R = v;
    TAMP->BKP1R = ((uint32_t)LIFE2_MAGIC << 16) | ((g_wiped_life ? 1u : 0u) << 10) | ((g_imp_used ? 1u : 0u) << 9) | ((uint32_t)((g_lbl_used + 1u) / 2u) & 0x1FFu);   /* v23: kept in pairs (9 bits hold 511 pairs), rounded up: a reset never gives one back */
}
/* RULE (24 Nov 2026): every RAM static this function refills must also be
 * cleared in g0_power_on() in g0/tests/host_g0/harness.inc. On a host the
 * statics keep their values across a simulated boot; a real boot starts them
 * from their initialisers. Add the new static to both places together. */
static int life_restore(void) {
    uint32_t v = TAMP->BKP0R;
    if ((v >> 16) != LIFE_MAGIC) return 0;
    uint8_t d = (uint8_t)((v >> 8) & 3u);
    g_door           = (d == DOOR_NOSTR || d == DOOR_BTC || d == DOOR_PASSKEY) ? d : DOOR_UNSET;
    g_mode_reset_arm = (v & (1u << 10)) ? 0 : 1;
    g_mode_btc_arm   = (v & (1u << 11)) ? 0 : 1;
    g_mode_pk_arm    = (v & (1u << 12)) ? 0 : 1;
    { uint8_t r = (uint8_t)((v >> 13) & 7u); g_vlt_refills = (r <= VLT_REFILLS_MAX) ? r : VLT_REFILLS_MAX; }   /* out of range = cap reached */
    uint8_t b = (uint8_t)(v & 0xFFu);
    g_pass_budget    = (b <= PASS_BUDGET_PER_LIFE) ? b : 0;
    {   uint32_t w = TAMP->BKP1R;   /* v15 */
        if ((w >> 16) == LIFE2_MAGIC) { uint16_t l = (uint16_t)((w & 0x1FFu) * 2u); g_lbl_used = (l <= VLT_LABEL_PER_LIFE) ? l : VLT_LABEL_PER_LIFE;   /* v23: pairs */ g_imp_used = (uint8_t)((w >> 9) & 1u); g_wiped_life = (uint8_t)((w >> 10) & 1u); }
        else { g_lbl_used = VLT_LABEL_PER_LIFE; g_imp_used = 1; g_wiped_life = 1; }   /* fail closed */
    }
    return 1;
}
/* v5.1 seed store. STORE_IN is the staging register for SEEDSTORE. The
 * "pending" record is what the last SEEDSEAL/ENTSEAL of this power-on life
 * produced: SEEDSTORE accepts an outer blob only for THAT inner ciphertext
 * (by hash) and THAT kind. It is not secret (a hash of ciphertext); it is
 * cleared on a successful store and by wipe_keys, and zeroed at every boot. */
static uint8_t g_store_in[STORE_IN_LEN]; static volatile uint8_t g_store_in_valid = 0;
/* ── anti-exfil state (27 Oct 2026) ─────────────────────────────────────────
 * AE_IN / AE_T are single-use inputs like HASH_IN (wiped by finish()). g_ae is
 * the one pending operation: the key, k0, R0, h and the message live here
 * between INIT and FINISH, in the same RAM the fetched scalar always lived
 * in, and are wiped by: AE_FINISH (any outcome), CMD_RESET (wipe_transient),
 * Stop-mode entry, WIPEKEYS, the AE_TIMEOUT_MS tick, and ram_scrub_at_boot.
 * An INIT while one is pending is refused and does NOT clear it (the host
 * cannot use a second INIT to make this chip forget a commitment it gave). */
static uint8_t g_ae_in[AE_IN_LEN]; static volatile uint8_t g_ae_in_valid = 0;
static uint8_t g_ae_t[32];         static volatile uint8_t g_ae_t_valid = 0;
typedef struct {
    uint8_t  kind;        /* AE_KIND_* ; AE_KIND_NONE = nothing pending */
    uint8_t  key[32];     /* the Nostr scalar, or the BIP-32 leaf key */
    uint8_t  k0[32];
    uint8_t  r0[33];
    uint8_t  h[32];
    uint8_t  msg[32];     /* event id / BIP-143 sighash / BIP-137 digest */
    uint8_t  pub33[33];   /* Bitcoin kinds: the leaf pubkey, for the release checks */
    uint8_t  btc_kind;    /* BTCSIGN request kind byte, echoed in BTC_OUT[6] */
    uint8_t  vault;       /* v14: a VSIGN_INIT signature (k_pub); pub33[0..31] = its x-only key */
    uint32_t t0;          /* HAL_GetTick() at INIT */
} ae_pending_t;
static ae_pending_t g_ae;
static void ae_wipe(void) { secure_wipe(&g_ae, sizeof(g_ae)); }
static int  ae_expired(void) { return g_ae.kind != AE_KIND_NONE && (HAL_GetTick() - g_ae.t0) > AE_TIMEOUT_MS; }
static uint8_t g_pend_ihash[32]; static uint8_t g_pend_kind = 0; static uint8_t g_pend_valid = 0;
/* v5.1 Door-1 boot lock. 0 at every physical boot (ram_scrub_at_boot). Set
 * by a successful DOOR1LOCK (the PCR was pushed off the unlocked value, or is
 * authenticated-absent) or by SETKEYS (the ESP32 recreates the PCR locked in
 * the same onboarding). While 0 this chip refuses to fetch the Nostr scalar,
 * so an ESP32 that skips the lock at boot gets no Nostr signatures at all,
 * whatever state an unclean power-down left the SE's PCR in. */
static uint8_t g_door1_locked = 0;
/* v5.1 seal window. A seed may be sealed and stored ONLY in the power-on life
 * in which SETKEYS ran (onboarding), and only before any door is committed
 * (the ESP32 commits a door before any radio comes up). Without this, a
 * keyed wallet with no seed page (an nsec-only restore) would accept a seed
 * of the ESP32's choosing at any later time. RAM only: a reboot closes it. */
static uint8_t g_seal_window = 0;
#define SELFTEST_LEN 27   /* 30 Oct 2026: +[24] passkey arm, +[25] generic doors present; v19: +[26] RDP level */
static uint8_t g_selftest[SELFTEST_LEN];   /* v6: 22 bytes — see tx_next() for the live tail */

static volatile uint8_t g_status = G0_ST_IDLE;
static volatile uint8_t g_cmd_pending = 0;
static volatile uint8_t g_addr_wake   = 0;   /* set by the ADDR ISR: a REAL address match woke us */
static uint8_t g_sleep_entries = 0, g_sleep_wakes = 0;  /* diagnostics, reported in SELFTEST[14..15] */
static uint8_t g_deep_entries = 0;           /* SLEEPDEEP entries (SE cut), SELFTEST[21] */

/* SE051 ENA driver (PB2, UFQFPN32 pin 17). Push-pull so the 1 M pull-up never has to fight
 * leakage; the pull-up only matters while the G0 is in reset or unprogrammed. */
static inline void se_ena_write(int on) {
    HAL_GPIO_WritePin(SE_ENA_PORT, SE_ENA_PIN, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
}
static inline uint8_t se_ena_level(void) {
    return (uint8_t)(HAL_GPIO_ReadPin(SE_ENA_PORT, SE_ENA_PIN) == GPIO_PIN_SET);
}
static void se_ena_init(void) {
    __HAL_RCC_GPIOB_CLK_ENABLE();
    /* ODR first, then mode: the pin goes from hi-Z (pull-up holding ENA high)
     * straight to driven-high with no low glitch — a glitch here would drop
     * the SE into DPD for a moment and lose nothing persistent, but it would
     * cost the ESP32 a T=1 resync it is not expecting. */
    se_ena_write(1);
    GPIO_InitTypeDef g = {0};
    g.Pin = SE_ENA_PIN; g.Mode = GPIO_MODE_OUTPUT_PP; g.Pull = GPIO_NOPULL; g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(SE_ENA_PORT, &g);
}
static volatile uint8_t g_reset_pending = 0;

/* ---------------------------------------------------------------------------
 * The blind relay (step 3)
 *
 * RELAY_OUT is one read-stream [len_hi][len_lo][payload] from byte 0 on EVERY
 * read; the ESP32 reads 2 bytes, then 2+len (g0_pump_relay). Nothing here
 * advances across reads. RELAY_IN is accepted only in NEED_RELAY, only at
 * exactly 2+len bytes with len matching its own header (invariant 1), and
 * flips STATUS to BUSY inside the ISR so the ESP32 cannot pump the same frame
 * twice. The command thread sleeps in WFI meanwhile and wakes on the tick.
 * ------------------------------------------------------------------------- */
static uint8_t  g_relay_out[2 + RELAY_MAX];      /* header + C-APDU */
static volatile uint16_t g_relay_out_len = 0;    /* payload bytes */
static uint8_t  g_relay_in[RELAY_MAX];           /* R-APDU */
static volatile uint16_t g_relay_in_len = 0;
static volatile uint8_t  g_relay_in_ready = 0;

/* Entropy for the SCP03 host challenge. No TRNG on this die: the pool is
 * K_SE (secret), the tick, the SysTick fraction, and every card challenge the
 * SE has ever sent us (its certified TRNG) — so from the second session on the
 * host challenge is unpredictable to anyone who does not hold K_SE. */
static uint8_t g_pool[32];
static void entropy_mix(const uint8_t *d, size_t n) {
    uint32_t t = HAL_GetTick(), st = SysTick->VAL;
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_pool, 32); sha256_update(&c, (const uint8_t *)&t, 4);
    sha256_update(&c, (const uint8_t *)&st, 4); sha256_update(&c, g_kse, KSE_LEN);
    if (d && n) sha256_update(&c, d, n);
    sha256_final(&c, g_pool);
}
#include "hedge.inc"   /* v18: hedge32 (the host tests include the same file after their own entropy_mix) */
static void host_challenge(uint8_t hc[8]) {
    static const uint8_t label[] = "favilla-g0-host-challenge";
    uint8_t h[32]; entropy_mix(label, sizeof(label) - 1);
    sha256(g_pool, 32, h); memcpy(hc, h, 8); secure_wipe(h, 32);
}

/* 19 Oct 2026 (review C2, power side channel via the INA232 on the ESP32's
 * bus). Two countermeasures that live HERE, in RDP2-protected G0 firmware,
 * so code running on the ESP32 cannot turn them off:
 *   - secp256k1 context blinding: the generator multiplication runs on a
 *     random offset of the scalar, re-drawn every BLIND_EVERY key operations,
 *     so no two runs of traces share the same intermediate values for long.
 *   - a random delay of 0..~1.5 ms before every key operation, so a sampled
 *     current trace cannot be lined up with the start of the computation.
 * Seeds come from the entropy pool (SE TRNG card challenges, K_SE, clocks),
 * which the ESP32 cannot predict. Outputs are unchanged: BIP-340 / RFC6979
 * signatures do not depend on the blinding. */
#define BLIND_EVERY 4
static uint8_t g_blind_ops = 0;
static void ctx_reblind(void) {
    static const uint8_t label[] = "favilla-g0-secp-blind";
    uint8_t seed[32];
    entropy_mix(label, sizeof(label) - 1);
    sha256(g_pool, 32, seed);
    (void)secp256k1_context_randomize(g_ctx, seed);
    secure_wipe(seed, 32);
    g_blind_ops = 0;
}
static void sca_jitter(void) {
    static const uint8_t label[] = "favilla-g0-jitter";
    uint8_t h[32];
    entropy_mix(label, sizeof(label) - 1);
    sha256(g_pool, 32, h);
    uint32_t n = ((uint32_t)h[0] | ((uint32_t)h[1] << 8)) & 0x3FFFu;   /* 0..16383 loops, ~0..1.5 ms at 64 MHz */
    secure_wipe(h, 32);
    for (volatile uint32_t i = 0; i < n; i++) { __NOP(); }
}
static int is_key_op(uint8_t cmd) {
    switch (cmd) {
    case G0_CMD_SIGN_INIT: case G0_CMD_AE_FINISH: case G0_CMD_ECDH: case G0_CMD_PUBKEY: case G0_CMD_CACHEKEY:
    case G0_CMD_PROVISION: case G0_CMD_SESSIONTEST:
    case G0_CMD_DOORKEYS: case G0_CMD_BTCSIGN_INIT: case G0_CMD_MSGSIGN_INIT:
    case 0x22:   /* G0_CMD_PKSIGN (pk_glue.inc, included below) */
    case 0x28:   /* G0_CMD_VAULT (vault_glue.inc): AES / HMAC under K_vault on ESP32-chosen data (review 2 Nov 2026) */
    case G0_CMD_VSIGN_INIT:   /* v14: Schnorr with k_pub (vpub_glue.inc), review 2 Nov 2026 */
    case 0x31: case 0x32: case 0x33: case 0x39:   /* Emberwill EM_SET / EM_CER_INIT / EM_CER_FIN / EM_PULSE (ember_glue.inc) */
        return 1;
    default: return 0;
    }
}

/* scp03 transport: park, wait for the ESP32, hand back. Returns 0 ok. */
static int relay_xfer(void *ctx, const uint8_t *apdu, size_t alen,
                      uint8_t *rsp, size_t rcap, size_t *rlen) {
    (void)ctx;
    if (alen == 0 || alen > RELAY_MAX) return -1;
    g_relay_out[0] = (uint8_t)(alen >> 8); g_relay_out[1] = (uint8_t)alen;
    memcpy(g_relay_out + 2, apdu, alen);
    g_relay_in_ready = 0; g_relay_in_len = 0;
    __disable_irq(); g_relay_out_len = (uint16_t)alen; g_status = G0_ST_NEED_RELAY; __enable_irq();
    uint32_t t0 = HAL_GetTick();
    while (!g_relay_in_ready) {
        if (g_reset_pending) { g_status = G0_ST_BUSY; return -4; }       /* ESP32 aborted */
        if (HAL_GetTick() - t0 > RELAY_TIMEOUT_MS) { g_status = G0_ST_BUSY; return -2; }
        __WFI();
    }
    size_t n = g_relay_in_len;
    if (n < 2 || n > rcap) { secure_wipe(g_relay_in, sizeof(g_relay_in)); return -3; }
    memcpy(rsp, g_relay_in, n); *rlen = n;
    secure_wipe(g_relay_in, n); secure_wipe(g_relay_out, 2 + alen); g_relay_out_len = 0;
    return 0;
}

/* Diagnostic for SESSIONTEST, 64 bytes on SIG_OUT:
 *   0..3  "G0SE"   4 ver   5 result (0 ok, else the failing step: 1 CreateSession,
 *         2 INIT UPDATE, 3 card cryptogram (wrong K_SE), 4 EXT AUTH, 5 ReadObject,
 *         6 CipherOneShot, 7 CloseSession)
 *   6 scp03 stage reached   7 rc (int8)   8..9 last SE SW   10 relay steps used
 *   11 flags: b0 scalar == RAM stub copy, b1 RAM stub present, b2 keys valid,
 *             b3 blob read was 48 bytes
 *   12..13 elapsed ms   14..21 session id   22..29 card challenge   rest 0
 * Nothing secret is in here: the session id is dead by the time this is read. */
static uint8_t g_sesdiag[64];

/* THE STEP-4 FETCH. Opens this chip's own SE session through the relay, reads
 * the 48-byte blob (allowed only while the Door-1 PCR holds the unlocked value),
 * strips the SE's layer with the daily wrap key inside the same session, closes
 * the session, then strips K_G0's layer locally. The SE never emits the scalar;
 * the bus never carries anything but session ciphertext. */
static int fetch_scalar_se(uint8_t scalar[32], uint32_t obj, uint8_t *diag) {
    scp03_session_t s; uint8_t hc[8], cc[8] = {0}, blob[SE_BLOB_LEN], inner[32];
    size_t bl = 0; int step = 1, rc;
    uint32_t t0 = HAL_GetTick();
    memset(&s, 0, sizeof(s));
    if (!g_keys_valid) { rc = -100; goto out; }
    if (!g_door1_locked) { rc = -105; step = 0xE7; goto out; }   /* v5.1: no Door-1 boot lock this life */
    host_challenge(hc);
    rc = scp03_open(&s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    entropy_mix(cc, 8);
    if (rc) { step = 1 + s.stage; goto out; }   /* 1 CreateSession, 2 INIT UPDATE, 3 cryptogram (wrong K_SE), 4 EXT AUTH */
    step = 5; rc = scp03_read_object(&s, obj, blob, sizeof(blob), &bl);
    if (rc == 0 && bl != SE_BLOB_LEN) rc = SCP03_E_FORMAT;
    if (rc) { scp03_close(&s); goto out; }
    step = 6; rc = scp03_cipher_oneshot(&s, SE_OBJ_AES_WRAP_DAILY, 1, blob + 16, blob, inner);
    if (rc) { scp03_close(&s); goto out; }
    step = 7; rc = scp03_close(&s);                    /* a close failure is reported, not fatal */
    {   /* inner = AES-256-CBC(K_G0, IV=kg0_iv, scalar) — same as kg0_seal() */
        uint8_t iv[16]; kg0_iv(iv);
        struct AES_ctx a; AES_init_ctx_iv(&a, g_kg0, iv);
        memcpy(scalar, inner, 32); AES_CBC_decrypt_buffer(&a, scalar, 32);
        secure_wipe(&a, sizeof(a)); secure_wipe(iv, 16);
    }
    if (!rc) step = 0;
out:
    if (diag) {
        memset(diag, 0, 64);
        diag[0]='G'; diag[1]='0'; diag[2]='S'; diag[3]='E'; diag[4]=SESSIONTEST_VER;
        diag[5] = (uint8_t)step; diag[6] = s.stage; diag[7] = (uint8_t)(int8_t)rc;
        diag[8] = (uint8_t)(s.last_sw >> 8); diag[9] = (uint8_t)s.last_sw; diag[10] = s.nxfer;
        diag[11] = (uint8_t)((g_keys_valid ? 4 : 0) | (bl == SE_BLOB_LEN ? 8 : 0));
        put16(diag + 12, HAL_GetTick() - t0);
        memcpy(diag + 14, s.sid, 8); memcpy(diag + 22, cc, 8);
    }
    scp03_wipe(&s);
    secure_wipe(blob, sizeof(blob)); secure_wipe(inner, sizeof(inner)); secure_wipe(hc, 8);
    return (step == 0 || step == 7) ? 0 : -1;   /* 7 = scalar good, close failed */
}

#include "pk_glue.inc"   /* restorable passkeys: PKSIGN / PKSCRUB (30 Oct 2026) */
#include "totp.h"         /* v17: HOTP / TOTP for VAULT op TOTP */
#include "vault_glue.inc" /* vault records: VAULT SEAL / OPEN / TAG (2 Nov 2026) */
#include "vpub_glue.inc"  /* v14 (2 Nov 2026): vault backup publishing key, PUBSEAL + VSIGN_INIT */

/* A new command or input is accepted whenever nothing is executing. The
 * ESP32 reads SIG_OUT and then simply issues the next command; it only sends
 * RESET on failure paths. So SIG_READY and ERROR both count as "free". */
static int accepting(void) {
    return g_cmd_pending == 0 &&
           (g_status == G0_ST_IDLE || g_status == G0_ST_SIG_READY || g_status == G0_ST_ERROR);
}

/* ---------------------------------------------------------------------------
 * Crypto primitives on the (RAM-resident, step 2) scalar
 * ------------------------------------------------------------------------- */

/* IV for the K_G0 wrap is derived from K_G0 so the sealed value stays 32
 * bytes and the SE wrap path is unchanged. Not secret; binds the IV to the
 * key so two devices with different K_G0 never share an IV. */
static void kg0_iv(uint8_t iv[16]) {
    uint8_t h[32];
    static const uint8_t label[] = "favilla-g0-wrap-iv";
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, h);
    memcpy(iv, h, 16); secure_wipe(h, sizeof(h));
}

static void kg0_seal(const uint8_t scalar[32], uint8_t ct[32]) {
    uint8_t iv[16]; kg0_iv(iv);
    struct AES_ctx a; AES_init_ctx_iv(&a, g_kg0, iv);
    memcpy(ct, scalar, 32); AES_CBC_encrypt_buffer(&a, ct, 32);
    secure_wipe(&a, sizeof(a)); secure_wipe(iv, sizeof(iv));
}

/* Every scalar op goes through the SE session (step 4). The scalar exists in
 * G0 RAM only for the few ms between unwrap and use, then is wiped by the
 * caller. Returns 0 on success; a relay/session/PCR failure returns non-zero
 * and the operation fails closed. */
static int true_pubkey_fill(const uint8_t scalar[32]);
static uint8_t g_true_pk_ok;           /* defined with g_true_pk below */
static int fetch_scalar(uint8_t scalar[32]) {
    int rc = fetch_scalar_se(scalar, SE_OBJ_NOSTR_SCALAR, NULL);
    if (rc == 0) {
        /* 28 Oct 2026 (silicon): the first fetch of a life is the unlock-time
         * pubkey request, and the tier-1 hook used to fire before the cached
         * pubkey existed, so the owner stayed unbound until the next fetch and
         * a Pulse straight after unlock was refused (-29). Fill the cache
         * first; do_pubkey then finds it already filled (same work, once). */
        if (!g_true_pk_ok) (void)true_pubkey_fill(scalar);
        em_glue_tier1(1);              /* Emberwill tier-1 life: a PIN-gated fetch (r7) */
    }
    return rc;
}

/* SESSIONTEST: exercise the whole SE fetch path and report the diagnostic.
 * Post step-4 there is no RAM stub to compare against, so the scalar==RAM flag
 * (bit0) and RAM-copy-present flag (bit1) are no longer set — a real fetch that
 * returns rc 0 through CloseSession is itself the proof. Never outputs the
 * scalar. Kept as a standing health check; harmless to leave enabled. */
/* Two-door: reset MODE_PCR to NEUTRAL over the G0's own SCP03 session.
 * Gated by the boot one-shot: only the FIRST call after a physical boot does
 * anything; later calls (same power cycle) are refused. MODE_PCR's SE policy
 * grants DELETE (reset) to the G0 auth object ONLY, so this is the sole path
 * to neutral, and it is anchored to the G0's physical reset. Returns 0 on a
 * successful reset, -1 if not armed (already used this boot / not a fresh boot),
 * negative SCP03 codes on session failure. Writes a 64-byte diag on SIG_OUT
 * (reuses the G0SE layout) — never anything secret.
 *
 * WritePCR(reset): CLA via scp03 session, INS_WRITE 0x01, P1_PCR 0x09, P2 0x00,
 * data = TAG_1(0x41) len 4 = MODE_PCR id, NO TAG_2/TAG_3 (=> reset to initial). */
static int g0_read_mode_pcr(scp03_session_t *s, uint8_t out[32]);   /* defined below */

static const uint8_t MODE_CONST_SPENT[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','S','P','E','N','T',
  0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
/* v3: the PIN-session "arm". Before MODEBTC the ESP32 extends the latch with
 * this constant from inside an open PIN session (the SE verified a PIN to
 * open it). This chip then only mints BTC from an ARMed value:
 *   ARM_N = SHA256(NEUTRAL || ARM)   fresh boot   -> extend(S) once per physical boot
 *   ARM_S = SHA256(SPENT   || ARM)   after a burn -> reset, extend(S), no limit
 *   ARM_B = SHA256(BTC     || ARM)   leftover     -> reset, extend(S)
 * Bare NEUTRAL/SPENT/BTC (nobody entered a PIN since the last burn) -> refuse.
 * The arm extend is a WRITE, which both PINs hold, so the SE cannot tell which
 * PIN armed — that is accepted: either PIN is user-typed, and in a NOSTR life
 * the latch is NOSTR and NOSTR||ARM matches nothing. */
static const uint8_t MODE_CONST_NOSTR[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','N','O','S','T','R',
  0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
static const uint8_t MODE_CONST_ARM[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','A','R','M',
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

/* Generic doors (30 Oct 2026): the secret behind door d's latch value.
 * d = 2 (BTC) is S itself, so V_2 is byte-identical to the BTC value every
 * onboarded unit already uses. Other doors: SHA256(S || "FAVILLA-DOOR" || d).
 * The derived value never leaves this chip and is wiped by the caller. */
static const uint8_t DOOR_TAG[12] = { 'F','A','V','I','L','L','A','-','D','O','O','R' };
static void door_secret(uint8_t d, uint8_t out[32]) {
    if (d == DOOR_BTC) { memcpy(out, g_kmode, 32); return; }
    uint8_t b[32 + 12 + 1];
    memcpy(b, g_kmode, 32); memcpy(b + 32, DOOR_TAG, 12); b[44] = d;
    sha256(b, sizeof(b), out);
    secure_wipe(b, sizeof(b));
}
/* 17 Sep 2026: classify a latch value for the ESP32's boot UX.
 * 1 NEUTRAL  2 NOSTR  3 BTC  4 SPENT  5 ARMed (any of ARM_N/ARM_S/ARM_B, or
 * the PASSKEY door's ARM_S3/ARM_V3)  6 PASSKEY open (V_3)  7 PASSKEY spent
 * (30 Oct 2026)  0 none of these (wedged / unknown). Values are public; only S is secret
 * and it never leaves — BTC/SPENT/ARM_* are derived from S in RAM and wiped. */
static uint8_t mode_latch_class(const uint8_t cur[32]) {
    uint8_t zero32[32] = {0}, neutral[32], nostr[32], btc[32], spent[32], a[32], buf[64];
    uint8_t cls = 0;
    sha256(zero32, 32, neutral);
    memcpy(buf, neutral, 32); memcpy(buf + 32, MODE_CONST_NOSTR, 32); sha256(buf, 64, nostr);
    if (!memcmp(cur, neutral, 32)) cls = 1;
    else if (!memcmp(cur, nostr, 32)) cls = 2;
    else if (g_keys_valid) {
        memcpy(buf, neutral, 32); memcpy(buf + 32, g_kmode, 32); sha256(buf, 64, btc);
        memcpy(buf, btc, 32);     memcpy(buf + 32, MODE_CONST_SPENT, 32); sha256(buf, 64, spent);
        if (!memcmp(cur, btc, 32)) cls = 3;
        else if (!memcmp(cur, spent, 32)) cls = 4;
        else {
            memcpy(buf, neutral, 32); memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, a);
            if (!memcmp(cur, a, 32)) cls = 5;
            memcpy(buf, spent, 32); memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, a);
            if (!memcmp(cur, a, 32)) cls = 5;
            memcpy(buf, btc, 32); memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, a);
            if (!memcmp(cur, a, 32)) cls = 5;
            if (!cls) {   /* 30 Oct 2026: the PASSKEY door's values */
                uint8_t s3[32];
                door_secret(DOOR_PASSKEY, s3);
                memcpy(buf, neutral, 32); memcpy(buf + 32, s3, 32); sha256(buf, 64, btc);     /* btc := V_3 */
                memcpy(buf, btc, 32);     memcpy(buf + 32, MODE_CONST_SPENT, 32); sha256(buf, 64, spent);   /* spent := SPENT_3 */
                if (!memcmp(cur, btc, 32)) cls = 6;
                else if (!memcmp(cur, spent, 32)) cls = 7;
                else {
                    memcpy(buf, spent, 32); memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, a);
                    if (!memcmp(cur, a, 32)) cls = 5;
                    memcpy(buf, btc, 32); memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, a);
                    if (!memcmp(cur, a, 32)) cls = 5;
                }
                secure_wipe(s3, 32);
            }
        }
    }
    secure_wipe(btc, 32); secure_wipe(spent, 32); secure_wipe(a, 32); secure_wipe(buf, 64);
    return cls;
}

static int do_modereset(void) {
    memset(g_sesdiag, 0, 64);
    g_sesdiag[0]='M'; g_sesdiag[1]='R'; g_sesdiag[2]='S'; g_sesdiag[3]='T';
    g_sesdiag[4] = 2;   /* v2: diag[20] carries the latch class on a refused (0xEE) reset */
    /* NOTE: every exit below returns 0. finish() wipes g_sig_out and raises
     * ERROR whenever rc != 0, which would destroy the very diagnostic the ESP32
     * needs to read — that is exactly what made a spent one-shot look like
     * "G0 unreachable". The MRST diagnostic IS the result (same contract as
     * do_sessiontest); success/failure is read from diag[5], not from rc. */
    if (!g_mode_reset_arm) {                 /* one-shot spent, or not a fresh boot */
        g_sesdiag[5] = 0xEE;                 /* "not armed" marker */
        /* 17 Sep 2026: still READ the latch and report its class in diag[20]
         * (0xFF = could not read), so the ESP32 can tell "soft reboot inside
         * the same life, carry on" from "wrong door for this latch, power
         * cycle needed" BEFORE it shows a PIN screen. Read only, no write. */
        g_sesdiag[20] = 0xFF;
        if (g_keys_valid) {
            scp03_session_t rs; uint8_t rhc[8], rcc[8] = {0}, cur[32];
            memset(&rs, 0, sizeof(rs));
            host_challenge(rhc);
            if (scp03_open(&rs, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, rhc, rcc) == 0) {
                entropy_mix(rcc, 8);
                if (g0_read_mode_pcr(&rs, cur) == 0) g_sesdiag[20] = mode_latch_class(cur);
                scp03_close(&rs);
            }
            scp03_wipe(&rs); secure_wipe(rhc, 8); secure_wipe(cur, 32);
        }
        uint32_t up = HAL_GetTick();
        g_sesdiag[12]=(uint8_t)up; g_sesdiag[13]=(uint8_t)(up>>8); g_sesdiag[14]=(uint8_t)(up>>16); g_sesdiag[15]=(uint8_t)(up>>24);
        g_sesdiag[16]=(uint8_t)g_boot_rcc_csr; g_sesdiag[17]=(uint8_t)(g_boot_rcc_csr>>8);
        g_sesdiag[18]=(uint8_t)(g_boot_rcc_csr>>16); g_sesdiag[19]=(uint8_t)(g_boot_rcc_csr>>24);
        g_sesdiag[21]=g_life_resumed;   /* 16 Oct 2026: 1 = this boot resumed a life token (reset without power loss) */
        memcpy(g_sig_out, g_sesdiag, 64);
        return 0;
    }
    if (!g_keys_valid) { g_sesdiag[5]=0xE0; memcpy(g_sig_out,g_sesdiag,64); return 0; }

    scp03_session_t s; uint8_t hc[8], cc[8] = {0};
    memset(&s, 0, sizeof(s));
    int step = 1, rc;
    host_challenge(hc);
    rc = scp03_open(&s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    entropy_mix(cc, 8);
    if (rc) { step = 1 + s.stage; goto out; }

    /* WritePCR(reset) on MODE_PCR: TAG_1 id only. hasle=0. */
    {
        uint32_t oid = SE_OBJ_PCR_MODE;
        uint8_t data[6];
        data[0] = 0x41; data[1] = 0x04;
        data[2] = (uint8_t)(oid >> 24); data[3] = (uint8_t)(oid >> 16);
        data[4] = (uint8_t)(oid >> 8);  data[5] = (uint8_t)oid;
        step = 5;
        rc = scp03_cmd(&s, 0x01 /*INS_WRITE*/, 0x09 /*P1_PCR*/, 0x00 /*P2*/,
                       data, sizeof(data), 0 /*hasle*/, NULL, 0, NULL);
    }
    scp03_close(&s);
    if (!rc) { step = 0; g_mode_reset_arm = 0; life_save(); }   /* BURN the one-shot on success */
out:
    g_sesdiag[5] = (uint8_t)step;
    g_sesdiag[6] = s.stage;
    g_sesdiag[7] = (uint8_t)(int8_t)rc;
    g_sesdiag[8] = (uint8_t)(s.last_sw >> 8); g_sesdiag[9] = (uint8_t)s.last_sw;
    g_sesdiag[10] = s.nxfer;
    g_sesdiag[11] = g_mode_reset_arm;              /* 0 after a successful burn */
    {   /* 12..15 uptime ms LE, 16..19 RCC->CSR at boot LE */
        uint32_t up = HAL_GetTick();
        g_sesdiag[12]=(uint8_t)up; g_sesdiag[13]=(uint8_t)(up>>8); g_sesdiag[14]=(uint8_t)(up>>16); g_sesdiag[15]=(uint8_t)(up>>24);
        g_sesdiag[16]=(uint8_t)g_boot_rcc_csr; g_sesdiag[17]=(uint8_t)(g_boot_rcc_csr>>8);
        g_sesdiag[18]=(uint8_t)(g_boot_rcc_csr>>16); g_sesdiag[19]=(uint8_t)(g_boot_rcc_csr>>24);
    }
    memcpy(g_sig_out, g_sesdiag, 64);
    scp03_wipe(&s); secure_wipe(hc, 8);
    return 0;   /* always 0 — see the note above; outcome is in diag[5] */
}

/* Two-door (16 Sep 2026, v2): put MODE_PCR at BTC = SHA256(NEUTRAL || S) for
 * ONE seed unwrap. The ESP32 burns the latch to SPENT the moment the seed is
 * in RAM, so BTC never persists — a power-off, crash or pulled G0 leaves
 * SPENT, which no key gate matches. Every unwrap therefore needs this chip
 * again. What this chip agrees to depends on what the latch READS (over its
 * own session, so the value is SE-authenticated, not ESP32-supplied):
 *
 *   NEUTRAL   fresh G0 boot reset it     -> extend(S), ONCE per physical boot
 *   SPENT     a legitimately-entered BTC  -> reset, then extend(S); no limit
 *             life burned it after use
 *   BTC       leftover (crash in the      -> reset, then extend(S) — never
 *             unwrap window)                accepted as found (v2.1)
 *   NOSTR / anything else               -> refuse (0xEA). This is the rule
 *             that keeps a Nostr-life RCE out: from NOSTR the only route to
 *             BTC is a reset, and this chip will not reset from NOSTR.
 *
 * SPENT = SHA256(BTC || "FAVILLA-MODE-SPENT" zero-padded to 32) — the same
 * constant mode_pcr.inc uses. diag[5]: 0 ok | 0xEE NEUTRAL but one-shot spent
 * | 0xEF no S | 0xE0 no keys | 0xEA latch not NEUTRAL/SPENT | 0xEB latch
 * unreadable | else failing step. diag[20] = latch class seen (1 NEUTRAL,
 * 2 SPENT, 3 BTC-already, 4 other). Always returns 0 (diag contract). */
static int g0_read_mode_pcr(scp03_session_t *s, uint8_t out[32]) {
    uint32_t oid = SE_OBJ_PCR_MODE;
    uint8_t data[6] = { 0x41, 0x04, (uint8_t)(oid >> 24), (uint8_t)(oid >> 16), (uint8_t)(oid >> 8), (uint8_t)oid };
    uint8_t rsp[96]; size_t rl = 0;
    int rc = scp03_cmd(s, 0x02 /*INS_READ*/, 0x00 /*P1_DEFAULT*/, 0x00 /*P2*/, data, sizeof(data), 1 /*hasle*/, rsp, sizeof(rsp), &rl);
    if (rc) return rc;
    /* Tolerant TLV scan (16 Sep 2026 v2.1 fix): the SE returns the value in a
     * TLV whose tag byte and length encoding vary by applet, and the decrypted
     * body may carry trailing bytes. The old exact "41 20 <32>" match rejected
     * a valid read as -3 (0xEB). Walk TLVs, accept the first value of length
     * 32 whatever its tag — this mirrors what the ESP32's parseTLVLength-based
     * reader does. */
    size_t i = 0;
    while (i + 2 <= rl) {
        uint8_t tag = rsp[i++];
        size_t len = rsp[i++];
        if (len == 0x81) { if (i >= rl) break; len = rsp[i++]; }
        else if (len == 0x82) { if (i + 1 >= rl) break; len = ((size_t)rsp[i] << 8) | rsp[i+1]; i += 2; }
        if (i + len > rl) break;
        if (len == 32) { (void)tag; memcpy(out, rsp + i, 32); return 0; }
        i += len;
    }
    return -3;
}
/* Generic doors (30 Oct 2026): do_modedoor(d) is the old do_modebtc() with
 * the door as a parameter. For d = DOOR_BTC every byte it writes and every
 * diagnostic it returns is unchanged ("MBTC", the same arm, S itself). For
 * d = DOOR_PASSKEY the secret is S_3, the one-shot is g_mode_pk_arm, the diag
 * tag is "MDOR" with diag[21] = 3. The caller (door_permits + the dispatch)
 * guarantees d is the door this chip holds. In the code below "btc" means
 * V_d and "spent" means SPENT_d. */
static int do_modedoor(uint8_t d) {
    uint8_t *arm = (d == DOOR_PASSKEY) ? &g_mode_pk_arm : &g_mode_btc_arm;
    memset(g_sesdiag, 0, 64);
    if (d == DOOR_BTC) { g_sesdiag[0]='M'; g_sesdiag[1]='B'; g_sesdiag[2]='T'; g_sesdiag[3]='C'; }
    else               { g_sesdiag[0]='M'; g_sesdiag[1]='D'; g_sesdiag[2]='O'; g_sesdiag[3]='R'; g_sesdiag[21] = d; }
    g_sesdiag[4]=3;   /* v3: ARM classes */
    if (d != DOOR_BTC && d != DOOR_PASSKEY) { g_sesdiag[5] = 0xED; memcpy(g_sig_out, g_sesdiag, 64); return 0; }
    if (!g_keys_valid)   { g_sesdiag[5] = 0xE0; memcpy(g_sig_out, g_sesdiag, 64); return 0; }
    {   int z = 1, f = 1;
        for (int i = 0; i < KMODE_LEN; i++) { if (g_kmode[i] != 0x00) z = 0; if (g_kmode[i] != 0xFF) f = 0; }
        if (z || f) { g_sesdiag[5] = 0xEF; memcpy(g_sig_out, g_sesdiag, 64); return 0; } }

    /* the values this chip can recognise */
    uint8_t zero32[32] = {0}, neutral[32], btc[32], spent[32], buf[64], sd[32];
    uint8_t arm_n[32], arm_s[32], arm_b[32];
    door_secret(d, sd);
    sha256(zero32, 32, neutral);
    memcpy(buf, neutral, 32); memcpy(buf + 32, sd, 32); sha256(buf, 64, btc);
    memcpy(buf, btc, 32);     memcpy(buf + 32, MODE_CONST_SPENT, 32); sha256(buf, 64, spent);
    memcpy(buf, neutral, 32); memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, arm_n);
    memcpy(buf, spent, 32);   memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, arm_s);
    memcpy(buf, btc, 32);     memcpy(buf + 32, MODE_CONST_ARM, 32); sha256(buf, 64, arm_b);

    scp03_session_t s; uint8_t hc[8], cc[8] = {0};
    memset(&s, 0, sizeof(s));
    int step = 1, rc; uint16_t sw = 0; uint8_t cur[32]; uint8_t cls = 4;
    host_challenge(hc);
    rc = scp03_open(&s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    entropy_mix(cc, 8);
    if (rc) { step = 1 + s.stage; sw = s.last_sw; goto out; }

    step = 4;
    rc = g0_read_mode_pcr(&s, cur);
    if (rc) { sw = s.last_sw; step = 0xEB; goto close; }
    /* diag[20]: 1 ARM_N, 2 ARM_S, 3 ARM_B (accepted); 5/6/7 bare NEUTRAL/SPENT/BTC
     * (refused 0xEC: no PIN session armed it); 4 other (refused 0xEA). */
    if      (!memcmp(cur, arm_n, 32))   cls = 1;
    else if (!memcmp(cur, arm_s, 32))   cls = 2;
    else if (!memcmp(cur, arm_b, 32))   cls = 3;
    else if (!memcmp(cur, neutral, 32)) cls = 5;
    else if (!memcmp(cur, spent, 32))   cls = 6;
    else if (!memcmp(cur, btc, 32))     cls = 7;
    g_sesdiag[20] = cls;
    if (cls >= 5 && cls <= 7) { step = 0xEC; rc = 0; goto close; }   /* v3: not armed by a PIN session */

    /* v2.1/v3: a latch that already reads BTC (armed or not) is NEVER accepted
     * as-is. Reset and extend again, exactly like SPENT — so every unwrap is
     * preceded by an extend THIS chip just did. From ARM_N the reset is not
     * needed by policy but the value must return to NEUTRAL before extend(S),
     * and only this chip can reset — so ARM_N is reset too, under the
     * one-shot. */
    if (cls == 3) cls = 2;
    if (cls == 1) {
        if (!*arm) { step = 0xEE; rc = 0; goto close; }   /* ARM_N without a fresh boot: no */
        *arm = 0; life_save();                            /* one extend from NEUTRAL per door per physical boot */
        uint32_t oid = SE_OBJ_PCR_MODE;
        uint8_t rst[6] = { 0x41, 0x04, (uint8_t)(oid >> 24), (uint8_t)(oid >> 16), (uint8_t)(oid >> 8), (uint8_t)oid };
        step = 5;
        rc = scp03_cmd(&s, 0x01, 0x09, 0x00, rst, sizeof(rst), 0, NULL, 0, NULL);
        if (rc) { sw = s.last_sw; goto close; }
    } else if (cls == 2) {
        /* SPENT: a real BTC life happened this power cycle and was burned.
         * Reset to NEUTRAL (this chip holds DELETE), then extend. */
        uint32_t oid = SE_OBJ_PCR_MODE;
        uint8_t rst[6] = { 0x41, 0x04, (uint8_t)(oid >> 24), (uint8_t)(oid >> 16), (uint8_t)(oid >> 8), (uint8_t)oid };
        step = 5;
        rc = scp03_cmd(&s, 0x01, 0x09, 0x00, rst, sizeof(rst), 0, NULL, 0, NULL);
        if (rc) { sw = s.last_sw; goto close; }
    } else {
        step = 0xEA; rc = 0; goto close;                     /* NOSTR / non-canonical: refuse */
    }
    {
        uint32_t oid = SE_OBJ_PCR_MODE;
        uint8_t data[6 + 2 + KMODE_LEN];
        data[0] = 0x41; data[1] = 0x04;
        data[2] = (uint8_t)(oid >> 24); data[3] = (uint8_t)(oid >> 16);
        data[4] = (uint8_t)(oid >> 8);  data[5] = (uint8_t)oid;
        data[6] = 0x43; data[7] = KMODE_LEN;                 /* TAG_3 = extend data */
        memcpy(data + 8, sd, KMODE_LEN);                     /* S_d (S itself for the BTC door) */
        step = 6;
        rc = scp03_cmd(&s, 0x01 /*INS_WRITE*/, 0x09 /*P1_PCR*/, 0x00, data, sizeof(data), 0, NULL, 0, NULL);
        secure_wipe(data, sizeof(data));
        sw = s.last_sw;
        if (!rc) step = 0;
    }
close:
    scp03_close(&s);
out:
    g_sesdiag[5] = (uint8_t)step;
    g_sesdiag[6] = s.stage;
    g_sesdiag[7] = (uint8_t)(int8_t)rc;
    g_sesdiag[8] = (uint8_t)(sw >> 8); g_sesdiag[9] = (uint8_t)sw;
    g_sesdiag[10] = s.nxfer;
    g_sesdiag[11] = *arm;
    {   uint32_t up = HAL_GetTick();
        g_sesdiag[12]=(uint8_t)up; g_sesdiag[13]=(uint8_t)(up>>8); g_sesdiag[14]=(uint8_t)(up>>16); g_sesdiag[15]=(uint8_t)(up>>24);
        g_sesdiag[16]=(uint8_t)g_boot_rcc_csr; g_sesdiag[17]=(uint8_t)(g_boot_rcc_csr>>8);
        g_sesdiag[18]=(uint8_t)(g_boot_rcc_csr>>16); g_sesdiag[19]=(uint8_t)(g_boot_rcc_csr>>24); }
    memcpy(g_sig_out, g_sesdiag, 64);
    scp03_wipe(&s); secure_wipe(hc, 8); secure_wipe(btc, 32); secure_wipe(spent, 32); secure_wipe(buf, 64);
    secure_wipe(arm_n, 32); secure_wipe(arm_s, 32); secure_wipe(arm_b, 32); secure_wipe(sd, 32);
    return 0;
}
static int do_modebtc(void) { return do_modedoor(DOOR_BTC); }   /* the original command, now an alias for door 2 */

/* MODEDEL RETIRED (19 Oct 2026, review finding 3). DO NOT RE-ADD.
 * This was a wipe helper that let anyone ask this chip to delete MODE_PCR,
 * on the reasoning that deleting the latch only bricks both doors. It does
 * not: a deleted object id can be re-created (anonymously, v5.1 silicon
 * notes) with any INITIAL value, and the BTC value SHA256(NEUTRAL || S) is
 * public (it sits in the seed wrap key's policy and in the ESP32's nvs_sec).
 * Delete + re-create at the BTC value = a latch that reads BTC with no S and
 * no G0 extend, which is the guarantee the whole two-door design rests on.
 * Same class of hole as the v5.1 Door-1 PCR fix.
 * MODE_PCR is now deletable only by SE_AUTH_OBJ_RECOVER inside WIPEALL,
 * after the seed wrap key is confirmed gone (see do_wipeall). Wiped wallets
 * do not need the old latch removed: each onboarding takes a fresh object
 * generation, so a surviving MODE_PCR from a dead generation names nothing.
 * Bench check that should FAIL on this build: Nostr life -> raw cmd 0x0C ->
 * the command is not accepted (commit_write drops it, status stays IDLE). */

/* ===========================================================================
 * v4.1 (24 Sep 2026) — WIPEALL: the recovery credential
 * ===========================================================================
 * The SE locks a PIN object for good at its tenth wrong verify. If the daily
 * PIN locks, nothing that only the daily PIN may delete can ever be deleted,
 * and the chip can never be re-onboarded: a brick. An RCE on the ESP32 can do
 * that in a second; so can ten typos over a lifetime if the counter is
 * cumulative. The recovery credential closes it:
 *   - SE_AUTH_OBJ_RECOVER is an AESKey auth object (K_RECOVER, derived from
 *     K_SE and never delivered separately). AESKey objects are created with
 *     maxAttempts 0 = unlimited, so spamming it cannot lock it.
 *   - Every object's policy grants it DELETE and nothing else.
 *   - It is used ONLY here, in one fixed order: key material and gates first,
 *     the PIN objects LAST, itself at the very end. The ESP32 cannot ask this
 *     chip to delete one object on its own, so a PIN object can never be
 *     deleted while the objects it guards still exist (a deleted-and-recreated
 *     PIN would otherwise be a PIN reset).
 * The ESP32 (or an RCE) can invoke this at will: the result is a wallet that
 * must be restored from words - a denial of service, the same class as
 * erasing NVS - never a lock, and never a key. Door-agnostic.
 * WALL diag (SIG_OUT): "WALL" ver rc | [6..7] done mask (bit i = object i
 * deleted) | [8..9] missing mask (SW 6A88 not found = fine) | [10] stage |
 * [11] rc8 | [12..13] last SW | [14] nxfer. rc: 0 all present objects gone,
 * 0xE0 no keys, 1..4 session open, 0xD0 one or more deletes refused or
 * skipped (incl. a pre-gen-9 G0 auth object, which has no RECOVER right). */
static void krecover_key(uint8_t key[16]) {
    static const uint8_t label[] = "favilla-recover-key";
    uint8_t h[32]; sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kse, KSE_LEN); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, h); memcpy(key, h, 16); secure_wipe(h, 32);
}
/* v5.1: secrets and gates of THIS generation, then RECOVER itself. The PIN
 * objects are NOT here: RECOVER holds no right on them (a deleted PIN can be
 * recreated with a known value = a PIN reset). They stay as dead objects; the
 * next onboarding uses the next generation. The Door-1 PCR is not here
 * either (RECOVER has no right on it, v5.1).
 *
 * 20 Oct 2026 (N2): this chip's own SE auth object (K_SE) IS here now, second
 * to last. Every object whose policy names it (scalar, nsec import, both wrap
 * keys, the latch) is deleted before it, and it is deleted ONLY if each of
 * those is gone (done or already absent): a deleted-and-recreated auth object
 * under a known key could otherwise act as "the G0" towards a survivor. The
 * SE policy grants RECOVER DELETE on it from generation 9 (se_signer.cpp,
 * se_provision_g0_identity); an older object refuses with 6986, which is
 * reported (0xD0) but does not stop the wipe, so legacy units still wipe. */
#define WIPE_N 15   /* 2 Nov 2026 (v14): +VPUB before the G0 auth object (its policy names it). 30 Oct 2026: +PK_SCRATCH, +PK_MASTER. 2 Nov 2026 (2b): +K_PK, +K_PKN, +PK_MASTER_P before the latch (both keys name it) */
#define WIPE_IDX_SEEDWRAP 3   /* wipe_order(3) == SE_OBJ_AES_WRAP_SEED */
#define WIPE_IDX_KPK      6   /* wipe_order(6) == SE_OBJ_K_PK (its rights are gated on MODE_PCR) */
#define WIPE_IDX_KPKN     7   /* wipe_order(7) == SE_OBJ_K_PKN (likewise) */
#define WIPE_IDX_G0AUTH  13   /* wipe_order(13) == SE_AUTH_OBJ_G0 */
/* bits of wipe_order() indices whose policies name SE_AUTH_OBJ_G0 */
#define WIPE_G0AUTH_DEPS  ((1u << 0) | (1u << 1) | (1u << 2) | (1u << 3) | (1u << 6) | (1u << 7) | (1u << 8) | (1u << 9) | (1u << 10) | (1u << 11) | (1u << 12))
static uint32_t wipe_order(int i) {
    switch (i) {
    case 0: return SE_OBJ_NOSTR_SCALAR;   case 1: return SE_OBJ_NSEC_IMPORT;
    case 2: return SE_OBJ_AES_WRAP_DAILY; case 3: return SE_OBJ_AES_WRAP_SEED;
    case 4: return SE_OBJ_PAIR_WRAP;      case 5: return SE_OBJ_DOOR1_SECRET;
    case 6: return SE_OBJ_K_PK;           case 7: return SE_OBJ_K_PKN;         /* 2b: absent on older units = "missing", fine */
    case 8: return SE_OBJ_PK_MASTER_P;
    case 9: return SE_OBJ_PCR_MODE;
    case 10: return SE_OBJ_PK_SCRATCH;    case 11: return SE_OBJ_PK_MASTER;    /* restorable passkeys; absent on most units = "missing", fine */
    case 12: return SE_OBJ_VPUB;          /* v14: vault publishing key copy; absent on older units = "missing", fine */
    case 13: return SE_AUTH_OBJ_G0;       /* N2: only once 0,1,2,3,6..12 are gone */
    default: return SE_AUTH_OBJ_RECOVER;   /* last: our own session dies with it */
    }
}
static int do_wipeall(void) {
    memset(g_sesdiag, 0, 64);
    g_sesdiag[0]='W'; g_sesdiag[1]='A'; g_sesdiag[2]='L'; g_sesdiag[3]='L'; g_sesdiag[4]=1;
    if (!g_keys_valid) { g_sesdiag[5] = 0xE0; memcpy(g_sig_out, g_sesdiag, 64); return 0; }
    scp03_session_t s; uint8_t hc[8], cc[8] = {0}, kr[16];
    memset(&s, 0, sizeof(s));
    int step = 1, rc; uint16_t sw = 0, done = 0, missing = 0;
    krecover_key(kr);
    host_challenge(hc);
    rc = scp03_open(&s, relay_xfer, NULL, kr, SE_AUTH_OBJ_RECOVER, hc, cc);
    secure_wipe(kr, 16);
    entropy_mix(cc, 8);
    if (rc) { step = 1 + s.stage; sw = s.last_sw; g_sesdiag[5] = (uint8_t)step; goto out; }
    step = 5;
    for (int i = 0; i < WIPE_N; i++) {
        uint32_t oid = wipe_order(i);
        uint8_t data[6];
        data[0] = 0x41; data[1] = 0x04;
        data[2] = (uint8_t)(oid >> 24); data[3] = (uint8_t)(oid >> 16);
        data[4] = (uint8_t)(oid >> 8);  data[5] = (uint8_t)oid;
        /* 19 Oct 2026 (finding 3): MODE_PCR and our own RECOVER object go
         * ONLY if the seed wrap key is gone. If the seed key survived (a
         * policy refusal, an old object without the RECOVER right) and the
         * latch were deleted, its id could be re-created at the public BTC
         * value and the seed key would answer the spend PIN in any life.
         * Stopping here keeps RECOVER, so K_SE is kept (WIPEKEYS gate) and the
         * wipe can be retried. A forged "absent" SW from the relay cannot
         * fake this: skipping a command breaks the SCP03 MAC chain, so every
         * later command in the session fails at the SE. */
        if (oid == SE_OBJ_PCR_MODE && !(done & (1u << WIPE_IDX_SEEDWRAP)) && !(missing & (1u << WIPE_IDX_SEEDWRAP))) {
            g_sesdiag[5] = 0xD1;   /* seed wrap key still present: latch and RECOVER kept */
            break;
        }
        /* 2 Nov 2026 (2b): the same rule for the passkey keys, whose rights are
         * gated on the latch: a surviving K_PK / K_PKN must not meet a latch that
         * was re-created at a chosen value. */
        if (oid == SE_OBJ_PCR_MODE && (!((done | missing) & (1u << WIPE_IDX_KPK)) || !((done | missing) & (1u << WIPE_IDX_KPKN)))) {
            g_sesdiag[5] = 0xD2;   /* a passkey key still present: latch and RECOVER kept */
            break;
        }
        /* 20 Oct 2026 (N2): our own auth object goes only once everything that
         * names it is gone. If any of those survived (a refusal above), skip
         * it - it stays a dead object, as before - and carry on to RECOVER. */
        if (oid == SE_AUTH_OBJ_G0 && (((done | missing) & WIPE_G0AUTH_DEPS) != WIPE_G0AUTH_DEPS)) {
            g_sesdiag[5] = 0xD0;
            continue;
        }
        int r = scp03_cmd(&s, 0x04 /*INS_MGMT*/, 0x00, 0x28 /*P2_DELETE_OBJECT*/, data, sizeof(data), 0, NULL, 0, NULL);
        sw = s.last_sw;
        if (r == 0) done |= (uint16_t)(1u << i);
        else if (sw == 0x6985 || sw == 0x6A88 || sw == 0x6A82) missing |= (uint16_t)(1u << i);   /* not there: fine. Silicon (24 Sep 2026): this SE answers 6985 for a delete of an absent object; a policy refusal is 6986 */
        else { g_sesdiag[5] = 0xD0; }                                            /* refused: keep going, report */
        if (i == WIPE_N - 1) break;   /* the last delete was our own auth object; the session is gone with it */
    }
    if (g_sesdiag[5] == 0) step = 0;
    if (done & (uint16_t)(1u << (WIPE_N - 1))) g_recover_gone = 1;   /* authenticated: R-MAC verified 9000 */
    g_pk_scratch_own = 0;   /* restorable passkeys: the scratch object is gone (or must be re-claimed) */
    scp03_close(&s);
out:
    g_sesdiag[6] = (uint8_t)(done >> 8); g_sesdiag[7] = (uint8_t)done;
    g_sesdiag[8] = (uint8_t)(missing >> 8); g_sesdiag[9] = (uint8_t)missing;
    g_sesdiag[10] = s.stage; g_sesdiag[11] = (uint8_t)(int8_t)rc;
    g_sesdiag[12] = (uint8_t)(sw >> 8); g_sesdiag[13] = (uint8_t)sw; g_sesdiag[14] = s.nxfer;
    (void)step;
    memcpy(g_sig_out, g_sesdiag, 64);
    scp03_wipe(&s); secure_wipe(hc, 8);
    return 0;
}

/* WIPEKEYS gate (24 Sep 2026; hardened 14 Oct 2026). K_RECOVER is derived from
 * K_SE, so if this chip forgot K_SE while the recovery object still stood on
 * the SE, nothing could ever open it again and a locked PIN object would be a
 * brick after all - an RCE that sends WIPEKEYS before spamming the PIN. So
 * K_SE is forgotten ONLY once the recovery object is PROVABLY gone.
 *
 * 14 Oct 2026 (pentest prep, finding N3): the earlier gate also accepted
 * "absent" from an error status word - 6985/6A88 on the delete, or any
 * non-9000 at CreateSession. Those SWs arrive BEFORE any R-MAC check (an
 * error response carries no MAC), so the ESP32 that pumps the relay can forge
 * them and have this chip forget K_SE while the object still exists. Only
 * two signals are now accepted, both authenticated under a session key the
 * ESP32 does not hold:
 *   (a) WIPEALL's own delete of SE_AUTH_OBJ_RECOVER returned 9000 with a good
 *       R-MAC (the `done` bit), or
 *   (b) a CheckObjectExists on SE_AUTH_OBJ_RECOVER, issued INSIDE an SCP03
 *       session opened as SE_AUTH_OBJ_G0, answered 9000 (R-MAC checked,
 *       body decrypted) with result 0x02 = does not exist.
 * Anything else - relay never pumped, cryptogram failure, a refusal, an
 * error SW, a G0 auth object that is itself gone - keeps the keys and answers
 * ERROR. That is the safe direction: a chip that keeps K_SE can always retry
 * WIPEALL through RECOVER later. 0 = may forget. */
static int recover_obj_absent_authenticated(void) {
    scp03_session_t s; uint8_t hc[8], cc[8] = {0};
    memset(&s, 0, sizeof(s));
    host_challenge(hc);
    int rc = scp03_open(&s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    secure_wipe(hc, 8);
    entropy_mix(cc, 8);
    if (rc) { scp03_wipe(&s); return 0; }                 /* cannot prove anything: treat as present */
    uint8_t data[6];
    data[0] = 0x41; data[1] = 0x04;
    data[2] = (uint8_t)(SE_AUTH_OBJ_RECOVER >> 24); data[3] = (uint8_t)(SE_AUTH_OBJ_RECOVER >> 16);
    data[4] = (uint8_t)(SE_AUTH_OBJ_RECOVER >> 8);  data[5] = (uint8_t)SE_AUTH_OBJ_RECOVER;
    uint8_t out[8]; size_t olen = 0;
    /* AN12543 CheckObjectExists: INS_MGMT P1_DEFAULT P2_EXIST(0x27), TAG_1 oid.
     * Response body TLV[TAG_1] = 1 byte: 0x01 exists, 0x02 does not exist. */
    int r = scp03_cmd(&s, 0x04 /*INS_MGMT*/, 0x00, 0x27 /*P2_EXIST*/, data, sizeof(data), 1, out, sizeof(out), &olen);
    scp03_close(&s);
    scp03_wipe(&s);
    if (r != 0) return 0;                                   /* only an authenticated 9000 counts */
    int absent = 0;
    if (olen >= 3 && out[0] == 0x41 && out[1] == 0x01) absent = (out[2] == 0x02);
    else if (olen == 1)                                    absent = (out[0] == 0x02);
    secure_wipe(out, sizeof(out));
    return absent;
}
static int wipekeys_gate(void) {
    if (!g_keys_valid) return 0;
    if (g_recover_gone) return 0;                           /* (a) an earlier WIPEALL this life deleted it, authenticated */
    do_wipeall();
    if (g_recover_gone) return 0;                           /* (a) this WIPEALL deleted it, authenticated */
    if (recover_obj_absent_authenticated()) return 0;       /* (b) authenticated "does not exist" via the G0 auth object */
    return -1;
}

/* ===========================================================================
 * v3 — the seed inside this chip
 * ======================================================================== */

/* Inner seed wrap key + IV, derived from K_G0 so SETKEYS is unchanged and no
 * new secret has to be delivered. Distinct from the scalar's kg0_iv() domain.
 * AES-256-CBC over the 64-byte seed, fixed IV per device (one key, one
 * plaintext — a fixed IV is fine, as for the scalar). */
static void kseed_key(uint8_t key[32]) {
    static const uint8_t label[] = "favilla-g0-seedwrap-key";
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, key);
}
static void kseed_iv(const uint8_t key[32], uint8_t iv[16]) {
    static const uint8_t label[] = "favilla-g0-seedwrap-iv";
    uint8_t h[32]; sha256_ctx c; sha256_init(&c);
    sha256_update(&c, key, 32); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, h); memcpy(iv, h, 16); secure_wipe(h, 32);
}
static void seed_inner_crypt(uint8_t buf64[64], int encrypt) {
    uint8_t key[32], iv[16]; kseed_key(key); kseed_iv(key, iv);
    struct AES_ctx a; AES_init_ctx_iv(&a, key, iv);
    if (encrypt) AES_CBC_encrypt_buffer(&a, buf64, 64); else AES_CBC_decrypt_buffer(&a, buf64, 64);
    secure_wipe(&a, sizeof(a)); secure_wipe(key, 32); secure_wipe(iv, 16);
}

/* v4: the entropy container's inner layer uses its own key domain so a seed
 * blob and an entropy blob can never be confused: decrypting one with the
 * other's key yields noise, and the container carries a magic that noise
 * will not reproduce. */
static void kent_key(uint8_t key[32]) {
    static const uint8_t label[] = "favilla-g0-entwrap-key";
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, key);
}
static void ent_inner_crypt(uint8_t buf64[64], int encrypt) {
    uint8_t key[32], iv[16]; kent_key(key); kseed_iv(key, iv);   /* iv label is keyed by the key, so it differs too */
    struct AES_ctx a; AES_init_ctx_iv(&a, key, iv);
    if (encrypt) AES_CBC_encrypt_buffer(&a, buf64, 64); else AES_CBC_decrypt_buffer(&a, buf64, 64);
    secure_wipe(&a, sizeof(a)); secure_wipe(key, 32); secure_wipe(iv, 16);
}

/* v5 FETCH (15 Oct 2026). pkt: the 96-byte SEED_IN/ENT_IN inner packet =
 * inner CT(64) || "FVI5" || zero(28), produced by the ESP32 inside a verified
 * SPEND PIN session (the SE stripped its own layer there, and only there).
 * ent: 0 = seed (strip K_SEEDWRAP), 1 = entropy container (strip K_ENTWRAP).
 * Sequence: own SCP03 session -> read MODE_PCR, require == BTC (computed here
 * from S) -> BURN to SPENT in the same session -> close -> strip our layer.
 * The latch check is what keeps "one PIN-armed door per signature": an ESP32
 * that cached an inner packet from an earlier life cannot replay it, because
 * BTC only exists after MODEBTC, which only accepts a PIN-ARMed latch.
 * Steps: 0xE0 no keys | 0xE1 no packet | 0xE6 not a v5 inner packet |
 * v5.1: 0xE8 no seed stored on this chip | 0xE9 wrong kind | 0xEA packet is
 * not the inner layer of the stored seed | 0xEF no S | 1..4 session | 5 latch read | 9 latch is not BTC | 7 burn |
 * 8 close (tolerated). Returns 0 on success (step 0 or 8). */
static int fetch_blob_se(const uint8_t *pkt, int ent, uint8_t seed[64], int *step_out, uint8_t diag[8]) {
    scp03_session_t s; uint8_t hc[8], cc[8] = {0}; int step = 1, rc = 0; uint16_t sw = 0;
    uint8_t zero32[32] = {0}, neutral[32], btc[32], buf[64], cur[32];
    memset(&s, 0, sizeof(s));
    if (!g_keys_valid) { rc = -100; step = 0xE0; goto out; }
    if (!pkt) { rc = -101; step = 0xE1; goto out; }
    if (memcmp(pkt + 64, INNER_PKT_MAGIC, 4) != 0) { rc = -102; step = 0xE6; goto out; }
    {   /* v5.1: the packet must be the inner layer of THE seed stored on this
         * chip, of the kind stored. Checked before any SE traffic, so a wrong
         * packet costs nothing and burns nothing. */
        uint8_t k = 0, ih[32], h[32];
        if (!ss_load(&k, NULL, ih)) { rc = -106; step = 0xE8; goto out; }
        if (k != (ent ? SS_KIND_ENTROPY : SS_KIND_SEED)) { rc = -107; step = 0xE9; goto out; }
        sha256(pkt, 64, h);
        int same = (memcmp(h, ih, 32) == 0);
        secure_wipe(h, 32); secure_wipe(ih, 32);
        if (!same) { rc = -108; step = 0xEA; goto out; }
    }
    {   int z = 1, f = 1;
        for (int i = 0; i < KMODE_LEN; i++) { if (g_kmode[i] != 0x00) z = 0; if (g_kmode[i] != 0xFF) f = 0; }
        if (z || f) { rc = -103; step = 0xEF; goto out; } }
    sha256(zero32, 32, neutral);
    memcpy(buf, neutral, 32); memcpy(buf + 32, g_kmode, 32); sha256(buf, 64, btc);
    host_challenge(hc);
    rc = scp03_open(&s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    entropy_mix(cc, 8);
    if (rc) { step = 1 + s.stage; sw = s.last_sw; goto out; }
    step = 5; rc = g0_read_mode_pcr(&s, cur);
    if (rc) { sw = s.last_sw; goto close; }
    if (memcmp(cur, btc, 32) != 0) { step = 9; rc = -104; goto close; }   /* no live BTC door: refuse */
    {   /* BURN: extend MODE_PCR with SPENT. TAG_3 = extend data (silicon fact). */
        uint32_t oid = SE_OBJ_PCR_MODE;
        uint8_t data[6 + 2 + 32];
        data[0] = 0x41; data[1] = 0x04;
        data[2] = (uint8_t)(oid >> 24); data[3] = (uint8_t)(oid >> 16);
        data[4] = (uint8_t)(oid >> 8);  data[5] = (uint8_t)oid;
        data[6] = 0x43; data[7] = 32; memcpy(data + 8, MODE_CONST_SPENT, 32);
        step = 7;
        rc = scp03_cmd(&s, 0x01 /*INS_WRITE*/, 0x09 /*P1_PCR*/, 0x00, data, sizeof(data), 0, NULL, 0, NULL);
        sw = s.last_sw;
        if (rc) goto close;                                   /* no burn -> no seed */
    }
    step = 8; rc = scp03_close(&s);
    memcpy(seed, pkt, 64);
    if (ent) ent_inner_crypt(seed, 0); else seed_inner_crypt(seed, 0);
    if (!rc) step = 0;
    goto out;
close:
    scp03_close(&s);
out:
    if (diag) { diag[0] = s.stage; diag[1] = (uint8_t)(int8_t)rc; diag[2] = (uint8_t)(sw >> 8); diag[3] = (uint8_t)sw; diag[4] = s.nxfer; }
    if (step_out) *step_out = step;
    scp03_wipe(&s); secure_wipe(hc, 8);
    secure_wipe(btc, 32); secure_wipe(buf, 64); secure_wipe(cur, 32);
    if (step != 0 && step != 8) { secure_wipe(seed, 64); return -1; }
    return 0;
}

/* SEEDSEAL: onboarding only. SEED_IN[0..63] = plaintext seed (this is the
 * air-gapped ceremony, the same trust window as PROVISION). Answers the
 * 64-byte inner ciphertext on SIG_OUT; the ESP32 then SE-wraps each 32-byte
 * half under the seed wrap key and hands the 96-byte blob back to THIS chip
 * (SEEDSTORE, v5.1). It is never stored on the ESP32. */
/* v5.1: refused while a seed is stored here (a sealed seed of the ESP32's
 * choosing could otherwise be swapped in), and the result's hash is kept as
 * the pending record SEEDSTORE must match. */
static void pend_set(uint8_t kind) {
    sha256(g_sig_out, 64, g_pend_ihash); g_pend_kind = kind; g_pend_valid = 1;
}
static int do_seedseal(void) {
    if (!g_seed_in_valid || !g_keys_valid) return -1;
    if (ss_present() || !g_seal_window) return -1;
    memcpy(g_sig_out, g_seed_in, 64);
    seed_inner_crypt(g_sig_out, 1);
    pend_set(SS_KIND_SEED);
    return 0;
}

/* SEEDSTORE (v5.1). STORE_IN = kind || outer(96). SIG_OUT diag (always rc 0):
 *   0..3 "SSTO" 4 ver(1) 5 rc: 0 stored | 0xE0 no keys | 0xE1 no STORE_IN |
 *   0xE7 a seed is already stored (write-once) | 0xE8 no SEEDSEAL/ENTSEAL this
 *   life | 0xE9 kind differs from the seal | 0xEA flash write/verify failed |
 *   0xEB seal window closed (not the onboarding life, or a door was committed)
 *   6..37 the stored inner hash (on rc 0), so the ESP32 can cross-check. */
static int do_seedstore(void) {
    memset(g_sig_out, 0, 64);
    g_sig_out[0]='S'; g_sig_out[1]='S'; g_sig_out[2]='T'; g_sig_out[3]='O'; g_sig_out[4]=1;
    uint8_t rc = 0;
    if (!g_keys_valid)                         rc = 0xE0;
    else if (!g_store_in_valid)                rc = 0xE1;
    else if (!g_seal_window)                   rc = 0xEB;
    else if (ss_present())                     rc = 0xE7;
    else if (!g_pend_valid)                    rc = 0xE8;
    else if (g_store_in[0] != g_pend_kind)     rc = 0xE9;
    else if (!ss_store(g_pend_kind, g_store_in + 1, g_pend_ihash)) rc = 0xEA;
    if (rc == 0) { memcpy(g_sig_out + 6, g_pend_ihash, 32); secure_wipe(g_pend_ihash, 32); g_pend_valid = 0; g_seal_window = 0; }
    g_sig_out[5] = rc;
    return 0;
}

/* SEEDGET (v5.1). BTC_OUT: 0..3 "SGET" 4 ver(1) 5 rc (0 | 0xE8 none stored)
 *   6 kind  8..103 outer blob  104..135 inner hash. All of it is ciphertext or
 *   a hash of ciphertext; door-agnostic. */
static int do_seedget(void) {
    memset(g_btc_out, 0, BTC_OUT_LEN);
    g_btc_out[0]='S'; g_btc_out[1]='G'; g_btc_out[2]='E'; g_btc_out[3]='T'; g_btc_out[4]=1;
    uint8_t k = 0;
    if (ss_load(&k, g_btc_out + 8, g_btc_out + 104)) { g_btc_out[5] = 0; g_btc_out[6] = k; }
    else g_btc_out[5] = 0xE8;
    return 0;
}

/* DOOR1LOCK (v5.1). Extend SE_OBJ_PCR_UNLOCK with a fixed junk value over this
 * chip's own session. The PCR's policy (ESP32 pcrCreateLocked) gives this
 * chip WRITE (extend) only: no reset, no delete, no read. Extending can only
 * move the PCR AWAY from the unlocked value, which is SHA256(rest || X) where X
 * is read from an object only the daily PIN can read (SE_OBJ_DOOR1_SECRET), so
 * neither this chip nor anyone holding its keys can extend back to it.
 * Only the daily PIN session resets and re-unlocks.
 * Absent PCR (fresh device): proven by an authenticated CheckObjectExists ->
 * locked by definition (the ESP32 creates it locked).
 * SIG_OUT diag: "D1LK" 4 ver(1) 5 rc: 0 locked now | 1 PCR absent (proven) |
 *   0xE0 no keys | 1..4 session | 6 extend refused | 7 existence check failed
 *   6 stage 7 rc(int8) 8..9 SW. Always returns 0. */
static const uint8_t DOOR1_LOCK_JUNK[32] = {
  'F','A','V','I','L','L','A','-','D','O','O','R','1','-','B','O','O','T','-','L','O','C','K',
  0,0,0,0,0,0,0,0,0 };
static int do_door1lock(void) {
    memset(g_sig_out, 0, 64);
    g_sig_out[0]='D'; g_sig_out[1]='1'; g_sig_out[2]='L'; g_sig_out[3]='K'; g_sig_out[4]=1;
    if (!g_keys_valid) { g_sig_out[5] = 0xE0; return 0; }
    scp03_session_t s; uint8_t hc[8], cc[8] = {0}; uint8_t rc8 = 0; int rc; uint16_t sw = 0;
    memset(&s, 0, sizeof(s));
    host_challenge(hc);
    rc = scp03_open(&s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    entropy_mix(cc, 8);
    if (rc) { rc8 = (uint8_t)(1 + s.stage); sw = s.last_sw; goto out; }
    {
        uint32_t oid = SE_OBJ_PCR_UNLOCK;
        uint8_t data[6 + 2 + 32];
        data[0] = 0x41; data[1] = 0x04;
        data[2] = (uint8_t)(oid >> 24); data[3] = (uint8_t)(oid >> 16);
        data[4] = (uint8_t)(oid >> 8);  data[5] = (uint8_t)oid;
        data[6] = 0x43; data[7] = 32; memcpy(data + 8, DOOR1_LOCK_JUNK, 32);
        rc = scp03_cmd(&s, 0x01 /*INS_WRITE*/, 0x09 /*P1_PCR*/, 0x00, data, sizeof(data), 0, NULL, 0, NULL);
        sw = s.last_sw;
        if (rc == 0) { rc8 = 0; g_door1_locked = 1; scp03_close(&s); goto out; }
    }
    {   /* Refused. Only an AUTHENTICATED "does not exist" counts as locked: an
         * error SW carries no MAC and the relay could forge it. */
        uint8_t data[6]; uint8_t o[8]; size_t ol = 0;
        data[0] = 0x41; data[1] = 0x04;
        data[2] = (uint8_t)(SE_OBJ_PCR_UNLOCK >> 24); data[3] = (uint8_t)(SE_OBJ_PCR_UNLOCK >> 16);
        data[4] = (uint8_t)(SE_OBJ_PCR_UNLOCK >> 8);  data[5] = (uint8_t)SE_OBJ_PCR_UNLOCK;
        int r = scp03_cmd(&s, 0x04 /*INS_MGMT*/, 0x00, 0x27 /*P2_EXIST*/, data, sizeof(data), 1, o, sizeof(o), &ol);
        int absent = 0;
        if (r == 0) {
            if (ol >= 3 && o[0] == 0x41 && o[1] == 0x01) absent = (o[2] == 0x02);
            else if (ol == 1)                           absent = (o[0] == 0x02);
        }
        if (absent) { rc8 = 1; g_door1_locked = 1; }
        else rc8 = (r == 0) ? 6 : 7;
        scp03_close(&s);
    }
out:
    g_sig_out[5] = rc8; g_sig_out[6] = s.stage; g_sig_out[7] = (uint8_t)(int8_t)rc;
    g_sig_out[8] = (uint8_t)(sw >> 8); g_sig_out[9] = (uint8_t)sw;
    scp03_wipe(&s); secure_wipe(hc, 8);
    return 0;
}

/* ===========================================================================
 * v4 (24 Sep 2026) — per-session passphrase: the ENTROPY inside this chip
 * ======================================================================== */

/* ENTSEAL: onboarding only, the same trust window as SEEDSEAL. ENT_IN[0] =
 * word count (12 or 24), ENT_IN[1..32] = entropy (16 or 32 bytes, zero
 * padded), rest ignored. Builds the 64-byte container
 *   "FENT" | wc | entropy[32] | zero[27]
 * encrypts it under K_ENTWRAP and answers the inner ciphertext on SIG_OUT;
 * the ESP32 then SE-wraps each 32-byte half exactly as for a seed and stores
 * the 96-byte blob in NVS, tagged as an entropy blob. */
static int do_entseal(void) {
    if (!g_ent_in_valid || !g_keys_valid) return -1;
    if (ss_present() || !g_seal_window) return -1;   /* v5.1: as SEEDSEAL */
    uint8_t wc = g_ent_in[0];
    if (wc != 12 && wc != 24) return -1;
    memset(g_sig_out, 0, 64);
    g_sig_out[0] = ENT_MAGIC0; g_sig_out[1] = ENT_MAGIC1; g_sig_out[2] = ENT_MAGIC2; g_sig_out[3] = ENT_MAGIC3;
    g_sig_out[4] = wc;
    memcpy(g_sig_out + 5, g_ent_in + 1, 32);
    ent_inner_crypt(g_sig_out, 1);
    pend_set(SS_KIND_ENTROPY);
    return 0;
}

/* Container + passphrase -> 64-byte BIP-39 seed. The mnemonic is rebuilt from
 * the entropy with this chip's own copy of the word list (same table as the
 * ESP32's), then PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048).
 * The passphrase is opaque bytes: no character check, no trimming — the
 * ESP32 enforces printable ASCII at entry; here only the length is bounded,
 * by construction of PASS_IN. Returns 0 ok, -1 bad container. */
static int derive_from_container(const uint8_t cont[64], const uint8_t *pass, uint8_t plen, uint8_t seed[64]) {
    if (cont[0] != ENT_MAGIC0 || cont[1] != ENT_MAGIC1 || cont[2] != ENT_MAGIC2 || cont[3] != ENT_MAGIC3) return -1;
    int wc = cont[4];
    if (wc != 12 && wc != 24) return -1;
    char mn[224]; uint8_t salt[8 + PASS_MAX];
    int ml = bip39_mnemonic_from_entropy(cont + 5, wc, mn, sizeof(mn));
    if (ml < 0) { secure_wipe(mn, sizeof(mn)); return -1; }
    memcpy(salt, "mnemonic", 8); if (plen) memcpy(salt + 8, pass, plen);
    pbkdf2_hmac_sha512_64((const uint8_t *)mn, (size_t)ml, salt, 8 + (size_t)plen, 2048, seed);
    secure_wipe(mn, sizeof(mn)); secure_wipe(salt, sizeof(salt));
    return 0;
}

/* Which passphrase applies to this life. A fresh PASS_IN (staging) replaces the
 * cached one and costs one unit of the per-life budget; with the budget spent
 * the staging buffer is refused and the cached passphrase (if any) stays. The
 * budget is what turns "DOORKEYS with any passphrase" from an unlimited
 * guessing oracle for an in-life RCE into five tries per battery pull.
 * Returns 0 ok, 0xE3 no passphrase at all, 0xE4 budget spent. */
static uint8_t resolve_pass(void) {
    if (g_pass_in_valid) {
        uint8_t l = g_pass_in[0];
        if (l > PASS_MAX) { secure_wipe(g_pass_in, sizeof(g_pass_in)); g_pass_in_valid = 0; return 0xE3; }
        if (g_pass_budget == 0) { secure_wipe(g_pass_in, sizeof(g_pass_in)); g_pass_in_valid = 0; return 0xE4; }
        g_pass_budget--; life_save();
        secure_wipe(g_pass, sizeof(g_pass));
        memcpy(g_pass, g_pass_in + 1, l); g_pass_len = l; g_pass_valid = 1;
        secure_wipe(g_pass_in, sizeof(g_pass_in)); g_pass_in_valid = 0;
    }
    return g_pass_valid ? 0 : 0xE3;
}

/* The seed for a DOORKEYS/BTCSIGN, whichever kind of wallet this is:
 *   ENT_IN present  -> entropy wallet: resolve passphrase, fetch + burn, derive.
 *   SEED_IN present -> seed wallet (v3): fetch + burn, done.
 * Both fetches walk the same gate (v5: the SE layer already stripped by the
 * spend PIN; here MODE_PCR == BTC is checked over this chip's session and
 * burned before anything leaves), so a per-session wallet costs one PBKDF2 per
 * signature and nothing else. rc as DOORKEYS byte 5. */
static uint8_t get_seed(uint8_t seed[64], int *step, uint8_t d[8]) {
    if (g_ent_in_valid) {
        uint8_t pr = resolve_pass();
        if (pr) return pr;
        uint8_t cont[64];
        if (fetch_blob_se(g_ent_in, 1, cont, step, d) != 0) { secure_wipe(cont, 64); return (uint8_t)*step; }
        int rc = derive_from_container(cont, g_pass, g_pass_len, seed);
        secure_wipe(cont, 64);
        if (rc) { secure_wipe(seed, 64); return 0xE5; }     /* not an entropy container (wrong blob for this key) */
        em_glue_tier1(0);                                    /* Emberwill tier-1 life: spend PIN */
        return 0;
    }
    if (g_seed_in_valid) {
        if (fetch_blob_se(g_seed_in, 0, seed, step, d) != 0) return (uint8_t)*step;
        em_glue_tier1(0);
        return 0;
    }
    return 0xE1;
}

/* DOORKEYS, BTC_OUT (192):
 *   0..3 "DKEY"  4 ver (2 = v5 inner packet)  5 rc (0 ok | 0xE0 no keys | 0xE1 no
 *   SEED_IN/ENT_IN | 0xE6 not a v5 inner packet | 0xEF no S | 1..9 fetch step | 0xD2 derivation failed | v4: 0xE3 no passphrase for an entropy wallet |
 *   0xE4 passphrase budget spent this power-on life | 0xE5 blob is not an
 *   entropy container)   6..9 master fp
 *   10..42 xpub84 pub33   43..74 cc   75..78 parent fp
 *   79..111 xpub48 pub33  112..143 cc 144..147 parent fp
 *   148..179 sealed-state key
 *   180 stage  181 rc(int8)  182..183 SW  184 relay steps  185..186 ms
 * Always returns 0 (the diagnostic IS the result); key bytes are present only
 * when rc == 0. */
static int do_doorkeys(void) {
    uint8_t seed[64]; int step = 0; uint8_t d[8] = {0}; uint32_t t0 = HAL_GetTick();
    memset(g_btc_out, 0, BTC_OUT_LEN);
    g_btc_out[0]='D'; g_btc_out[1]='K'; g_btc_out[2]='E'; g_btc_out[3]='Y'; g_btc_out[4]=DOORKEYS_VER;
    { uint8_t gr = get_seed(seed, &step, d); if (gr) { g_btc_out[5] = gr; goto out; } }
    {
        btc_xprv a; btc_xpub_t x; uint8_t mfp[4], pfp[4]; int ok = 1;
        if (btc_account(g_ctx, seed, 84, &a, mfp, pfp) || btc_xpub_of(g_ctx, &a, pfp, &x)) ok = 0;
        else { memcpy(g_btc_out + 6, mfp, 4); memcpy(g_btc_out + 10, x.pub, 33); memcpy(g_btc_out + 43, x.cc, 32); memcpy(g_btc_out + 75, x.parent_fp, 4); }
        if (ok && (btc_account(g_ctx, seed, 48, &a, NULL, pfp) || btc_xpub_of(g_ctx, &a, pfp, &x))) ok = 0;
        else if (ok) { memcpy(g_btc_out + 79, x.pub, 33); memcpy(g_btc_out + 112, x.cc, 32); memcpy(g_btc_out + 144, x.parent_fp, 4); }
        if (ok) btc_state_key(seed, g_btc_out + 148);
        secure_wipe(&a, sizeof(a)); secure_wipe(&x, sizeof(x));
        if (!ok) { memset(g_btc_out + 6, 0, 174); g_btc_out[5] = 0xD2; }
        else g_btc_out[5] = 0;
    }
out:
    secure_wipe(seed, 64);
    g_btc_out[180] = d[0]; g_btc_out[181] = d[1]; g_btc_out[182] = d[2]; g_btc_out[183] = d[3]; g_btc_out[184] = d[4];
    put16(g_btc_out + 185, HAL_GetTick() - t0);
    return 0;
}

/* BTCSIGN_INIT (anti-exfil, 27 Oct 2026), BTC_OUT (192), "BSIG" v3:
 *   0..3 "BSIG"  4 ver=3  5 rc (0 ok | 0xE0/0xE1/0xE6/0xE8..0xEA/0xEF/1..9 as
 *   DOORKEYS | 0xE2 no BTC_IN or no AE_IN | 0xD1 bad request | 0xD2 derivation |
 *   0xD5 nonce commitment failed | 0xD6 another signature is pending)
 *   6 kind  7 0  8..40 pub33  41..73 R0 (compressed)  113..144 sighash
 *   145 stage  146 rc(int8)  147..148 SW  149 relay steps  150..151 ms
 * The seed is fetched (and the latch burned) HERE, the leaf key derived and
 * the sighash computed, then the seed is wiped: only the 32-byte leaf key,
 * k0, R0, h and the sighash stay in g_ae until AE_FINISH. The sighash is
 * echoed so the ESP32 can compare it with its own bip143.h computation of
 * the same input and refuse on mismatch (a field KAT of both implementations,
 * every signature). AE_IN must be zeros(32) || h: the message half has no
 * meaning for a Bitcoin input (the sighash is computed here) and is required
 * to be zero so the two kinds of INIT cannot be confused on the wire. */
static int ae_in_msg_is_zero(void) { uint8_t acc = 0; for (int i = 0; i < 32; i++) acc |= g_ae_in[i]; return acc == 0; }

static int do_btcsign_init(void) {
    uint8_t seed[64]; int step = 0; uint8_t d[8] = {0}; uint32_t t0 = HAL_GetTick();
    memset(g_btc_out, 0, BTC_OUT_LEN);
    g_btc_out[0]='B'; g_btc_out[1]='S'; g_btc_out[2]='I'; g_btc_out[3]='G'; g_btc_out[4]=BTCSIGN_VER;
    g_btc_out[6] = g_btc_in[0];
    if (!g_btc_in_valid || !g_ae_in_valid) { g_btc_out[5] = 0xE2; goto out; }
    if (!ae_in_msg_is_zero()) { g_btc_out[5] = 0xD1; goto out; }
    if (g_ae.kind != AE_KIND_NONE) { g_btc_out[5] = 0xD6; goto out; }   /* refused; the pending one is kept */
    { uint8_t gr = get_seed(seed, &step, d); if (gr) { g_btc_out[5] = gr; goto out; } }
    {
        int rc = btc_sign_prepare(g_ctx, seed, g_btc_in, g_ae.key, g_ae.pub33, g_ae.msg);
        if (rc != 0) { ae_wipe(); g_btc_out[5] = (uint8_t)(0xD0 + (uint8_t)(-rc)); goto out; }
        memcpy(g_ae.h, g_ae_in + 32, 32);
        { uint8_t hx[32]; hedge32("favilla-g0-ecdsa-hedge", g_ae.h, hx);   /* v18: RFC 6979 extra data = h hedged with fresh bytes; g_ae.h (the host commitment AE_FINISH checks t against) is unchanged */
          const int ir = ae_ecdsa_init(g_ctx, g_ae.key, g_ae.msg, hx, g_ae.k0, g_ae.r0); secure_wipe(hx, 32);
          if (ir != 0) { ae_wipe(); g_btc_out[5] = 0xD5; goto out; } }
        g_ae.btc_kind = g_btc_in[0];
        g_ae.t0 = HAL_GetTick();
        g_ae.kind = AE_KIND_ECDSA;          /* last: nothing is pending until everything above held */
        g_btc_out[5] = 0;
        memcpy(g_btc_out + 8, g_ae.pub33, 33);
        memcpy(g_btc_out + 41, g_ae.r0, 33);
        memcpy(g_btc_out + 113, g_ae.msg, 32);
    }
out:
    secure_wipe(seed, 64);
    g_btc_out[145] = d[0]; g_btc_out[146] = d[1]; g_btc_out[147] = d[2]; g_btc_out[148] = d[3]; g_btc_out[149] = d[4];
    put16(g_btc_out + 150, HAL_GetTick() - t0);
    return 0;
}

/* MSGSIGN_INIT (BIP-137 + anti-exfil), BTC_OUT (192), "MSIG" v2:
 *   0..3 "MSIG"  4 ver=2  5 rc (as BTCSIGN_INIT; 0xD1 bad request)
 *   8..40 pub33  41..73 R0  106..137 digest
 *   145 stage  146 rc(int8)  147..148 SW  149 relay steps  150..151 ms
 * Every message signature costs one spend-PIN-armed door and burns the latch,
 * exactly like a transaction input. The digest is built here from the message
 * bytes (btc_msg_prepare), never accepted as a hash. */
static int do_msgsign_init(void) {
    uint8_t seed[64]; int step = 0; uint8_t d[8] = {0}; uint32_t t0 = HAL_GetTick();
    memset(g_btc_out, 0, BTC_OUT_LEN);
    g_btc_out[0]='M'; g_btc_out[1]='S'; g_btc_out[2]='I'; g_btc_out[3]='G'; g_btc_out[4]=MSGSIGN_VER_AE;
    if (!g_btc_in_valid || !g_ae_in_valid) { g_btc_out[5] = 0xE2; goto out; }
    /* validate the whole request BEFORE the fetch burns the latch */
    if (!btc_msg_request_valid(g_btc_in) || !ae_in_msg_is_zero()) { g_btc_out[5] = 0xD1; goto out; }
    if (g_ae.kind != AE_KIND_NONE) { g_btc_out[5] = 0xD6; goto out; }
    { uint8_t gr = get_seed(seed, &step, d); if (gr) { g_btc_out[5] = gr; goto out; } }
    {
        int rc = btc_msg_prepare(g_ctx, seed, g_btc_in, g_ae.key, g_ae.pub33, g_ae.msg);
        if (rc != 0) { ae_wipe(); g_btc_out[5] = (uint8_t)(0xD0 + (uint8_t)(-rc)); goto out; }
        memcpy(g_ae.h, g_ae_in + 32, 32);
        { uint8_t hx[32]; hedge32("favilla-g0-ecdsa-hedge", g_ae.h, hx);   /* v18: RFC 6979 extra data = h hedged with fresh bytes; g_ae.h (the host commitment AE_FINISH checks t against) is unchanged */
          const int ir = ae_ecdsa_init(g_ctx, g_ae.key, g_ae.msg, hx, g_ae.k0, g_ae.r0); secure_wipe(hx, 32);
          if (ir != 0) { ae_wipe(); g_btc_out[5] = 0xD5; goto out; } }
        g_ae.t0 = HAL_GetTick();
        g_ae.kind = AE_KIND_ECDSA_RC;
        g_btc_out[5] = 0;
        memcpy(g_btc_out + 8, g_ae.pub33, 33);
        memcpy(g_btc_out + 41, g_ae.r0, 33);
        memcpy(g_btc_out + 106, g_ae.msg, 32);
    }
out:
    secure_wipe(seed, 64);
    g_btc_out[145] = d[0]; g_btc_out[146] = d[1]; g_btc_out[147] = d[2]; g_btc_out[148] = d[3]; g_btc_out[149] = d[4];
    put16(g_btc_out + 150, HAL_GetTick() - t0);
    return 0;
}

static int do_sessiontest(void) {
    uint8_t scalar[32];
    (void)fetch_scalar_se(scalar, SE_OBJ_NOSTR_SCALAR, g_sesdiag);
    secure_wipe(scalar, 32);
    memcpy(g_sig_out, g_sesdiag, 64);
    return 0;                                /* the diagnostic IS the result; always readable */
}

/* Nostr ECDH wants the raw X coordinate, not SHA256(compressed point). */
static int ecdh_x_only(unsigned char *out, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)y32; (void)data; memcpy(out, x32, 32); return 1;
}

/* 19 Oct 2026: the identity's x-only pubkey, cached once per power-on life
 * and used to verify every signature before release. Filled by PUBKEY (the
 * ESP32 asks for the pubkey at every unlock, before any signing): computed
 * twice from that one scalar with a re-blind in between and compared, so one
 * glitch cannot plant a wrong value (at worst it makes every later check fail
 * = no signatures, never a bad one). One SE session per command, always: a
 * second fetch would exceed the ESP32's relay step guard. Reset whenever the
 * keys change. */
static secp256k1_xonly_pubkey g_true_pk;
static uint8_t g_true_pk_ok = 0;   /* tentatively declared above fetch_scalar */
static int true_pubkey_fill(const uint8_t scalar[32]) {
    secp256k1_keypair k1, k2; secp256k1_xonly_pubkey a, b; uint8_t sa[32], sb[32]; int ok;
    ok = secp256k1_keypair_create(g_ctx, &k1, scalar) && secp256k1_keypair_xonly_pub(g_ctx, &a, NULL, &k1);
    ctx_reblind();
    ok = ok && secp256k1_keypair_create(g_ctx, &k2, scalar) && secp256k1_keypair_xonly_pub(g_ctx, &b, NULL, &k2);
    secure_wipe(&k1, sizeof(k1)); secure_wipe(&k2, sizeof(k2));
    if (!ok) return 0;
    secp256k1_xonly_pubkey_serialize(g_ctx, sa, &a); secp256k1_xonly_pubkey_serialize(g_ctx, sb, &b);
    if (memcmp(sa, sb, 32) != 0) return 0;
    g_true_pk = a; g_true_pk_ok = 1;
    return 1;
}

/* SIGN_INIT (Nostr, anti-exfil 27 Oct 2026). AE_IN = event id (32) || h (32).
 * SIG_OUT = R0 (33 bytes, compressed) followed by zeros. The scalar is fetched
 * over the SE session here and kept in g_ae (with k0) until AE_FINISH. */
static int do_sign_init(void) {
    uint8_t scalar[32], aux[32]; int rc = -1;
    if (!g_ae_in_valid) return -1;
    if (g_ae.kind != AE_KIND_NONE) return -1;        /* one at a time; the pending one is NOT cleared */
    if (fetch_scalar(scalar) != 0) return -1;
    /* Invariant 2: the nonce comes from BIP-340's own derivation.
     * 19 Oct 2026 (fault hardening): aux_rand = SHA256(K_G0 || msg || fresh
     * pool bytes), so the same message never gives the same nonce twice (one
     * glitched signature next to a good one over the same message is the
     * classic fault attack on deterministic signing). The pool (SE TRNG card
     * challenges, K_SE, clocks) is unpredictable to the ESP32. 27 Oct 2026:
     * ae_schnorr_init appends the host commitment h to this aux, so k0 is also
     * bound to the host's (still hidden) t. */
    {
        static const uint8_t label[] = "favilla-g0-bip340-aux";
        uint8_t fresh[32];
        entropy_mix(label, sizeof(label) - 1); sha256(g_pool, 32, fresh);
        sha256_ctx c; sha256_init(&c);
        sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, g_ae_in, 32); sha256_update(&c, fresh, 32); sha256_final(&c, aux);
        secure_wipe(fresh, 32);
    }
    if (!g_true_pk_ok) {
        /* No PUBKEY yet this life (the ESP32 always sends one at unlock).
         * Cache from this fetch but refuse THIS signature: a key glitched
         * on this very load must not both set the reference and sign. */
        (void)true_pubkey_fill(scalar);
    } else if (ae_schnorr_init(g_ctx, scalar, g_ae_in, aux, g_ae_in + 32, g_ae.k0, g_ae.r0) == 0) {
        memcpy(g_ae.key, scalar, 32);
        memcpy(g_ae.h, g_ae_in + 32, 32);
        memcpy(g_ae.msg, g_ae_in, 32);
        g_ae.t0 = HAL_GetTick();
        g_ae.kind = AE_KIND_SCHNORR;
        memcpy(g_sig_out, g_ae.r0, 33);
        rc = 0;
    } else ae_wipe();
    secure_wipe(scalar, 32); secure_wipe(aux, 32);
    return rc;
}

/* v14: AE_FINISH's release check for a vault signature (VSIGN_INIT,
 * vpub_glue.inc): it verifies against the key that made it, kept with the
 * pending operation in g_ae.pub33[0..31]. 1 = release. */
static int ae_vault_verify(const uint8_t sig[64]) {
    secp256k1_xonly_pubkey vp;
    return secp256k1_xonly_pubkey_parse(g_ctx, &vp, g_ae.pub33) &&
           secp256k1_schnorrsig_verify(g_ctx, sig, g_ae.msg, 32, &vp);
}

/* AE_FINISH: AE_T = t. Ends the pending operation whatever happens (success,
 * wrong t, no t, expired). Refused with no INIT pending.
 *   Nostr:   SIG_OUT = sig64, verified against the TRUE x-only pubkey cached
 *            once per life (19 Oct 2026 fault check) before release.
 *   Bitcoin: BTC_OUT "BSIG" v3: 5 rc (0 | 0xD3 sign/verify | 0xD4 DER | 0xD7
 *            nothing pending / expired | 0xD8 t does not open h | 0xE2 no t)
 *            6 kind  7 der_len  8..40 pub33  41..112 DER  113..144 sighash
 *            152..184 R0 echo  150..151 ms
 *   Message: BTC_OUT "MSIG" v2: 5 rc (as above)  8..40 pub33  41..105 sig65
 *            106..137 digest  152..184 R0 echo  150..151 ms
 * The Bitcoin kinds always return 0 (the diagnostic IS the result, as every
 * BTC_OUT command does); the Nostr kind fails closed as plain ERROR. */
static int do_ae_finish(void) {
    uint8_t kind = g_ae.kind, h2[32]; int rc = -1, code = 0; uint32_t t0 = HAL_GetTick();
    if (kind == AE_KIND_ECDSA || kind == AE_KIND_ECDSA_RC) {
        memset(g_btc_out, 0, BTC_OUT_LEN);
        if (kind == AE_KIND_ECDSA) { g_btc_out[0]='B'; g_btc_out[1]='S'; g_btc_out[2]='I'; g_btc_out[3]='G'; g_btc_out[4]=BTCSIGN_VER; g_btc_out[6] = g_ae.btc_kind; }
        else                       { g_btc_out[0]='M'; g_btc_out[1]='S'; g_btc_out[2]='I'; g_btc_out[3]='G'; g_btc_out[4]=MSGSIGN_VER_AE; }
    }
    if (kind == AE_KIND_NONE || ae_expired()) { code = 0xD7; goto out; }
    if (!g_ae_t_valid) { code = 0xE2; goto out; }
    ae_host_commit(kind, g_ae_t, h2);
    if (memcmp(h2, g_ae.h, 32) != 0) { code = 0xD8; goto out; }   /* t does not open the commitment the nonce was bound to */
    switch (kind) {
    case AE_KIND_SCHNORR: {
        uint8_t sig[64];
        if (ae_schnorr_finish(g_ctx, g_ae.key, g_ae.msg, g_ae.k0, g_ae.r0, g_ae_t, sig) == 0 &&
            (g_ae.vault ? ae_vault_verify(sig)      /* v14: a vault signature verifies against k_pub */
                        : (g_true_pk_ok && secp256k1_schnorrsig_verify(g_ctx, sig, g_ae.msg, 32, &g_true_pk)))) {
            memcpy(g_sig_out, sig, 64); rc = 0;
        }
        secure_wipe(sig, 64);
        break; }
    case AE_KIND_ECDSA: {
        secp256k1_ecdsa_signature sig; uint8_t dl = 0;
        if (ae_ecdsa_finish(g_ctx, kind, g_ae.key, g_ae.msg, g_ae.k0, g_ae.r0, g_ae_t, &sig, NULL) != 0) { code = 0xD3; break; }
        int r = btc_sign_release(g_ctx, g_ae.key, g_ae.msg, g_ae.pub33, &sig, g_btc_out + 41, &dl);
        secure_wipe(&sig, sizeof(sig));
        if (r != 0) { memset(g_btc_out + 41, 0, 72); code = (uint8_t)(0xD0 + (uint8_t)(-r)); break; }
        g_btc_out[7] = dl;
        memcpy(g_btc_out + 8, g_ae.pub33, 33); memcpy(g_btc_out + 113, g_ae.msg, 32); memcpy(g_btc_out + 152, g_ae.r0, 33);
        break; }
    case AE_KIND_ECDSA_RC: {
        secp256k1_ecdsa_recoverable_signature rs;
        if (ae_ecdsa_finish(g_ctx, kind, g_ae.key, g_ae.msg, g_ae.k0, g_ae.r0, g_ae_t, NULL, &rs) != 0) { code = 0xD3; break; }
        int r = btc_msg_release(g_ctx, g_ae.msg, g_ae.pub33, &rs, g_btc_out + 41);
        secure_wipe(&rs, sizeof(rs));
        if (r != 0) { memset(g_btc_out + 41, 0, 65); code = (uint8_t)(0xD0 + (uint8_t)(-r)); break; }
        memcpy(g_btc_out + 8, g_ae.pub33, 33); memcpy(g_btc_out + 106, g_ae.msg, 32); memcpy(g_btc_out + 152, g_ae.r0, 33);
        break; }
    default: code = 0xD7; break;
    }
out:
    ae_wipe();                                   /* FINISH always ends the pending operation */
    if (kind == AE_KIND_ECDSA || kind == AE_KIND_ECDSA_RC) {
        g_btc_out[5] = code;
        put16(g_btc_out + 150, HAL_GetTick() - t0);
        return 0;                                /* diag is the result */
    }
    (void)code;
    return rc;
}

static int do_pubkey(void) {
    uint8_t scalar[32]; int rc = -1;
    if (fetch_scalar(scalar) != 0) return -1;
    secp256k1_keypair kp; secp256k1_xonly_pubkey pk;
    if (secp256k1_keypair_create(g_ctx, &kp, scalar) &&
        secp256k1_keypair_xonly_pub(g_ctx, &pk, NULL, &kp) &&
        secp256k1_xonly_pubkey_serialize(g_ctx, g_sig_out, &pk)) rc = 0;
    if (rc == 0 && !g_true_pk_ok) (void)true_pubkey_fill(scalar);   /* 19 Oct 2026: reference for sign checks */
    secure_wipe(&kp, sizeof(kp)); secure_wipe(scalar, 32);
    return rc;
}

static int do_ecdh(void) {
    uint8_t scalar[32], comp[33]; int rc = -1;
    if (!g_hash_in_valid) return -1;                 /* HASH_IN carries the peer x */
    if (fetch_scalar(scalar) != 0) return -1;
    comp[0] = 0x02; memcpy(comp + 1, g_hash_in, 32); /* lift as even-y, per NIP-04/44 */
    secp256k1_pubkey peer;
    if (secp256k1_ec_pubkey_parse(g_ctx, &peer, comp, 33) &&     /* rejects off-curve x */
        secp256k1_ecdh(g_ctx, g_sig_out, &peer, scalar, ecdh_x_only, NULL)) rc = 0;
    secure_wipe(scalar, 32);
    return rc;
}

static int do_cachekey(void) {
    uint8_t scalar[32];
    if (fetch_scalar(scalar) != 0) return -1;
    static const uint8_t salt[] = "favilla-dm-cache", info[] = "favilla-dm-cache-v2";
    hkdf_sha256_32(salt, sizeof(salt) - 1, scalar, 32, info, sizeof(info) - 1, g_sig_out);
    secure_wipe(scalar, 32);
    return 0;
}

static int do_provision(void) {
    if (!g_hash_in_valid || !g_keys_valid) return -1;
    kg0_seal(g_hash_in, g_sig_out);                  /* 32 bytes of CT on SIG_OUT */
    /* No RAM copy kept (step 4): the sealed blob goes to the SE and every later
     * read comes back through the session. The plaintext scalar dies with
     * g_hash_in in finish(). */
    return 0;
}

static int do_setkeys(void) {
    if (!g_keys_in_valid) return -1;
    /* 14 Oct 2026 (pentest prep, finding N4): SETKEYS is refused while a key
     * record is live. Otherwise any code on the ESP32 could overwrite K_SE /
     * K_G0 / S with bytes of its choosing - the same orphaned-recovery-object
     * brick the WIPEKEYS gate exists to prevent, plus a scalar and seed whose
     * inner layer is now under a K_G0 nobody holds. Keys change only through
     * WIPEKEYS (which runs the gate) followed by a fresh SETKEYS. */
    if (g_keys_valid) return -1;
    /* v21 (22 Nov 2026, audit #53): SETKEYS only before any door is committed.
     * Onboarding always runs in a door-UNSET life (a KEY with no wallet boots
     * offline and commits no door). In a committed life (a NOSTR life with its
     * radios up) WIPEALL + WIPEKEYS + SETKEYS used to reopen the seal window,
     * so SEEDSEAL + SEEDSTORE (and PKMASTER) could take a seed of the caller's
     * choosing. Refusing here keeps the window closed for the whole life. */
    if (g_door != DOOR_UNSET) return -1;
    /* v22 (23 Nov 2026, audit #60): and never in the life that wiped the keys.
     * With the door UNSET (a boot whose door commit failed) the swap chain was
     * WIPEALL + WIPEKEYS + SETKEYS + onboard; it now needs a power cycle in the
     * middle, which only the owner can do. A first-ever onboarding has no wipe. */
    if (g_wiped_life) return -1;
    /* v5.1: no keys = no wallet. A seed page left behind (an upgrade from a
     * pre-v5.1 key page, or a torn wipe) belongs to no one; clear it so this
     * onboarding's SEEDSEAL is not refused. */
    if (ss_present() && !ss_erase()) return -1;
    /* STEP 5: persist BEFORE acking. ks_store erases, writes, reads back and
     * verifies the digest + the exact key bytes; it returns 1 only if the page
     * is durably correct. If it fails we do NOT set the RAM copy and do NOT
     * ack — the ESP32 then refuses to rely on the SE auth object, so a G0 that
     * could not store the keys never leaves the SE holding an unusable auth key. */
    {   uint8_t g = g_keys_in[KSE_LEN + KG0_LEN + KMODE_LEN];   /* v5.1 generation */
        if (g < 1 || g > SE_GEN_MAX) return -1;
        if (!ks_store(g_keys_in, g_keys_in + KSE_LEN, g_keys_in + KSE_LEN + KG0_LEN, g)) return -1;
        gen_set(g); }
    memcpy(g_kse, g_keys_in, KSE_LEN);
    memcpy(g_kg0, g_keys_in + KSE_LEN, KG0_LEN);
    memcpy(g_kmode, g_keys_in + KSE_LEN + KG0_LEN, KMODE_LEN);
    g_keys_valid = 1; g_recover_gone = 0;   /* a new identity has its own recovery object */
    g_pk_scratch_own = 0; g_pk_dirty = 0; g_pk_master_done = 0;   /* restorable passkeys: new generation, new window */
    uv_clear();                                                   /* user verification: new keys, new PIN */
    g_true_pk_ok = 0;                        /* 19 Oct 2026: new identity, new cached pubkey */
    /* v5.1: the ESP32 deleted and recreated SE_OBJ_PCR_UNLOCK (locked, with
     * this chip's extend right) inside the user's daily PIN session just
     * before sending these keys (se_provision_g0_identity), so whatever state
     * Door 1 is in now was set under that PIN in this life. */
    g_door1_locked = 1;
    g_seal_window = 1;   /* v5.1: this onboarding may seal + store one seed */
    entropy_mix(NULL, 0);
    /* Ack = SHA256(K_SE || K_G0 || S || gen) over all KEYS_LEN (81) bytes. We reach
     * here only if flash verified, so the ack certifies durable storage. */
    sha256(g_keys_in, KEYS_LEN, g_sig_out);
    return 0;
}

static void wipe_transient(void) {
    secure_wipe(g_relay_out, sizeof(g_relay_out)); g_relay_out_len = 0;
    secure_wipe(g_relay_in, sizeof(g_relay_in)); g_relay_in_len = 0; g_relay_in_ready = 0;
    secure_wipe(g_hash_in, sizeof(g_hash_in)); g_hash_in_valid = 0;
    secure_wipe(g_keys_in, sizeof(g_keys_in)); g_keys_in_valid = 0;
    secure_wipe(g_seed_in, sizeof(g_seed_in)); g_seed_in_valid = 0;   /* v3 */
    secure_wipe(g_btc_in, sizeof(g_btc_in));   g_btc_in_valid = 0;    /* v3 */
    secure_wipe(g_ent_in, sizeof(g_ent_in));   g_ent_in_valid = 0;    /* v4 */
    secure_wipe(g_pass_in, sizeof(g_pass_in)); g_pass_in_valid = 0;   /* v4: staging only; g_pass lives for the power-on life */
    secure_wipe(g_store_in, sizeof(g_store_in)); g_store_in_valid = 0; /* v5.1 */
    secure_wipe(g_ae_in, sizeof(g_ae_in)); g_ae_in_valid = 0;         /* anti-exfil */
    secure_wipe(g_ae_t, sizeof(g_ae_t));   g_ae_t_valid = 0;
    secure_wipe(g_pk_in, sizeof(g_pk_in)); g_pk_in_valid = 0;         /* restorable passkeys: single-use */
    secure_wipe(g_pkm_in, sizeof(g_pkm_in)); g_pkm_valid = 0;          /* v19: the ESP32 writes the master's inner layer before every op */
    secure_wipe(g_vlt_in, sizeof(g_vlt_in)); g_vlt_in_valid = 0;      /* vault records */
    secure_wipe(g_vlt_out, sizeof(g_vlt_out));                        /* an opened record never outlives a RESET */
    ae_wipe();                                                        /* CMD_RESET forgets a pending INIT (k0 and the key go with it) */
    secure_wipe(g_sig_out, sizeof(g_sig_out));
    secure_wipe(g_btc_out, sizeof(g_btc_out));
    em_glue_wipe_transient();                                         /* Emberwill: stage, inputs, ceremony */
}
static void wipe_keys(void) {
    secure_wipe(g_kse, sizeof(g_kse)); secure_wipe(g_kg0, sizeof(g_kg0));
    secure_wipe(g_kmode, sizeof(g_kmode)); g_keys_valid = 0; g_recover_gone = 0;
    secure_wipe(g_pass, sizeof(g_pass)); g_pass_len = 0; g_pass_valid = 0;   /* v4: a wipe forgets the passphrase too */
    uv_clear();   /* user verification ref (31 Oct 2026) */
    ks_erase();   /* STEP 5: a wallet wipe must not leave keys in flash */
    gen_set(0xFF);
    ss_erase();   /* v5.1: nor the seed blob (useless without the SE objects, but a wipe is a wipe) */
    secure_wipe(g_pend_ihash, 32); g_pend_valid = 0;
    g_door1_locked = 0; g_seal_window = 0;
    secure_wipe(&g_true_pk, sizeof(g_true_pk)); g_true_pk_ok = 0;   /* 19 Oct 2026 */
    secure_wipe(g_pkm_in, sizeof(g_pkm_in)); g_pkm_valid = 0;          /* v19 */
    ae_wipe();                                                        /* anti-exfil: no pending signature outlives the keys */
}

/* ---------------------------------------------------------------------------
 * Boot self-test (step 1), unchanged in substance
 * ------------------------------------------------------------------------- */
static int run_selftest(void) {
    uint8_t npass = 0, ntotal = 0, flags = 0; uint32_t t_sign = 0, t_verify = 0, t_ecdh = 0;
    for (size_t i = 0; i < BIP340_NVECS; i++) {
        const bip340_vec_t *v = &BIP340_VECS[i];
        if (v->has_sk) { ntotal++; secp256k1_keypair kp; uint8_t sig[64]; uint32_t t0 = HAL_GetTick();
            int ok = secp256k1_keypair_create(g_ctx, &kp, v->sk) && secp256k1_schnorrsig_sign32(g_ctx, sig, v->msg, &kp, v->aux);
            t_sign += HAL_GetTick() - t0; if (ok && !memcmp(sig, v->sig, 64)) npass++; else flags |= 0x01; secure_wipe(&kp, sizeof(kp)); }
        ntotal++; { secp256k1_xonly_pubkey pk; int parsed = secp256k1_xonly_pubkey_parse(g_ctx, &pk, v->pk); uint32_t t0 = HAL_GetTick();
            int ok = parsed && secp256k1_schnorrsig_verify(g_ctx, v->sig, v->msg, 32, &pk);
            t_verify += HAL_GetTick() - t0; if ((ok ? 1 : 0) == v->expect_ok) npass++; else flags |= 0x02; }
    }
    { ntotal++; static const uint8_t a[32] = { [31] = 0x03 };
      static const uint8_t b[32] = { 0xB7,0xE1,0x51,0x62,0x8A,0xED,0x2A,0x6A,0xBF,0x71,0x58,0x80,0x9C,0xF4,0xF3,0xC7,0x62,0xE7,0x16,0x0F,0x38,0xB4,0xDA,0x56,0xA7,0x84,0xD9,0x04,0x51,0x90,0xCF,0xEF };
      secp256k1_pubkey A, B; uint8_t s1[32], s2[32]; uint32_t t0 = HAL_GetTick();
      int ok = secp256k1_ec_pubkey_create(g_ctx, &A, a) && secp256k1_ec_pubkey_create(g_ctx, &B, b) &&
               secp256k1_ecdh(g_ctx, s1, &B, a, ecdh_x_only, NULL) && secp256k1_ecdh(g_ctx, s2, &A, b, ecdh_x_only, NULL);
      t_ecdh += HAL_GetTick() - t0; if (ok && !memcmp(s1, s2, 32)) npass++; else flags |= 0x04; }
    /* v8 (27 Oct 2026): anti-exfil KATs through the real INIT / FINISH cores
     * with a fixed t. Same inputs must give the same R0 and the same final
     * signature as the host run that generated include/antiexfil_vectors.h,
     * which pins the tweak derivation (the one place a bug would live). Two
     * BIP-340 and two ECDSA vectors: ~0.4 s each on the M0+, so the boot
     * self-test grows from ~4.8 s to ~6.4 s; the ESP32's boot wait is 12 s. */
#ifdef BENCH_LEAKY_NONCE
    /* BENCH ONLY: the leaky nonce fails these four vectors by construction,
     * and a failed self-test makes this chip refuse every command (seen on
     * silicon 27 Oct 2026: 20/24, flags 0x18, boot status ERROR). Skip them
     * here so the dishonest signatures reach the ESP32 and ITS check is what
     * is being tested. A ship build never has this flag. */
    if (0)
#endif
    for (size_t i = 0; i < AE_SCHNORR_NVECS; i++) {
        const ae_schnorr_vec_t *v = &AE_SCHNORR_VECS[i]; uint8_t k0[32], r0[33], sig[64]; ntotal++;
        int ok = ae_schnorr_init(g_ctx, v->sk, v->msg, v->aux, v->h, k0, r0) == 0 && !memcmp(r0, v->r0, 33) &&
                 ae_schnorr_finish(g_ctx, v->sk, v->msg, k0, r0, v->t, sig) == 0 && !memcmp(sig, v->sig, 64);
        if (ok) npass++; else flags |= 0x08;
        secure_wipe(k0, 32); secure_wipe(sig, 64);
    }
#ifdef BENCH_LEAKY_NONCE
    if (0)
#endif
    for (size_t i = 0; i < AE_ECDSA_NVECS; i++) {
        const ae_ecdsa_vec_t *v = &AE_ECDSA_VECS[i]; uint8_t k0[32], r0[33], c64[64]; secp256k1_ecdsa_signature sg; ntotal++;
        int ok = ae_ecdsa_init(g_ctx, v->key, v->msg, v->h, k0, r0) == 0 && !memcmp(r0, v->r0, 33) &&
                 ae_ecdsa_finish(g_ctx, AE_KIND_ECDSA, v->key, v->msg, k0, r0, v->t, &sg, NULL) == 0 &&
                 secp256k1_ecdsa_signature_serialize_compact(g_ctx, c64, &sg) && !memcmp(c64, v->sig, 64);
        if (ok) npass++; else flags |= 0x10;
        secure_wipe(k0, 32); secure_wipe(&sg, sizeof(sg));
    }
    memset(g_selftest, 0, sizeof(g_selftest));
    g_selftest[0]='G'; g_selftest[1]='0'; g_selftest[2]='S'; g_selftest[3]='T'; g_selftest[4]=SELFTEST_VER;
    g_selftest[5]=npass; g_selftest[6]=ntotal; g_selftest[7]=flags;
    put16(g_selftest+8, t_sign); put16(g_selftest+10, t_verify); put16(g_selftest+12, t_ecdh);
    return (npass == ntotal && flags == 0) ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * MPU (16 Sep 2026): no-execute everywhere except the code in flash.
 *
 * The G0's only attacker-facing input is the I2C relay from an ESP32 that may
 * be compromised. Its parsers (lib/scp03 + the MODE_PCR TLV walk) are fuzzed
 * clean (tests/run_fuzz_scp03.sh), but a Cortex-M0+ has no stack canaries, so
 * the MPU is the backstop: if a memory bug is ever found, it faults instead of
 * running attacker code. Regions (higher number wins on overlap):
 *   0  flash    0x08000000 128 KB  RO  execute      the firmware
 *   1  data pages 0x0801D800 10 KB RW  NO execute   v5.1 seed store + K_SE/K_G0/S; 28 Oct 2026 + Emberwill plan/state (16 KB region, 3 low subregions off)
 *   2  SRAM     0x20000000 128 KB  RW  NO execute
 *   3  SRAM     0x20020000  16 KB  RW  NO execute   (144 KB is not a power of two)
 *   4  periph   0x40000000 512 MB  RW  NO execute   device memory
 * Background: the ARM default map (MPU_PRIVILEGED_DEFAULT) for anything not
 * listed — flash alias at 0x00000000, system memory, option bytes. The PPB
 * (SCB/NVIC/SysTick) is always accessible on ARMv6-M regardless of MPU.
 * Flash programming goes through the FLASH peripheral registers, not through
 * stores to the flash address, so RO flash does not break key_store.c.
 * A fault lands in HardFault_Handler (startup default: infinite loop) — the
 * chip stops answering I2C, the ESP32 sees "G0 not responding" and fails
 * closed; a battery pull restores it. Nothing secret is reachable from a
 * halted core.
 * ------------------------------------------------------------------------- */
static uint8_t g_mpu_srd = 0x00;   /* subregion-disable mask for the next mpu_region() call */
static void mpu_region(uint8_t num, uint32_t base, uint8_t size, uint8_t ap, uint8_t xn,
                       uint8_t c, uint8_t b, uint8_t sh) {
    MPU_Region_InitTypeDef r = {0};
    r.Enable = MPU_REGION_ENABLE; r.Number = num; r.BaseAddress = base; r.Size = size;
    r.SubRegionDisable = g_mpu_srd; g_mpu_srd = 0x00; r.TypeExtField = MPU_TEX_LEVEL0;
    r.AccessPermission = ap; r.DisableExec = xn;
    r.IsShareable = sh; r.IsCacheable = c; r.IsBufferable = b;
    HAL_MPU_ConfigRegion(&r);
}
/* RAM scrub at boot (17 Sep 2026). Startup zeroes .bss only; the stack and
 * heap region keeps whatever the previous life left there. Normally nothing
 * secret survives — every fetch wipes its buffers before returning — but a
 * brownout in the ~800 ms the seed is in RAM skips that wipe, and SRAM
 * retains through a short rail dip. So zero everything between the end of
 * .bss and the current stack frame before any command runs: ~135 KB at
 * 64 MHz, about a millisecond. Runs from main() with the MSP near the top of
 * RAM, so the only live stack is main()'s own frame, protected by the margin. */
extern uint32_t _ebss;
static void ram_scrub_at_boot(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_ebss;
    uint32_t sp = __get_MSP();
    volatile uint32_t *top = (volatile uint32_t *)((sp - 512u) & ~3u);   /* leave main()'s frame + margin */
    while (p < top) *p++ = 0;
}

static void mpu_init(void) {
    /* 16 Sep 2026 bench: the first MPU build locked up — vectors are fetched
     * from 0x00000000 (the flash alias) unless VTOR says otherwise, and that
     * address was outside every region, so the first SysTick faulted and the
     * HardFault vector fetch faulted too. Point VTOR at the real flash. */
    SCB->VTOR = FLASH_BASE;
    __DSB(); __ISB();
    HAL_MPU_Disable();
    mpu_region(0, 0x08000000u, MPU_REGION_SIZE_128KB, MPU_REGION_PRIV_RO,    MPU_INSTRUCTION_ACCESS_ENABLE,
               MPU_ACCESS_CACHEABLE, MPU_ACCESS_NOT_BUFFERABLE, MPU_ACCESS_NOT_SHAREABLE);
    /* Key page is READ/WRITE: HAL_FLASH_Program writes flash by STORING to the
     * flash address (the controller intercepts with PG set), so a read-only
     * region here faults the first key-store write — found 17 Sep 2026 on the
     * first re-onboard after the MPU went in (G0 hung mid-SETKEYS, bus down).
     * Still no-execute: the page holds K_SE/K_G0/S, never code. */
    /* 28 Oct 2026 (Emberwill): the data pages now start at 0x0801D800 (plan +
     * two state pages, src/ember_store.h) below the seed and key pages. ARMv6-M
     * regions are power-of-two sized and aligned, so region 1 is 16 KB at
     * 0x0801C000 with its first three 2 KB subregions disabled: 0x0801C000..
     * 0x0801D7FF stays under region 0 (the image may reach 0x0801D7FF), and
     * 0x0801D800..0x0801FFFF (Emberwill, seed, keys) is RW, no-execute. */
    g_mpu_srd = 0x07;
    mpu_region(1, 0x0801C000u, MPU_REGION_SIZE_16KB,  MPU_REGION_FULL_ACCESS, MPU_INSTRUCTION_ACCESS_DISABLE,
               MPU_ACCESS_CACHEABLE, MPU_ACCESS_NOT_BUFFERABLE, MPU_ACCESS_NOT_SHAREABLE);
    mpu_region(2, 0x20000000u, MPU_REGION_SIZE_128KB, MPU_REGION_FULL_ACCESS, MPU_INSTRUCTION_ACCESS_DISABLE,
               MPU_ACCESS_CACHEABLE, MPU_ACCESS_BUFFERABLE, MPU_ACCESS_SHAREABLE);
    mpu_region(3, 0x20020000u, MPU_REGION_SIZE_16KB,  MPU_REGION_FULL_ACCESS, MPU_INSTRUCTION_ACCESS_DISABLE,
               MPU_ACCESS_CACHEABLE, MPU_ACCESS_BUFFERABLE, MPU_ACCESS_SHAREABLE);
    mpu_region(4, 0x40000000u, MPU_REGION_SIZE_512MB, MPU_REGION_FULL_ACCESS, MPU_INSTRUCTION_ACCESS_DISABLE,
               MPU_ACCESS_NOT_CACHEABLE, MPU_ACCESS_BUFFERABLE, MPU_ACCESS_SHAREABLE);
    /* Background = ARM default map for anything not listed above (the flash
     * alias at 0, system memory, option bytes): peripherals are already
     * no-execute there, and SRAM is covered by regions 2/3 which override it.
     * Strictly safer than faulting on an address this table forgot. */
    HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);
}

/* ---------------------------------------------------------------------------
 * Clocks: HSI16 -> PLL -> 64 MHz
 * ------------------------------------------------------------------------- */
static void SystemClock_Config(void) {
    RCC_OscInitTypeDef osc = {0}; RCC_ClkInitTypeDef clk = {0};
    osc.OscillatorType = RCC_OSCILLATORTYPE_HSI; osc.HSIState = RCC_HSI_ON; osc.HSIDiv = RCC_HSI_DIV1;
    osc.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    osc.PLL.PLLState = RCC_PLL_ON; osc.PLL.PLLSource = RCC_PLLSOURCE_HSI; osc.PLL.PLLM = RCC_PLLM_DIV1;
    osc.PLL.PLLN = 8; osc.PLL.PLLP = RCC_PLLP_DIV2; osc.PLL.PLLQ = RCC_PLLQ_DIV2; osc.PLL.PLLR = RCC_PLLR_DIV2;
    HAL_RCC_OscConfig(&osc);
    clk.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1;
    clk.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK; clk.AHBCLKDivider = RCC_SYSCLK_DIV1; clk.APB1CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_2);
}

/* ---------------------------------------------------------------------------
 * I2C1 target, PB6/PB7 AF6. Register-select: first byte of a write selects
 * the register; the remaining bytes are its payload; a read streams it.
 * ------------------------------------------------------------------------- */
static I2C_HandleTypeDef hi2c1;
#include "ember_glue.inc"   /* Emberwill, 28 Oct 2026 */

#define RX_MAX (1 + 2 + 512)                 /* reg + relay header + payload */
static uint8_t s_rx[RX_MAX];
static volatile uint16_t s_rx_n = 0;       /* bytes received in the current write */
static uint8_t s_rx_sink;                  /* overflow bytes land here and are dropped */
static volatile uint8_t s_writing = 0;
static uint8_t s_reg = 0xFF;
static uint8_t s_tx_zero = 0;
static uint16_t s_tx_idx = 0;

void HAL_I2C_MspInit(I2C_HandleTypeDef *h) {
    if (h->Instance != I2C1) return;
    __HAL_RCC_GPIOB_CLK_ENABLE(); __HAL_RCC_I2C1_CLK_ENABLE();
    GPIO_InitTypeDef g = {0}; g.Pin = GPIO_PIN_6 | GPIO_PIN_7; g.Mode = GPIO_MODE_AF_OD;
    g.Pull = GPIO_NOPULL; g.Speed = GPIO_SPEED_FREQ_HIGH; g.Alternate = GPIO_AF6_I2C1;
    HAL_GPIO_Init(GPIOB, &g);
    HAL_NVIC_SetPriority(I2C1_IRQn, 0, 0); HAL_NVIC_EnableIRQ(I2C1_IRQn);
}
static void MX_I2C1_Init(void) {
    hi2c1.Instance = I2C1; hi2c1.Init.Timing = 0x10B17DB5;   /* 64 MHz PCLK, 100 kHz */
    hi2c1.Init.OwnAddress1 = (G0_I2C_ADDR << 1); hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE; hi2c1.Init.OwnAddress2 = 0;
    hi2c1.Init.OwnAddress2Masks = I2C_OA2_NOMASK; hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
    HAL_I2C_Init(&hi2c1);
    HAL_I2CEx_ConfigAnalogFilter(&hi2c1, I2C_ANALOGFILTER_ENABLE);
    HAL_I2CEx_ConfigDigitalFilter(&hi2c1, 0);
}

/* A write has ended (STOP, or a repeated START turning into a read). Commit
 * it: select the register and, if it carried a payload of exactly the right
 * length, accept the payload. Wrong length: dropped (invariant 1). */
static void commit_write(size_t n) {
    if (n < 1) return;
    s_reg = s_rx[0];
    size_t plen = n - 1;
    switch (s_reg) {
    case G0_REG_CMD:
        if (plen != 1) break;
        switch (s_rx[1]) {
        case G0_CMD_PROVISION: case G0_CMD_ECDH: case G0_CMD_PUBKEY:   /* SIGN / BTCSIGN / MSGSIGN retired 27 Oct 2026: not accepted here */
        case G0_CMD_CACHEKEY: case G0_CMD_SETKEYS: case G0_CMD_WIPEKEYS: case G0_CMD_SESSIONTEST:
        case G0_CMD_MODERESET: case G0_CMD_MODEBTC:   /* MODEDEL retired 19 Oct 2026 (see the MODEDEL RETIRED note) */
        case G0_CMD_SEEDSEAL: case G0_CMD_DOORKEYS:
        case G0_CMD_SLEEP: case G0_CMD_DOORNOSTR: case G0_CMD_DOORBTC:
        case G0_CMD_DOORPASSKEY: case G0_CMD_MODEDOOR:   /* generic doors, 30 Oct 2026 */
        case G0_CMD_PKSIGN: case G0_CMD_PKSCRUB: case G0_CMD_PKMASTER:   /* restorable passkeys, 30 Oct 2026 */
        case G0_CMD_UVSET: case G0_CMD_UVCHECK: case G0_CMD_UVCLEAR:     /* user verification, 31 Oct 2026 */
        case G0_CMD_VAULT:                                               /* vault records, 2 Nov 2026 */
        case G0_CMD_VSIGN_INIT:                                          /* v14: vault backup signature */
        case G0_CMD_ENTSEAL: case G0_CMD_WIPEALL: case G0_CMD_SLEEPDEEP:
        case G0_CMD_SEEDSTORE: case G0_CMD_SEEDGET: case G0_CMD_DOOR1LOCK:
        case G0_CMD_SIGN_INIT: case G0_CMD_AE_FINISH: case G0_CMD_BTCSIGN_INIT: case G0_CMD_MSGSIGN_INIT:   /* anti-exfil, 27 Oct 2026 */
        case G0_CMD_EM_HEADER: case G0_CMD_EM_SET: case G0_CMD_EM_CER_INIT: case G0_CMD_EM_CER_FIN:       /* Emberwill, 28 Oct 2026 */
        case G0_CMD_EM_COMMIT: case G0_CMD_EM_PROOF: case G0_CMD_EM_LIFE: case G0_CMD_EM_STATUS:
        case G0_CMD_EM_RELEASE: case G0_CMD_EM_PULSE: case G0_CMD_EM_CLEAR: case G0_CMD_EM_AWAY: case G0_CMD_EM_SAVE:
            if (accepting()) { g_cmd_pending = s_rx[1]; g_status = G0_ST_BUSY; }
            break;
        case G0_CMD_RESET: g_reset_pending = 1; break;
        /* SE power: applied here, in the ISR, with NO status change (see the
         * SEPWR block by the command table). ON is unconditional — it is the
         * safe direction and the ESP32's first word after a wake. */
        case G0_CMD_SEPWR_ON:  se_ena_write(1); break;
        case G0_CMD_SEPWR_OFF: if (accepting()) se_ena_write(0); break;
        default: break;
        }
        break;
    case G0_REG_HASH_IN:
        if (plen == 32 && accepting()) { memcpy(g_hash_in, s_rx + 1, 32); g_hash_in_valid = 1; }
        break;
    case G0_REG_KEYS_IN:
        if (plen == KEYS_LEN && accepting()) { memcpy(g_keys_in, s_rx + 1, KEYS_LEN); g_keys_in_valid = 1; }
        break;
    case G0_REG_SEED_IN:   /* v3, invariant 1: exactly 96 or dropped */
        if (plen == SEED_IN_LEN && accepting()) { memcpy(g_seed_in, s_rx + 1, SEED_IN_LEN); g_seed_in_valid = 1; }
        break;
    case G0_REG_BTC_IN:    /* v3, invariant 1: exactly 416 or dropped */
        if (plen == BTC_REQ_LEN && accepting()) { memcpy(g_btc_in, s_rx + 1, BTC_REQ_LEN); g_btc_in_valid = 1; }
        break;
    case G0_REG_ENT_IN:    /* v4, invariant 1: exactly 96 or dropped */
        if (plen == SEED_IN_LEN && accepting()) { memcpy(g_ent_in, s_rx + 1, SEED_IN_LEN); g_ent_in_valid = 1; }
        break;
    case G0_REG_STORE_IN:  /* v5.1, invariant 1: exactly 97 or dropped */
        if (plen == STORE_IN_LEN && accepting()) { memcpy(g_store_in, s_rx + 1, STORE_IN_LEN); g_store_in_valid = 1; }
        break;
    case G0_REG_PASS_IN:   /* v4, invariant 1: exactly 101 or dropped; content is opaque */
        if (plen == PASS_IN_LEN && accepting()) { memcpy(g_pass_in, s_rx + 1, PASS_IN_LEN); g_pass_in_valid = 1; }
        break;
    case G0_REG_AE_IN:     /* anti-exfil, invariant 1: exactly 64 or dropped; both halves are opaque 32-byte fields */
        if (plen == AE_IN_LEN && accepting()) { memcpy(g_ae_in, s_rx + 1, AE_IN_LEN); g_ae_in_valid = 1; }
        break;
    case G0_REG_PK_IN:     /* restorable passkeys, invariant 1: exactly 97 or dropped */
        if (plen == PK_IN_LEN && accepting()) { memcpy(g_pk_in, s_rx + 1, PK_IN_LEN); g_pk_in_valid = 1; }
        break;
    case G0_REG_PKM_IN:    /* v19: the passkey master's inner layer from the passkey session, exactly 64 or dropped */
        if (plen == PKM_IN_LEN && accepting()) { memcpy(g_pkm_in, s_rx + 1, PKM_IN_LEN); g_pkm_valid = 1; }
        break;
    case G0_REG_VAULT_IN:  /* vault records, invariant 1: exactly 514 or dropped */
        if (plen == VLT_IN_LEN && accepting()) { memcpy(g_vlt_in, s_rx + 1, VLT_IN_LEN); g_vlt_in_valid = 1; }
        break;
    case G0_REG_AE_T:      /* anti-exfil, invariant 1: exactly 32 or dropped */
        if (plen == 32 && accepting()) { memcpy(g_ae_t, s_rx + 1, 32); g_ae_t_valid = 1; }
        break;
    case G0_REG_RELAY_IN:
        /* Only while a frame is out, only a self-consistent length. Accepting it
         * moves STATUS to BUSY right here so the ESP32's next poll cannot re-pump. */
        if (g_status == G0_ST_NEED_RELAY && plen >= 2 + 2 && plen <= 2 + RELAY_MAX &&
            (((size_t)s_rx[1] << 8) | s_rx[2]) == plen - 2) {
            memcpy(g_relay_in, s_rx + 3, plen - 2);
            g_relay_in_len = (uint16_t)(plen - 2);
            g_status = G0_ST_BUSY;
            g_relay_in_ready = 1;
        }
        break;
    default:
        if (accepting()) (void)em_commit_write(s_reg, s_rx + 1, plen);   /* Emberwill registers, exact lengths */
        break;
    }
    if (plen) secure_wipe(s_rx + 1, plen);
}
/* Bytes are received ONE AT A TIME with our own counter. The HAL zeroes
 * XferCount on the STOP-after-short-write path (it files the early STOP as an
 * AF error and clears the handle before ListenCplt), so it cannot be used to
 * recover the length. Per-byte receive is ~90 us of ISR per byte at 100 kHz
 * on a 64 MHz core — irrelevant. */
/* 11bl (issue #47 item 6): clear what the current write has received. */
static void rx_wipe(void) {
    size_t w = (s_rx_n < RX_MAX) ? s_rx_n : RX_MAX;
    if (w) secure_wipe(s_rx, w);
    s_rx_n = 0;
}
static void rx_arm(I2C_HandleTypeDef *h) {
    uint8_t *dst = (s_rx_n < RX_MAX) ? &s_rx[s_rx_n] : &s_rx_sink;
    HAL_I2C_Slave_Seq_Receive_IT(h, dst, 1, I2C_NEXT_FRAME);
}
static void latch_write(void) {
    if (!s_writing) return;
    s_writing = 0;
    /* review 2 Nov 2026: an overlong write is not cut down to a valid one. It
     * selects its register and its payload is dropped (invariant 1). Before,
     * a 516+ byte write to VAULT_IN (plen = RX_MAX - 1) was accepted as 514. */
    size_t n = (s_rx_n <= RX_MAX) ? s_rx_n : 1;
    commit_write(n);
    /* 11bl (issue #47 item 6): wipe every byte this write put in s_rx, not
     * just an accepted payload. A write of the wrong length, or one longer than
     * RX_MAX, left its bytes (SEED_IN, KEYS_IN, PASS_IN...) in SRAM until the
     * next long write. */
    rx_wipe();
}

static void tx_next(I2C_HandleTypeDef *h) {
    const uint8_t *src = &s_tx_zero;
    switch (s_reg) {
    case G0_REG_STATUS:   src = (const uint8_t *)&g_status; break;
    case G0_REG_SIG_OUT:  if (g_status == G0_ST_SIG_READY && s_tx_idx < 64) src = &g_sig_out[s_tx_idx]; break;
    case G0_REG_SELFTEST:
        /* bytes 14..15 are live Stop-mode counters, refreshed on every read so
         * the ESP32 can see them after a sleep without the G0 rebooting.
         * v4 (23 Sep 2026): bytes 16..18 are the one-shot arms and the key
         * state, also live. The ESP32 reads them BEFORE it offers onboarding:
         * an onboard needs the MODERESET one-shot (canonical NEUTRAL), and on
         * a soft reboot it is already spent — without this the flow ran all
         * the way to "G0 mode reset failed" and looped through wipe+onboard
         * forever. Reporting the arm is not a security hole: reading it does
         * not consume it, and an RCE learns nothing it could not learn by
         * sending MODERESET (which WOULD consume it). */
        g_selftest[14] = g_sleep_entries; g_selftest[15] = g_sleep_wakes;
        g_selftest[16] = g_mode_reset_arm;
        g_selftest[17] = g_mode_btc_arm;
        g_selftest[18] = g_keys_valid;
        g_selftest[19] = g_door;                       /* v5: 0 unset / 1 NOSTR / 2 BTC / 3 PASSKEY (v9), live */
        g_selftest[20] = se_ena_level();               /* v6: SE051 ENA as driven right now (1 = SE powered) */
        g_selftest[21] = g_deep_entries;               /* v6: SLEEPDEEP (SE-cut) entries since the G0 last booted */
        g_selftest[22] = g_gen;                        /* v7 (v5.1): SE object generation, 0xFF = no keys */
        g_selftest[23] = 1;                            /* v8: anti-exfil present (every signing path is INIT + FINISH) */
        g_selftest[24] = g_mode_pk_arm;                /* v9 (30 Oct 2026): PASSKEY-door one-shot, live */
        g_selftest[25] = 1;                            /* v9: generic doors present (door 3 = PASSKEY, MODEDOOR); [19] may now read 3 */
        g_selftest[26] = (uint8_t)(FLASH->OPTR & 0xFFu);  /* v19: read protection, 0xAA none, 0xCC level 2, else level 1 (the KEY shows DEV UNIT unless 0xCC) */
        if (s_tx_idx < SELFTEST_LEN) src = &g_selftest[s_tx_idx];
        break;
    case G0_REG_BTC_OUT:  if (g_status == G0_ST_SIG_READY && s_tx_idx < BTC_OUT_LEN) src = &g_btc_out[s_tx_idx]; break;   /* v3 */
    case G0_REG_VAULT_OUT: if (g_status == G0_ST_SIG_READY && s_tx_idx < VLT_OUT_LEN) src = &g_vlt_out[s_tx_idx]; break;   /* vault records */
    case G0_REG_EM_OUT:   if (g_status == G0_ST_SIG_READY && s_tx_idx < 3u + g_em_out_len) src = &g_em_out[s_tx_idx]; break;   /* Emberwill */
    case G0_REG_RELAY_OUT:                    /* header + payload, from byte 0, every read */
        if (g_status == G0_ST_NEED_RELAY && s_tx_idx < 2u + g_relay_out_len) src = &g_relay_out[s_tx_idx];
        break;
    default: break;   /* write-only or unknown registers read as 0x00 (invariant 3) */
    }
    s_tx_idx++;
    HAL_I2C_Slave_Seq_Transmit_IT(h, (uint8_t *)src, 1, I2C_NEXT_FRAME);
}

void HAL_I2C_AddrCallback(I2C_HandleTypeDef *h, uint8_t dir, uint16_t addr) {
    (void)addr;
    g_addr_wake = 1;              /* genuine address match — lets enter_stop_mode() exit its loop */
    if (dir == I2C_DIRECTION_TRANSMIT) {
        if (s_writing) rx_wipe();   /* 11bl: a write cut short by a new START is dropped, and wiped */
        s_writing = 1; s_rx_n = 0;
        rx_arm(h);
    } else {
        latch_write();           /* repeated START after write(reg) */
        s_tx_idx = 0;
        tx_next(h);
    }
}
void HAL_I2C_SlaveTxCpltCallback(I2C_HandleTypeDef *h) { tx_next(h); }
void HAL_I2C_SlaveRxCpltCallback(I2C_HandleTypeDef *h) {
    if (s_rx_n < 0xFFFF) s_rx_n++;
    rx_arm(h);
}
void HAL_I2C_ListenCpltCallback(I2C_HandleTypeDef *h) { latch_write(); HAL_I2C_EnableListen_IT(h); }
void HAL_I2C_ErrorCallback(I2C_HandleTypeDef *h) { HAL_I2C_EnableListen_IT(h); }

void SysTick_Handler(void) { HAL_IncTick(); }
void I2C1_IRQHandler(void) { HAL_I2C_EV_IRQHandler(&hi2c1); HAL_I2C_ER_IRQHandler(&hi2c1); }

/* ---------------------------------------------------------------------------
 * main: run one latched command at a time, from thread context
 * ------------------------------------------------------------------------- */
/* ── Door memory command + gate (24 Sep 2026) ───────────────────────────────
 * DOOR diag on SIG_OUT: "DOOR", [4]=1, [5]= 0 set now / 1 already this door /
 * 0xEE refused: other door already latched, [6]= door now held. Always rc 0
 * so the diagnostic survives finish(). */
static int do_door(uint8_t want) {
    memset(g_sesdiag, 0, 64);
    g_sesdiag[0]='D'; g_sesdiag[1]='O'; g_sesdiag[2]='O'; g_sesdiag[3]='R'; g_sesdiag[4]=1;
    g_seal_window = 0;   /* v5.1: any door commit ends the onboarding seal window */
    if (g_door == DOOR_UNSET)  { g_door = want; g_sesdiag[5] = 0; life_save(); }
    else if (g_door == want)   { g_sesdiag[5] = 1; }
    else                       { g_sesdiag[5] = 0xEE; }
    g_sesdiag[6] = g_door;
    memcpy(g_sig_out, g_sesdiag, 64);
    return 0;
}
/* 1 = this command may run under the door currently held, 0 = refuse. */
static int door_permits(uint8_t cmd) {
    { int e = em_door_permits(cmd); if (e >= 0) return e; }   /* Emberwill, 28 Oct 2026 */
    switch (cmd) {
    case G0_CMD_MODEBTC: case G0_CMD_DOORKEYS: case G0_CMD_BTCSIGN_INIT: case G0_CMD_MSGSIGN_INIT:
        return g_door == DOOR_BTC;                 /* Bitcoin side: only in a declared BTC life */
    case G0_CMD_MODEDOOR:                          /* 30 Oct 2026: mints for the held door; only doors that have a latch value */
        return g_door == DOOR_BTC || g_door == DOOR_PASSKEY;
    case G0_CMD_SIGN_INIT: case G0_CMD_ECDH: case G0_CMD_PUBKEY: case G0_CMD_CACHEKEY:
    case G0_CMD_PROVISION: case G0_CMD_SESSIONTEST:
    case G0_CMD_VSIGN_INIT:                        /* v14: vault backups are signed in the NOSTR life (radio), never PASSKEY */
        /* Nostr side: only in an unset or NOSTR life. 30 Oct 2026: was
         * "!= DOOR_BTC", which would have let them run in a PASSKEY life. */
        return g_door == DOOR_UNSET || g_door == DOOR_NOSTR;
    case G0_CMD_PKSIGN:                            /* restorable passkeys */
    case G0_CMD_VAULT:                             /* vault records */
        /* v19 (13 Nov 2026, one door one PIN): a PASSKEY life only. The NOSTR copy
         * of the master (K_PKN, the "In NOSTR mode" gate) is gone: the master
         * opens with the passkey PIN alone (pk_fetch_master_in). */
        return g_door == DOOR_PASSKEY;
    case G0_CMD_AE_FINISH:                         /* finishes whatever INIT the door already admitted */
        return (g_ae.kind == AE_KIND_SCHNORR) ? (g_door == DOOR_UNSET || g_door == DOOR_NOSTR)
             : (g_ae.kind == AE_KIND_NONE)    ? 1          /* nothing pending: refused in do_ae_finish */
             : (g_door == DOOR_BTC);
    default:
        return 1;                                  /* keys, wipe, modereset/del, seedseal, sleep, door: door-agnostic */
    }
}

/* 19 Oct 2026 (review finding 4): no Nostr work in an UNSET life. The first
 * Nostr key command commits the NOSTR door, so a later DOORBTC in the same
 * power-on life hits first-wins and is refused, whatever the ESP32 did or
 * failed to do with its own door commit. PROVISION is not in the list: it only
 * seals bytes it is given (onboarding) and releases nothing. The onboarding
 * seal window is deliberately left as it was. */
static void door_autocommit(uint8_t cmd) {
    if (g_door != DOOR_UNSET) return;
    switch (cmd) {
    case G0_CMD_SIGN_INIT: case G0_CMD_ECDH: case G0_CMD_PUBKEY:
    case G0_CMD_CACHEKEY: case G0_CMD_SESSIONTEST: case G0_CMD_EM_PULSE:
    case G0_CMD_VSIGN_INIT:                        /* v19: PKSIGN and VAULT are PASSKEY-only, so they never commit NOSTR */
        g_door = DOOR_NOSTR; life_save(); break;
    default: break;
    }
}

static void finish(int rc) {
    /* Inputs are single-use whatever the outcome. */
    secure_wipe(g_hash_in, sizeof(g_hash_in)); g_hash_in_valid = 0;
    secure_wipe(g_keys_in, sizeof(g_keys_in)); g_keys_in_valid = 0;
    secure_wipe(g_seed_in, sizeof(g_seed_in)); g_seed_in_valid = 0;   /* v3: single-use */
    secure_wipe(g_btc_in, sizeof(g_btc_in));   g_btc_in_valid = 0;
    secure_wipe(g_ent_in, sizeof(g_ent_in));   g_ent_in_valid = 0;    /* v4: single-use, like SEED_IN */
    secure_wipe(g_pass_in, sizeof(g_pass_in)); g_pass_in_valid = 0;   /* v4: staging consumed or dropped */
    secure_wipe(g_store_in, sizeof(g_store_in)); g_store_in_valid = 0; /* v5.1 */
    secure_wipe(g_ae_in, sizeof(g_ae_in)); g_ae_in_valid = 0;         /* anti-exfil: single-use, like HASH_IN */
    secure_wipe(g_ae_t, sizeof(g_ae_t));   g_ae_t_valid = 0;
    secure_wipe(g_pk_in, sizeof(g_pk_in)); g_pk_in_valid = 0;         /* restorable passkeys: single-use */
    secure_wipe(g_vlt_in, sizeof(g_vlt_in)); g_vlt_in_valid = 0;      /* vault records: single-use */
    if (rc != 0) { secure_wipe(g_sig_out, sizeof(g_sig_out)); secure_wipe(g_btc_out, sizeof(g_btc_out)); }
    g_status = (rc == 0) ? G0_ST_SIG_READY : G0_ST_ERROR;
}

/* ── Explicit low-power sleep (18 Sep 2026) ────────────────────────────────
 * Entered ONLY on an ESP32-sent G0_CMD_SLEEP, which the ESP32 issues just
 * before its own deep sleep. The G0 drops to Stop mode (~5 uA vs the ~2-4 mA
 * of the WFI idle) and wakes on the next I2C address match — i.e. the moment
 * the ESP32 addresses 0x42 again on the next boot. Because the ESP32 only
 * sends this when it is done talking to the G0, no relay or command is ever
 * in flight across the sleep.
 *
 * SAFETY / WITNESS: Stop mode RETAINS SRAM, so the one-shot arm, the loaded
 * keys and the latch state all survive unchanged. Stop is NOT a reset, so the
 * power-cycle witness is unaffected: a sleep/wake cycle does not re-arm the
 * one-shot. Only a real battery cycle (RCC reset flags) does. SysTick stops in
 * Stop, but nothing that runs mid-command depends on it here; the boot-evidence
 * uptime uses HAL_GetTick, which resumes from where it left off (it undercounts
 * the sleep interval, which only makes a stale one-shot look YOUNGER, never
 * older — it can never forge a fresh power cycle, so it fails safe).
 *
 * On exit the 64 MHz PLL is off (Stop runs the wake on HSI16), so
 * SystemClock_Config() MUST run before any crypto or the next sign is ~4x slow. */
static void MX_I2C1_Init(void);
static void enter_stop_mode(int se_off) {
    /* Route I2C1 from HSI16 so the peripheral can detect an address match
     * while the core is in Stop (PCLK is gated in Stop). Set via the RCCEx
     * struct (the G0 API). We do NOT DeInit/Init the peripheral: that would
     * drop listen mode and tear down the target state. */
    RCC_PeriphCLKInitTypeDef pc = {0};
    pc.PeriphClockSelection = RCC_PERIPHCLK_I2C1;
    pc.I2c1ClockSelection   = RCC_I2C1CLKSOURCE_HSI;
    HAL_RCCEx_PeriphCLKConfig(&pc);
    hi2c1.Instance->CR1 |= I2C_CR1_WUPEN;           /* wake-up from Stop on address match */

    /* The SLEEP command's own write just finished; any STOPF/ADDR left over
     * from it would pop us straight out of Stop. Make sure listen is armed
     * (the ListenCplt path re-arms it after every transfer) and clear stale
     * events, then wait for a REAL address match, re-entering Stop on any
     * spurious wake. This loop is what was missing: Stop exits on ANY enabled
     * interrupt, so a single stray event previously ended the sleep and the
     * G0 fell back to the ~2.5 mA WFI idle. */
    HAL_I2C_EnableListen_IT(&hi2c1);
    __HAL_I2C_CLEAR_FLAG(&hi2c1, I2C_FLAG_STOPF);
    g_addr_wake = 0;
    g_status = G0_ST_IDLE;                           /* answer IDLE up to the last moment */
    if (g_sleep_entries < 255) g_sleep_entries++;
    if (se_off) {
        /* SLEEPDEEP: cut the SE for the whole Stop interval. The ESP32 has
         * already closed its PIN session and will not touch the SE again
         * before its own deep sleep; the next thing on the bus is its boot
         * probe of 0x42, which is also our wake. GPIO output state is
         * retained in Stop, so ENA stays low without any clock running. */
        se_ena_write(0);
        if (g_deep_entries < 255) g_deep_entries++;
    }

    HAL_SuspendTick();
    while (!g_addr_wake) {
        HAL_PWR_EnterSTOPMode(PWR_LOWPOWERREGULATOR_ON, PWR_STOPENTRY_WFI);
        /* woke: if it was not an address match, go straight back down */
    }
    HAL_ResumeTick();
    if (g_sleep_wakes < 255) g_sleep_wakes++;
    /* EVERY Stop exit restores the SE, whether or not this sleep cut it and
     * whatever the bench did with SEPWR_OFF beforehand: an address match
     * means the ESP32 is up and talking, and it will want the SE. This is
     * the fail-safe that makes "SE dark while the ESP32 is awake" impossible
     * to reach by crashing anywhere in goSleep(). */
    se_ena_write(1);

    SystemClock_Config();                            /* restore 64 MHz PLL — mandatory */
    hi2c1.Instance->CR1 &= ~I2C_CR1_WUPEN;
    pc.I2c1ClockSelection = RCC_I2C1CLKSOURCE_PCLK1; /* back to PCLK1 for the 64 MHz timing */
    HAL_RCCEx_PeriphCLKConfig(&pc);
    /* Listen stays armed; the address match that woke us is already being
     * serviced by the ISR (the ESP32's first transaction of the new boot). */
}

int main(void) {
    g_boot_rcc_csr = RCC->CSR;          /* reset-cause flags, before HAL touches anything */
    __HAL_RCC_CLEAR_RESET_FLAGS();      /* so the NEXT boot's flags are its own */
    HAL_Init();
    SystemClock_Config();
    ram_scrub_at_boot();                /* nothing from a previous life survives into this one */
    mpu_init();                         /* no-execute RAM/peripherals/key page from here on */
    se_ena_init();                      /* 13 Oct 2026: take over SE051 ENA (PB2) from the pull-up, driven HIGH (SE on) */

    /* 16 Sep 2026: open the I2C port BEFORE the ~4.8 s self-test and answer
     * BUSY while it runs. Until now the port opened only after the self-test,
     * so an ESP32 booting from the same battery insertion probed 0x42 while
     * the G0 was still computing and logged "NOT FOUND" (fail-closed for the
     * whole boot). BUSY is refused by accepting(), so no register write and no
     * command can land before the crypto is proven; STATUS reads are fine. */
    MX_I2C1_Init();
    g_status = G0_ST_BUSY;
    HAL_I2C_EnableListen_IT(&hi2c1);

    g_ctx = secp256k1_context_preallocated_create(g_ctx_buf, SECP256K1_CONTEXT_NONE);
    int selftest_ok = g_ctx ? run_selftest() : -1;

    /* STEP 5: recover persisted keys. If a valid record is in flash the device
     * is already onboarded — no re-onboard needed after a reboot or reflash of
     * the ESP32. A corrupt/absent record leaves g_keys_valid = 0, so every
     * Nostr op fails closed and the ESP32 routes to onboarding, exactly as an
     * un-onboarded device should. */
    {   uint8_t g = 0xFF;
        if (ks_load(g_kse, g_kg0, g_kmode, &g) && g >= 1 && g <= SE_GEN_MAX) { gen_set(g); g_keys_valid = 1; entropy_mix(NULL, 0);
            uint8_t L = 0;   /* v24: the vault limit set in Settings (none written: no limit) */
            if (ks_lim_load(&L) && VLT_LIM_OK(L)) { g_vlt_limit = L; g_vlt_limit_next = L; g_vlt_open_left = L; g_vlt_tag_left = L; } }
        else { secure_wipe(g_kse, KSE_LEN); secure_wipe(g_kg0, KG0_LEN); secure_wipe(g_kmode, KMODE_LEN); gen_set(0xFF); } }

    /* Two-door: arm the MODE_RESET one-shot. main() runs ONLY on a physical G0
     * reset (battery cycle), so this is the un-forgeable "fresh power cycle"
     * signal. The first MODE_RESET command consumes it; nothing re-arms it
     * short of another physical boot. */
    g_mode_reset_arm = 1;
    g_pass_budget = PASS_BUDGET_PER_LIFE;   /* v4: passphrase tries per physical boot; never re-armed */
    g_mode_btc_arm   = 1;   /* the BTC-door one-shot: physical boot only, see do_modebtc */
    g_mode_pk_arm    = 1;   /* the PASSKEY-door one-shot (30 Oct 2026): same rule, see do_modedoor */
    /* 16 Oct 2026: a life token in the backup domain lets a NON-power reset
     * (NRST, software, watchdog) keep the door and the spent one-shots instead
     * of re-arming. A POWER reset (PWRRSTF: power-on or brown-out) is a fresh
     * life as before, even if the backup domain still holds a token: the 3V3
     * rail decays slowly off the caps when the battery is pulled (G0 and SE
     * in sleep draw microamps), so a token can survive a 2-3 s pull, and the
     * user must not need a 15 s pull to see the door screen. Brown-out is not
     * a usable gap here: the G0's POR (~1.6 V) sits below the ESP32's brown-
     * out detector (~2.4 V), so any sag that resets this chip has already
     * reset the ESP32; only flash-persistent code could exploit it, and that
     * is secure boot's domain (see the g_door comment). */
    life_bkp_enable();
    if (!(g_boot_rcc_csr & RCC_CSR_PWRRSTF) && life_restore()) g_life_resumed = 1;
    else life_save();

    /* I2C was opened above; only the status changes now that the self-test
     * (and the key load) are done. */
    if (selftest_ok == 0) ctx_reblind();   /* 19 Oct 2026 (C2): never sign with an unblinded context */
    if (selftest_ok == 0) em_glue_boot();  /* Emberwill: plan + state from flash, header clock from the newest settled anchor */
    g_status = (selftest_ok == 0) ? G0_ST_IDLE : G0_ST_ERROR;

    for (;;) {
        if (g_reset_pending) {
            g_reset_pending = 0; g_cmd_pending = 0;
            wipe_transient();
            g_status = (selftest_ok == 0) ? G0_ST_IDLE : G0_ST_ERROR;
            continue;
        }
        if (ae_expired()) ae_wipe();        /* anti-exfil: an INIT with no FINISH inside AE_TIMEOUT_MS is forgotten (SysTick wakes this loop every ms) */
        em_glue_tick();                     /* Emberwill: the ceremony's account key is forgotten after EM_CER_TIMEOUT_MS idle */
        uint8_t cmd = g_cmd_pending;
        if (cmd == 0) { __WFI(); continue; }
        g_cmd_pending = 0;
        if (cmd == G0_CMD_SLEEP)     { ae_wipe(); em_glue_abort(); enter_stop_mode(0); continue; }  /* returns on wake; no result to send. Stop entry forgets a pending INIT (and a ceremony). */
        if (cmd == G0_CMD_SLEEPDEEP) { ae_wipe(); em_glue_abort(); enter_stop_mode(1); continue; }  /* same, with the SE cut until the wake */
        secure_wipe(g_sig_out, sizeof(g_sig_out));       /* previous result is gone */
        secure_wipe(g_btc_out, sizeof(g_btc_out));
        if (selftest_ok != 0) { finish(-1); continue; }   /* broken crypto never signs */
        if (!door_permits(cmd)) {
            /* Door memory refusal. MODEBTC answers with its own diag so the
             * ESP32 can show "wrong mode - restart" precisely; everything
             * else fails closed as a plain ERROR (no output). */
            if (cmd == G0_CMD_MODEBTC || cmd == G0_CMD_MODEDOOR) {
                memset(g_sesdiag, 0, 64);
                if (cmd == G0_CMD_MODEBTC) { g_sesdiag[0]='M'; g_sesdiag[1]='B'; g_sesdiag[2]='T'; g_sesdiag[3]='C'; }
                else                       { g_sesdiag[0]='M'; g_sesdiag[1]='D'; g_sesdiag[2]='O'; g_sesdiag[3]='R'; }
                g_sesdiag[4]=3;
                g_sesdiag[5] = 0xED; g_sesdiag[6] = g_door;
                memcpy(g_sig_out, g_sesdiag, 64);
                finish(0);
            } else {
                finish(-3);
            }
            continue;
        }

        if (cmd != G0_CMD_VAULT) secure_wipe(g_vlt_out, sizeof(g_vlt_out));   /* review 2 Nov 2026: an opened record never outlives its command, even if the ESP32's RESET was lost */
        door_autocommit(cmd);   /* 19 Oct 2026, finding 4: see door_autocommit() */
        if (is_key_op(cmd)) sca_jitter();   /* 19 Oct 2026 (C2): see ctx_reblind() */

        int rc;
        if (em_cmd(cmd)) { rc = do_em(cmd); if (is_key_op(cmd) && ++g_blind_ops >= BLIND_EVERY) ctx_reblind(); finish(rc); continue; }   /* Emberwill */
        switch (cmd) {
        case G0_CMD_SIGN_INIT:   rc = do_sign_init();   break;   /* anti-exfil, 27 Oct 2026 */
        case G0_CMD_VSIGN_INIT:  rc = do_vsign_init();  break;   /* v14: vault backup, anti-exfil as SIGN_INIT */
        case G0_CMD_AE_FINISH:   rc = do_ae_finish();   break;
        case G0_CMD_PROVISION: rc = do_provision(); break;
        case G0_CMD_ECDH:      rc = do_ecdh();      break;
        case G0_CMD_PUBKEY:    rc = do_pubkey();    break;
        case G0_CMD_CACHEKEY:  rc = do_cachekey();  break;
        case G0_CMD_SETKEYS:   rc = do_setkeys();   break;
        case G0_CMD_SESSIONTEST: rc = do_sessiontest(); break;
        case G0_CMD_MODERESET:   rc = do_modereset();   break;
        case G0_CMD_MODEBTC:     rc = do_modebtc();     break;
        case G0_CMD_SEEDSEAL:    rc = do_seedseal();    break;   /* v3 */
        case G0_CMD_ENTSEAL:     rc = do_entseal();     break;   /* v4 */
        case G0_CMD_WIPEALL:     rc = do_wipeall();     break;   /* v4.1: door-agnostic, diag is the result */
        case G0_CMD_DOORKEYS:    rc = do_doorkeys();    break;   /* v3 */
        case G0_CMD_BTCSIGN_INIT: rc = do_btcsign_init(); break;   /* v3 + anti-exfil */
        case G0_CMD_WIPEKEYS:
            if (wipekeys_gate() != 0) { finish(-4); continue; }   /* recovery object still on the SE: keys stay */
            wipe_keys(); wipe_transient();
            g_wiped_life = 1; life_save();   /* v22: no SETKEYS until power loss */
            g_status = G0_ST_IDLE; continue;
        case G0_CMD_DOORNOSTR:   rc = do_door(DOOR_NOSTR); break;   /* door memory */
        case G0_CMD_DOORBTC:     rc = do_door(DOOR_BTC);   break;
        case G0_CMD_DOORPASSKEY: rc = do_door(DOOR_PASSKEY); break;   /* generic doors, 30 Oct 2026 */
        case G0_CMD_MODEDOOR:    rc = do_modedoor(g_door); break;     /* the HELD door, never a caller's choice */
        case G0_CMD_SEEDSTORE:   rc = do_seedstore();   break;   /* v5.1 */
        case G0_CMD_SEEDGET:     rc = do_seedget();     break;   /* v5.1 */
        case G0_CMD_DOOR1LOCK:   rc = do_door1lock();   break;   /* v5.1 */
        case G0_CMD_MSGSIGN_INIT: rc = do_msgsign_init(); break;   /* BIP-137 + anti-exfil */
        case G0_CMD_PKSIGN:      rc = do_pksign();      break;   /* restorable passkeys, 30 Oct 2026 */
        case G0_CMD_PKSCRUB:     rc = do_pkscrub();     break;
        case G0_CMD_PKMASTER:    rc = do_pkmaster();    break;   /* onboarding seal window only */
        case G0_CMD_UVSET:       rc = do_uvset();       break;   /* user verification, 31 Oct 2026 */
        case G0_CMD_UVCHECK:     rc = do_uvcheck();     break;
        case G0_CMD_UVCLEAR:     rc = do_uvclear();     break;
        case G0_CMD_VAULT:       rc = do_vault();       break;   /* vault records, 2 Nov 2026 */
        default:               rc = -1;             break;
        }
        if (is_key_op(cmd) && ++g_blind_ops >= BLIND_EVERY) ctx_reblind();   /* 19 Oct 2026 (C2) */
        finish(rc);
    }
}
