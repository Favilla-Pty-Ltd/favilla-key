// =============================================================================
// g0_signer.cpp — ESP32 side of the isolated Nostr signer
// =============================================================================
//
// This file is deliberately dumb. It moves bytes and reads a status byte.
// It contains no key material, no session logic, and it never interprets the
// contents of a relayed frame. Keep it that way: every piece of intelligence
// added here is attack surface on the processor we are trying to keep the key
// away from.
// =============================================================================

#include "g0_signer.h"
#include "se_signer.h"   // favilla::se_transceive_raw
#include <Wire.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <esp_task_wdt.h>   // 24 Sep 2026: WIPEALL + gated WIPEKEYS back to back exceed the 5 s loopTask watchdog
#include <esp_random.h>
#include <esp_heap_caps.h>   // 28 Oct 2026: Emberwill bench buffers in PSRAM     // 27 Oct 2026: esp_fill_random, XOR'd with the SE051 TRNG for the anti-exfil t
#include "secp256k1.h"      // 27 Oct 2026: field / point primitives for the host-side anti-exfil check
#include "antiexfil_host.h" // 27 Oct 2026: ae_host_commit / ae_host_check / schnorr_verify / ecdsa_verify_rs

// Definition of the hook declared in secp256k1.h. Installed by g0_init() so
// every NIP-04/44 ECDH routes to the isolated signer. Left null until then,
// which makes those paths fail closed rather than silently using RAM ECDH.
bool (*g_nostr_ecdh_hook)(const uint8_t peer_xonly32[32], uint8_t shared[32]) = nullptr;

static bool s_present = false;
// 2 Oct 2026: Stop-mode bookkeeping for the idle-dim sleep. s_asleep is set by
// g0_sleep() and cleared by the first successful STATUS read afterwards; every
// register access checks it first (g0_wake_locked) so no command ever sends
// its first byte into a G0 that is still bringing its clocks up.
static volatile bool s_asleep = false;
static volatile uint32_t s_lastActivityMs = 0;
// 11cf (power, 21 Nov 2026): every bus user wakes the G0 first (11k), so with
// the screen dark a battery or accelerometer read woke it out of Stop, and the
// 5 s quiet rule then kept it awake (WFI, about 2.5 to 4 mA) for as long as
// those reads kept coming. s_cmdSeq counts real G0 register accesses;
// s_cmdSeqAtWake is its value when the G0 last woke. If they still match, the
// wake was only a courtesy for another device's frame and the G0 can go
// straight back to Stop (g0_resleep_if_untouched). The Stop time and the wakes
// are counted for the power census.
static uint32_t s_cmdSeq = 0, s_cmdSeqAtWake = 0;   // changed under the bus lock only
static bool     s_wakeQuiet = false;
static uint32_t s_asleepSinceMs = 0, s_stopMsTotal = 0, s_wakes = 0, s_courtesyResleeps = 0;
static inline void g0_mark_asleep() { s_asleep = true; s_asleepSinceMs = millis(); }
static uint8_t s_resetArmed = 0xFF;   // MODERESET one-shot at boot: 1 armed, 0 spent, 0xFF unknown (see g0_reset_armed)
static uint8_t s_door = 0xFF;         // door memory: 0 unset, 1 NOSTR, 2 BTC, 0xFF unknown (see g0_door)
static uint8_t s_seEna = 0xFF;        // SE051 ENA as reported at g0_init() (SELFTEST v6 byte 20); 0xFF unknown
// 27 Oct 2026: anti-exfil. s_aePresent from SELFTEST v8 byte 23; s_aeFault is
// latched by the first host-check mismatch and never cleared short of a reboot.
static uint8_t s_aePresent = 0xFF;
static uint8_t s_pkPresent = 0;   // 30 Oct 2026: SELFTEST v10 = PKSIGN / PKSCRUB
static uint8_t s_uvPresent = 0;   // 31 Oct 2026: SELFTEST v11 = UVSET / UVCHECK / UVCLEAR
static uint8_t s_vaultPresent = 0;   // 2 Nov 2026: SELFTEST v12 = VAULT
static uint8_t s_vpubPresent = 0;    // 2 Nov 2026: SELFTEST v14 = vault backup publishing key
static uint8_t s_v17Present = 0;     // 7 Nov 2026: SELFTEST v17 = VAULT TOTP
static uint8_t s_limPresent = 0;     // 25 Nov 2026: SELFTEST v24 = the owner's vault limit
static uint8_t s_v15Present = 0;     // 3 Nov 2026: SELFTEST v15 = IMPORT + LABEL
static uint8_t s_pk2bPresent = 0;    // 2 Nov 2026: SELFTEST v13 = Vault phase 2b
static uint8_t s_doorPinPresent = 0; // 13 Nov 2026: SELFTEST v19 = one door one PIN
static uint8_t s_rdp = 0;            // SELFTEST v19 byte 26
static uint8_t s_pkm[G0_PKM_LEN]; static bool s_pkmValid = false;   // v19: the master's inner || tag for this window
static bool    s_aeFault = false;
// 11 Nov 2026: whether a self-test register with the G0ST magic has been read
// this boot. Before this, one failed 24-byte read at boot left every
// capability flag at 0 while s_present stayed true, and the KEY then called a
// current G0 "too old" for the vault, the backup and the one-time codes until
// the next reboot (seen on the bench as VBR_NOG0 from the app's backup
// button, 11 Nov). The read is now retried at boot and, if still missing,
// again when a feature first asks (capsRecheck), once every 2 s at most.
static bool     s_stSeen = false;
static uint32_t s_stRetryAt = 0;
static bool g0_read_reg(uint8_t reg, uint8_t* out, size_t len);
static void capsFromSelfTest(const uint8_t* selfTest) {
  s_pkPresent = (selfTest[4] >= G0_SELFTEST_VER_PK) ? 1 : 0;
  s_uvPresent = (selfTest[4] >= G0_SELFTEST_VER_UV) ? 1 : 0;
  s_vaultPresent = (selfTest[4] >= G0_SELFTEST_VER_VAULT) ? 1 : 0;
  s_pk2bPresent = (selfTest[4] >= G0_SELFTEST_VER_PK2B) ? 1 : 0;
  s_vpubPresent = (selfTest[4] >= G0_SELFTEST_VER_VPUB) ? 1 : 0;
  s_v15Present = (selfTest[4] >= G0_SELFTEST_VER_V15) ? 1 : 0;
  s_v17Present = (selfTest[4] >= G0_SELFTEST_VER_V17) ? 1 : 0;
  s_limPresent = (selfTest[4] >= G0_SELFTEST_VER_LIMIT) ? 1 : 0;
  s_doorPinPresent = (selfTest[4] >= G0_SELFTEST_VER_DOORPIN) ? 1 : 0;
  s_rdp = (selfTest[4] >= G0_SELFTEST_VER_DOORPIN) ? selfTest[26] : 0;
  s_stSeen = true;
}
static bool selfTestMagic(const uint8_t* t) { return t[0]=='G' && t[1]=='0' && t[2]=='S' && t[3]=='T'; }
// The identity's x-only pubkey, cached from the last successful PUBKEY so the
// BIP-340 verify after every signature costs no extra G0 round trip. Cleared
// whenever the keys change.
static uint8_t s_pubkey[32]; static bool s_pubkeyOk = false;
bool    g0_antiexfil_faulted() { return s_aeFault; }
uint8_t g0_antiexfil_present() { return s_aePresent; }
static void capsRecheck();
static bool pkm_write();   // v19, below g0_pk_master
bool g0_pk_present() { capsRecheck(); return s_pkPresent == 1; }
static void ae_fault(const char* what) {
  s_aeFault = true;
  Serial.printf("[G0] ANTI-EXFIL FAULT: %s - signature discarded, signing latched off until reboot\n", what);
}
// t = SE051 TRNG XOR esp_fill_random, as the seed path does. Fails closed: no
// SE randomness, no t, no signature (the G0 fetch needs the SE anyway).
static bool ae_draw_t(uint8_t t[32]) {
  uint8_t se[32], esp[32];
  if (!favilla::se_random(se, 32)) { Serial.println("[G0] anti-exfil: SE051 TRNG unavailable - refusing to sign"); return false; }
  esp_fill_random(esp, 32);
  for (int i = 0; i < 32; i++) t[i] = se[i] ^ esp[i];
  mbedtls_platform_zeroize(se, 32); mbedtls_platform_zeroize(esp, 32);
  return true;
}
#ifdef FAVILLA_BENCH_ANTIEXFIL_SKIP
#warning "FAVILLA_BENCH_ANTIEXFIL_SKIP: the anti-exfil host check is DISABLED. Bench builds only."
#endif
static void (*s_lock)()   = nullptr;
static void (*s_unlock)() = nullptr;

static inline void bus_lock()   { if (s_lock)   s_lock();   }
static inline void bus_unlock() { if (s_unlock) s_unlock(); }

void g0_set_bus_lock(void (*lock_fn)(), void (*unlock_fn)()) {
  s_lock = lock_fn; s_unlock = unlock_fn;
}

bool g0_present() { return s_present; }
// 23 Nov 2026 (#60): does anything ACK at the G0's address? Used only to tell
// "the G0 is really not fitted" (no ACK, radios may run without it) from "the
// G0 is there but the boot probe failed" (ACK: the radio guard must not let a
// radio up with its door unset). Caller holds the bus lock.
bool g0_bus_ack() {
  Wire.beginTransmission(G0_I2C_ADDR);
  return Wire.endTransmission() == 0;
}

const char* g0_status_name(uint8_t st) {
  switch (st) {
    case G0_ST_IDLE:       return "IDLE";
    case G0_ST_NEED_RELAY: return "NEED_RELAY";
    case G0_ST_BUSY:       return "BUSY";
    case G0_ST_SIG_READY:  return "SIG_READY";
    case G0_ST_ERROR:      return "ERROR";
    default:               return "UNKNOWN";
  }
}

// -----------------------------------------------------------------------------
// Raw register access. Caller holds the bus lock.
// -----------------------------------------------------------------------------

// Raw STATUS read with no sleep handling — used by the wake path itself.
static bool g0_status_raw(uint8_t* st) {
  Wire.beginTransmission(G0_I2C_ADDR);
  Wire.write(G0_REG_STATUS);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom((int)G0_I2C_ADDR, 1) != 1) return false;
  *st = Wire.read();
  return true;
}

// Called with the bus lock held, before any register access. If the G0 was
// put into Stop mode by g0_sleep(), the first address match on 0x42 wakes it:
// the G0 stretches SCL through its clock bring-up, so that very transaction
// normally completes. Retry a few STATUS pings anyway so a NACK during the
// wake can never surface as a failed sign — the callers above all `break` on
// the first failed status read.
static void g0_wake_locked() {
  if (!s_asleep) return;
  uint8_t st = 0xFF; bool ok = false; int tries = 0;
  for (; tries < 10; tries++) {
    ok = g0_status_raw(&st);
    if (ok) break;
    delay(2);
  }
  s_asleep = false;
  s_stopMsTotal += millis() - s_asleepSinceMs; s_wakes++; s_cmdSeqAtWake = s_cmdSeq;   // 11cf
  s_lastActivityMs = millis();   // 31 Oct 2026: before the log line, so the re-sleep timer never sees a woken G0 as 2 h idle
  if (!s_wakeQuiet || !ok)   // 11cf: a courtesy wake for another device's frame is counted, not logged (it happens about once a second in the dark)
    Serial.printf("[G0] wake from Stop: %s (%d poll%s, status %s)\n",
                  ok ? "ok" : "NO ANSWER", tries + 1, tries ? "s" : "", ok ? g0_status_name(st) : "-");
}

static bool g0_write_reg(uint8_t reg, const uint8_t* data, size_t len) {
  g0_wake_locked();
  s_lastActivityMs = millis(); s_cmdSeq++;   // 11cf
  Wire.beginTransmission(G0_I2C_ADDR);
  Wire.write(reg);
  if (len && data) Wire.write(data, len);
  return Wire.endTransmission() == 0;
}

static bool g0_read_reg(uint8_t reg, uint8_t* out, size_t len) {
  g0_wake_locked();
  s_lastActivityMs = millis(); s_cmdSeq++;   // 11cf
  Wire.beginTransmission(G0_I2C_ADDR);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;      // repeated START
  size_t got = Wire.requestFrom((int)G0_I2C_ADDR, (int)len);
  if (got != len) return false;
  for (size_t i = 0; i < len; i++) out[i] = Wire.read();
  return true;
}

// STATUS is idempotent — reading it never advances the G0 state machine, so it
// is always safe to poll and always safe to re-read after an ESP32 reset.
static bool g0_status(uint8_t* st) {
  return g0_read_reg(G0_REG_STATUS, st, 1);
}

static bool g0_cmd(uint8_t cmd) {
  return g0_write_reg(G0_REG_CMD, &cmd, 1);
}

// -----------------------------------------------------------------------------
// Init
// -----------------------------------------------------------------------------

// fwd decl — defined below
bool g0_ecdh(const uint8_t peer_xonly32[32], uint8_t shared_out[G0_ECDH_LEN]);

bool g0_init() {
  s_present = false;
  s_asleep = false;        // the boot probe below is itself the wake after a deep sleep
  s_resetArmed = 0xFF;
  s_door = 0xFF;
  s_aePresent = 0xFF; s_pubkeyOk = false;

  // The Arduino core's default Wire buffer is 128 bytes (I2C_BUFFER_LENGTH).
  // A relay frame is up to G0_RELAY_MAX bytes plus a 2-byte length header plus
  // the register byte on writes, so grow the buffers first. Verified against
  // core 3.3.3 Wire.cpp: setBufferSize() may be called AFTER Wire.begin() — it
  // frees and reallocates both rx/tx buffers under the bus lock. Must not be
  // called while a transaction is in flight, so it is done under our lock.
  bus_lock();
  Wire.setBufferSize(G0_WIRE_BUF);
  uint8_t st = 0xFF;
  // 16 Sep 2026: the G0 runs its ~4.8 s BIP-340/ECDH self-test BEFORE it
  // opens its I2C port, and this probe lands ~5 s after a shared power-on —
  // a coin toss that came up "NOT FOUND" on most battery cycles. Wait for it:
  // poll for up to G0_BOOT_WAIT_MS, then judge. (The G0 firmware now also
  // opens I2C first and answers BUSY during the self-test, so on a matched
  // pair the first poll succeeds; this loop covers a G0 on older firmware.)
  const uint32_t G0_BOOT_WAIT_MS = 12000;   // 27 Oct 2026: the v8 self-test adds four anti-exfil KATs (~6.4 s total)
  uint32_t t0 = millis(); bool ok = false; int tries = 0;
  for (;;) {
    ok = g0_status(&st); tries++;
    if (ok && st != G0_ST_BUSY) break;          // answered and not still self-testing
    if (millis() - t0 > G0_BOOT_WAIT_MS) break;
    delay(100);
  }
  if (tries > 1) Serial.printf("[G0] boot wait: %s after %lu ms (%d polls)\n",
                               ok ? "answered" : "NO ANSWER", (unsigned long)(millis() - t0), tries);
  // Bring-up diagnostics register (G0 firmware step 1+): the G0 runs its
  // BIP-340/ECDH self-test at boot and reports here. A stub answers zeros,
  // so the magic check keeps this silent until the real firmware is on.
  // 23 Sep 2026: read 20 bytes. SELFTEST v4 appends the live one-shot arms
  // (16 = MODERESET arm, 17 = MODEBTC arm, 18 = keys valid). A v3 G0 answers
  // 0x00 for bytes past its 16-byte register (unknown offsets read as zero),
  // and the version byte keeps us from believing those zeros.
  // 13 Oct 2026: 22 bytes. SELFTEST v6 appends byte 20 = SE051 ENA level and
  // byte 21 = SLEEPDEEP (SE-cut) entries; older G0s answer zeros past their
  // register and the version byte gates the print.
  uint8_t selfTest[27] = {0};   // 27 Oct 2026: v8 appends byte 23 = anti-exfil present; v19: byte 26 = RDP level (an older G0 answers 0 past its end)
  bool haveSelfTest = false;
  for (int a = 0; ok && a < 3 && !haveSelfTest; a++) {   // 11 Nov 2026: three tries, one bad read must not cost the whole boot
    memset(selfTest, 0, sizeof(selfTest));
    haveSelfTest = g0_read_reg(G0_REG_SELFTEST, selfTest, sizeof(selfTest)) && selfTestMagic(selfTest);
    if (!haveSelfTest) delay(50);
  }
  bus_unlock();
  if (ok && !haveSelfTest) Serial.println("[G0] SELF-TEST REGISTER NOT READ (3 tries): capabilities unknown for now, re-read on first use");

  if (!ok) {
    Serial.println("[G0] not responding on I2C");
    return false;
  }
  if (haveSelfTest && selfTest[0]=='G' && selfTest[1]=='0' && selfTest[2]=='S' && selfTest[3]=='T') {
    Serial.printf("[G0] self-test v%u: %u/%u passed, flags=0x%02X, sign %u ms, verify %u ms, ecdh %u ms\n",
                  selfTest[4], selfTest[5], selfTest[6], selfTest[7],
                  (unsigned)(selfTest[8] | (selfTest[9] << 8)),
                  (unsigned)(selfTest[10] | (selfTest[11] << 8)),
                  (unsigned)(selfTest[12] | (selfTest[13] << 8)));
    // Stop-mode diagnostics (18 Sep 2026): entries = times the G0 entered Stop
    // on a SLEEP command; wakes = times a genuine I2C address match brought it
    // back. On a normal boot after a sleep both should be >=1 and equal; if
    // entries > wakes the G0 is still asleep-looping (should not happen at
    // this point, since this read is itself the wake); if both are 0 the SLEEP
    // command never arrived or was refused.
    Serial.printf("[G0] stop-mode: entries %u, wakes %u\n", selfTest[14], selfTest[15]);
    if (selfTest[5] != selfTest[6] || selfTest[7] != 0)
      Serial.println("[G0] SELF-TEST FAILED - secp256k1 on the G0 is not trustworthy");
    if (selfTest[4] >= 6) {
      s_seEna = selfTest[20] ? 1 : 0;
      Serial.printf("[G0] SE power: ENA %s | deep sleeps (SE cut) %u\n", selfTest[20] ? "HIGH (SE on)" : "LOW (SE in DPD!)", selfTest[21]);
    }
    if (selfTest[4] >= 5) {
      s_door = selfTest[19];
      Serial.printf("[G0] door memory: %s\n", s_door==1 ? "NOSTR" : s_door==2 ? "BTC" : "unset (fresh power cycle or first onboard)");
    } else {
      Serial.println("[G0] door memory: not supported by this G0 firmware (pre-v5) - update the G0");
    }
    capsFromSelfTest(selfTest);
    Serial.printf("[G0] passkey door move (2b): %s\n", s_pk2bPresent ? "present" : "absent (self-test < v13): restorable passkeys and records stay off");
    Serial.printf("[G0] vault records (VAULT): %s\n", s_vaultPresent ? "present" : "absent (self-test < v12)");
    Serial.printf("[G0] vault import window and password labels (v15): %s\n", s_v15Present ? "present" : "absent (self-test < v15)");
    Serial.printf("[G0] hedged signing nonces (v18): %s\n", selfTest[4] >= G0_SELFTEST_VER_V18 ? "yes - a signature is never repeated over the same message" : "no (self-test < v18)");
    Serial.printf("[G0] one-time codes computed in the G0 (v17): %s\n", s_v17Present ? "present - the secret never leaves the G0" : "absent (self-test < v17)");
    Serial.printf("[G0] passkeys signed by the G0 itself (v16): %s\n", selfTest[4] >= G0_SELFTEST_VER_V16 ? "yes - the SE051 never sees a site key" : "no (self-test < v16): the SE051 signs");
    Serial.printf("[G0] user verification check (UVCHECK): %s\n", s_uvPresent ? "present" : "absent (self-test < v11)");
    Serial.printf("[G0] restorable passkeys (PKSIGN): %s\n", s_pkPresent ? "present" : "absent (self-test < v10)");
    if (selfTest[4] >= G0_SELFTEST_VER_AE) {
      s_aePresent = selfTest[23] ? 1 : 0;
      Serial.printf("[G0] anti-exfil: %s (self-test v%u)\n", selfTest[23] ? "present - every signature is host-nonce committed" : "ABSENT", selfTest[4]);
    } else {
      s_aePresent = 0;
      Serial.printf("[G0] anti-exfil: ABSENT - G0 self-test v%u is older than v8; this build will not sign with it. Flash the anti-exfil G0.\n", selfTest[4]);
    }
    if (selfTest[4] >= 4) {
      s_resetArmed = selfTest[16] ? 1 : 0;
      Serial.printf("[G0] one-shots: mode-reset %s, mode-btc %s | keys %s\n",
                    selfTest[16] ? "ARMED (fresh power cycle)" : "spent (soft reboot)",
                    selfTest[17] ? "armed" : "spent",
                    selfTest[18] ? "present" : "absent");
    }
  }
  if (st != G0_ST_IDLE) {
    // ANY non-IDLE boot status is stale state from before this boot. The G0
    // does NOT reboot when the ESP32 soft-resets (it stays powered), so it can
    // legitimately still hold SIG_READY from the last command — or ERROR, if
    // that command failed. Clear ALL of them: inheriting unknown state means
    // every later command fails, and a stale in-flight scalar must not persist.
    // ERROR used to be excluded here, which left the G0 wedged for the whole
    // boot (seen on silicon: "boot status ERROR" then every command dead).
    Serial.printf("[G0] boot status %s — clearing\n", g0_status_name(st));
    g0_reset();
    delay(20);                       // let the reset land before the next command
    uint8_t s2 = 0xFF;
    if (g0_status(&s2)) Serial.printf("[G0] status after reset: %s\n", g0_status_name(s2));
    if (s2 != G0_ST_IDLE) {
      Serial.println("[G0] WARNING: still not IDLE after reset — commands may fail this boot");
    }
  }
  s_present = true;

  // Route all identity-key ECDH (NIP-04/44) through the G0 from here on.
  // Ephemeral session/pairing ECDH is unaffected and stays local.
  g_nostr_ecdh_hook = g0_ecdh;

  Serial.println("[G0] isolated Nostr signer present (sign + ecdh)");
  return true;
}

bool g0_reset() {
  bus_lock();
  bool ok = g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

// Fire-and-forget: tell the G0 to enter Stop mode. Sent by the ESP32 only from
// goSleep(), just before esp_deep_sleep_start(). We do NOT wait for a reply —
// the G0 sleeps immediately and there is nothing to read back. On the next boot
// the first I2C address to 0x42 wakes it; g0_init()'s probe is exactly that, so
// no explicit wake step is needed. Safe to call even if the G0 is absent.
bool g0_sleep() {
  if (!s_present) return false;
  if (s_asleep) return true;        // already down; a second write would only wake it
  bus_lock();
  bool ok = g0_cmd(G0_CMD_SLEEP);   // single register write; no relay, no result
  if (ok) g0_mark_asleep();
  delay(10);   // 11k: let the G0 reach Stop before anything else uses the bus (its entry is sub-ms)
  bus_unlock();
  return ok;
}

// 13 Oct 2026: ENA-wired boards. Same shape as g0_sleep() but the G0 drops
// SE051 ENA on its way into Stop. The caller has already closed the PIN
// session and must not touch the SE again; the next boot's probe is the wake
// AND the SE power-on (every Stop exit raises ENA). Fire-and-forget.
bool g0_sleep_deep() {
  if (!s_present) return false;
  bus_lock();
  if (s_asleep) {
    // Already in Stop from the idle dim with the SE still up. The one write
    // below is itself the wake; the G0 then takes SLEEPDEEP as the next
    // command and goes straight back down with ENA low.
    g0_wake_locked();
  }
  bool ok = g0_cmd(G0_CMD_SLEEPDEEP);
  if (ok) g0_mark_asleep();
  bus_unlock();
  Serial.printf("[G0] -> Stop + SE051 ENA low: %s\n", ok ? "sent" : "FAILED (G0 did not ACK)");
  return ok;
}

bool g0_se_power(bool on) {
  if (!s_present) return false;
  bus_lock();
  bool ok = g0_cmd(on ? G0_CMD_SEPWR_ON : G0_CMD_SEPWR_OFF);
  bus_unlock();
  if (ok) s_seEna = on ? 1 : 0;
  Serial.printf("[G0] SE051 ENA -> %s: %s\n", on ? "HIGH" : "LOW", ok ? "ok" : "FAILED");
  return ok;
}

uint8_t g0_se_ena() { return s_seEna; }

// Raw: does address 0x48 (SE051 T=1 default) ACK? Zero-length write.
static bool se_addr_acks() {
  Wire.beginTransmission(0x48);
  return Wire.endTransmission() == 0;
}

bool g0_se_power_on_early(uint32_t* ms) {
  uint32_t t0 = millis();
  bus_lock();
  // 1. Wake the G0 if it is in Stop: the first address match on 0x42 is the
  //    wake, and the G0 raises ENA on every Stop exit. Retry a few pings - the
  //    G0 stretches SCL through its clock bring-up but a NACK is possible.
  uint8_t st = 0xFF; bool g0ok = false; int pings = 0;
  for (; pings < 10 && !g0ok; pings++) { g0ok = g0_status_raw(&st); if (!g0ok) delay(2); }
  // 2. Explicit ON for the G0-awake-but-ENA-low case (bench SEPWR_OFF, or an
  //    ESP32 reset between SLEEPDEEP being sent and the G0 acting on it).
  //    ISR-applied, no status change, harmless when ENA is already high.
  if (g0ok) { uint8_t c = G0_CMD_SEPWR_ON; Wire.beginTransmission(G0_I2C_ADDR); Wire.write(G0_REG_CMD); Wire.write(c); Wire.endTransmission(); }
  // 3. Wait for the SE to come out of DPD and boot: poll its address ACK.
  //    Cold boot / SE already up: first poll succeeds, cost ~0 ms.
  bool seok = false; int polls = 0;
  const uint32_t SE_BOOT_WAIT_MS = 300;
  for (;;) {
    seok = se_addr_acks(); polls++;
    if (seok) break;
    if (millis() - t0 > SE_BOOT_WAIT_MS) break;
    delay(5);
  }
  bus_unlock();
  uint32_t dt = millis() - t0;
  if (ms) *ms = dt;
  Serial.printf("[G0] SE power-on at boot: G0 %s (%d ping%s), SE051 %s after %lu ms (%d poll%s)\n",
                g0ok ? "answered" : "NO ANSWER", pings, pings == 1 ? "" : "s",
                seok ? "ACKs" : "NO ACK", (unsigned long)dt, polls, polls == 1 ? "" : "s");
  return seok;
}

// 16 Oct 2026: SE051 hardware reset over ENA, usable BEFORE g0_init() (the
// boot recovery ladder runs while s_present is still false). Why it exists:
// an ESP32 reset that lands mid T=1 frame leaves the SE051 wedged - it ACKs
// its address but every RESYNCH times out, and after a few of those it stops
// ACKing altogether. Nothing on the bus can clear that state; only a VCC cut
// can. ENA low puts the SE in Deep Power-down (VOUT->VCC cut), ENA high boots
// it clean. Persistent objects are untouched. Returns true when the SE ACKs
// its address again within the boot window.
bool g0_se_power_cycle_early(uint32_t* ms) {
  uint32_t t0 = millis();
  bus_lock();
  uint8_t st = 0xFF; bool g0ok = false;
  for (int i = 0; i < 10 && !g0ok; i++) { g0ok = g0_status_raw(&st); if (!g0ok) delay(2); }
  bool seok = false; int polls = 0;
  if (g0ok) {
    uint8_t off = G0_CMD_SEPWR_OFF, on = G0_CMD_SEPWR_ON;
    Wire.beginTransmission(G0_I2C_ADDR); Wire.write(G0_REG_CMD); Wire.write(off); Wire.endTransmission();
    delay(200);   // let VCC fall: the SE051 needs a real DPD entry, not a glitch
    Wire.beginTransmission(G0_I2C_ADDR); Wire.write(G0_REG_CMD); Wire.write(on); Wire.endTransmission();
    uint32_t t1 = millis();
    for (;;) {
      delay(5);
      seok = se_addr_acks(); polls++;
      if (seok) break;
      if (millis() - t1 > 800) break;
    }
    if (seok) delay(20);   // address ACK comes a little before T=1 is ready
  }
  bus_unlock();
  uint32_t dt = millis() - t0;
  if (ms) *ms = dt;
  Serial.printf("[G0] SE051 ENA power cycle: G0 %s, SE051 %s after %lu ms (%d poll%s)\n",
                g0ok ? "answered" : "NO ANSWER (cannot cycle ENA)", seok ? "ACKs" : "NO ACK", (unsigned long)dt, polls, polls == 1 ? "" : "s");
  return seok;
}

// 2 Oct 2026: idle-dim sleep support. The ESP32 now sends SLEEP whenever the
// screen dims (not only before deep sleep), so the G0 spends the dark hours in
// Stop (~5 uA) instead of WFI idle (~2.5-4 mA). Any command wakes it through
// g0_wake_locked(); these let the main loop see and drive that state.
bool g0_is_asleep() { return s_asleep; }
// 31 Oct 2026: the dim re-sleep. The quiet time is judged UNDER the bus lock,
// so a command another task is running (a passkey sign on the FIDO task)
// holds this off until it is done, and then counts as activity.
bool g0_sleep_if_idle(uint32_t quietMs) {
  if (!s_present || s_asleep) return false;
  bus_lock();
  bool ok = false;
  if (!s_asleep && (uint32_t)(millis() - s_lastActivityMs) >= quietMs) {
    ok = g0_cmd(G0_CMD_SLEEP);
    if (ok) { g0_mark_asleep(); delay(10); }   // 11k: as in g0_sleep
  }
  bus_unlock();
  return ok;
}
uint32_t g0_idle_ms() { return millis() - s_lastActivityMs; }
// 11cf: a quiet wake for another device's bus frame (i2cWakeG0First).
bool g0_wake_quiet() {
  if (!s_present || !s_asleep) return true;
  bus_lock();
  s_wakeQuiet = true; g0_wake_locked(); s_wakeQuiet = false;
  bus_unlock();
  return true;
}
// 11cf: straight back to Stop if nothing has used the G0 since it last woke.
// Judged under the bus lock, so a command that starts in between keeps it up.
bool g0_resleep_if_untouched() {
  if (!s_present || s_asleep || s_cmdSeq != s_cmdSeqAtWake) return false;
  bus_lock();
  bool ok = false;
  if (!s_asleep && s_cmdSeq == s_cmdSeqAtWake) {
    ok = g0_cmd(G0_CMD_SLEEP);
    if (ok) { g0_mark_asleep(); s_courtesyResleeps++; delay(10); }   // 11k: as in g0_sleep
  }
  bus_unlock();
  return ok;
}
// 11cf: for the power census. Stop time includes the current stretch.
uint32_t g0_stop_ms()  { return s_stopMsTotal + (s_asleep ? millis() - s_asleepSinceMs : 0); }
uint32_t g0_wakes()    { return s_wakes; }
uint32_t g0_courtesy_resleeps() { return s_courtesyResleeps; }
bool g0_wake() {
  if (!s_present || !s_asleep) return true;
  bus_lock();
  g0_wake_locked();
  bus_unlock();
  return true;
}

// -----------------------------------------------------------------------------
// The relay pump
// -----------------------------------------------------------------------------
//
// This is the whole of the ESP32's involvement in the G0<->SE conversation:
// read an opaque frame from the G0, hand it to the SE, hand the SE's reply
// back. The bytes are never inspected. If a compromised ESP32 tampers with
// them, the SCP03 CMAC fails inside the G0 and the signature is refused —
// tampering costs the attacker the operation, not the key.
//
// favilla::se_transceive_raw() is provided by se_signer.cpp: it writes an APDU
// to the SE and returns the response verbatim, with no parsing. Declared in
// se_signer.h (namespace favilla) — do NOT redeclare it here at global scope,
// that compiles and then fails to link.

static bool g0_pump_relay() {
  // RELAY_OUT is a single read-stream: every read of the register starts from
  // byte 0 and yields [len_hi][len_lo][payload...]. An I2C target cannot know
  // how many bytes the master intends to clock, so it cannot switch between a
  // "header only" and a "body" reply; the master therefore reads the 2-byte
  // header (and NACKs), then re-reads the register for header+body. The G0
  // must NOT advance any read pointer across reads of this register.
  uint8_t hdr[2];
  if (!g0_read_reg(G0_REG_RELAY_OUT, hdr, 2)) {
#if G0_RELAY_TRACE
    Serial.println("[G0] relay: header read (2B) FAILED");
#endif
    return false;
  }
  size_t flen = ((size_t)hdr[0] << 8) | hdr[1];
#if G0_RELAY_TRACE
  Serial.printf("[G0] relay: hdr %02X %02X -> flen %u\n", hdr[0], hdr[1], (unsigned)flen);
#endif
  if (flen == 0 || flen > G0_RELAY_MAX) {
    Serial.printf("[G0] relay frame length %u out of range\n", (unsigned)flen);
    return false;
  }

  static uint8_t frame[2 + G0_RELAY_MAX];
  if (!g0_read_reg(G0_REG_RELAY_OUT, frame, 2 + flen)) {
#if G0_RELAY_TRACE
    Serial.printf("[G0] relay: body read (%uB) FAILED\n", (unsigned)(2 + flen));
#endif
    return false;
  }
  if (frame[0] != hdr[0] || frame[1] != hdr[1]) {
#if G0_RELAY_TRACE
    Serial.printf("[G0] relay: header changed %02X%02X -> %02X%02X\n", hdr[0], hdr[1], frame[0], frame[1]);
#endif
    Serial.println("[G0] relay frame header changed between reads");
    return false;
  }

  // Straight to the SE. No interpretation.
  static uint8_t resp[G0_RELAY_MAX];
  size_t resp_len = 0;
  if (!favilla::se_transceive_raw(frame + 2, flen, resp, sizeof(resp), &resp_len)) {
    Serial.println("[G0] SE transceive failed during relay");
    return false;
  }
#if G0_RELAY_TRACE
  Serial.printf("[G0] relay C[%u]:", (unsigned)flen);
  for (size_t i = 0; i < flen && i < 40; i++) Serial.printf(" %02X", frame[2 + i]);
  Serial.printf("  R[%u]:", (unsigned)resp_len);
  for (size_t i = 0; i < resp_len && i < 40; i++) Serial.printf(" %02X", resp[i]);
  Serial.println();
#endif
  if (resp_len == 0 || resp_len > G0_RELAY_MAX) return false;

  // And straight back to the G0, length-prefixed.
  static uint8_t out[2 + G0_RELAY_MAX];
  out[0] = (uint8_t)(resp_len >> 8);
  out[1] = (uint8_t)(resp_len & 0xFF);
  memcpy(out + 2, resp, resp_len);
  bool wok = g0_write_reg(G0_REG_RELAY_IN, out, resp_len + 2);
#if G0_RELAY_TRACE
  if (!wok) Serial.println("[G0] RELAY_IN write failed");
#endif
  return wok;
}

// -----------------------------------------------------------------------------
// Signing
// -----------------------------------------------------------------------------

// One INIT or FINISH exchange on the Nostr path: write the input register,
// send the command, pump the relay, read SIG_OUT. Caller holds the bus lock.
static bool g0_ae_exchange(uint8_t reg, const uint8_t* in, size_t inLen, uint8_t cmd, uint8_t out64[64], const char* what) {
  if (!g0_write_reg(reg, in, inLen)) return false;
  if (!g0_cmd(cmd)) return false;
  uint32_t start = millis(); int steps = 0;
  for (;;) {
    if (millis() - start > G0_POLL_TIMEOUT_MS) { Serial.printf("[G0] %s timeout\n", what); return false; }
    uint8_t st;
    if (!g0_status(&st)) return false;
    if (st == G0_ST_NEED_RELAY) {
      if (++steps > G0_MAX_RELAY_STEPS) { Serial.println("[G0] relay step guard tripped"); return false; }
      if (!g0_pump_relay()) return false;
      continue;
    }
    if (st == G0_ST_BUSY) { delay(2); continue; }
    if (st == G0_ST_SIG_READY) return g0_read_reg(G0_REG_SIG_OUT, out64, 64);
    if (st == G0_ST_ERROR) {
      // Most commonly: no daily PIN session. The G0 enforces this against
      // the SE, so it is not something this processor can bypass. On FINISH:
      // t did not open h, nothing pending, or the 10 s window expired.
      Serial.printf("[G0] %s: signer returned ERROR (no session, relay fault, or refused)\n", what);
      return false;
    }
    delay(1);
  }
}

// 27 Oct 2026: anti-exfil. Two round trips, one check, one verify. See
// antiexfil_host.h for the protocol; g0 antiexfil.c for the other half.
bool g0_schnorr_sign(const uint8_t msg32[32], uint8_t sig_out[G0_SIG_LEN]) {
  if (!s_present) {
    Serial.println("[G0] sign denied: signer not present");
    return false;
  }
  if (s_aeFault) { Serial.println("[G0] sign denied: ANTI-EXFIL FAULT latched this boot"); return false; }
  if (s_aePresent != 1) { Serial.println("[G0] sign denied: G0 firmware has no anti-exfil (self-test < v8)"); return false; }
  if (!s_pubkeyOk && !g0_get_pubkey(s_pubkey)) { Serial.println("[G0] sign denied: identity pubkey unavailable for the verify"); return false; }

  uint8_t t[32], ae_in[64], r0[33], out[64];
  if (!ae_draw_t(t)) return false;
  memcpy(ae_in, msg32, 32); ae_host_commit(AE_KIND_SCHNORR, t, ae_in + 32);

  bool ok = false;
  uint32_t tInit = 0, tFin = 0, tChk = 0, tVer = 0, t0 = millis();   // 11d: where a sign's time goes
  bus_lock();                       // held across the ENTIRE exchange
  do {
    // 1. INIT: message + commitment to t -> R0
    if (!g0_ae_exchange(G0_REG_AE_IN, ae_in, 64, G0_CMD_SIGN_INIT, out, "sign init")) break;
    memcpy(r0, out, 33); tInit = millis() - t0; t0 = millis();
    // 2. FINISH: reveal t -> signature
    if (!g0_ae_exchange(G0_REG_AE_T, t, 32, G0_CMD_AE_FINISH, out, "sign finish")) break;
    tFin = millis() - t0; t0 = millis();
    ok = true;
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);    // never leave the G0 mid-operation (RESET also forgets a pending INIT)
  bus_unlock();
  if (!ok) { mbedtls_platform_zeroize(t, 32); mbedtls_platform_zeroize(out, 64); return false; }

  // 3. The check that makes the property real, then the ordinary verify.
#ifdef FAVILLA_BENCH_ANTIEXFIL_SKIP
  Serial.println("[G0] anti-exfil: host check SKIPPED (bench build)");
#else
  if (!ae_host_check(AE_KIND_SCHNORR, r0, t, out)) {
    ae_fault("Nostr: x(R0 + H(R0||t)G) != R");
    mbedtls_platform_zeroize(out, 64); mbedtls_platform_zeroize(t, 32);
    return false;
  }
  tChk = millis() - t0; t0 = millis();
  if (!schnorr_verify(s_pubkey, msg32, out)) {
    ae_fault("Nostr: BIP-340 verify failed against the identity pubkey");
    mbedtls_platform_zeroize(out, 64); mbedtls_platform_zeroize(t, 32);
    return false;
  }
  tVer = millis() - t0;
#endif
  Serial.printf("[G0] sign: G0 init %lu ms, G0 finish %lu ms, host check %lu ms, verify %lu ms (CPU %u MHz)\n",
                (unsigned long)tInit, (unsigned long)tFin, (unsigned long)tChk, (unsigned long)tVer, (unsigned)getCpuFrequencyMhz());
#ifdef FAVILLA_BENCH_ANTIEXFIL_LOG_T
  { char hx[131]; for (int i = 0; i < 32; i++) sprintf(hx + 2*i, "%02x", t[i]); Serial.printf("[SIGNDIAG] ae t=%s\n", hx);
    for (int i = 0; i < 33; i++) sprintf(hx + 2*i, "%02x", r0[i]); Serial.printf("[SIGNDIAG] ae R0=%s\n", hx); }
#endif
  memcpy(sig_out, out, 64);
  mbedtls_platform_zeroize(out, 64); mbedtls_platform_zeroize(t, 32);
  return true;
}

// Phase 3 (2 Nov 2026): a vault backup signature. The same two steps and host
// checks as g0_schnorr_sign; the key is k_pub, read by the G0 from SE_OBJ_VPUB.
bool g0_vault_sign(const uint8_t msg32[32], const uint8_t pub32[32], uint8_t sig_out[64]) {
  if (!s_present || s_vpubPresent != 1) { Serial.println("[G0] vault sign denied: G0 has no VSIGN (self-test < v14)"); return false; }
  if (s_aeFault) { Serial.println("[G0] vault sign denied: ANTI-EXFIL FAULT latched this boot"); return false; }
  uint8_t t[32], ae_in[64], r0[33], out[64];
  if (!ae_draw_t(t)) return false;
  memcpy(ae_in, msg32, 32); ae_host_commit(AE_KIND_SCHNORR, t, ae_in + 32);
  bool ok = false;
  bus_lock();
  do {
    if (!g0_ae_exchange(G0_REG_AE_IN, ae_in, 64, G0_CMD_VSIGN_INIT, out, "vault sign init")) break;
    memcpy(r0, out, 33);
    if (!g0_ae_exchange(G0_REG_AE_T, t, 32, G0_CMD_AE_FINISH, out, "vault sign finish")) break;
    ok = true;
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (!ok) { mbedtls_platform_zeroize(t, 32); mbedtls_platform_zeroize(out, 64); return false; }
  if (!ae_host_check(AE_KIND_SCHNORR, r0, t, out)) {
    ae_fault("Vault: x(R0 + H(R0||t)G) != R");
    mbedtls_platform_zeroize(out, 64); mbedtls_platform_zeroize(t, 32);
    return false;
  }
  // A wrong stored public key is not a G0 fault (no latch): refuse and say so.
  if (!schnorr_verify(pub32, msg32, out)) {
    Serial.println("[G0] vault sign: the signature does not verify against the stored publishing key - not published");
    mbedtls_platform_zeroize(out, 64); mbedtls_platform_zeroize(t, 32);
    return false;
  }
  memcpy(sig_out, out, 64);
  mbedtls_platform_zeroize(out, 64); mbedtls_platform_zeroize(t, 32);
  return true;
}

// Phase 3 curve helpers for vault_backup.cpp (see vault_backup.h).
bool vbh_xonly_pub(const uint8_t k[32], uint8_t x32[32]) {
  uint8_t a = 0; for (int i = 0; i < 32; i++) a |= k[i];
  if (!a || !sc_b32_lt_n(k)) return false;
  sc s; sc_from_b32(&s, k);
  JPt Pj; pt_mul_base(&Pj, &s);
  Pt P; jpt_to_affine(&P, &Pj); fe_norm(&P.x);
  fe_to_b32(x32, &P.x);
  mbedtls_platform_zeroize(&s, sizeof s);
  return true;
}
bool vbh_schnorr_verify(const uint8_t pub32[32], const uint8_t msg32[32], const uint8_t sig64[64]) { return schnorr_verify(pub32, msg32, sig64); }

bool g0_session_test() {
  if (!s_present) { Serial.println("[G0] session test: signer not present"); return false; }
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(G0_CMD_SESSIONTEST)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) { Serial.println("[G0] session test timeout"); break; }
      uint8_t st;
      if (!g0_status(&st)) break;
      if (st == G0_ST_NEED_RELAY) {
        if (++steps > G0_MAX_RELAY_STEPS) { Serial.println("[G0] relay step guard tripped"); break; }
        if (!g0_pump_relay()) break;
        continue;
      }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      if (st == G0_ST_ERROR) { Serial.println("[G0] session test: G0 returned ERROR"); break; }
      delay(1);
    }
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (!ok) return false;
  if (!(d[0]=='G' && d[1]=='0' && d[2]=='S' && d[3]=='E')) { Serial.println("[G0] session test: bad diagnostic magic"); return false; }
  static const char* stepName[] = { "OK", "CreateSession", "INITIALIZE UPDATE", "card cryptogram (K_SE mismatch)",
                                    "EXTERNAL AUTHENTICATE", "ReadObject(scalar)", "CipherOneShot(daily)", "CloseSession" };
  if (d[5] == 0xE7) {   // v5.1
    Serial.println("[G0] session test: FAIL - the G0 has not locked Door 1 this power-on life (DOOR1LOCK never succeeded); Nostr refused");
    return false;
  }
  uint8_t step = d[5] < 8 ? d[5] : 7;
  Serial.printf("[G0] session test v%u: %s%s | stage %u rc %d SW %02X%02X relay steps %u %u ms | scalar==RAM %s (RAM copy %s, keys %s, blob48 %s) | sid %02X%02X%02X%02X%02X%02X%02X%02X\n",
                d[4], (d[5] == 0 || d[5] == 7) ? "PASS" : "FAIL at ", (d[5] == 0) ? "" : stepName[step],
                d[6], (int8_t)d[7], d[8], d[9], d[10], (unsigned)(d[12] | (d[13] << 8)),
                (d[11] & 1) ? "yes" : "no", (d[11] & 2) ? "present" : "absent",
                (d[11] & 4) ? "valid" : "MISSING", (d[11] & 8) ? "yes" : "no",
                d[14], d[15], d[16], d[17], d[18], d[19], d[20], d[21]);
  return d[5] == 0 || d[5] == 7;
}

// -----------------------------------------------------------------------------
// Two-door power-cycle witness
// -----------------------------------------------------------------------------
// Ask the G0 to reset the SE's mode latch to NEUTRAL. The G0 complies ONLY if
// its one-shot is still armed — armed in its main() which runs only on a real
// physical reset (NRST -> TC2030, no ESP32 path), burned on the first success.
// So this returns true at most once per battery cycle no matter how often it is
// called, and a compromised ESP32 spamming it gains nothing: the authority is
// the G0's boot state, not the request. The reset itself travels inside the
// G0's own SCP03 session (K_SE, which this chip has never seen), so we cannot
// forge it either — we are only the doorbell.
//
// Returns true if the latch was actually reset this call.
static uint8_t s_lastLatchClass = 0xFF;
uint8_t g0_last_latch_class() { return s_lastLatchClass; }

// 23 Sep 2026: the MODERESET one-shot as the G0 reported it at g0_init()
// (SELFTEST v4 byte 16). Read once at boot, before anything could consume it.
uint8_t g0_reset_armed() { return s_resetArmed; }

uint8_t g0_door() { return s_door; }

// v5.1: the SE object generation the G0 holds (SELFTEST v7 byte 22). Waits
// out the G0's boot self-test (the register reads zero until it is done).
// Returns 0xFF when the G0 has no keys, 0xFE when it cannot say (absent,
// pre-v5.1 firmware).
uint8_t g0_peek_generation() {
  uint8_t d[23] = {0};
  uint32_t t0 = millis();
  for (;;) {
    bus_lock();
    bool ok = g0_read_reg(G0_REG_SELFTEST, d, sizeof(d));
    bus_unlock();
    if (ok && d[0]=='G' && d[1]=='0' && d[2]=='S' && d[3]=='T') break;
    if (millis() - t0 > 8000) { Serial.println("[G0] generation: no SELFTEST answer"); return 0xFE; }
    delay(50);
  }
  if (d[4] < 7) { Serial.printf("[G0] generation: SELFTEST v%u is older than v5.1\n", d[4]); return 0xFE; }
  if (d[22] != 0xFF && (d[22] < 1 || d[22] > G0_GEN_MAX)) return 0xFE;
  return d[22];
}

uint8_t g0_peek_door() {
  uint8_t d[20] = {0};
  bus_lock();
  bool ok = g0_read_reg(G0_REG_SELFTEST, d, sizeof(d));
  bus_unlock();
  if (!ok) return 0xFF;
  if (!(d[0]=='G' && d[1]=='0' && d[2]=='S' && d[3]=='T')) return 0xFF;   // fresh boot: register still zero / BUSY
  if (d[4] < 5) return 0xFF;
  return d[19];
}

bool g0_door_commit(uint8_t door, uint8_t* held) {
  if (held) *held = 0xFF;
  if (!s_present) return false;
  if (door != 1 && door != 2 && door != 3) return false;   // 30 Oct 2026: 3 = PASSKEY (generic-door G0)
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) { Serial.println("[G0] door commit: skipped, G0 not idle"); return false; } }
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(door == 3 ? G0_CMD_DOORPASSKEY : door == 2 ? G0_CMD_DOORBTC : G0_CMD_DOORNOSTR)) break;
    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY || st == G0_ST_ERROR) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      delay(1);
    }
  } while (0);
  bus_unlock();
  if (!ok || !(d[0]=='D' && d[1]=='O' && d[2]=='O' && d[3]=='R')) {
    Serial.println("[G0] door commit: no diagnostic (G0 unreachable or pre-v5 firmware)");
    return false;
  }
  s_door = d[6];
  if (held) *held = d[6];
  const char* nm = door == 3 ? "PASSKEY" : door == 2 ? "BTC" : "NOSTR";
  if (d[5] == 0)    { Serial.printf("[G0] door memory: %s latched for this power-on life\n", nm); return true; }
  if (d[5] == 1)    { Serial.printf("[G0] door memory: already %s (soft reboot)\n", nm); return true; }
  Serial.printf("[G0] door memory: REFUSED %s - the G0 holds %s until it loses power\n", nm, d[6]==1 ? "NOSTR" : d[6]==2 ? "BTC" : d[6]==3 ? "PASSKEY" : "?");
  return false;
}
const char* g0_latch_class_name(uint8_t cls) {
  switch (cls) {
    case 1: return "NEUTRAL"; case 2: return "NOSTR"; case 3: return "BTC";
    case 4: return "SPENT"; case 5: return "ARMed"; case 0: return "WEDGED (unknown value)";
    case 6: return "PASSKEY (open)"; case 7: return "PASSKEY SPENT";   // 30 Oct 2026: generic-door G0
    default: return "not read";
  }
}

bool g0_mode_reset() {
  s_lastLatchClass = 0xFF;
  if (!s_present) return false;
  // Do not fire into a G0 that is not IDLE — a command sent while it is mid
  // reset (or wedged in ERROR) gets no valid answer, which reads as a witness
  // failure when it is really a sequencing problem.
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) {
      // A FINISHED previous command (SIG_READY — e.g. the SETKEYS ack that
      // onboarding just read — or ERROR) is not "busy"; it is stale state the
      // G0 holds until told otherwise. Clear it exactly as boot does, then
      // proceed. Seen on silicon 11 Sep 2026: onboarding's mode reset was
      // skipped with "not idle (SIG_READY)" straight after SETKEYS, which
      // cascaded into no NOSTR commit, no daily wrap key and a failed scalar.
      Serial.printf("[G0] mode reset: clearing stale %s first\n", g0_status_name(st));
      g0_reset();
      delay(20);
      st = 0xFF; g0_status(&st);
    }
    if (st != G0_ST_IDLE) {
      Serial.printf("[G0] mode reset: skipped, G0 not idle (%s)\n",
                    (st == 0xFF) ? "no status" : g0_status_name(st));
      return false;
    } }
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(G0_CMD_MODERESET)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) {
        if (++steps > G0_MAX_RELAY_STEPS) break;
        if (!g0_pump_relay()) break;
        continue;
      }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      if (st == G0_ST_ERROR) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      delay(1);
    }
  } while (0);
  bus_unlock();
  if (!ok || !(d[0]=='M' && d[1]=='R' && d[2]=='S' && d[3]=='T')) {
    Serial.println("[G0] mode reset: no diagnostic (G0 unreachable or old firmware)");
    return false;
  }
  uint8_t step = d[5];
  // 16 Sep 2026 bench: the G0 now reports its own uptime and hardware reset
  // cause so "already spent" can be told apart from "never rebooted".
  //   RCC->CSR (G0B1): bit31 LPWRRSTF, 30 WWDGRSTF, 29 IWDGRSTF, 28 SFTRSTF,
  //   27 PWRRSTF (power/BOR), 26 PINRSTF (NRST), 25 OBLRSTF.
  { uint32_t up  = (uint32_t)d[12] | ((uint32_t)d[13]<<8) | ((uint32_t)d[14]<<16) | ((uint32_t)d[15]<<24);
    uint32_t csr = (uint32_t)d[16] | ((uint32_t)d[17]<<8) | ((uint32_t)d[18]<<16) | ((uint32_t)d[19]<<24);
    Serial.printf("[G0] boot evidence: uptime %lu ms | RCC_CSR %08lX (%s%s%s%s) | life %s\n",
                  (unsigned long)up, (unsigned long)csr,
                  (csr & (1ul<<27)) ? "POWER " : "", (csr & (1ul<<26)) ? "NRST " : "",
                  (csr & (1ul<<28)) ? "SOFT " : "", (csr & ((1ul<<29)|(1ul<<30))) ? "WDG " : "",
                  d[21] ? "RESUMED (reset without power loss: door and one-shots kept)" : "fresh (power loss)"); }
  if (step == 0) {
    Serial.printf("[G0] mode reset: latch NEUTRAL (fresh power cycle) | relay %u\n", d[10]);
    return true;
  }
  if (step == 0xEE) {
    s_lastLatchClass = (d[4] >= 2) ? d[20] : 0xFF;
    Serial.printf("[G0] mode reset: one-shot already spent this power cycle (expected on a soft reboot) | latch %s\n",
                  g0_latch_class_name(s_lastLatchClass));
    return false;
  }
  Serial.printf("[G0] mode reset: FAILED step %u rc %d SW %02X%02X\n",
                step, (int8_t)d[7], d[8], d[9]);
  return false;
}

// -----------------------------------------------------------------------------
// BTC door: extend MODE_PCR with the G0's secret S (16 Sep 2026)
// -----------------------------------------------------------------------------
// Same transport shape as g0_mode_reset: doorbell, relay pump, read the MBTC
// diagnostic. Authority is the G0's own one-shot; spamming this gains nothing.
// diag[5]: 0 = extended this call, 0xEE = one-shot already spent,
//          0xEF = no S provisioned, else the failing step.
bool g0_mode_btc() {
  if (!s_present) return false;
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) {
      Serial.printf("[G0] mode btc: clearing stale %s first\n", g0_status_name(st));
      g0_reset(); delay(20); st = 0xFF; g0_status(&st);
    }
    if (st != G0_ST_IDLE) {
      Serial.printf("[G0] mode btc: skipped, G0 not idle (%s)\n", (st == 0xFF) ? "no status" : g0_status_name(st));
      return false;
    } }
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(G0_CMD_MODEBTC)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > G0_MAX_RELAY_STEPS) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY || st == G0_ST_ERROR) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      delay(1);
    }
  } while (0);
  bus_unlock();
  if (!ok || !(d[0]=='M' && d[1]=='B' && d[2]=='T' && d[3]=='C')) {
    Serial.println("[G0] mode btc: no diagnostic (G0 unreachable or old firmware)");
    return false;
  }
  uint8_t step = d[5];
  if (step == 0)    { Serial.printf("[G0] mode btc: latch extended to BTC (witnessed this power cycle) | relay %u\n", d[10]); return true; }
  if (step == 0xEE) { Serial.println("[G0] mode btc: one-shot already spent this power cycle - power cycle required"); return false; }
  if (step == 0xEF) { Serial.println("[G0] mode btc: no S provisioned on this G0 - re-onboard"); return false; }
  if (step == 0xEC) { Serial.printf("[G0] mode btc: latch not ARMed by a PIN session (class %u) - refused (v3)\n", d[20]); return false; }
  if (step == 0xED) { Serial.printf("[G0] mode btc: REFUSED by door memory - this power-on life is %s (24 Sep 2026)\n", d[6]==1 ? "NOSTR" : "undeclared"); return false; }
  if (step == 0xEA) { Serial.printf("[G0] mode btc: latch is NOSTR/non-canonical (class %u) - power cycle required\n", d[20]); return false; }
  Serial.printf("[G0] mode btc: FAILED step %u rc %d SW %02X%02X\n", step, (int8_t)d[7], d[8], d[9]);
  return false;
}

// -----------------------------------------------------------------------------
// Generic doors: MODEDOOR (30 Oct 2026)
// -----------------------------------------------------------------------------
// The G0 mints for the door it holds; the caller cannot name one. diag "MDOR"
// (PASSKEY) or "MBTC" (BTC life), same byte meanings as MODEBTC; diag[21] = d.
bool g0_mode_door() {
  if (!s_present) return false;
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) { Serial.printf("[G0] mode door: skipped, G0 not idle (%s)\n", (st == 0xFF) ? "no status" : g0_status_name(st)); return false; } }
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(G0_CMD_MODEDOOR)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > G0_MAX_RELAY_STEPS) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY || st == G0_ST_ERROR) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      delay(1);
    }
  } while (0);
  bus_unlock();
  bool tagOk = (d[0]=='M' && d[1]=='D' && d[2]=='O' && d[3]=='R') || (d[0]=='M' && d[1]=='B' && d[2]=='T' && d[3]=='C');
  if (!ok || !tagOk) { Serial.println("[G0] mode door: no diagnostic (G0 unreachable, or firmware without generic doors)"); return false; }
  uint8_t step = d[5];
  if (step == 0)    { Serial.printf("[G0] mode door: latch minted for door %u (witnessed this power cycle) | relay %u\n", d[21] ? d[21] : 2, d[10]); return true; }
  if (step == 0xEE) { Serial.println("[G0] mode door: one-shot already spent this power cycle - power cycle required"); return false; }
  if (step == 0xEF) { Serial.println("[G0] mode door: no S provisioned on this G0 - re-onboard"); return false; }
  if (step == 0xEC) { Serial.printf("[G0] mode door: latch not ARMed by a PIN session (class %u) - refused\n", d[20]); return false; }
  if (step == 0xED) { Serial.printf("[G0] mode door: REFUSED by door memory - this power-on life is %s\n", d[6]==1 ? "NOSTR" : d[6]==0 ? "undeclared" : "?"); return false; }
  if (step == 0xEA) { Serial.printf("[G0] mode door: latch belongs to another door (class %u) - power cycle required\n", d[20]); return false; }
  Serial.printf("[G0] mode door: FAILED step %u rc %d SW %02X%02X\n", step, (int8_t)d[7], d[8], d[9]);
  return false;
}

// -----------------------------------------------------------------------------
// v3: Bitcoin inside the G0
// -----------------------------------------------------------------------------

// Run one command that answers on BTC_OUT: optional SEED_IN + BTC_IN writes,
// then poll, pumping the relay, and read BTC_OUT in SIG_READY. The G0 always
// finishes these with SIG_READY and carries success/failure INSIDE the
// diagnostic (byte 5), so an ERROR status here means "G0 did not run it".
static bool g0_btc_cmd(uint8_t cmd, const uint8_t* seed_blob, const uint8_t* req,
                       uint8_t out[G0_BTC_OUT_LEN], uint8_t kind = 0,
                       const uint8_t* pass101 = nullptr,
                       const uint8_t* ae_in64 = nullptr, const uint8_t* ae_t32 = nullptr) {
  if (!s_present) return false;
  // 27 Oct 2026: AE_FINISH continues the INIT that just answered SIG_READY.
  // A RESET here would wipe the G0's pending nonce, so FINISH skips the
  // idle-clearing step; SIG_READY is an accepting state on the G0.
  const bool finishing = (cmd == G0_CMD_AE_FINISH);
  { uint8_t st = 0xFF;
    if (!finishing && g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (finishing) { g0_status(&st); if (st != G0_ST_SIG_READY) { Serial.printf("[G0] btc finish: G0 is %s, not SIG_READY from INIT\n", (st == 0xFF) ? "silent" : g0_status_name(st)); return false; } }
    else if (st != G0_ST_IDLE) { Serial.printf("[G0] btc cmd %02X: skipped, G0 not idle (%s)\n", cmd, (st == 0xFF) ? "no status" : g0_status_name(st)); return false; } }
  bool ok = false;
  bus_lock();
  do {
    // v4: an entropy wallet's blob goes to ENT_IN (the register IS the type);
    // the passphrase, when delivering one, goes first and is opaque bytes.
    if (seed_blob && !g0_write_reg(kind == 1 ? G0_REG_ENT_IN : G0_REG_SEED_IN, seed_blob, G0_SEED_IN_LEN)) break;
    if (pass101 && !g0_write_reg(G0_REG_PASS_IN, pass101, G0_PASS_IN_LEN)) break;
    if (req && !g0_write_reg(G0_REG_BTC_IN, req, G0_BTC_REQ_LEN)) break;
    if (ae_in64 && !g0_write_reg(G0_REG_AE_IN, ae_in64, 64)) break;   // 27 Oct 2026: zeros(32) || h
    if (ae_t32 && !g0_write_reg(G0_REG_AE_T, ae_t32, 32)) break;      // 27 Oct 2026: the revealed t
    if (!g0_cmd(cmd)) break;
    uint32_t start = millis(); int steps = 0;
    const uint32_t tmo = (kind == 1) ? G0_ENT_POLL_TIMEOUT_MS : G0_BTC_POLL_TIMEOUT_MS;
    for (;;) {
      if (millis() - start > tmo) { Serial.printf("[G0] btc cmd %02X: timeout\n", cmd); break; }
      esp_task_wdt_reset();
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > G0_BTC_MAX_RELAY_STEPS) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_BTC_OUT, out, G0_BTC_OUT_LEN); break; }
      if (st == G0_ST_ERROR) { Serial.printf("[G0] btc cmd %02X: G0 ERROR (input not accepted?)\n", cmd); break; }
      delay(1);
    }
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

// ── Restorable passkeys (30 Oct 2026) ────────────────────────────────────────
// PKSIGN: PK_IN then the command; the G0 fetches S_pk (one session), then opens
// a second session for write -> sign (x2 at REGISTER) -> junk. Both finish with
// SIG_READY and carry the result in the diagnostic, like the BTC commands.
// fetch session (open 3 + read + DEC + close) + sign session (open 3 + write +
// sign x2 + junk + close) = 14 frames at REGISTER; the first of a G0 life adds
// delete + create (the G0 claims the scratch object), a junk retry adds ~5.
static constexpr int G0_PK_MAX_RELAY_STEPS = 32;   // + scratch claim (delete, create) + a junk retry in a fresh session
// 31 Oct 2026 (silicon): these run on the FIDO task, not the main loop, so
// the bus lock is taken BEFORE the first status read. Taken after it, the
// main loop's dim re-sleep could send SLEEP (and its own I2C) between the
// status read and the command; the KEY restarted on a sign-in after 2 h dark.
// 2 Nov 2026 (Vault phase 2b): in a PASSKEY life the G0 may decrypt the passkey
// master only while the latch reads V_3. main.cpp sets these hooks for that
// life; every PKSIGN and VAULT then runs inside its own window (ruling S2:
// one window per op until the bench says otherwise).
static bool (*s_winOpen)() = nullptr; static void (*s_winClose)() = nullptr;
void g0_set_window_hooks(bool (*openFn)(), void (*closeFn)()) { s_winOpen = openFn; s_winClose = closeFn; }
// 2 Nov 2026 (S2 follow-up, bench: a PASSKEY register took 5.0 to 5.5 s with
// 4 windows): a batch shares ONE window between the G0 ops of one request.
// The window opens lazily at the first op inside the batch and closes when the
// outermost batch ends. The bus lock is held for the whole batch, as H1 asks
// for a single window. Callers keep batches free of user waits.
static int  s_batch = 0;            // nesting depth (only counted when hooks are set)
static bool s_batchOpen = false;    // the window is open now
static bool s_batchFail = false;    // it failed to open in this batch: do not retry
void g0_window_batch_begin() {
  if (!s_winOpen) return;
  bus_lock();
  if (s_batch++ == 0) { s_batchOpen = false; s_batchFail = false; }
}
void g0_window_batch_end() {
  if (!s_winOpen || s_batch <= 0) return;
  if (--s_batch == 0) {
    if (s_batchOpen && s_winClose) s_winClose();
    s_batchOpen = false; s_batchFail = false;
  }
  bus_unlock();
}
// One op's entry into the window. Caller holds the bus lock.
static bool win_enter() {
  if (s_batch > 0) {
    if (!s_batchOpen && !s_batchFail) { s_batchOpen = s_winOpen(); s_batchFail = !s_batchOpen; }
    return s_batchOpen;
  }
  return s_winOpen();
}
static void win_leave() { if (s_batch > 0) return; if (s_winClose) s_winClose(); }
static bool g0_pk_run_inner(uint8_t cmd, const uint8_t* in97, uint8_t reg, uint8_t* out, size_t outLen);
static bool g0_pk_run(uint8_t cmd, const uint8_t* in97, uint8_t reg, uint8_t* out, size_t outLen) {
  const bool win = (cmd == G0_CMD_PKSIGN) && s_winOpen;
  if (!win) return g0_pk_run_inner(cmd, in97, reg, out, outLen);
  // Review 2 Nov 2026 (H1): one locked section from the ARM to the burn, so a
  // lock (PIN wiped) or another window cannot land between them.
  bus_lock();
  bool ok = false;
  if (win_enter()) { ok = g0_pk_run_inner(cmd, in97, reg, out, outLen); win_leave(); }
  else Serial.println("[G0] pk: passkey window did not open");
  bus_unlock();
  return ok;
}
static bool g0_pk_run_inner(uint8_t cmd, const uint8_t* in97, uint8_t reg, uint8_t* out, size_t outLen) {
  if (!s_present || s_pkPresent != 1) return false;
  bus_lock();   // recursive: g0_reset() below takes it again
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) { bus_unlock(); Serial.printf("[G0] pk cmd %02X: skipped, G0 not idle\n", cmd); return false; } }
  bool ok = false;
  do {
    if (in97 && !g0_write_reg(G0_REG_PK_IN, in97, G0_PK_IN_LEN)) break;
    if (cmd == G0_CMD_PKSIGN && !pkm_write()) break;   // v19
    if (!g0_cmd(cmd)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_BTC_POLL_TIMEOUT_MS) { Serial.printf("[G0] pk cmd %02X: timeout\n", cmd); break; }
      esp_task_wdt_reset();
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > G0_PK_MAX_RELAY_STEPS) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(reg, out, outLen); break; }
      if (st == G0_ST_ERROR) { Serial.printf("[G0] pk cmd %02X: G0 ERROR (refused: wrong door?)\n", cmd); break; }
      delay(1);
    }
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}
bool g0_pk_sign(const uint8_t in97[G0_PK_IN_LEN], uint8_t out[G0_BTC_OUT_LEN]) {
  memset(out, 0, G0_BTC_OUT_LEN);
  if (!g0_pk_run(G0_CMD_PKSIGN, in97, G0_REG_BTC_OUT, out, G0_BTC_OUT_LEN)) return false;
  return out[0]=='P' && out[1]=='K' && out[2]=='S' && out[3]=='G';
}
bool g0_pk_scrub(uint8_t* res, uint16_t* sw) {
  uint8_t d[64] = {0};
  if (res) *res = 0xFF;
  if (sw) *sw = 0;
  if (!g0_pk_run(G0_CMD_PKSCRUB, nullptr, G0_REG_SIG_OUT, d, 64)) return false;
  if (!(d[0]=='P' && d[1]=='K' && d[2]=='S' && d[3]=='C')) return false;
  if (res) *res = d[5];
  if (sw) *sw = (uint16_t)((d[7] << 8) | d[8]);
  return true;
}

static const char* g0_fetch_fail_name(uint8_t rc) {
  switch (rc) {
    case 0xE0: return "G0 has no keys";
    case 0xE1: return "no seed blob delivered";
    case 0xE2: return "no request delivered";
    case 0xE3: return "no passphrase held for this life";          // v4
    case 0xE4: return "passphrase budget spent - power cycle";     // v4
    case 0xE5: return "blob is not an entropy container";          // v4
    case 1: case 2: return "SE session open";
    case 3: return "card cryptogram (wrong K_SE)";
    case 4: return "EXTERNAL AUTHENTICATE";
    case 0xE6: return "not a v5 inner packet (ESP32 / G0 firmware mismatch)";   // v5
    case 0xEF: return "G0 has no door secret S";                                // v5
    case 0xE8: return "no seed stored on the G0";                               // v5.1
    case 0xE9: return "seed kind differs from the G0's stored kind";            // v5.1
    case 0xEA: return "packet is not the inner layer of the G0's stored seed";  // v5.1
    case 5: return "latch read failed";                                          // v5
    case 9: return "latch is not BTC (no live door)";                            // v5
    case 7: return "burn extend refused";
    case 0xD1: return "request rejected by G0";
    case 0xD2: return "derivation failed";
    case 0xD3: return "sign / verify-before-release failed";                     // 27 Oct 2026
    case 0xD4: return "DER / self-check failed";
    case 0xD5: return "nonce commitment failed";                                 // anti-exfil INIT
    case 0xD6: return "another signature is pending on the G0";                 // anti-exfil INIT
    case 0xD7: return "nothing pending / 10 s window expired";                   // anti-exfil FINISH
    case 0xD8: return "t does not open the commitment h";                        // anti-exfil FINISH
    default: return "unknown";
  }
}

bool g0_seed_seal(const uint8_t seed[64], uint8_t inner_out[64]) {
  if (!s_present) return false;
  uint8_t in[G0_SEED_IN_LEN] = {0};
  memcpy(in, seed, 64);
  bool ok = false;
  bus_lock();
  do {
    if (!g0_write_reg(G0_REG_SEED_IN, in, G0_SEED_IN_LEN)) break;
    if (!g0_cmd(G0_CMD_SEEDSEAL)) break;
    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_SIG_OUT, inner_out, 64); break; }
      if (st == G0_ST_ERROR) break;
      delay(1);
    }
  } while (0);
  mbedtls_platform_zeroize(in, sizeof(in));
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (ok) {   // a G0 without keys answers ERROR; a stub answering zeros must not pass
    bool allz = true; for (int i = 0; i < 64; i++) if (inner_out[i]) { allz = false; break; }
    if (allz) ok = false;
  }
  Serial.printf("[G0] seed seal: %s\n", ok ? "inner layer applied" : "FAILED");
  return ok;
}

bool g0_ent_seal(const uint8_t* entropy, int word_count, uint8_t inner_out[64]) {
  if (!s_present) return false;
  if (!(word_count == 12 || word_count == 24)) return false;
  uint8_t in[G0_SEED_IN_LEN] = {0};
  in[0] = (uint8_t)word_count;
  memcpy(in + 1, entropy, word_count == 12 ? 16 : 32);
  bool ok = false;
  bus_lock();
  do {
    if (!g0_write_reg(G0_REG_ENT_IN, in, G0_SEED_IN_LEN)) break;
    if (!g0_cmd(G0_CMD_ENTSEAL)) break;
    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_SIG_OUT, inner_out, 64); break; }
      if (st == G0_ST_ERROR) break;
      delay(1);
    }
  } while (0);
  mbedtls_platform_zeroize(in, sizeof(in));
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (ok) {
    bool allz = true; for (int i = 0; i < 64; i++) if (inner_out[i]) { allz = false; break; }
    if (allz) ok = false;
  }
  Serial.printf("[G0] entropy seal: %s\n", ok ? "inner layer applied" : "FAILED");
  return ok;
}

// ── v5.1: seed store on the G0 + Door-1 boot lock ───────────────────────────
// Shared poll for the three short v5.1 commands. reg/len: what to read back.
static bool g0_v51_run(uint8_t cmd, uint8_t reg, uint8_t* out, size_t len, int maxRelay) {
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) return false; }
  bool ok = false;
  if (!g0_cmd(cmd)) return false;
  uint32_t start = millis(); int steps = 0;
  for (;;) {
    if (millis() - start > G0_POLL_TIMEOUT_MS) break;
    uint8_t st;
    if (!g0_status(&st)) { delay(3); continue; }
    if (st == G0_ST_NEED_RELAY) { if (++steps > maxRelay) break; if (!g0_pump_relay()) break; continue; }
    if (st == G0_ST_BUSY) { delay(2); continue; }
    if (st == G0_ST_SIG_READY) { ok = g0_read_reg(reg, out, len); break; }
    if (st == G0_ST_ERROR) break;
    delay(1);
  }
  return ok;
}

bool g0_seed_store(uint8_t kind, const uint8_t outer[96], uint8_t ihash_out[32], uint8_t* rc_out) {
  if (rc_out) *rc_out = 0xFF;
  if (!s_present) return false;
  uint8_t in[G0_STORE_IN_LEN];
  in[0] = kind; memcpy(in + 1, outer, 96);
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    { uint8_t st = 0xFF;
      if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); } }
    if (!g0_write_reg(G0_REG_STORE_IN, in, G0_STORE_IN_LEN)) break;
    ok = g0_v51_run(G0_CMD_SEEDSTORE, G0_REG_SIG_OUT, d, 64, 0);
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (!ok || !(d[0]=='S' && d[1]=='S' && d[2]=='T' && d[3]=='O')) {
    Serial.println("[G0] seed store: no answer (G0 firmware older than v5.1?) - seed NOT stored");
    return false;
  }
  if (rc_out) *rc_out = d[5];
  static const char* why[] = { "stored", "", "", "", "", "", "", "a seed is ALREADY stored (write-once; wipe first)",
                               "no SEEDSEAL/ENTSEAL this power-on life", "kind differs from the seal", "flash write/verify failed" };
  const char* w = (d[5] == 0) ? why[0] : (d[5] >= 0xE7 && d[5] <= 0xEA) ? why[d[5] - 0xE0] :
                  (d[5] == 0xE0) ? "G0 has no keys" : (d[5] == 0xE1) ? "no STORE_IN" :
                  (d[5] == 0xEB) ? "seal window closed (only during onboarding, before any door is committed)" : "unknown";
  Serial.printf("[G0] seed store: %s (rc %02X)\n", w, d[5]);
  if (d[5] != 0) return false;
  if (ihash_out) memcpy(ihash_out, d + 6, 32);
  return true;
}

bool g0_seed_get(uint8_t* kind, uint8_t outer[96], uint8_t ihash[32], bool* present_known_out) {
  if (present_known_out) *present_known_out = false;
  if (!s_present) return false;
  uint8_t d[G0_BTC_OUT_LEN] = {0};
  bus_lock();
  bool ok = g0_v51_run(G0_CMD_SEEDGET, G0_REG_BTC_OUT, d, G0_BTC_OUT_LEN, 0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (!ok || !(d[0]=='S' && d[1]=='G' && d[2]=='E' && d[3]=='T')) {
    Serial.println("[G0] seed get: no answer (G0 unreachable or firmware older than v5.1)");
    return false;
  }
  if (present_known_out) *present_known_out = true;
  if (d[5] != 0) return false;                        // 0xE8: no seed stored on the G0
  if (kind) *kind = d[6];
  if (outer) memcpy(outer, d + 8, 96);
  if (ihash) memcpy(ihash, d + 104, 32);
  return true;
}

static bool s_door1_locked_boot = false;
bool g0_door1_locked_this_boot() { return s_door1_locked_boot; }
bool g0_door1_lock() {
  if (!s_present) return false;
  uint8_t d[64] = {0};
  bus_lock();
  bool ok = g0_v51_run(G0_CMD_DOOR1LOCK, G0_REG_SIG_OUT, d, 64, G0_MAX_RELAY_STEPS);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (!ok || !(d[0]=='D' && d[1]=='1' && d[2]=='L' && d[3]=='K')) {
    Serial.println("[G0] Door-1 boot lock: no answer (G0 unreachable or firmware older than v5.1) - Nostr stays off");
    return false;
  }
  if (d[5] == 0 || d[5] == 1) {
    s_door1_locked_boot = true;
    Serial.printf("[G0] Door-1 boot lock: %s\n", d[5] == 0 ? "PCR pushed off the unlocked value" : "PCR absent (authenticated) - nothing to lock");
    return true;
  }
  const char* w = d[5] == 0xE0 ? "G0 has no keys" : d[5] == 6 ? "SE refused the extend (PCR from before v5.1? wipe + re-onboard)" :
                  d[5] == 7 ? "existence check failed" : "SE session";
  Serial.printf("[G0] Door-1 boot lock: FAILED %s (code %u stage %u rc %d SW %02X%02X) - Nostr stays off this life\n",
                w, d[5], d[6], (int8_t)d[7], d[8], d[9]);
  return false;
}

void g0_pack_inner_packet(const uint8_t inner[64], uint8_t pkt[G0_SEED_IN_LEN]) {
  memset(pkt, 0, G0_SEED_IN_LEN);
  memcpy(pkt, inner, 64);
  pkt[64] = 'F'; pkt[65] = 'V'; pkt[66] = 'I'; pkt[67] = '5';
}

bool g0_door_keys(const uint8_t blob[G0_SEED_IN_LEN], g0_door_keys_t* out) {
  return g0_door_keys_kind(blob, 0, nullptr, 0, out, nullptr);
}

bool g0_door_keys_kind(const uint8_t blob[G0_SEED_IN_LEN], uint8_t kind,
                       const char* pass, size_t pass_len,
                       g0_door_keys_t* out, uint8_t* rc_out) {
  uint8_t d[G0_BTC_OUT_LEN] = {0};
  uint8_t p101[G0_PASS_IN_LEN] = {0};
  const uint8_t* pp = nullptr;
  if (rc_out) *rc_out = 0xFF;
  if (kind == 1 && pass) {
    if (pass_len > 100) return false;
    p101[0] = (uint8_t)pass_len; memcpy(p101 + 1, pass, pass_len); pp = p101;
  }
  bool got = g0_btc_cmd(G0_CMD_DOORKEYS, blob, nullptr, d, kind, pp);
  mbedtls_platform_zeroize(p101, sizeof(p101));
  if (!got) { Serial.println("[G0] door keys: no answer"); return false; }
  if (!(d[0]=='D' && d[1]=='K' && d[2]=='E' && d[3]=='Y')) { Serial.println("[G0] door keys: bad diagnostic (old firmware?)"); return false; }
  if (d[4] < G0_BTC_OUT_VER_MIN) {
    // A pre-v5 G0 tried to DEC the seed key from its OWN session. On a KEY
    // onboarded with v5 the SE must refuse that (rc 05, SW 6986): the bench
    // proof that the G0's secrets alone no longer open the seed.
    Serial.printf("[G0] door keys: G0 firmware is pre-v5 (ver %u) - its own-session seed DEC answered rc %02X SW %02X%02X%s - flash the v5 G0\n",
                  d[4], d[5], d[182], d[183], (d[5] == 5 && d[182] == 0x69 && d[183] == 0x86) ? " (SE REFUSED the G0: v5 policy holds)" : "");
    mbedtls_platform_zeroize(d, sizeof(d)); return false; }
  if (rc_out) *rc_out = d[5];
  if (d[5] != 0) {
    Serial.printf("[G0] door keys: FAILED rc %02X (%s) stage %u rc8 %d SW %02X%02X relay %u %u ms\n",
                  d[5], g0_fetch_fail_name(d[5]), d[180], (int8_t)d[181], d[182], d[183], d[184], d[185] | (d[186] << 8));
    return false;
  }
  memcpy(out->master_fp, d + 6, 4);
  memcpy(out->xpub84_pub, d + 10, 33); memcpy(out->xpub84_cc, d + 43, 32); memcpy(out->xpub84_parent_fp, d + 75, 4);
  memcpy(out->xpub48_pub, d + 79, 33); memcpy(out->xpub48_cc, d + 112, 32); memcpy(out->xpub48_parent_fp, d + 144, 4);
  memcpy(out->state_key, d + 148, 32);
  unsigned relay = d[184], ms = d[185] | (d[186] << 8);
  mbedtls_platform_zeroize(d, sizeof(d));
  Serial.printf("[G0] door keys: ok (fp %02x%02x%02x%02x) | inner layer stripped + latch burned on the G0 | relay %u | %u ms\n",
                out->master_fp[0], out->master_fp[1], out->master_fp[2], out->master_fp[3], relay, ms);
  return true;
}

// 27 Oct 2026: anti-exfil. BTCSIGN_INIT does the fetch + burn + derivation
// and answers pub33, R0 and the sighash; AE_FINISH takes t and answers the
// DER signature. This processor checks x(R0 + H(R0||t)G) == r and verifies
// the signature against pub33 over the sighash (both new; until now it only
// compared pub33 and the sighash with its own). Any mismatch: discard, latch.
bool g0_btc_sign(const uint8_t blob[G0_SEED_IN_LEN], const uint8_t req[G0_BTC_REQ_LEN],
                 uint8_t pub33_out[33], uint8_t der_out[72], uint8_t* der_len_out,
                 uint8_t sighash_out[32], uint8_t kind) {
  uint8_t d[G0_BTC_OUT_LEN] = {0}, t[32], ae_in[64] = {0}, r0[33], pub33[33], sighash[32];
  *der_len_out = 0;
  if (s_aeFault) { Serial.println("[G0] btc sign denied: ANTI-EXFIL FAULT latched this boot"); return false; }
  if (s_aePresent != 1) { Serial.println("[G0] btc sign denied: G0 firmware has no anti-exfil (self-test < v8)"); return false; }
  if (!ae_draw_t(t)) return false;
  ae_host_commit(AE_KIND_ECDSA, t, ae_in + 32);
  // 1. INIT
  if (!g0_btc_cmd(G0_CMD_BTCSIGN_INIT, blob, req, d, kind, nullptr, ae_in, nullptr)) { Serial.println("[G0] btc sign: no answer to INIT"); mbedtls_platform_zeroize(t, 32); return false; }
  if (!(d[0]=='B' && d[1]=='S' && d[2]=='I' && d[3]=='G')) { Serial.println("[G0] btc sign: bad diagnostic (old firmware?)"); mbedtls_platform_zeroize(t, 32); return false; }
  if (d[4] < 3) { Serial.printf("[G0] btc sign: BSIG v%u has no anti-exfil - flash the anti-exfil G0\n", d[4]); mbedtls_platform_zeroize(t, 32); return false; }
  if (d[5] != 0) {
    Serial.printf("[G0] btc sign INIT: FAILED rc %02X (%s) stage %u rc8 %d SW %02X%02X relay %u %u ms\n",
                  d[5], g0_fetch_fail_name(d[5]), d[145], (int8_t)d[146], d[147], d[148], d[149], d[150] | (d[151] << 8));
    mbedtls_platform_zeroize(t, 32); return false;
  }
  memcpy(pub33, d + 8, 33); memcpy(r0, d + 41, 33); memcpy(sighash, d + 113, 32);
  unsigned relay = d[149], ms0 = d[150] | (d[151] << 8);
  // 2. FINISH
  memset(d, 0, sizeof(d));
  if (!g0_btc_cmd(G0_CMD_AE_FINISH, nullptr, nullptr, d, kind, nullptr, nullptr, t)) { Serial.println("[G0] btc sign: no answer to FINISH"); mbedtls_platform_zeroize(t, 32); return false; }
  if (!(d[0]=='B' && d[1]=='S' && d[2]=='I' && d[3]=='G') || d[5] != 0) {
    Serial.printf("[G0] btc sign FINISH: FAILED rc %02X (%s) %u ms\n", d[5], g0_fetch_fail_name(d[5]), d[150] | (d[151] << 8));
    mbedtls_platform_zeroize(t, 32); return false;
  }
  uint8_t dl = d[7];
  if (dl < 8 || dl > 72 || d[41] != 0x30 || d[42] != dl - 2) { Serial.println("[G0] btc sign: malformed DER"); mbedtls_platform_zeroize(t, 32); return false; }
  if (memcmp(d + 8, pub33, 33) != 0 || memcmp(d + 113, sighash, 32) != 0 || memcmp(d + 152, r0, 33) != 0) {
    ae_fault("Bitcoin: FINISH echoed a different pubkey / sighash / R0 than INIT");
    mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false;
  }
  // 3. the check, then the verify
  uint8_t r[32], sgn[32];
  if (!der_to_rs(d + 41, dl, r, sgn)) { Serial.println("[G0] btc sign: DER does not parse"); mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false; }
#ifdef FAVILLA_BENCH_ANTIEXFIL_SKIP
  Serial.println("[G0] anti-exfil: host check SKIPPED (bench build)");
#else
  if (!ae_host_check(AE_KIND_ECDSA, r0, t, r)) {
    ae_fault("Bitcoin: x(R0 + H(R0||t)G) != r");
    mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false;
  }
  if (!ecdsa_verify_rs(pub33, sighash, r, sgn)) {
    ae_fault("Bitcoin: ECDSA verify failed against the leaf pubkey");
    mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false;
  }
#endif
#ifdef FAVILLA_BENCH_ANTIEXFIL_LOG_T
  { char hx[131]; for (int i = 0; i < 32; i++) sprintf(hx + 2*i, "%02x", t[i]); Serial.printf("[SIGNDIAG] ae btc t=%s\n", hx); }
#endif
  memcpy(pub33_out, pub33, 33); memcpy(der_out, d + 41, 72); *der_len_out = dl; memcpy(sighash_out, sighash, 32);
  Serial.printf("[G0] btc sign: ok kind %u der %u | anti-exfil check + ECDSA verify passed | inner layer stripped + latch burned on the G0 | relay %u | init %u ms finish %u ms\n",
                d[6], dl, relay, ms0, d[150] | (d[151] << 8));
  mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32);
  return true;
}

// BIP-137 message signing (15 Oct 2026). Same fetch + burn as a transaction
// input: blob = the inner packet from a fresh spend-PIN session, one per message.
bool g0_msg_sign(const uint8_t blob[G0_SEED_IN_LEN], uint8_t kind,
                 uint32_t change, uint32_t index, const char* msg, size_t msg_len,
                 uint8_t pub33_out[33], uint8_t sig65_out[65], uint8_t digest_out[32]) {
  if (change > 1 || (index & 0x80000000UL) || !msg || msg_len < 1 || msg_len > G0_MSG_MAX) return false;
  if (s_aeFault) { Serial.println("[G0] msg sign denied: ANTI-EXFIL FAULT latched this boot"); return false; }
  if (s_aePresent != 1) { Serial.println("[G0] msg sign denied: G0 firmware has no anti-exfil (self-test < v8)"); return false; }
  uint8_t req[G0_BTC_REQ_LEN] = {0};
  req[0] = 'F'; req[1] = 'M'; req[2] = 'S'; req[3] = 'G'; req[4] = 1;
  req[5] = (uint8_t)change;
  req[6] = (uint8_t)index; req[7] = (uint8_t)(index >> 8); req[8] = (uint8_t)(index >> 16); req[9] = (uint8_t)(index >> 24);
  req[10] = (uint8_t)msg_len; memcpy(req + 11, msg, msg_len);
  uint8_t d[G0_BTC_OUT_LEN] = {0}, t[32], ae_in[64] = {0}, r0[33], pub33[33], digest[32];
  if (!ae_draw_t(t)) { mbedtls_platform_zeroize(req, sizeof(req)); return false; }
  ae_host_commit(AE_KIND_ECDSA_RC, t, ae_in + 32);
  // 1. INIT (27 Oct 2026: anti-exfil; same fetch + burn as a transaction input)
  bool ok = g0_btc_cmd(G0_CMD_MSGSIGN_INIT, blob, req, d, kind, nullptr, ae_in, nullptr);
  mbedtls_platform_zeroize(req, sizeof(req));
  if (!ok) { Serial.println("[G0] msg sign: no answer to INIT"); mbedtls_platform_zeroize(t, 32); return false; }
  if (!(d[0]=='M' && d[1]=='S' && d[2]=='I' && d[3]=='G')) { Serial.println("[G0] msg sign: bad diagnostic (G0 firmware without message signing?)"); mbedtls_platform_zeroize(t, 32); return false; }
  if (d[4] < 2) { Serial.printf("[G0] msg sign: MSIG v%u has no anti-exfil - flash the anti-exfil G0\n", d[4]); mbedtls_platform_zeroize(t, 32); return false; }
  if (d[5] != 0) {
    Serial.printf("[G0] msg sign INIT: FAILED rc %02X (%s) stage %u rc8 %d SW %02X%02X relay %u %u ms\n",
                  d[5], g0_fetch_fail_name(d[5]), d[145], (int8_t)d[146], d[147], d[148], d[149], d[150] | (d[151] << 8));
    mbedtls_platform_zeroize(t, 32); return false;
  }
  memcpy(pub33, d + 8, 33); memcpy(r0, d + 41, 33); memcpy(digest, d + 106, 32);
  unsigned relay = d[149];
  // 2. FINISH
  memset(d, 0, sizeof(d));
  if (!g0_btc_cmd(G0_CMD_AE_FINISH, nullptr, nullptr, d, kind, nullptr, nullptr, t)) { Serial.println("[G0] msg sign: no answer to FINISH"); mbedtls_platform_zeroize(t, 32); return false; }
  if (!(d[0]=='M' && d[1]=='S' && d[2]=='I' && d[3]=='G') || d[5] != 0) {
    Serial.printf("[G0] msg sign FINISH: FAILED rc %02X (%s)\n", d[5], g0_fetch_fail_name(d[5])); mbedtls_platform_zeroize(t, 32); return false;
  }
  if (d[41] < 39 || d[41] > 42) { Serial.println("[G0] msg sign: unexpected BIP-137 header"); mbedtls_platform_zeroize(t, 32); return false; }
  if (memcmp(d + 8, pub33, 33) != 0 || memcmp(d + 106, digest, 32) != 0 || memcmp(d + 152, r0, 33) != 0) {
    ae_fault("Message: FINISH echoed a different pubkey / digest / R0 than INIT");
    mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false;
  }
#ifdef FAVILLA_BENCH_ANTIEXFIL_SKIP
  Serial.println("[G0] anti-exfil: host check SKIPPED (bench build)");
#else
  if (!ae_host_check(AE_KIND_ECDSA_RC, r0, t, d + 42)) {
    ae_fault("Message: x(R0 + H(R0||t)G) != r");
    mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false;
  }
  if (!ecdsa_verify_rs(pub33, digest, d + 42, d + 74)) {
    ae_fault("Message: ECDSA verify failed against the leaf pubkey");
    mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32); return false;
  }
#endif
  memcpy(pub33_out, pub33, 33); memcpy(sig65_out, d + 41, 65); memcpy(digest_out, digest, 32);
  Serial.printf("[G0] msg sign: ok | anti-exfil check + ECDSA verify passed | inner layer stripped + latch burned on the G0 | relay %u | %u ms\n",
                relay, d[150] | (d[151] << 8));
  mbedtls_platform_zeroize(d, sizeof(d)); mbedtls_platform_zeroize(t, 32);
  return true;
}

static void g0_put32le(uint8_t* p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

bool g0_btc_build_request(uint8_t req[G0_BTC_REQ_LEN], uint8_t kind,
                          uint32_t version, uint32_t locktime,
                          const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                          const uint8_t hashOutputs[32], const uint8_t outpoint[36],
                          uint32_t nSequence, uint64_t amount,
                          uint32_t change, uint32_t index,
                          const uint8_t* witness_script, size_t witness_script_len) {
  memset(req, 0, G0_BTC_REQ_LEN);
  if (kind == 1) { if (witness_script_len != 0) return false; }
  else if (kind == 2) { if (!witness_script || witness_script_len == 0 || witness_script_len > 252) return false; }
  else return false;
  if (change > 1 || (index & 0x80000000UL)) return false;
  req[0] = kind; req[1] = 0x01;
  req[2] = (uint8_t)witness_script_len; req[3] = (uint8_t)(witness_script_len >> 8);
  g0_put32le(req + 4, version); g0_put32le(req + 8, locktime);
  memcpy(req + 12, hashPrevouts, 32); memcpy(req + 44, hashSequence, 32); memcpy(req + 76, hashOutputs, 32);
  memcpy(req + 108, outpoint, 36);
  g0_put32le(req + 144, nSequence);
  for (int i = 0; i < 8; i++) req[148 + i] = (uint8_t)(amount >> (8 * i));
  g0_put32le(req + 156, change); g0_put32le(req + 160, index);
  if (witness_script_len) memcpy(req + 164, witness_script, witness_script_len);
  return true;
}

// g0_mode_delete() RETIRED 19 Oct 2026 (review finding 3). The G0 no longer
// accepts MODEDEL: a deletable latch can be re-created already reading BTC.
// MODE_PCR is removed only by the G0's WIPEALL. DO NOT RE-ADD.

bool g0_wipe_all(uint16_t* done, uint16_t* missing, uint8_t* rc_out) {
  if (done) *done = 0; if (missing) *missing = 0; if (rc_out) *rc_out = 0xFF;
  if (!s_present) return false;
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) { Serial.println("[G0] wipe all: skipped, G0 not idle"); return false; } }
  uint8_t d[64] = {0};
  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(G0_CMD_WIPEALL)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_BTC_POLL_TIMEOUT_MS) break;   // up to 14 relay round trips
      esp_task_wdt_reset();
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > 40) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY || st == G0_ST_ERROR) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      delay(1);
    }
  } while (0);
  bus_unlock();
  if (!ok || !(d[0]=='W' && d[1]=='A' && d[2]=='L' && d[3]=='L')) {
    Serial.println("[G0] wipe all: no diagnostic (G0 unreachable or old firmware)");
    return false;
  }
  uint16_t dn = (uint16_t)((d[6] << 8) | d[7]), ms = (uint16_t)((d[8] << 8) | d[9]);
  if (done) *done = dn; if (missing) *missing = ms;
  if (rc_out) *rc_out = d[5];
  if (d[5] == 0xD1) { Serial.printf("[G0] wipe all: STOPPED - seed wrap key not removed, latch + recovery object kept (deleted %04X)\n", dn); return false; }
  if (d[5] == 0xD2) { Serial.printf("[G0] wipe all: STOPPED - a passkey key (K_PK / K_PKN) not removed, latch + recovery object kept (deleted %04X)\n", dn); return false; }
  if (d[5] == 0) { Serial.printf("[G0] wipe all: ok (deleted %04X, absent %04X, relay %u)\n", dn, ms, d[14]); return true; }
  Serial.printf("[G0] wipe all: rc %02X (deleted %04X, absent %04X) stage %u rc8 %d SW %02X%02X\n",
                d[5], dn, ms, d[10], (int8_t)d[11], d[12], d[13]);
  return false;
}

#ifdef FAVILLA_BENCH_PROBES
uint8_t g0_bench_raw_cmd(uint8_t cmd, uint32_t waitMs) {
  if (!s_present) return 0xFF;
  uint8_t st = 0xFF;
  bus_lock();
  if (g0_cmd(cmd)) {
    uint32_t start = millis();
    while (millis() - start < waitMs) {
      if (g0_status(&st) && (st == G0_ST_IDLE || st == G0_ST_ERROR || st == G0_ST_SIG_READY)) break;
      delay(20);   // NEED_RELAY / BUSY: deliberately NOT pumped
    }
  }
  bus_unlock();
  Serial.printf("[G0-BENCH] raw cmd %02X -> status %s (%02X) after up to %lu ms, relay never pumped\n",
                cmd, (st == 0xFF) ? "no answer" : g0_status_name(st), st, (unsigned long)waitMs);
  if (st == G0_ST_NEED_RELAY) g0_cmd(G0_CMD_RESET);   // abandon the stranded frame so the G0 is usable again
  return st;
}
#endif  // FAVILLA_BENCH_PROBES

// -----------------------------------------------------------------------------
// ECDH
// -----------------------------------------------------------------------------

bool g0_ecdh(const uint8_t peer_xonly32[32], uint8_t shared_out[G0_ECDH_LEN]) {
  if (!s_present) {
    Serial.println("[G0] ecdh denied: signer not present");
    return false;
  }

  bool ok = false;
  bus_lock();
  do {
    if (!g0_write_reg(G0_REG_HASH_IN, peer_xonly32, 32)) break;
    if (!g0_cmd(G0_CMD_ECDH)) break;

    uint32_t start = millis();
    int steps = 0;
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) break;

      if (st == G0_ST_NEED_RELAY) {
        if (++steps > G0_MAX_RELAY_STEPS) break;
        if (!g0_pump_relay()) break;
        continue;
      }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) {
        uint8_t buf[G0_SIG_LEN];
        if (g0_read_reg(G0_REG_SIG_OUT, buf, G0_SIG_LEN)) {
          memcpy(shared_out, buf, G0_ECDH_LEN);
          mbedtls_platform_zeroize(buf, sizeof(buf));
          ok = true;
        }
        break;
      }
      if (st == G0_ST_ERROR) {
        // Most likely an invalid peer public key, rejected by the on-curve
        // check on the G0. Also covers "no PIN session".
        Serial.println("[G0] ecdh returned ERROR (bad peer key, or no session)");
        break;
      }
      delay(1);
    }
  } while (0);

  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

// -----------------------------------------------------------------------------
// No-input commands (pubkey, cache key)
//
// Same relay pump as signing; the only difference is that nothing is written to
// HASH_IN first and only the first 32 bytes of SIG_OUT are meaningful.
// -----------------------------------------------------------------------------

static bool g0_simple_cmd(uint8_t cmd, uint8_t out32[32]) {
  if (!s_present) return false;

  bool ok = false;
  bus_lock();
  do {
    if (!g0_cmd(cmd)) break;
    uint32_t start = millis();
    int steps = 0;
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) break;
      if (st == G0_ST_NEED_RELAY) {
        if (++steps > G0_MAX_RELAY_STEPS) break;
        if (!g0_pump_relay()) break;
        continue;
      }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) {
        uint8_t buf[G0_SIG_LEN];
        if (g0_read_reg(G0_REG_SIG_OUT, buf, G0_SIG_LEN)) {
          memcpy(out32, buf, 32);
          mbedtls_platform_zeroize(buf, sizeof(buf));
          ok = true;
        }
        break;
      }
      if (st == G0_ST_ERROR) break;
      delay(1);
    }
  } while (0);

  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

bool g0_get_pubkey(uint8_t xonly_out[32]) {
  bool ok = g0_simple_cmd(G0_CMD_PUBKEY, xonly_out);
  if (ok) { memcpy(s_pubkey, xonly_out, 32); s_pubkeyOk = true; }   // 27 Oct 2026: reference for the post-sign verify
  return ok;
}

bool g0_get_cache_key(uint8_t key_out[32]) {
  return g0_simple_cmd(G0_CMD_CACHEKEY, key_out);
}

// -----------------------------------------------------------------------------
// Onboarding — seal a scalar under K_G0
// -----------------------------------------------------------------------------

// 11 Nov 2026: the boot read of the self-test register failed? Try again when
// a feature asks, at most every 2 s. Only the capability bytes are taken late;
// the door memory and one-shot arms stay as boot saw them (boot logic has run).
// The bus lock is the recursive I2C mutex, so a caller already holding it is fine.
static void capsRecheck() {
  if (!s_present || s_stSeen) return;
  uint32_t now = millis();
  if (s_stRetryAt && (int32_t)(now - s_stRetryAt) < 0) return;
  s_stRetryAt = now + 2000;
  uint8_t t[27] = {0};
  bus_lock();
  bool ok = g0_read_reg(G0_REG_SELFTEST, t, sizeof(t)) && selfTestMagic(t);
  bus_unlock();
  if (!ok) return;
  capsFromSelfTest(t);
  Serial.printf("[G0] self-test v%u read late: vault %s, backup key %s, codes %s\n", t[4],
                s_vaultPresent ? "present" : "absent", s_vpubPresent ? "present" : "absent", s_v17Present ? "present" : "absent");
}
bool g0_caps_known() { capsRecheck(); return s_stSeen; }
bool g0_uv_present() { capsRecheck(); return s_uvPresent == 1; }
bool g0_vault_present() { capsRecheck(); return s_vaultPresent == 1; }
bool g0_pk2b_present() { capsRecheck(); return s_pk2bPresent == 1; }
bool g0_vpub_present() { capsRecheck(); return s_vpubPresent == 1; }
bool g0_v15_present() { capsRecheck(); return s_v15Present == 1; }
bool g0_v17_present() { capsRecheck(); return s_v17Present == 1; }
bool g0_limit_present() { capsRecheck(); return s_limPresent == 1; }
// 2 Nov 2026: one VAULT command. The bus lock is held from the first status
// read to the RESET at the end (the FIDO task calls this, see g0_pk_run). The
// RESET wipes VAULT_OUT on the G0, so an opened record does not stay there.
static bool g0_vault_inner(uint8_t op, const uint8_t* data, size_t n, uint8_t* out, size_t* outN, uint8_t* res, uint8_t* left);
bool g0_vault(uint8_t op, const uint8_t* data, size_t n, uint8_t* out, size_t* outN, uint8_t* res, uint8_t* left) {
  if (s_winOpen) {   // 2b: PASSKEY life - one window around this VAULT op
    if (res) *res = 0xFF;
    if (outN) *outN = 0;
    bus_lock();   // review (H1): ARM, op and burn as one locked section
    bool r = false;
    if (win_enter()) { r = g0_vault_inner(op, data, n, out, outN, res, left); win_leave(); }
    else Serial.println("[G0] vault: passkey window did not open");
    bus_unlock();
    return r;
  }
  return g0_vault_inner(op, data, n, out, outN, res, left);
}
static bool g0_vault_inner(uint8_t op, const uint8_t* data, size_t n, uint8_t* out, size_t* outN, uint8_t* res, uint8_t* left) {
  if (res) *res = 0xFF;
  if (outN) *outN = 0;
  if (!s_present || s_vaultPresent != 1 || n > G0_VAULT_DATA_MAX) return false;
  // One PSRAM block, taken on first use and kept: under the bus lock only (two
  // tasks call this). 2 Nov 2026: was 1 KB of static internal RAM.
  static uint8_t* s_vbuf = nullptr;
  bool ok = false;
  bus_lock();
  if (!s_vbuf) s_vbuf = (uint8_t*)heap_caps_malloc(G0_VAULT_IN_LEN + G0_VAULT_OUT_LEN, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!s_vbuf) { bus_unlock(); Serial.println("[G0] vault: no memory"); return false; }
  uint8_t* in = s_vbuf; uint8_t* o = s_vbuf + G0_VAULT_IN_LEN;
  memset(in, 0, G0_VAULT_IN_LEN); in[0] = op; in[1] = (uint8_t)(n >> 8); in[2] = (uint8_t)n;
  if (n) memcpy(in + 3, data, n);
  do {
    uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_cmd(G0_CMD_RESET); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) { Serial.println("[G0] vault: skipped, G0 not idle"); break; }
    if (!g0_write_reg(G0_REG_VAULT_IN, in, G0_VAULT_IN_LEN)) break;
    if (!pkm_write()) break;   // v19: the master's inner layer from the passkey session
    if (!g0_cmd(G0_CMD_VAULT)) break;
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_BTC_POLL_TIMEOUT_MS) { Serial.println("[G0] vault: timeout"); break; }
      esp_task_wdt_reset();
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > G0_PK_MAX_RELAY_STEPS) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_VAULT_OUT, o, G0_VAULT_OUT_LEN); break; }
      if (st == G0_ST_ERROR) { Serial.println("[G0] vault: G0 ERROR (refused: wrong door?)"); break; }
      delay(1);
    }
  } while (0);
  g0_cmd(G0_CMD_RESET);   // always: wipes VAULT_OUT on the G0
  mbedtls_platform_zeroize(in, G0_VAULT_IN_LEN);
  if (ok && !(o[0] == 'V' && o[1] == 'L' && o[2] == 'T' && o[3] == '1')) ok = false;
  if (ok) {
    size_t l = ((size_t)o[8] << 8) | o[9];
    if (l > G0_VAULT_DATA_MAX) ok = false;
    else {
      if (res) *res = o[5];
      if (left) *left = o[7];
      if (out && l) memcpy(out, o + 12, l);
      if (outN) *outN = l;
    }
  }
  mbedtls_platform_zeroize(o, G0_VAULT_OUT_LEN);
  bus_unlock();
  return ok;
}
// One HASH_IN command answered on SIG_OUT ("UVCK" diag). PIN digits, zero padded.
static bool g0_uv_cmd(uint8_t cmd, const char* pin, uint8_t d[64]) {
  if (!s_present || s_uvPresent != 1) return false;
  bus_lock();   // before the status read, as g0_pk_run (31 Oct 2026)
  { uint8_t st = 0xFF;
    if (g0_status(&st) && (st == G0_ST_SIG_READY || st == G0_ST_ERROR)) { g0_reset(); delay(20); st = 0xFF; g0_status(&st); }
    if (st != G0_ST_IDLE) { bus_unlock(); return false; } }
  uint8_t in[32] = {0};
  if (pin) { size_t n = strnlen(pin, 32); memcpy(in, pin, n); }
  bool ok = false;
  do {
    if (pin && !g0_write_reg(G0_REG_HASH_IN, in, 32)) break;
    if (!g0_cmd(cmd)) break;
    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st; if (!g0_status(&st)) break;
      if (st == G0_ST_SIG_READY) { ok = g0_read_reg(G0_REG_SIG_OUT, d, 64); break; }
      if (st == G0_ST_ERROR) break;
      delay(2);
    }
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  mbedtls_platform_zeroize(in, sizeof(in));
  return ok && d[0]=='U' && d[1]=='V' && d[2]=='C' && d[3]=='K';
}
bool g0_uv_set(const char* pin) { uint8_t d[64] = {0}; return g0_uv_cmd(G0_CMD_UVSET, pin, d) && d[5] == 0; }
int  g0_uv_check(const char* pin, uint8_t* left) {
  uint8_t d[64] = {0};
  if (left) *left = 0;
  if (!g0_uv_cmd(G0_CMD_UVCHECK, pin, d)) return -1;
  if (left) *left = d[6];
  return d[5] == 0 ? 1 : d[5] == 0xE2 ? 0 : -1;
}
void g0_uv_clear() { uint8_t d[64]; g0_uv_cmd(G0_CMD_UVCLEAR, nullptr, d); }

void g0_pkm_set(const uint8_t pkm[G0_PKM_LEN]) { memcpy(s_pkm, pkm, G0_PKM_LEN); s_pkmValid = true; }
void g0_pkm_clear() { mbedtls_platform_zeroize(s_pkm, sizeof s_pkm); s_pkmValid = false; }
bool g0_doorpin_present() { capsRecheck(); return s_doorPinPresent == 1; }
uint8_t g0_rdp_level() { capsRecheck(); return s_rdp; }
// v19: before each PKSIGN / VAULT, after the RESET that clears the G0's inputs.
static bool pkm_write() { return !s_pkmValid || s_doorPinPresent != 1 || g0_write_reg(G0_REG_PKM_IN, s_pkm, G0_PKM_LEN); }   // a pre-v19 G0 has no PKM_IN
bool g0_pk_master(const uint8_t spk[32], uint8_t sealed64[G0_PKM_LEN]) {
  if (!s_present || s_pkPresent != 1) return false;
  bool ok = false;
  bus_lock();
  do {
    if (!g0_write_reg(G0_REG_HASH_IN, spk, 32)) break;
    if (!g0_cmd(G0_CMD_PKMASTER)) break;
    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) break;
      if (st == G0_ST_SIG_READY) {
        uint8_t buf[G0_SIG_LEN];
        if (g0_read_reg(G0_REG_SIG_OUT, buf, G0_SIG_LEN)) { memcpy(sealed64, buf, G0_PKM_LEN); ok = true; }   // v19: inner || tag
        mbedtls_platform_zeroize(buf, sizeof(buf));
        break;
      }
      if (st == G0_ST_ERROR) break;   // outside the seal window, or already used this window
      delay(2);
    }
  } while (0);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

bool g0_seal_scalar(const uint8_t scalar[32], uint8_t out_blob[G0_SEALED_BLOB_LEN]) {
  if (!s_present) return false;

  bool ok = false;
  bus_lock();
  do {
    // Reuse HASH_IN as the 32-byte inbound payload register; the command
    // distinguishes the operation. Keeps the register map minimal.
    if (!g0_write_reg(G0_REG_HASH_IN, scalar, 32)) break;
    if (!g0_cmd(G0_CMD_PROVISION)) break;

    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;
      uint8_t st;
      if (!g0_status(&st)) break;
      if (st == G0_ST_SIG_READY) {
        // Sealed ciphertext is returned on SIG_OUT (32 of its 64 byte width).
        uint8_t buf[G0_SIG_LEN];
        if (g0_read_reg(G0_REG_SIG_OUT, buf, G0_SIG_LEN)) {
          memcpy(out_blob, buf, G0_SEALED_BLOB_LEN);
          mbedtls_platform_zeroize(buf, sizeof(buf));
          ok = true;
        }
        break;
      }
      if (st == G0_ST_ERROR) break;
      delay(2);
    }
  } while (0);

  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

// -----------------------------------------------------------------------------
// Onboarding key delivery
// -----------------------------------------------------------------------------
bool g0_set_keys(const uint8_t k_se[G0_KSE_LEN], const uint8_t k_g0[G0_KG0_LEN], const uint8_t k_mode[G0_KMODE_LEN], uint8_t gen) {
  if (!s_present) return false;
  if (gen < 1 || gen > G0_GEN_MAX) return false;
  s_pubkeyOk = false; mbedtls_platform_zeroize(s_pubkey, 32);   // 27 Oct 2026: new identity, new reference pubkey

  // What the G0 must echo back once it has committed all three keys to flash.
  // 16 Sep 2026: the payload carries a third key, S (G0_KMODE_LEN). The G0
  // stores it beside K_SE/K_G0 and uses it ONLY to extend MODE_PCR on request
  // (G0_CMD_MODEBTC). Like the other two it travels through this chip exactly
  // once, at onboarding, and is zeroised by the caller straight after.
  uint8_t keys[G0_KEYS_LEN];
  memcpy(keys, k_se, G0_KSE_LEN);
  memcpy(keys + G0_KSE_LEN, k_g0, G0_KG0_LEN);
  memcpy(keys + G0_KSE_LEN + G0_KG0_LEN, k_mode, G0_KMODE_LEN);
  keys[G0_KSE_LEN + G0_KG0_LEN + G0_KMODE_LEN] = gen;   // v5.1: the SE object generation
  uint8_t expect[32];
  mbedtls_sha256(keys, sizeof(keys), expect, 0);

  bool ok = false;
  bus_lock();
  do {
    if (!g0_write_reg(G0_REG_KEYS_IN, keys, sizeof(keys))) break;
    if (!g0_cmd(G0_CMD_SETKEYS)) break;

    uint32_t start = millis();
    for (;;) {
      if (millis() - start > G0_POLL_TIMEOUT_MS) break;   // flash write is slow-ish; 3 s is ample
      uint8_t st;
      // SETKEYS makes the G0 write its flash key page. On the STM32G0 a flash
      // erase/program STALLS the core (code runs from the same flash bank), so
      // for ~20-25 ms the G0 cannot service this I2C bus and will NACK. A NACK
      // here is NOT a failure — it means "busy in flash, come back". Poll
      // through NACKs until SIG_READY or the real timeout; only a genuine ERROR
      // aborts. (Fix: previously `break` here gave up the instant the status
      // read raced the flash-erase stall, which is why onboarding intermittently
      // failed at "G0 did not confirm keys".)
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_SIG_READY) {
        uint8_t buf[G0_SIG_LEN];
        if (g0_read_reg(G0_REG_SIG_OUT, buf, G0_SIG_LEN)) {
          // Constant-time compare is not required (the value is not secret),
          // but the check itself is: a stub that answers zeros must FAIL here.
          ok = (memcmp(buf, expect, 32) == 0);
          if (!ok) Serial.println("[G0] set_keys: acknowledgement mismatch - keys NOT confirmed stored");
        }
        break;
      }
      if (st == G0_ST_ERROR) break;
      delay(1);
    }
  } while (0);

  mbedtls_platform_zeroize(keys, sizeof(keys));
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  return ok;
}

bool g0_wipe_keys() {
  if (!s_present) return false;
  s_pubkeyOk = false; mbedtls_platform_zeroize(s_pubkey, 32);   // 27 Oct 2026
  bool ok = false; bool refused = false;
  bus_lock();
  do {
    if (!g0_cmd(G0_CMD_WIPEKEYS)) break;
    // 24 Sep 2026: WIPEKEYS is gated on the G0 - it runs WIPEALL over the relay
    // first and forgets K_SE only once the recovery object is off the SE. So
    // this call must PUMP the relay and allow WIPEALL's ~15 round trips.
    uint32_t start = millis(); int steps = 0;
    for (;;) {
      if (millis() - start > G0_BTC_POLL_TIMEOUT_MS) break;
      esp_task_wdt_reset();
      uint8_t st;
      if (!g0_status(&st)) { delay(3); continue; }
      if (st == G0_ST_NEED_RELAY) { if (++steps > 40) break; if (!g0_pump_relay()) break; continue; }
      if (st == G0_ST_BUSY) { delay(2); continue; }
      if (st == G0_ST_IDLE)  { ok = true; break; }
      if (st == G0_ST_ERROR) { refused = true; break; }
      delay(1);
    }
  } while (0);
  bus_unlock();
  if (refused) Serial.println("[G0] wipe keys: REFUSED - recovery object still on the SE (WIPEALL did not finish); keys kept");
  return ok;
}

// =============================================================================
// Emberwill driver (28 Oct 2026). 11cd: FAVILLA_EMBERWILL (release and bench).
// Talks to the Emberwill G0 image (g0w-ember, src/ember_glue.inc). Every
// Emberwill command answers SIG_READY with EM_OUT = rc (int8) | len (u16) |
// payload. No RESET is ever sent between Emberwill commands: a RESET makes
// the G0 forget a ceremony in progress (that is deliberate on the G0 side).
// =============================================================================
#ifdef FAVILLA_EMBERWILL
static const size_t EM_WIRE_BUF = 1300;
// Big bench buffers live in PSRAM, allocated on first use: internal RAM is what
// the TLS handshake (em sync) and WiFi need, and a bench build already has less.
static uint8_t* em_psram(size_t n) { return (uint8_t*)heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); }   // EM_OUT can be 3 + 1175 bytes (a sealed coupon blob)

static bool em_wire_big() {
  static bool done = false;
  if (!done) { Wire.setBufferSize(EM_WIRE_BUF); done = true; }
  return true;
}

// Poll one Emberwill command to completion, pumping the SE relay when the
// G0 asks (EM_SET fetches the seed, EM_PULSE the scalar). Caller holds the lock.
static bool em_run_locked(uint8_t cmd, int8_t* rc, uint8_t* payload, size_t cap, size_t* len, uint32_t tmo_ms) {
  static uint8_t* buf = nullptr; const size_t BUFN = 3 + 1200;
  *rc = -128; if (len) *len = 0;
  if (!buf && !(buf = em_psram(BUFN))) return false;
  if (!g0_cmd(cmd)) return false;
  uint32_t start = millis(); int steps = 0;
  for (;;) {
    if (millis() - start > tmo_ms) { Serial.printf("[EMB] cmd %02X: timeout\n", cmd); return false; }
    esp_task_wdt_reset();
    uint8_t st;
    if (!g0_status(&st)) { delay(3); continue; }
    if (st == G0_ST_NEED_RELAY) { if (++steps > G0_BTC_MAX_RELAY_STEPS) { Serial.println("[EMB] relay step guard"); return false; } if (!g0_pump_relay()) return false; continue; }
    if (st == G0_ST_BUSY) { delay(2); continue; }
    if (st == G0_ST_ERROR) { Serial.printf("[EMB] cmd %02X: G0 ERROR (refused by the door, or not an Emberwill G0)\n", cmd); return false; }
    if (st == G0_ST_SIG_READY) break;
    delay(1);
  }
  if (!g0_read_reg(0x1F, buf, 3)) return false;
  size_t n = (size_t)buf[1] | ((size_t)buf[2] << 8);
  if (n > BUFN - 3) return false;
  if (n && !g0_read_reg(0x1F, buf, 3 + n)) return false;
  *rc = (int8_t)buf[0];
  if (payload && n <= cap) memcpy(payload, buf + 3, n);
  if (len) *len = (n <= cap) ? n : 0;
  return true;
}

bool g0_em_cmd(uint8_t cmd, int8_t* rc, uint8_t* payload, size_t cap, size_t* len, uint32_t tmo_ms) {
  if (!s_present) return false;
  bus_lock(); em_wire_big();
  bool ok = em_run_locked(cmd, rc, payload, cap, len, tmo_ms);
  bus_unlock();
  return ok;
}

bool g0_em_write(uint8_t reg, const uint8_t* d, size_t n) {
  if (!s_present) return false;
  bus_lock(); em_wire_big();
  bool ok = g0_write_reg(reg, d, n);
  bus_unlock();
  return ok;
}

// Stage a variable item through EM_CHUNK: total (2) | index (2) | 64 bytes.
bool g0_em_stage(const uint8_t* d, size_t n) {
  if (n == 0 || n > 2048) return false;
  bool ok = true;
  bus_lock(); em_wire_big();
  for (size_t off = 0, i = 0; ok && off < n; off += 64, i++) {
    uint8_t c[68] = {0};
    c[0] = (uint8_t)n; c[1] = (uint8_t)(n >> 8); c[2] = (uint8_t)i; c[3] = (uint8_t)(i >> 8);
    memcpy(c + 4, d + off, (n - off < 64) ? n - off : 64);
    ok = g0_write_reg(0x1D, c, sizeof c);
  }
  bus_unlock();
  return ok;
}

bool g0_em_header(const uint8_t hdr80[80], bool quorum, int8_t* rc, uint8_t status96[96]) {
  uint8_t in[81]; memcpy(in, hdr80, 80); in[80] = quorum ? 1 : 0;
  size_t n = 0;
  if (!g0_em_write(0x1B, in, 81)) return false;
  return g0_em_cmd(0x30, rc, status96, 96, &n, 3000) && n == 96;
}

// The ceremony: EM_SET (seed packet from the spend session), then every
// signature as CER_INIT / CER_FIN with the host relation checked on each,
// blobs handed to `sink`, then EM_COMMIT. True only if all of it held.
bool g0_em_ceremony(const uint8_t set430[430], const uint8_t seedpkt[G0_SEED_IN_LEN], uint8_t kind,
                    bool (*sink)(uint16_t k, const uint8_t* blob, size_t n),
                    void (*progress)(unsigned s, unsigned nsig),
                    const EmCerHooks* hooks) {
  static uint8_t* out = nullptr; const size_t OUTN = 1200; size_t n = 0; int8_t rc = 0;
  if (!out && !(out = em_psram(OUTN))) return false;
  if (!hooks || !hooks->onSet || !hooks->onSig || !hooks->onDone) { Serial.println("[EMB] ceremony refused: no ceremony check"); return false; }
  auto abortCer = [&](const char* why) {   // 11cd: the G0 forgets the ceremony (account key, pending nonce); nothing is committed
    bus_lock(); g0_cmd(G0_CMD_RESET); bus_unlock();
    Serial.printf("[EMB] ceremony STOPPED by the ESP32's check: %s\n", why);
    return false;
  };
  uint32_t t0 = millis();
  if (s_aeFault) { Serial.println("[EMB] ceremony refused: ANTI-EXFIL FAULT latched this boot"); return false; }
  bus_lock(); em_wire_big();
  bool ok = g0_write_reg(kind == 1 ? G0_REG_ENT_IN : G0_REG_SEED_IN, seedpkt, G0_SEED_IN_LEN) &&
            g0_write_reg(0x1C, set430, 430) &&
            em_run_locked(0x31, &rc, out, OUTN, &n, 20000);
  bus_unlock();
  if (ok && rc == 0 && n == 2) return abortCer("this G0 is older than v20 (no ceremony check); flash the G0 first");
  if (!ok || rc != 0 || n != 6) { Serial.printf("[EMB] EM_SET failed: rc %d (payload %u bytes, first %02X)\n", rc, (unsigned)n, n ? out[0] : 0); return false; }
  unsigned ntx = out[0], nsig = out[1];
  const uint32_t tip0 = (uint32_t)out[2] | ((uint32_t)out[3] << 8) | ((uint32_t)out[4] << 16) | ((uint32_t)out[5] << 24);
  if (!hooks->onSet(tip0)) return abortCer("could not start the check (plan or keys)");
  Serial.printf("[EMB] EM_SET ok: %u transactions, %u signatures (%lu ms incl. seed fetch + building every transaction)\n",
                ntx, nsig, (unsigned long)(millis() - t0));
  unsigned blobs = 0, bad = 0; uint32_t ms_min = 0xFFFFFFFF, ms_max = 0, ms_sum = 0;
  for (unsigned s = 0; s < nsig; s++) {
    if (progress) progress(s + 1, nsig);
    uint8_t t[32], ae[64] = {0}, r0[33], r[32];
    if (!ae_draw_t(t)) return false;
    ae_host_commit(AE_KIND_ECDSA, t, ae + 32);
    uint32_t ts = millis(); unsigned k = 0, input = 0; size_t bl = 0;
    bus_lock();
    ok = g0_write_reg(G0_REG_AE_IN, ae, 64) && em_run_locked(0x32, &rc, out, OUTN, &n, 8000) && rc == 0 && n >= 70;
    bool checked = false;
    if (ok) { k = out[0] | (out[1] << 8); input = out[2]; memcpy(r0, out + 3, 33);
      // 11cd (v20): what is about to be signed, checked before the signature is made
      const size_t tl = (size_t)out[68] | ((size_t)out[69] << 8);
      ok = n == 70 + tl && hooks->onSig(k, input, out + 36, tl ? out + 70 : nullptr, tl);
      checked = !ok; }
    if (ok) ok = g0_write_reg(G0_REG_AE_T, t, 32) && em_run_locked(0x33, &rc, out, OUTN, &n, 8000) && rc == 0 && n >= 34;
    bus_unlock();
    if (!ok) { mbedtls_platform_zeroize(t, 32);
      if (checked) return abortCer("a transaction does not match the plan (see the line above)");
      Serial.printf("[EMB] signature %u: G0 refused (rc %d)\n", s, rc); return false; }
    memcpy(r, out, 32); bl = (size_t)out[32] | ((size_t)out[33] << 8);
    uint32_t dt = millis() - ts; ms_sum += dt; if (dt < ms_min) ms_min = dt; if (dt > ms_max) ms_max = dt;
#ifndef FAVILLA_BENCH_ANTIEXFIL_SKIP
    if (!ae_host_check(AE_KIND_ECDSA, r0, t, r)) { bad++; ae_fault("Emberwill ceremony: x(R0 + H(R0||t)G) != r"); }
#endif
    mbedtls_platform_zeroize(t, 32);
    Serial.printf("[EMB]   sig %2u: tx %u input %u  %lu ms  relation %s%s\n", s + 1, k, input, (unsigned long)dt,
                  bad ? "FAILED" : "ok", bl ? "  -> sealed blob" : "");
    if (bad) return false;
    if (bl) { if (sink && !sink((uint16_t)k, out + 34, bl)) { Serial.println("[EMB] blob store failed"); return false; } blobs++; }
  }
  if (blobs != ntx) { Serial.printf("[EMB] %u blobs for %u transactions\n", blobs, ntx); return false; }
  if (!hooks->onDone()) return abortCer("not every transaction was checked");
  bus_lock(); ok = em_run_locked(0x34, &rc, out, OUTN, &n, 8000) && rc == 0; bus_unlock();
  Serial.printf("[EMB] EM_COMMIT %s | %u signatures, every one passed the host relation | per signature %lu..%lu ms (mean %lu) | total %lu ms\n",
                ok ? "ok" : "FAILED", nsig, (unsigned long)ms_min, (unsigned long)ms_max, (unsigned long)(nsig ? ms_sum / nsig : 0),
                (unsigned long)(millis() - t0));
  return ok;
}

// EM_PULSE: the G0 builds the Pulse, signs it with anti-exfil (AE_FINISH as
// for any Nostr signature), the host checks the relation and BIP-340, then
// feeds it back through EM_LIFE as the owner's life.
bool g0_em_pulse(char* json_out, size_t cap, uint8_t id_out[32], uint8_t sig_out[64]) {
  static uint8_t* out = nullptr; const size_t OUTN = 1200; size_t n = 0; int8_t rc = 0;
  if (!out && !(out = em_psram(OUTN))) return false;
  if (s_aeFault) return false;
  if (!s_pubkeyOk) { uint8_t pk[32]; if (!g0_get_pubkey(pk)) { Serial.println("[EMB] pulse: no identity pubkey"); return false; } }
  uint8_t t[32], ae[64] = {0}, r0[33], sig[64], ser[256], id[32]; size_t sl;
  if (!ae_draw_t(t)) return false;
  ae_host_commit(AE_KIND_SCHNORR, t, ae + 32);
  uint32_t t0 = millis();
  bus_lock(); em_wire_big();             // held across INIT and FINISH: nothing else may touch the pending nonce
  bool ok = g0_write_reg(G0_REG_AE_IN, ae, 64) && em_run_locked(0x39, &rc, out, OUTN, &n, 8000) && rc == 0 && n > 35;
  if (ok) {
    memcpy(r0, out, 33); sl = (size_t)out[33] | ((size_t)out[34] << 8);
    ok = sl <= sizeof ser && sl + 35 <= n;
    if (ok) { memcpy(ser, out + 35, sl); ok = g0_ae_exchange(G0_REG_AE_T, t, 32, G0_CMD_AE_FINISH, sig, "pulse finish"); }
  } else Serial.printf("[EMB] EM_PULSE refused rc %d (no plan / owner not bound / more than one Quiet since the last PIN)\n", rc);
  if (!ok) g0_cmd(G0_CMD_RESET);
  bus_unlock();
  if (!ok) { mbedtls_platform_zeroize(t, 32); return false; }
  mbedtls_sha256(ser, sl, id, 0);
#ifndef FAVILLA_BENCH_ANTIEXFIL_SKIP
  if (!ae_host_check(AE_KIND_SCHNORR, r0, t, sig)) { mbedtls_platform_zeroize(t, 32); ae_fault("Pulse: x(R0 + H(R0||t)G) != R"); return false; }
  if (!schnorr_verify(s_pubkey, id, sig)) { mbedtls_platform_zeroize(t, 32); ae_fault("Pulse: BIP-340 verify failed"); return false; }
#endif
  mbedtls_platform_zeroize(t, 32);
  Serial.printf("[EMB] pulse built + signed in %lu ms, relation + BIP-340 ok\n", (unsigned long)(millis() - t0));
  // back in as life
  ok = g0_em_stage(ser, sl) && g0_em_write(0x1E, sig, 64) && g0_em_cmd(0x36, &rc, nullptr, 0, nullptr, 3000);
  Serial.printf("[EMB] EM_LIFE with the signed Pulse: %s (rc %d)\n", ok && rc == 0 ? "accepted" : "REFUSED", rc);
  if (json_out && cap) { size_t m = sl < cap - 1 ? sl : cap - 1; memcpy(json_out, ser, m); json_out[m] = 0; }
  if (id_out) memcpy(id_out, id, 32);
  if (sig_out) memcpy(sig_out, sig, 64);
  return ok && rc == 0;
}
#endif  // FAVILLA_EMBERWILL
