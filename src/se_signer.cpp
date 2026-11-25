// ============================================================
// se_signer.cpp — Favilla KEY V22.1 SE051 driver implementation
//
// Implemented through M7 Step 3:
//   - se_init / se_is_ready                      (Step 1)
//   - se_object_exists                           (Step 1)
//   - se_aes_wrap_block / se_aes_unwrap_block    (Step 1)
//   - se_pin_session_open/close/is_open          (Step 2; stub until Step 5)
//   - seed_store / seed_unwrap_to_ram /
//     seed_is_provisioned / seed_erase_from_nvs  (Step 2)
//   - se_schnorr_sign                            (Step 3)
//
// Stubbed (return false, log clear message) until later steps:
//   - se_ecdh                                    ← Step 4
//   - se_provision_*                             ← Step 6
//
// All low-level plumbing (I²C, T=1' framing, APDU build/parse) is
// in an anonymous namespace and does not leak into other TUs. This
// is the canonical M6.4 bring-up code, lifted verbatim and module-
// scoped — no behavioural changes.
//
// ============================================================

#include "se_signer.h"
#include <Wire.h>
#include <Preferences.h>
#include "nv_domains.h"   // NVSPART_SEC - seed blob lives in the security partition
#include <esp_system.h>
#include <esp_task_wdt.h>   // bench probes (ec_gate_probe.inc) feed the watchdog in long SE loops
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "secp256k1.h"   // schnorr_sign (retained for other callers; NOT used for Nostr)
#include "g0_signer.h"   // isolated Nostr signer — see se_schnorr_sign / se_provision_nostr_scalar
void dispAntiExfilFaultForever();   // main.cpp, 27 Oct 2026: SIGNER FAULT screen on an anti-exfil mismatch

namespace favilla {
// v5.1 generation ids (se_signer.h). Start at SE_GEN_NONE: until the G0 says
// which generation is live, every id points at an unused range, so a lookup
// reads "absent" and the device routes to onboarding instead of half-trusting
// objects of an old generation.
static uint8_t  g_gen = SE_GEN_NONE;
static inline uint32_t genId(uint32_t base, uint8_t g) { return base + ((uint32_t)g << 8); }
uint32_t SE_OBJ_AES_WRAP       = genId(0x20000020u, SE_GEN_NONE);
uint32_t SE_OBJ_AES_WRAP_SEED  = genId(0x20000020u, SE_GEN_NONE);
uint32_t SE_OBJ_AES_WRAP_DAILY = genId(0x20000022u, SE_GEN_NONE);
uint32_t SE_OBJ_NOSTR_SCALAR   = genId(0x20000002u, SE_GEN_NONE);
uint32_t SE_AUTH_OBJ_G0        = genId(0x20000030u, SE_GEN_NONE);
uint32_t SE_AUTH_OBJ_RECOVER   = genId(0x20000035u, SE_GEN_NONE);
uint32_t SE_OBJ_PCR_UNLOCK     = genId(0x20000031u, SE_GEN_NONE);
uint32_t SE_OBJ_DOOR1_SECRET   = genId(0x20000036u, SE_GEN_NONE);
uint32_t SE_OBJ_NSEC_IMPORT    = genId(0x20000003u, SE_GEN_NONE);
uint32_t SE_OBJ_USER_PIN       = genId(0x70000003u, SE_GEN_NONE);
uint32_t SE_OBJ_PIN_DAILY      = genId(0x70000003u, SE_GEN_NONE);
uint32_t SE_OBJ_PIN_SPEND      = genId(0x70000005u, SE_GEN_NONE);
uint32_t SE_OBJ_PIN_PASSKEY    = genId(0x70000007u, SE_GEN_NONE);   // 30 Oct 2026: passkey door PIN
uint32_t SE_OBJ_PK_SCRATCH     = genId(0x20000037u, SE_GEN_NONE);   // 30 Oct 2026: restorable passkeys scratch key (G0 only)
uint32_t SE_OBJ_PK_MASTER      = genId(0x20000038u, SE_GEN_NONE);   // 30 Oct 2026: restorable passkeys master S_pk, sealed. 2b: the NOSTR copy, under K_PKN
uint32_t SE_OBJ_K_PK           = genId(0x20000039u, SE_GEN_NONE);   // 2 Nov 2026 (2b): outer key of the PASSKEY copy
uint32_t SE_OBJ_K_PKN          = genId(0x2000003Au, SE_GEN_NONE);   // 2 Nov 2026 (2b): outer key of the NOSTR copy (the gate)
uint32_t SE_OBJ_PK_MASTER_P    = genId(0x2000003Bu, SE_GEN_NONE);   // 2 Nov 2026 (2b): the PASSKEY copy of the master
uint32_t SE_OBJ_VPUB           = genId(0x2000003Cu, SE_GEN_NONE);   // 2 Nov 2026 (phase 3): the vault backup publishing key copy
uint32_t SE_OBJ_K_IXN          = genId(0x2000003Du, SE_GEN_NONE);   // 3 Nov 2026 (P4-10): AES, wraps the site index key for the NOSTR life (exists only while the gate is open)
uint16_t g_lastCreateSessionSW = 0;   // 25 Sep 2026: 6986 at CreateSession = auth object LOCKED (silicon fact #6)

// ============================================================
// Internal-only plumbing
// ============================================================
namespace {

// ── SE051 wire constants ─────────────────────────────────────
constexpr uint8_t SE051_ADDR = 0x48;

// Shared-I2C-bus lock hooks (set by main.cpp via se_set_bus_lock). Null on the
// bench (no other I2C masters), so calls are guarded.
void (*g_busLock)()   = nullptr;
void (*g_busUnlock)() = nullptr;

constexpr uint8_t NAD_HOST_TO_SE = 0x5A;
constexpr uint8_t NAD_SE_TO_HOST = 0xA5;
constexpr uint8_t PCB_IBLOCK_NS0 = 0x00;
constexpr uint8_t PCB_IBLOCK_NS1 = 0x40;

constexpr uint8_t INS_WRITE  = 0x01;
constexpr uint8_t INS_READ   = 0x02;
constexpr uint8_t INS_CRYPTO = 0x03;
constexpr uint8_t INS_MGMT   = 0x04;

constexpr uint8_t P1_DEFAULT = 0x00;
constexpr uint8_t P1_BINARY  = 0x06;
constexpr uint8_t P1_CIPHER  = 0x0E;

constexpr uint8_t P2_DEFAULT         = 0x00;
constexpr uint8_t P2_DELETE_OBJECT   = 0x28;
constexpr uint8_t P2_ENCRYPT_ONESHOT = 0x37;
constexpr uint8_t P2_DECRYPT_ONESHOT = 0x38;

constexpr uint8_t AES_CBC_NOPAD = 0x0D;

// M5 session/PIN APDU constants (verbatim from M5 bringup, AN12543)
constexpr uint8_t INS_PROCESS       = 0x05;
constexpr uint8_t INS_AUTH_OBJECT   = 0x40;
constexpr uint8_t P1_USERID         = 0x07;
constexpr uint8_t P2_SESSION_CREATE = 0x1B;
constexpr uint8_t P2_SESSION_CLOSE  = 0x1C;
constexpr uint8_t P2_SESSION_USERID = 0x2C;
constexpr uint8_t P2_DELETE_ALL     = 0x2A;   // AN12413 Tab.274 / AN12543 Tab.339: DeleteAll = 80 04 00 2A
                                              // (was 0x06 — wrong, the SE answered 6B00 "wrong P1/P2")
constexpr uint8_t P2_RANDOM         = 0x49;   // AN12543 §4.x: GetRandom (TRNG → host)
constexpr uint8_t TAG_SESSION_ID    = 0x10;
constexpr uint8_t TAG_POLICY        = 0x11;
constexpr uint8_t TAG_MAX_ATTEMPTS  = 0x12;

constexpr uint8_t TAG_1 = 0x41;
constexpr uint8_t TAG_2 = 0x42;
constexpr uint8_t TAG_3 = 0x43;
constexpr uint8_t TAG_4 = 0x44;

// Policy access-right bits (AN12543 §3.x). A policy entry grants the
// listed permissions to an auth object identified by ID. Self-policy
// (entry where authObjId == the object's own ID) controls what the
// object's own authenticated session is permitted to do.
constexpr uint32_t POLICY_OBJ_ALLOW_READ   = 0x00200000UL;
constexpr uint32_t POLICY_OBJ_ALLOW_WRITE  = 0x00100000UL;
constexpr uint32_t POLICY_OBJ_ALLOW_DELETE = 0x00040000UL;
// AN12543 Rev 4.5 Table 63 — symmetric-key crypto-use rights. Used to bind
// the AES wrap key's CipherOneShot to the user PIN session (V1 Path-1 fix).
constexpr uint32_t POLICY_OBJ_ALLOW_ENC    = 0x02000000UL;  // allow encryption
constexpr uint32_t POLICY_OBJ_ALLOW_DEC    = 0x01000000UL;  // allow decryption
// NXP Plug & Trust se05x_const.h — the AND-gate bit. An entry carrying it is
// the extended form [len=0x2C][auth:4][rules:4][PCR id:4][expected value:32]
// (AN12543 3.7.1.2) and is satisfied only for THAT auth object's session AND
// only while the PCR equals the expected value. Confirmed on silicon Jul 2026.
constexpr uint32_t POLICY_OBJ_REQUIRE_PCR_VALUE = 0x00010000UL;


// ── Isolated-signer (G0) constants ──────────────────────────
constexpr uint8_t  INS_TRANSIENT = 0x80;   // OR'd into INS: object lives in transient memory
constexpr uint8_t  P1_AES        = 0x03;
constexpr uint8_t  P1_PCR        = 0x09;   // kSE05x_P1_PCR

// PCR lifecycle (semantics reverse-engineered from the July run's readback):
//   created with initial value I  -> at rest the PCR reads SHA256(I)
//   extend with X                 -> PCR = SHA256(PCR || X)
//   reset (WritePCR, TAG_1 only)  -> back to SHA256(I)
// "Unlocked" is SHA256(SHA256(I) || X). Until v5 X was a public constant and
// the gate was only WHO may extend. v5.1: X is derived from a secret only the
// daily PIN can read (SE_OBJ_DOOR1_SECRET), so the G0 can also be given
// extend (to lock at boot) without being able to unlock.
constexpr uint8_t PCR_INITIAL[32] = {0};
// v5.1: PCR_UNLOCK_CONST (the public unlock extend) is gone; see door1ReadX.

// ── Two-door MODE gate (NOSTR/BTC) ──────────────────────────
// The mode latch PCR (persistent, 2-PIN policy) and its three values. Defined
// HERE (early, in this scope) because the wrap-key provisioner and
// se_pin_destroy below reference them; the APDU-level create/extend/read
// functions that need the file-local helpers live in mode_pcr.inc, included
// at the end of the file. Values are not secret — the gate is WHO may extend.
uint32_t SE_OBJ_PCR_MODE_FWD = 0x20000033u + ((uint32_t)SE_GEN_NONE << 8);   // v5.1: per generation, set by se_set_generation
static const uint8_t MODE_CONST_NOSTR[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','N','O','S','T','R',0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
static const uint8_t MODE_CONST_BTC[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','B','T','C',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
static uint8_t g_mode_neutral[32];   // SHA256(PCR_INITIAL)  = at rest / NEUTRAL
static uint8_t g_mode_nostr[32];     // SHA256(NEUTRAL || MODE_CONST_NOSTR)
static uint8_t g_mode_btc[32];       // SHA256(NEUTRAL || S)  — S is the G0's secret (16 Sep 2026)
static bool    g_mode_vals_valid = false;
static bool    g_mode_btc_from_g0 = false;   // true once g_mode_btc is the S-derived value
// Passkey door (30 Oct 2026): V_3 = SHA256(NEUTRAL || S_3), S_3 = SHA256(S ||
// "FAVILLA-DOOR" || 0x03) - the value the G0's MODEDOOR mints in a PASSKEY
// life. Derived from S at onboarding (the only time this chip holds S) and
// persisted next to the BTC value as "pkval". Public, like the BTC value: it is
// in every credential key's policy. Only the G0 can make the latch read it.
static uint8_t g_mode_pk[32];
static bool    g_mode_pk_valid = false;
static const char* MODE_KEY_PK = "pkval";
// ── BTC-door secret (16 Sep 2026) ────────────────────────────────────────────
// Why: with BTC = SHA256(NEUTRAL || public label) the spend PIN's WRITE right
// let the ESP32 extend to BTC on its own, so the SE only ever required that the
// G0 had reset the latch at SOME point in the past. Josh's ruling: the SE must
// not open the BTC path unless the G0 acted in THIS power cycle, and an RCE
// must not be able to fake that. So BTC is now derived from a 32-byte secret S
// that is generated here at onboarding, delivered to the G0 with its other
// keys (SETKEYS), and zeroised. The ESP32 keeps only the VALUE (public; it is
// literally in the seed key's policy) so it can verify the latch; it cannot
// produce it — only the G0's extend-with-S can, once per physical boot.
static uint8_t g_mode_secret_pending[32];
static bool    g_mode_secret_pending_valid = false;
static bool    g_mode_secret_delivered = false;   // v3: S reached the G0 this onboarding (SETKEYS acked); the value is satisfiable
static const char* MODE_NS  = "mode";
static const char* MODE_KEY = "btcval";
static void modeExt(const uint8_t base[32], const uint8_t k[32], uint8_t out[32]) {
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, base, 32); mbedtls_sha256_update(&c, k, 32);
  mbedtls_sha256_finish(&c, out); mbedtls_sha256_free(&c);
}
static void modeComputeValues() {
  mbedtls_sha256(PCR_INITIAL, 32, g_mode_neutral, 0);
  modeExt(g_mode_neutral, MODE_CONST_NOSTR, g_mode_nostr);
  // BTC: the S-derived value persisted at onboarding, if any. The label-based
  // value is kept ONLY as a fallback so pre-16-Sep units keep working until
  // they are re-onboarded; it is logged as such.
  Preferences p;
  bool have = false;
  if (p.begin(MODE_NS, true, NVSPART_SEC)) {
    if (p.getBytesLength(MODE_KEY) == 32) { p.getBytes(MODE_KEY, g_mode_btc, 32); have = true; }
    p.end();
  }
  if (!have) {
    modeExt(g_mode_neutral, MODE_CONST_BTC, g_mode_btc);
    Serial.println("[MODEPCR] BTC value is the LEGACY public-label value (no G0 secret provisioned) - re-onboard");
  }
  g_mode_btc_from_g0 = have;
  g_mode_pk_valid = false;
  if (p.begin(MODE_NS, true, NVSPART_SEC)) {
    if (p.getBytesLength(MODE_KEY_PK) == 32) { p.getBytes(MODE_KEY_PK, g_mode_pk, 32); g_mode_pk_valid = true; }
    p.end();
  }
  g_mode_vals_valid = true;
}
static void modeBtcSecretForget() {
  mbedtls_platform_zeroize(g_mode_secret_pending, 32);
  g_mode_secret_pending_valid = false;
}
static uint8_t g_pcr_at_rest[32];           // SHA256(PCR_INITIAL) — "locked"
static uint8_t g_pcr_unlocked[32];          // v5.1: SHA256(at_rest || X), X from SE_OBJ_DOOR1_SECRET (daily-read only)
static bool    g_pcr_unlocked_valid = false;   // v5.1: only after a daily session read the secret (or onboarding minted it)

// ── Module state ─────────────────────────────────────────────
bool    g_initialised      = false;
bool    g_ready            = false;
bool    g_pin_session_open = false;   // Step 6 (M5): real session
uint8_t g_session_id[8]    = {0};     // SE session handle while PIN session is open
uint32_t g_session_obj     = 0;       // Two-door: which PIN obj this session auths (0=none)
uint8_t g_t1_seq           = 0;

// ── NVS namespace for seed storage (Strategy A) ──────────────
// Separate namespace from V22's existing wallet data ("wallet")
// so the SE-backed seed coexists with the legacy ATECC-encrypted
// seed during Steps 1–4. Step 5 deletes the ATECC path entirely.
constexpr const char* NVS_NS       = "favilla_se";
constexpr const char* NVS_KEY_SEED = "seed_blob";
constexpr const char* NVS_KEY_SEEDKIND = "seed_kind";   // v4: 0 seed blob, 1 entropy container

// Wrapped seed layout: 2× (IV(16) || CT(32)) = 96 bytes
constexpr size_t SEED_BLOB_LEN = 2 * SE_BLOB_TOTAL_LEN;

// ── CRC16-X.25 for T=1' framing ──────────────────────────────
uint16_t crc16_x25(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int b = 0; b < 8; b++) {
      if (crc & 1) crc = (crc >> 1) ^ 0x8408;
      else         crc >>= 1;
    }
  }
  return ~crc;
}

// ── I²C retry-wrapped read/write ─────────────────────────────
bool i2cWriteRetry(const uint8_t *buf, size_t len, uint32_t timeout_ms) {
  uint32_t t0 = millis();
  do {
    Wire.beginTransmission(SE051_ADDR);
    Wire.write(buf, len);
    if (Wire.endTransmission() == 0) return true;
    delay(1);
  } while (millis() - t0 < timeout_ms);
  return false;
}

size_t i2cReadRetry(uint8_t *buf, size_t want, uint32_t timeout_ms) {
  uint32_t t0 = millis();
  do {
    size_t got = Wire.requestFrom((int)SE051_ADDR, (int)want);
    if (got == want) {
      for (size_t i = 0; i < want; i++) buf[i] = Wire.read();
      return got;
    }
    delay(1);
  } while (millis() - t0 < timeout_ms);
  return 0;
}

// ── T=1' PCB classification ──────────────────────────────────
bool pcb_is_iblock(uint8_t pcb) { return (pcb & 0x80) == 0x00; }
bool pcb_is_sblock(uint8_t pcb) { return (pcb & 0xC0) == 0xC0; }
bool pcb_is_sblock_request(uint8_t pcb) {
  return pcb_is_sblock(pcb) && ((pcb & 0x20) == 0x00);
}

// ── T=1' frame send/recv ─────────────────────────────────────
bool t1SendIBlock(const uint8_t *inf, size_t infLen) {
  uint8_t frame[300];
  frame[0] = NAD_HOST_TO_SE;
  frame[1] = (g_t1_seq & 1) ? PCB_IBLOCK_NS1 : PCB_IBLOCK_NS0;
  frame[2] = (uint8_t)infLen;
  if (infLen) memcpy(frame + 3, inf, infLen);
  uint16_t crc = crc16_x25(frame, 3 + infLen);
  frame[3 + infLen]     = crc & 0xFF;
  frame[3 + infLen + 1] = (crc >> 8) & 0xFF;
  g_t1_seq ^= 1;
  return i2cWriteRetry(frame, 3 + infLen + 2, 100);
}

bool t1SendSBlock(uint8_t subtype, bool isResponse,
                  const uint8_t *inf, size_t infLen) {
  uint8_t frame[64];
  frame[0] = NAD_HOST_TO_SE;
  frame[1] = 0xC0 | (isResponse ? 0x20 : 0x00) | (subtype & 0x1F);
  frame[2] = (uint8_t)infLen;
  if (infLen) memcpy(frame + 3, inf, infLen);
  uint16_t crc = crc16_x25(frame, 3 + infLen);
  frame[3 + infLen]     = crc & 0xFF;
  frame[3 + infLen + 1] = (crc >> 8) & 0xFF;
  return i2cWriteRetry(frame, 3 + infLen + 2, 100);
}

int t1RecvRawFrame(uint8_t *outPcb, uint8_t *infBuf, size_t infMax) {
  uint8_t header[3];
  if (i2cReadRetry(header, 3, 1500) != 3) return -1;
  if (header[0] != NAD_SE_TO_HOST) return -1;
  size_t infLen = header[2];
  // 11bl (issue #43): T=1 caps LEN at 254, and tail holds the body and the two
  // CRC bytes. A frame claiming 255 wrote one byte past tail[256] before.
  if (infLen > 254 || infLen > infMax) return -1;
  uint8_t tail[254 + 2];
  if (i2cReadRetry(tail, infLen + 2, 1500) != infLen + 2) return -1;
  // 11bl (issue #43): the frame's CRC (X.25 over NAD, PCB, LEN and the body,
  // low byte first, as t1SendFrame writes it and NXP's T=1 reads it) is checked
  // before the frame is used; a corrupted or injected answer is refused.
  {
    uint8_t fr[3 + 254];
    memcpy(fr, header, 3);
    if (infLen) memcpy(fr + 3, tail, infLen);
    const uint16_t crc = crc16_x25(fr, 3 + infLen);
    const uint16_t got = (uint16_t)tail[infLen] | ((uint16_t)tail[infLen + 1] << 8);
    if (crc != got) return -1;
  }
  *outPcb = header[1];
  if (infLen) memcpy(infBuf, tail, infLen);
  return (int)infLen;
}

int t1RecvIBlock(uint8_t *inf, size_t infMax) {
  for (int attempt = 0; attempt < 8; attempt++) {
    uint8_t pcb;
    uint8_t tmp[260];
    int n = t1RecvRawFrame(&pcb, tmp, sizeof(tmp));
    if (n < 0) return -1;
    if (pcb_is_iblock(pcb)) {
      if ((size_t)n > infMax) return -1;
      memcpy(inf, tmp, n);
      return n;
    }
    if (pcb_is_sblock_request(pcb)) {
      t1SendSBlock(pcb & 0x1F, true, tmp, n);
      continue;
    }
    return -1;
  }
  return -1;
}

bool t1TrySync() {
  for (int i = 0; i < 5; i++) {
    if (!t1SendSBlock(0x00, false, nullptr, 0)) { delay(20); continue; }
    uint8_t pcb;
    uint8_t inf[64];
    int n = t1RecvRawFrame(&pcb, inf, sizeof(inf));
    if (n >= 0 && pcb_is_sblock(pcb)) {
      g_t1_seq = 0;
      return true;
    }
    delay(20);
  }
  return false;
}

// ── APDU wrappers ────────────────────────────────────────────
int sendAPDU(const uint8_t *apdu, size_t apduLen,
             uint8_t *resp, size_t respMax) {
  // Hold the shared-I2C-bus lock for the ENTIRE T=1 exchange (send I-block +
  // receive I-block). Without this, another I2C peripheral (battery gauge,
  // haptics, expander) can transact between our send and recv, corrupting the
  // SE's T=1 framing → n=-1 / 6D00 failures. See se_set_bus_lock.
  if (g_busLock) g_busLock();
  bool sent = t1SendIBlock(apdu, apduLen);
  if (!sent) { if (g_busUnlock) g_busUnlock(); return -1; }
  int n = t1RecvIBlock(resp, respMax);
  if (g_busUnlock) g_busUnlock();
  return n;
}

size_t appendTLV(uint8_t *buf, size_t pos, size_t bufMax,
                 uint8_t tag, const uint8_t *val, size_t valLen) {
  if (pos + 2 + valLen + 2 > bufMax) return pos;
  buf[pos++] = tag;
  if (valLen < 0x80) {
    buf[pos++] = (uint8_t)valLen;
  } else {
    buf[pos++] = 0x81;
    buf[pos++] = (uint8_t)valLen;
  }
  memcpy(buf + pos, val, valLen);
  return pos + valLen;
}

size_t buildAPDU(uint8_t *out, size_t outMax,
                 uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                 const uint8_t *data, size_t dataLen, bool hasLe) {
  out[0] = cla; out[1] = ins; out[2] = p1; out[3] = p2;
  size_t pos = 4;
  if (dataLen > 0) {
    if (dataLen < 0x100) {
      out[pos++] = (uint8_t)dataLen;
    } else {
      out[pos++] = 0x00;
      out[pos++] = (dataLen >> 8) & 0xFF;
      out[pos++] = dataLen & 0xFF;
    }
    memcpy(out + pos, data, dataLen);
    pos += dataLen;
  }
  if (hasLe) out[pos++] = 0x00;
  return pos;
}

bool checkSW(const uint8_t *resp, int n, const char *what) {
  if (n < 2) { Serial.printf("[SE051] SW err %s (n=%d)\n", what, n); return false; }
  uint16_t sw = (resp[n-2] << 8) | resp[n-1];
  if (sw != 0x9000) { Serial.printf("[SE051] SW %s = %04X\n", what, sw); return false; }
  return true;
}

int parseTLVLength(const uint8_t *tlv, size_t tlvLen, size_t *outOffset) {
  if (tlvLen < 2) return -1;
  uint8_t first = tlv[1];
  if (first < 0x80) { *outOffset = 2; return first; }
  if (first == 0x81 && tlvLen >= 3) { *outOffset = 3; return tlv[2]; }
  if (first == 0x82 && tlvLen >= 4) { *outOffset = 4; return (tlv[2] << 8) | tlv[3]; }
  return -1;
}

bool selectIoTApplet() {
  // AID for the NXP IoT Applet — same on all SE050/SE051 variants
  static const uint8_t AID[] = {
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00
  };
  uint8_t apdu[40];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x00, 0xA4, 0x04, 0x00,
                              AID, sizeof(AID), true);
  uint8_t resp[64];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (!checkSW(resp, n, "SELECT")) return false;

  // The SELECT response carries the applet version info. The exact
  // TLV structure varies by applet release; for the V22.1 boot log
  // we report what M6.4 confirmed on this bench: applet 7.2.0,
  // AppletConfig 0x3FFF.
  //
  // DIAG (variant ID): dump the raw SELECT response so we can see the
  // actual version/config bytes this chip returns, instead of trusting
  // the static line below. se_print_variant() (called from se_init) does
  // the authoritative OEF-ID read via the Get-Version APDU.
  Serial.printf("[SE051] SELECT resp (%d bytes): ", n);
  for (int i = 0; i < n; i++) Serial.printf("%02X ", resp[i]);
  Serial.println();

  Serial.println("[SE051] Applet: 7.2.0  AppletConfig: 0x3FFF  (static log — see OEF ID below for true variant)");
  return true;
}

// ── Variant identifier (OEF ID) readout ──────────────────────────────
// Reads the SE05x applet "Get Version" data, which contains the OEF ID
// that distinguishes the orderable variant per NXP AN12973 Table 4:
//   A920 = SE051A2   (applet 7.2, lean — no RSA/EdDSA/cloud keys)
//   A8FA = SE051C2   (applet 7.2, cloud config — RSA/EdDSA/cloud keys)
//   A565 = SE051A2   (older applet 6.0)
//   A564 = SE051C2   (older applet 6.0)
//   A739 = SE051W2,  B36A = SE051H2
// This is the authoritative variant source — the boot AppletConfig line
// is hardcoded and does NOT identify the variant. Logs to serial only.
void se_print_variant() {
  // Get Version: CLA=0x80 INS=0x04 P1=0x00 P2=0x0B, Le present.
  uint8_t apdu[8];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, 0x04, 0x00, 0x0B,
                              nullptr, 0, true);
  uint8_t resp[64];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (n < 2) { Serial.println("[SE051] variant read: no response"); return; }

  Serial.printf("[SE051] GetVersion resp (%d bytes): ", n);
  for (int i = 0; i < n; i++) Serial.printf("%02X ", resp[i]);
  Serial.println();

  if (!checkSW(resp, n, "GetVersion")) return;

  // The version data is returned as a TLV (tag 0x41 on the IoT applet)
  // whose value ends with a 2-byte OEF ID. Rather than assume the exact
  // offset across applet revisions, scan for the known 2-byte OEF IDs in
  // the payload (excluding the trailing SW1SW2).
  struct { uint16_t oef; const char* name; } known[] = {
    { 0xA920, "SE051A2 (applet 7.2) — LEAN, recommended for Favilla" },
    { 0xA8FA, "SE051C2 (applet 7.2) — CLOUD config (RSA/EdDSA/cloud keys)" },
    { 0xA565, "SE051A2 (applet 6.0)" },
    { 0xA564, "SE051C2 (applet 6.0)" },
    { 0xA739, "SE051W2 (UWB)" },
    { 0xB36A, "SE051H2 (Matter/NFC)" },
  };
  int body = n - 2;  // strip SW1SW2
  bool found = false;
  for (int i = 0; i + 1 < body && !found; i++) {
    uint16_t v = (uint16_t)((resp[i] << 8) | resp[i + 1]);
    for (auto& k : known) {
      if (v == k.oef) {
        Serial.printf("[SE051] OEF ID 0x%04X => %s\n", v, k.name);
        found = true;
        break;
      }
    }
  }
  if (!found)
    Serial.println("[SE051] OEF ID not matched — inspect GetVersion bytes above "
                   "(compare against AN12973 Table 4)");
}

// ── Object existence probe ───────────────────────────────────
bool readObjectShallow(uint32_t obj_id, int *out_bodyLen) {
  uint8_t payload[16]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(obj_id >> 24), (uint8_t)(obj_id >> 16),
    (uint8_t)(obj_id >>  8), (uint8_t) obj_id
  };
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  uint8_t apdu[32];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_READ, P1_DEFAULT, P2_DEFAULT,
                              payload, p, true);
  uint8_t resp[96];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (n < 2) return false;
  uint16_t sw = (resp[n-2] << 8) | resp[n-1];
  if (sw != 0x9000) return false;
  if (out_bodyLen) *out_bodyLen = n - 2;
  return true;
}

// Forward declaration — processSessionCmd is defined later in this file
// (with the other session helpers) but aesOneShot needs it to route the
// PIN-bound CipherOneShot through the authenticated session.
int processSessionCmd(const uint8_t sessionId[8],
                      const uint8_t *innerApdu, size_t innerLen,
                      uint8_t *outResp, size_t outRespMax);
bool   deleteInSession(const uint8_t sessionId[8], uint32_t objId);
size_t buildPolicyEntry(uint8_t *out, size_t pos, size_t outMax,
                        uint32_t authObjId, uint32_t accessRights);
size_t buildPolicyEntryPcr(uint8_t *out, size_t pos, size_t outMax,
                           uint32_t authObjId, uint32_t accessRights,
                           uint32_t pcrId, const uint8_t expected[32]);

// ── AES CipherOneShot (shared by wrap_block / unwrap_block) ──
// Two-door: keyObjId selects which wrap key (SEED=spend-bound or DAILY-bound).
// The SE enforces the per-key PIN binding — the open session must match the
// key's policy or the SE returns 6985/6986.
bool aesOneShot(uint32_t keyObjId, uint8_t p2,
                const uint8_t in[32], const uint8_t iv[16],
                uint8_t out[32]) {
  uint8_t payload[128]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(keyObjId >> 24), (uint8_t)(keyObjId >> 16),
    (uint8_t)(keyObjId >>  8), (uint8_t) keyObjId
  };
  uint8_t mode = AES_CBC_NOPAD;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, &mode, 1);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, in,  32);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, iv,  16);
  // Build the CipherOneShot as an INNER APDU. The AES wrap key's policy
  // binds ENC/DEC to the SE_OBJ_USER_PIN session (V1 Path-1), so the SE
  // silicon requires this command to arrive INSIDE the authenticated
  // session. Sending it anonymously (the old behaviour) returns 6986.
  // Route it through processSessionCmd with the live session handle.
  uint8_t innerApdu[160];
  size_t innerLen = buildAPDU(innerApdu, sizeof(innerApdu),
                              0x80, INS_CRYPTO, P1_CIPHER, p2,
                              payload, p, true);
  const char *what = (p2 == P2_ENCRYPT_ONESHOT) ? "aes_wrap" : "aes_unwrap";
  if (!g_pin_session_open) {
    Serial.printf("[SE051] %s: no PIN session (CipherOneShot is session-bound)\n", what);
    return false;
  }
  uint8_t resp[80];
  int n = processSessionCmd(g_session_id, innerApdu, innerLen, resp, sizeof(resp));
  if (!checkSW(resp, n, what)) return false;
  size_t bodyLen = (size_t)n - 2;
  if (bodyLen < 2 || resp[0] != TAG_1) return false;
  size_t valOffset;
  int valLen = parseTLVLength(resp, bodyLen, &valOffset);
  if (valLen != 32) return false;
  memcpy(out, resp + valOffset, 32);
  return true;
}

// ── AES CipherOneShot, ANONYMOUS (no PIN session) ────────────
// Path-A device-identity primitive. Targets SE_OBJ_PAIR_WRAP, whose policy
// grants ENC/DEC to the NO-AUTH auth object (0x00000000) — so the SE silicon
// accepts this command sent as a plain top-level APDU, with NO authenticated
// session. This is what makes deviceIdentityInit() work while LOCKED.
//
// Deliberately a SEPARATE function from aesOneShot(): the PIN-bound path that
// protects the Nostr scalar and BIP-39 seed is proven and must not gain a code
// path that could ever route those objects anonymously. This function is hard-
// wired to SE_OBJ_PAIR_WRAP and is never called with any other object id.
bool aesOneShotAnon(uint8_t p2,
                    const uint8_t in[32], const uint8_t iv[16],
                    uint8_t out[32]) {
  if (!g_ready) {
    Serial.println("[SE051] pair_wrap: SE not ready");
    return false;
  }
  uint8_t payload[128]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(SE_OBJ_PAIR_WRAP >> 24), (uint8_t)(SE_OBJ_PAIR_WRAP >> 16),
    (uint8_t)(SE_OBJ_PAIR_WRAP >>  8), (uint8_t) SE_OBJ_PAIR_WRAP
  };
  uint8_t mode = AES_CBC_NOPAD;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, &mode, 1);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, in,  32);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, iv,  16);

  uint8_t apdu[160];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                             0x80, INS_CRYPTO, P1_CIPHER, p2,
                             payload, p, true);
  const char *what = (p2 == P2_ENCRYPT_ONESHOT) ? "pair_wrap" : "pair_unwrap";
  uint8_t resp[80];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (!checkSW(resp, n, what)) return false;
  size_t bodyLen = (size_t)n - 2;
  if (bodyLen < 2 || resp[0] != TAG_1) return false;
  size_t valOffset;
  int valLen = parseTLVLength(resp, bodyLen, &valOffset);
  if (valLen != 32) return false;
  memcpy(out, resp + valOffset, 32);
  return true;
}

// ── Fresh IV generation ──────────────────────────────────────
// Uses esp_random() which is hardware-RNG backed on ESP32-S3.
// 16 bytes filled from four 32-bit pulls.
void freshIV(uint8_t iv[16]) {
  for (int i = 0; i < 16; i += 4) {
    uint32_t r = esp_random();
    iv[i+0] = (r      ) & 0xFF;
    iv[i+1] = (r >>  8) & 0xFF;
    iv[i+2] = (r >> 16) & 0xFF;
    iv[i+3] = (r >> 24) & 0xFF;
  }
}


// ============================================================
// Provisioning and M5 PIN session helpers (used by public functions below)
// ============================================================

bool tryDeleteObject_internal(uint32_t obj_id) {
  uint8_t payload[8]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(obj_id >> 24), (uint8_t)(obj_id >> 16),
    (uint8_t)(obj_id >>  8), (uint8_t) obj_id
  };
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  uint8_t apdu[32];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_MGMT, P1_DEFAULT, P2_DELETE_OBJECT,
                              payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (n < 2) { Serial.printf("[SE051] delete 0x%08lx: no response\n",(unsigned long)obj_id); return false; }
  uint8_t sw1 = resp[n-2], sw2 = resp[n-1];
  // Accept "deleted", "not found", and "conditions not satisfied" (object
  // exists but type doesn't permit deletion via this command) — caller
  // just wants the slot to be writeable afterward.
  // Diagnostic logging distinguishes the three so a stuck object (6985) is
  // visible instead of masked as success:
  if (sw1 == 0x90 && sw2 == 0x00) {
    Serial.printf("[SE051] delete 0x%08lx: DELETED (9000)\n",(unsigned long)obj_id);
    return true;
  }
  if (sw1 == 0x6A && sw2 == 0x82) {
    Serial.printf("[SE051] delete 0x%08lx: absent (6A82, slot clean)\n",(unsigned long)obj_id);
    return true;
  }
  if (sw1 == 0x69 && sw2 == 0x85) {
    // 19 Oct 2026: 6985 is "conditions not satisfied". On the bench it came
    // back during onboarding for generation-6 IDs that had never been used and
    // were then created fine, so on its own it does not mean a stuck object
    // (most likely the SE's answer for an absent ID while a PIN session is
    // open). The caller's next create on the same ID is the real test: it
    // fails if something is there.
    Serial.printf("[SE051] delete 0x%08lx: 6985 (not deletable from here, or absent with a session open)\n",(unsigned long)obj_id);
    return true;  // (return behaviour unchanged; caller wants slot writeable)
  }
  Serial.printf("[SE051] delete 0x%08lx: unexpected SW=%02X%02X\n",(unsigned long)obj_id,sw1,sw2);
  return false;
}

bool writeWrappedBlob_internal(uint32_t obj_id, const uint8_t blob[SE_BLOB_TOTAL_LEN],
                               const uint8_t *policySet = nullptr, size_t policyLen = 0) {
  uint8_t payload[160]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(obj_id >> 24), (uint8_t)(obj_id >> 16),
    (uint8_t)(obj_id >>  8), (uint8_t) obj_id
  };
  uint8_t fileSize[2] = { 0x00, (uint8_t)SE_BLOB_TOTAL_LEN };
  if (policySet && policyLen) p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policySet, policyLen);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, fileSize, 2);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, blob, SE_BLOB_TOTAL_LEN);
  uint8_t apdu[192];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_WRITE, P1_BINARY, P2_DEFAULT,
                              payload, p, false);
  uint8_t resp[32];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return checkSW(resp, n, "WriteBinary");
}

// Shared scalar provisioning logic used by both nostr_scalar and
// imported_nsec — they differ only in target slot.
bool provisionScalarInto(uint32_t obj_id, const uint8_t scalar[32], const char *label) {
  if (!g_pin_session_open) {
    Serial.printf("[SE051] %s denied: no PIN session\n", label);
    return false;
  }
  if (!g_ready) {
    Serial.printf("[SE051] %s: SE not ready\n", label);
    return false;
  }
  if (g_session_obj != SE_OBJ_PIN_DAILY) {
    Serial.printf("[SE051] %s denied: open session is not the daily door\n", label);
    return false;
  }
  // The policy below REFERENCES the G0 auth object and the PCR. Both must exist
  // or the SE will refuse the write (and a scalar nobody can read is a bricked
  // identity anyway). se_provision_g0_identity() creates them.
  if (!se_object_exists(SE_AUTH_OBJ_G0) || !g_pcr_unlocked_valid) {
    Serial.printf("[SE051] %s denied: G0 auth object / PCR not provisioned "
                  "(call se_provision_g0_identity first)\n", label);
    return false;
  }
  if (!se_pcr_ensure_exists()) {
    Serial.printf("[SE051] %s: PCR missing and could not be created\n", label);
    return false;
  }
  // Re-provision: the previous object's policy grants DELETE to the daily
  // session only, so an anonymous delete would be refused (6986). Delete it
  // from inside the session we know is open.
  if (se_object_exists(obj_id) && !deleteInSession(g_session_id, obj_id)) {
    Serial.printf("[SE051] %s: delete-existing (in session) failed\n", label);
    return false;
  }
  uint8_t iv[16]; freshIV(iv);
  uint8_t ct[32];
  if (!se_aes_wrap_block_keyed(SE_OBJ_AES_WRAP_DAILY, scalar, iv, ct)) {
    Serial.printf("[SE051] %s: wrap failed\n", label);
    return false;
  }
  uint8_t blob[SE_BLOB_TOTAL_LEN];
  memcpy(blob, iv, 16);
  memcpy(blob + 16, ct, 32);

  // THE DOOR-1 GATE. Two entries, OR'd as the SE always does — but the first
  // is itself an AND:
  //   1. G0 auth object : READ, and only while PCR == unlocked value
  //   2. daily PIN      : DELETE only (wallet wipe / re-provision)
  // Nothing grants READ to the daily PIN or anonymously, so this processor
  // cannot read the blob back even with the PIN session open — which is the
  // whole point. Entry 1 is what the July rig's test 5 exercised.
  uint8_t policy[64]; size_t pp = 0;
  pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), SE_AUTH_OBJ_G0,
                           POLICY_OBJ_ALLOW_READ, SE_OBJ_PCR_UNLOCK, g_pcr_unlocked);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_DAILY, POLICY_OBJ_ALLOW_DELETE);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);   // v4.1: recovery wipe
  if (!writeWrappedBlob_internal(obj_id, blob, policy, pp)) {
    Serial.printf("[SE051] %s: write failed\n", label);
    return false;
  }
  Serial.printf("[SE051] %s OK (slot 0x%08lx)\n", label, (unsigned long)obj_id);
  return true;
}

// ── M5 PIN session helpers (verbatim ported from se051_bringup_m5) ──
//
// The SE session model:
//   1. CreateSession(authObjId) → returns 8-byte session handle.
//      The session is "open" but unauthenticated until PIN is verified.
//   2. ProcessSessionCmd wraps a normal APDU (like VerifySessionUserID)
//      and runs it within the named session.
//   3. VerifySessionUserID(pin) authenticates the session against the
//      PIN object. On success the session is "active" and subsequent
//      crypto operations within it bypass PIN gates.
//   4. CloseSession releases the session handle.
//
// For V22.1: every public function that requires PIN (signing, seed
// unwrap, scalar access) doesn't actually use g_session_id directly —
// the SE crypto APDUs (CipherOneShot, ReadObject) are anonymous and
// the SE-side enforcement happens via the AES key's policy object.
// What g_pin_session_open guards is the firmware-side fail-closed
// invariant. The SE-side enforcement comes from the PIN object's
// policy when we provision it (TODO: tighten policy in M9 hardening).

// APDU buildAPDU variant supporting an explicit Le byte (M5 only uses
// non-zero Le for CreateSession). M6.4-style buildAPDU always writes
// Le=0x00 when hasLe is true.
size_t buildAPDUWithLe(uint8_t *out, size_t outMax,
                       uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                       const uint8_t *data, size_t dataLen,
                       bool hasLe, uint8_t le) {
  size_t pos = buildAPDU(out, outMax, cla, ins, p1, p2, data, dataLen, false);
  if (hasLe && pos < outMax) {
    out[pos++] = le;
  }
  return pos;
}

bool createSession(uint32_t authObjId, uint8_t outSessionId[8]) {
  uint8_t id[4] = {
    (uint8_t)(authObjId >> 24), (uint8_t)(authObjId >> 16),
    (uint8_t)(authObjId >>  8), (uint8_t) authObjId
  };
  uint8_t payload[8]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  uint8_t apdu[32];
  size_t apduLen = buildAPDUWithLe(apdu, sizeof(apdu),
                                    0x80, INS_MGMT, P1_DEFAULT, P2_SESSION_CREATE,
                                    payload, p, true, 0x0C);
  uint8_t resp[32];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  g_lastCreateSessionSW = (n >= 2) ? (uint16_t)((resp[n-2] << 8) | resp[n-1]) : 0;
  if (!checkSW(resp, n, "CreateSession")) return false;
  size_t bodyLen = (size_t)n - 2;
  if (bodyLen < 2 || resp[0] != TAG_1) return false;
  size_t valOff;
  int valLen = parseTLVLength(resp, bodyLen, &valOff);
  if (valLen != 8) return false;
  memcpy(outSessionId, resp + valOff, 8);
  return true;
}

int processSessionCmd(const uint8_t sessionId[8],
                      const uint8_t *innerApdu, size_t innerLen,
                      uint8_t *outResp, size_t outRespMax) {
  uint8_t payload[260]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_SESSION_ID, sessionId, 8);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, innerApdu, innerLen);
  uint8_t apdu[270];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT,
                              payload, p, true);
  return sendAPDU(apdu, apduLen, outResp, outRespMax);
}

// Returns true if the PIN matched (SE returned 9000). False if PIN
// was wrong (6985 — SE decremented its hardware retry counter) or
// any other SE error.
bool verifySessionUserID(const uint8_t sessionId[8],
                         const uint8_t *pinValue, size_t pinLen) {
  uint8_t innerPayload[64]; size_t p = 0;
  p = appendTLV(innerPayload, p, sizeof(innerPayload), TAG_1, pinValue, pinLen);
  uint8_t innerApdu[96];
  size_t innerLen = buildAPDU(innerApdu, sizeof(innerApdu),
                               0x80, INS_MGMT, P1_DEFAULT, P2_SESSION_USERID,
                               innerPayload, p, false);
  uint8_t resp[64];
  int n = processSessionCmd(sessionId, innerApdu, innerLen, resp, sizeof(resp));
  if (n < 2) return false;
  uint16_t sw = ((uint16_t)resp[n - 2] << 8) | resp[n - 1];
  return sw == 0x9000;
}

// Extended policy entry: (authObjId session) AND (pcr == expected).
//   [0x2C][auth:4][rights:4][pcr id:4][expected:32]  = 45 bytes
size_t buildPolicyEntryPcr(uint8_t *out, size_t pos, size_t outMax,
                           uint32_t authObjId, uint32_t accessRights,
                           uint32_t pcrId, const uint8_t expected[32]) {
  if (pos + 45 > outMax) return pos;
  out[pos++] = 0x2C;
  out[pos++] = (uint8_t)(authObjId >> 24); out[pos++] = (uint8_t)(authObjId >> 16);
  out[pos++] = (uint8_t)(authObjId >>  8); out[pos++] = (uint8_t)(authObjId      );
  uint32_t ar = accessRights | POLICY_OBJ_REQUIRE_PCR_VALUE;
  out[pos++] = (uint8_t)(ar >> 24); out[pos++] = (uint8_t)(ar >> 16);
  out[pos++] = (uint8_t)(ar >>  8); out[pos++] = (uint8_t)(ar      );
  out[pos++] = (uint8_t)(pcrId >> 24); out[pos++] = (uint8_t)(pcrId >> 16);
  out[pos++] = (uint8_t)(pcrId >>  8); out[pos++] = (uint8_t)(pcrId      );
  memcpy(out + pos, expected, 32); pos += 32;
  return pos;
}

// v5.1 (15 Oct 2026). Until v5 the unlock extend was the PUBLIC constant
// PCR_UNLOCK_CONST, so the unlocked value was public too. Two holes followed:
//   1. The PCR's policy gave the RECOVER object DELETE. K_RECOVER derives from
//      K_SE, so anyone with the G0's flash could delete the PCR, recreate it
//      anonymously (a missing object has no policy to refuse the create) with
//      the unlocked value as its initial value, and read the scalar as the G0:
//      the Nostr key with no daily PIN.
//   2. The G0 could not be given WRITE (extend) to lock Door 1 at boot,
//      because anyone with K_SE could then extend at-rest -> unlocked.
// Now: X = SHA256(SE_OBJ_DOOR1_SECRET), a random 48-byte object that ONLY the
// daily PIN session may read. Unlocked = SHA256(at_rest || X). The PCR's
// policy is DAILY read/write/delete + G0 write (extend) only; RECOVER has no
// right on it at all. Extending can never reach the unlocked value without X,
// so the G0 (or anyone with its keys) can lock but never unlock.
void computePcrAtRest() {
  mbedtls_sha256(PCR_INITIAL, 32, g_pcr_at_rest, 0);
}
static void door1XFromSecret(const uint8_t secret48[SE_BLOB_TOTAL_LEN], uint8_t x[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  static const uint8_t label[] = "favilla-door1-unlock-x-v51";
  mbedtls_sha256_update(&c, label, sizeof(label) - 1);
  mbedtls_sha256_update(&c, secret48, SE_BLOB_TOTAL_LEN);
  mbedtls_sha256_finish(&c, x); mbedtls_sha256_free(&c);
}
static void computePcrUnlockedFromX(const uint8_t x[32]) {
  computePcrAtRest();
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, g_pcr_at_rest, 32);
  mbedtls_sha256_update(&c, x, 32);
  mbedtls_sha256_finish(&c, g_pcr_unlocked); mbedtls_sha256_free(&c);
  g_pcr_unlocked_valid = true;
}

// Create the Door-1 PCR, PERSISTENT, locked (initial value), writable only by
// the daily PIN object. Anonymous creation is allowed (the object does not
// exist yet, so no policy can refuse it) — proven by the July rig.
//
// Observed 9 Sep 2026 on silicon: a TRANSIENT PCR (INS|0x80) is created fine
// but every in-session operation on it — ReadObject, WritePCR reset — returns
// 6985, while the identical policy on a PERSISTENT PCR allowed read/extend/
// reset in July. So the PCR is persistent. Consequence: it survives power
// loss in whatever state it was left, and only the daily session can reset
// it — see se_init for what that means.
bool pcrCreateLocked() {
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_DAILY,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE); // 0x00340000
  // v5.1: the G0 may EXTEND only (G0_CMD_DOOR1LOCK at every boot). No READ, no
  // DELETE (= no reset, no delete-and-recreate). And RECOVER has NO right here
  // any more: its DELETE was the delete-and-recreate hole (see computePcrAtRest).
  // A wipe through RECOVER leaves this PCR behind; it guards nothing once the
  // scalar is gone, and se_provision_g0_identity() deletes and recreates it
  // from the daily session at the next onboarding.
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_G0, POLICY_OBJ_ALLOW_WRITE);
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_UNLOCK >> 24), (uint8_t)(SE_OBJ_PCR_UNLOCK >> 16),
                    (uint8_t)(SE_OBJ_PCR_UNLOCK >>  8), (uint8_t) SE_OBJ_PCR_UNLOCK };
  uint8_t payload[96]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, PCR_INITIAL, 32);
  uint8_t apdu[128];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                             0x80, INS_WRITE /* persistent, NOT INS_TRANSIENT */, P1_PCR, P2_DEFAULT,
                             payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return checkSW(resp, n, "WritePCR(create,persistent)");
}

// Extend (extend32 != nullptr) or reset (nullptr, TAG_1 only) the Door-1 PCR
// from inside the daily PIN session. Reset is gated by ALLOW_DELETE and can
// only ever LOCK, never unlock.
bool pcrUpdateInSession(const uint8_t sessionId[8], const uint8_t *extend32) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_UNLOCK >> 24), (uint8_t)(SE_OBJ_PCR_UNLOCK >> 16),
                    (uint8_t)(SE_OBJ_PCR_UNLOCK >>  8), (uint8_t) SE_OBJ_PCR_UNLOCK };
  uint8_t payload[48]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  if (extend32) p = appendTLV(payload, p, sizeof(payload), TAG_3, extend32, 32);
  uint8_t inner[64];
  size_t innerLen = buildAPDU(inner, sizeof(inner),
                              0x80, INS_WRITE, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[32];
  int n = processSessionCmd(sessionId, inner, innerLen, resp, sizeof(resp));
  return checkSW(resp, n, extend32 ? "WritePCR(extend)" : "WritePCR(reset)");
}

// Read the PCR value back inside the daily session (its policy grants READ to
// the daily PIN). Diagnostic only.
bool pcrReadInSession(const uint8_t sessionId[8], uint8_t out[32]) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_UNLOCK >> 24), (uint8_t)(SE_OBJ_PCR_UNLOCK >> 16),
                    (uint8_t)(SE_OBJ_PCR_UNLOCK >>  8), (uint8_t) SE_OBJ_PCR_UNLOCK };
  uint8_t payload[8]; size_t p = appendTLV(payload, 0, sizeof(payload), TAG_1, id, 4);
  uint8_t inner[32];
  size_t innerLen = buildAPDU(inner, sizeof(inner),
                              0x80, INS_READ, P1_DEFAULT, P2_DEFAULT, payload, p, true);
  uint8_t resp[96];
  int n = processSessionCmd(sessionId, inner, innerLen, resp, sizeof(resp));
  if (!checkSW(resp, n, "ReadObject(PCR)")) return false;
  size_t bodyLen = (size_t)n - 2, off = 0;
  if (bodyLen < 2 || resp[0] != TAG_1) return false;
  int len = parseTLVLength(resp, bodyLen, &off);
  if (len != 32 || off + 32 > bodyLen) return false;
  memcpy(out, resp + off, 32);
  return true;
}

// PCR state as observed from the daily session.
enum PcrState { PCR_UNREADABLE, PCR_LOCKED, PCR_UNLOCKED_OK, PCR_OTHER };
PcrState pcrState(const uint8_t sessionId[8]) {
  uint8_t v[32];
  if (!pcrReadInSession(sessionId, v)) return PCR_UNREADABLE;
  if (memcmp(v, g_pcr_at_rest, 32) == 0) return PCR_LOCKED;
  if (g_pcr_unlocked_valid && memcmp(v, g_pcr_unlocked, 32) == 0) return PCR_UNLOCKED_OK;
  return PCR_OTHER;
}

// PIN entered (daily session just verified): bring the PCR to the exact
// "unlocked" value. Observed 9 Sep 2026 on silicon: a TAG_1-only WritePCR on
// a PCR that is ALREADY at its initial value is refused with 6985, so never
// reset blindly — read first, reset only if it holds something else, extend
// only if it is at rest.
bool pcrUnlockInSession(const uint8_t sessionId[8], const uint8_t x[32]) {
  if (!x || !g_pcr_unlocked_valid) { Serial.println("[SE051] PCR unlock: no Door-1 secret this session - refusing"); return false; }
  // v5.1: two passes. The second covers a freshly CREATED PCR whose first
  // extend lands off the expected value (the same silicon quirk MODE_PCR has):
  // after one extend it is no longer at its initial value, so a reset is
  // allowed and the second extend starts from the canonical base.
  for (int pass = 0; pass < 2; pass++) {
    PcrState st = pcrState(sessionId);
    if (st == PCR_UNLOCKED_OK) { Serial.println("[SE051] PCR unlock: already unlocked"); return true; }
    if (st == PCR_OTHER) {
      if (!pcrUpdateInSession(sessionId, nullptr)) return false;       // -> SHA256(I)
      st = pcrState(sessionId);
    }
    if (st != PCR_LOCKED) {
      Serial.println("[SE051] PCR unlock: not at rest after reset - refusing to extend");
      return false;
    }
    if (!pcrUpdateInSession(sessionId, x)) return false;               // -> unlocked
    st = pcrState(sessionId);
    Serial.printf("[SE051] PCR unlock: readback %s\n",
                  st == PCR_UNLOCKED_OK ? "MATCHES expected" :
                  st == PCR_UNREADABLE  ? "unreadable (extend itself succeeded)" :
                                          "MISMATCH (retrying from a reset)");
    if (st == PCR_UNLOCKED_OK || st == PCR_UNREADABLE) return true;
  }
  return false;
}

bool deleteInSession(const uint8_t sessionId[8], uint32_t objId);   // defined below

// v5.1: read SE_OBJ_DOOR1_SECRET inside the daily session (its policy grants
// READ to the daily PIN and to nothing else) and derive X. Also sets the
// unlocked value. The secret and X never persist on this chip.
// Limits, stated plainly: the ESP32-SE link carries this read in clear on the
// I2C bus (as it carries the daily PIN itself), and X is fixed for the life
// of the wallet, so an ESP32 that is compromised once while the daily PIN is
// entered keeps X. X protects against holders of the G0's keys, not against
// a compromised ESP32 that has already seen the daily PIN.
static bool door1ReadX(const uint8_t sessionId[8], uint8_t x[32]) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_DOOR1_SECRET >> 24), (uint8_t)(SE_OBJ_DOOR1_SECRET >> 16),
                    (uint8_t)(SE_OBJ_DOOR1_SECRET >>  8), (uint8_t) SE_OBJ_DOOR1_SECRET };
  uint8_t payload[8]; size_t p = appendTLV(payload, 0, sizeof(payload), TAG_1, id, 4);
  uint8_t inner[32];
  size_t innerLen = buildAPDU(inner, sizeof(inner),
                              0x80, INS_READ, P1_DEFAULT, P2_DEFAULT, payload, p, true);
  uint8_t resp[96];
  int n = processSessionCmd(sessionId, inner, innerLen, resp, sizeof(resp));
  bool ok = false;
  if (checkSW(resp, n, "ReadObject(Door-1 secret)")) {
    size_t bodyLen = (size_t)n - 2, off = 0;
    if (bodyLen >= 2 && resp[0] == TAG_1) {
      int len = parseTLVLength(resp, bodyLen, &off);
      if (len == (int)SE_BLOB_TOTAL_LEN && off + SE_BLOB_TOTAL_LEN <= bodyLen) {
        door1XFromSecret(resp + off, x);
        computePcrUnlockedFromX(x);
        ok = true;
      }
    }
  }
  mbedtls_platform_zeroize(resp, sizeof(resp));
  if (!ok) mbedtls_platform_zeroize(x, 32);
  return ok;
}

// v5.1: mint a fresh Door-1 secret (onboarding, daily session open, G0 auth
// object already written). Any previous one is deleted from the session first.
static bool door1MintSecret(const uint8_t sessionId[8], uint8_t x[32]) {
  if (se_object_exists(SE_OBJ_DOOR1_SECRET) && !deleteInSession(sessionId, SE_OBJ_DOOR1_SECRET)) {
    Serial.println("[SE051] Door-1 secret: could not delete the previous one");
    return false;
  }
  uint8_t sec[SE_BLOB_TOTAL_LEN];
  if (!se_random(sec, sizeof(sec))) { Serial.println("[SE051] Door-1 secret: TRNG failed"); return false; }
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_DAILY, POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_DELETE);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);   // recovery wipe; delete reveals nothing
  bool ok = writeWrappedBlob_internal(SE_OBJ_DOOR1_SECRET, sec, policy, pp);
  mbedtls_platform_zeroize(sec, sizeof(sec));
  if (!ok) { Serial.println("[SE051] Door-1 secret: write failed"); return false; }
  // Read it back through the session: proves the policy grants the daily PIN
  // READ before anything is built on it, and derives X the same way every
  // later unlock will.
  if (!door1ReadX(sessionId, x)) { Serial.println("[SE051] Door-1 secret: read-back in the daily session FAILED"); return false; }
  Serial.println("[SE051] Door-1 secret minted (daily-PIN read only)");
  return true;
}

// Lock: reset only if the PCR is not already at rest (a no-op reset is 6985).
// v5.1: lock by EXTENDING junk, never by resetting. A reset leaves the PCR at
// its at-rest value, one extend (with X) away from unlocked, and the G0 holds
// extend: anyone with the G0's flash plus one leaked X could unlock. After a
// junk extend the only way back is a reset, which only the daily PIN holds.
static const uint8_t DOOR1_LOCK_JUNK_ESP[32] = {
  'F','A','V','I','L','L','A','-','D','O','O','R','1','-','L','O','C','K','-','E','S','P',0,0,0,0,0,0,0,0,0,0 };
bool pcrLockInSession(const uint8_t sessionId[8]) {
  return pcrUpdateInSession(sessionId, DOOR1_LOCK_JUNK_ESP);
}

bool closeSessionInternal(const uint8_t sessionId[8]) {
  uint8_t innerApdu[16];
  size_t innerLen = buildAPDU(innerApdu, sizeof(innerApdu),
                               0x80, INS_MGMT, P1_DEFAULT, P2_SESSION_CLOSE,
                               nullptr, 0, false);
  uint8_t resp[16];
  int n = processSessionCmd(sessionId, innerApdu, innerLen, resp, sizeof(resp));
  return checkSW(resp, n, "CloseSession");
}

bool deleteInSession(const uint8_t sessionId[8], uint32_t objId) {
  uint8_t id[4] = {
    (uint8_t)(objId >> 24), (uint8_t)(objId >> 16),
    (uint8_t)(objId >>  8), (uint8_t) objId
  };
  uint8_t payload[8]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  uint8_t innerApdu[32];
  size_t innerLen = buildAPDU(innerApdu, sizeof(innerApdu),
                               0x80, INS_MGMT, P1_DEFAULT, P2_DELETE_OBJECT,
                               payload, p, false);
  uint8_t resp[32];
  int n = processSessionCmd(sessionId, innerApdu, innerLen, resp, sizeof(resp));
  return checkSW(resp, n, "DeleteInSession");
}

// Encodes one policy entry into the PolicySet TLV body. Each entry is
// a length-prefixed 8-byte structure: 4-byte big-endian auth object ID
// + 4-byte big-endian access-rights bitmap. Multiple entries are
// concatenated; the PolicySet TLV (TAG_POLICY) wraps the whole set.
size_t buildPolicyEntry(uint8_t *out, size_t pos, size_t outMax,
                        uint32_t authObjId, uint32_t accessRights) {
  if (pos + 9 > outMax) return pos;  // not enough room — caller checks for advance
  out[pos++] = 8;
  out[pos++] = (uint8_t)(authObjId >> 24);
  out[pos++] = (uint8_t)(authObjId >> 16);
  out[pos++] = (uint8_t)(authObjId >>  8);
  out[pos++] = (uint8_t)(authObjId      );
  out[pos++] = (uint8_t)(accessRights >> 24);
  out[pos++] = (uint8_t)(accessRights >> 16);
  out[pos++] = (uint8_t)(accessRights >>  8);
  out[pos++] = (uint8_t)(accessRights      );
  return pos;
}

bool writeUserIDWithPolicy(uint32_t objId,
                           const uint8_t *useridValue, size_t useridLen,
                           uint16_t maxAttempts,
                           const uint8_t *policySet, size_t policyLen) {
  uint8_t id[4] = {
    (uint8_t)(objId >> 24), (uint8_t)(objId >> 16),
    (uint8_t)(objId >>  8), (uint8_t) objId
  };
  uint8_t maxAtt[2] = { (uint8_t)(maxAttempts >> 8), (uint8_t)maxAttempts };
  uint8_t payload[128]; size_t p = 0;
  if (policyLen > 0) {
    p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policySet, policyLen);
  }
  p = appendTLV(payload, p, sizeof(payload), TAG_MAX_ATTEMPTS, maxAtt, 2);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, useridValue, useridLen);
  uint8_t apdu[160];
  uint8_t ins = INS_WRITE | INS_AUTH_OBJECT;  // 0x41
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, ins, P1_USERID, P2_DEFAULT,
                              payload, p, false);
  uint8_t resp[32];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return checkSW(resp, n, "WriteUserID");
}

} // namespace (anonymous)

// ── v5.1 generations ────────────────────────────────────────────────────────
void se_set_generation(uint8_t g) {
  if (g != SE_GEN_NONE && (g < 1 || g > SE_GEN_MAX)) g = SE_GEN_NONE;
  g_gen = g;
  SE_OBJ_AES_WRAP       = genId(0x20000020u, g);
  SE_OBJ_AES_WRAP_SEED  = SE_OBJ_AES_WRAP;
  SE_OBJ_AES_WRAP_DAILY = genId(0x20000022u, g);
  SE_OBJ_NOSTR_SCALAR   = genId(0x20000002u, g);
  SE_AUTH_OBJ_G0        = genId(0x20000030u, g);
  SE_AUTH_OBJ_RECOVER   = genId(0x20000035u, g);
  SE_OBJ_PCR_UNLOCK     = genId(0x20000031u, g);
  SE_OBJ_DOOR1_SECRET   = genId(0x20000036u, g);
  SE_OBJ_NSEC_IMPORT    = genId(0x20000003u, g);
  SE_OBJ_USER_PIN       = genId(0x70000003u, g);
  SE_OBJ_PIN_DAILY      = SE_OBJ_USER_PIN;
  SE_OBJ_PIN_SPEND      = genId(0x70000005u, g);
  SE_OBJ_PIN_PASSKEY    = genId(0x70000007u, g);   // 30 Oct 2026
  SE_OBJ_PK_SCRATCH     = genId(0x20000037u, g);   // 30 Oct 2026, restorable passkeys
  SE_OBJ_PK_MASTER      = genId(0x20000038u, g);
  SE_OBJ_K_PK           = genId(0x20000039u, g);
  SE_OBJ_K_PKN          = genId(0x2000003Au, g);
  SE_OBJ_PK_MASTER_P    = genId(0x2000003Bu, g);
  SE_OBJ_VPUB           = genId(0x2000003Cu, g);
  SE_OBJ_K_IXN          = genId(0x2000003Du, g);
  SE_OBJ_PCR_MODE_FWD   = genId(0x20000033u, g);
  g_pcr_unlocked_valid  = false;   // belongs to the previous generation's Door-1 secret
  Serial.printf("[SE051] object generation %s%u (PIN daily 0x%08lX, G0 auth 0x%08lX)\n",
                g == SE_GEN_NONE ? "NONE/" : "", (unsigned)g,
                (unsigned long)SE_OBJ_PIN_DAILY, (unsigned long)SE_AUTH_OBJ_G0);
}
uint8_t se_generation() { return g_gen; }
#ifdef FAVILLA_BENCH_PROBES
// v5.1 bench probe (strip before ship): anonymous delete, true if the object is gone afterwards.
bool se_bench_anon_delete(uint32_t id) {
  if (!g_ready || !se_object_exists(id)) return false;
  tryDeleteObject_internal(id);
  return !se_object_exists(id);
}
#endif

bool se_begin_new_generation() {
  if (!g_ready) return false;
  // Only on a G0 that answers "no keys". A silent or pre-v5.1 G0 (0xFE), or
  // one that holds a wallet, must never let an onboarding burn a generation.
  uint8_t gg = g0_peek_generation();
  if (gg != 0xFF) {
    Serial.printf("[SE051] new generation refused: the G0 reports %s\n", gg == 0xFE ? "nothing (absent / pre-v5.1)" : "a live wallet");
    return false;
  }
  static const uint32_t bases[] = { 0x20000020u, 0x20000022u, 0x20000002u, 0x20000030u, 0x20000035u,
                                    0x20000031u, 0x20000036u, 0x20000003u, 0x70000003u, 0x70000005u,
                                    0x20000033u, 0x70000007u };   // 30 Oct 2026: + the passkey PIN
  // A pre-v5.1 seed blob in NVS belongs to no wallet from here on: drop it now,
  // not only after the next successful seed_store.
  seed_erase_from_nvs();
  for (uint8_t g = 1; g <= SE_GEN_MAX; g++) {
    bool used = false;
    for (uint32_t b : bases) if (se_object_exists(genId(b, g))) { used = true; break; }
    if (!used) { se_set_generation(g); Serial.printf("[SE051] onboarding on fresh object generation %u\n", (unsigned)g); return true; }
  }
  Serial.println("[SE051] no free object generation left - the SE is full of dead wallets");
  return false;
}

// ── BTC-door secret: public entry points (favilla scope, 16 Sep 2026) ───────
// Defined HERE, after the anonymous namespace, because the header declares
// them in favilla:: — the first cut put them inside the anonymous namespace
// (different linkage, undefined reference) and ahead of g_ready.
// Called at the start of the DAILY onboarding session, BEFORE the seed wrap
// key is created (its policy embeds g_mode_btc). Generates S, derives and
// persists the BTC value, and parks S for se_provision_g0_identity().
bool mode_btc_secret_begin() {
  if (!g_ready) return false;
  if (!g_mode_vals_valid) modeComputeValues();
  if (!se_random(g_mode_secret_pending, 32)) { Serial.println("[MODEPCR] S: TRNG failed"); return false; }
  modeExt(g_mode_neutral, g_mode_secret_pending, g_mode_btc);
  Preferences p;
  bool saved = false;
  if (p.begin(MODE_NS, false, NVSPART_SEC)) { saved = p.putBytes(MODE_KEY, g_mode_btc, 32) == 32; p.end(); }
  if (!saved) { mbedtls_platform_zeroize(g_mode_secret_pending, 32); Serial.println("[MODEPCR] S: could not persist BTC value"); return false; }
  g_mode_secret_pending_valid = true;
  g_mode_secret_delivered = false;
  g_mode_btc_from_g0 = true;
  Serial.println("[MODEPCR] BTC value now derived from the G0 secret S (pending delivery to G0)");
#ifdef FAVILLA_PASSKEY_DOOR
  {   // 30 Oct 2026: the passkey door's value, from the same S (see g_mode_pk)
    uint8_t b[45], s3[32];
    memcpy(b, g_mode_secret_pending, 32); memcpy(b + 32, "FAVILLA-DOOR", 12); b[44] = 3;
    mbedtls_sha256(b, sizeof(b), s3, 0);
    modeExt(g_mode_neutral, s3, g_mode_pk);
    mbedtls_platform_zeroize(b, sizeof(b)); mbedtls_platform_zeroize(s3, sizeof(s3));
    bool pk = false;
    if (p.begin(MODE_NS, false, NVSPART_SEC)) { pk = p.putBytes(MODE_KEY_PK, g_mode_pk, 32) == 32; p.end(); }
    g_mode_pk_valid = pk;
    if (!pk) { modeBtcSecretForget(); Serial.println("[MODEPCR] S: could not persist the PASSKEY value - S forgotten, onboarding fails"); return false; }
    Serial.println("[MODEPCR] PASSKEY value V_3 derived from S and saved");
  }
#endif
  return true;
}
void mode_btc_value_erase() {
  Preferences p;
  if (p.begin(MODE_NS, false, NVSPART_SEC)) { p.clear(); p.end(); }
  g_mode_btc_from_g0 = false;
  g_mode_secret_delivered = false;
  g_mode_pk_valid = false;   // 30 Oct 2026: "pkval" went with the namespace clear above
}


// ============================================================
// Public surface
// ============================================================

// ── se_set_bus_lock ──────────────────────────────────────────
// Register the shared-I2C-bus mutex so every APDU exchange is atomic w.r.t.
// other I2C peripherals (battery gauge, haptics, expander). See header.
void se_set_bus_lock(void (*lock_fn)(), void (*unlock_fn)()) {
  g_busLock   = lock_fn;
  g_busUnlock = unlock_fn;
}

// ── se_init ──────────────────────────────────────────────────
bool se_init(int sda_pin, int scl_pin, uint32_t freq_hz) {
  // Wire.begin is safe to call multiple times on ESP32-Arduino —
  // the second call reconfigures pins/frequency. But re-binding
  // pins mid-run can disturb other I²C devices on the same bus,
  // so we only Wire.begin once per cold boot.
  if (!g_initialised) {
    Wire.begin(sda_pin, scl_pin);
    Wire.setClock(freq_hz);
    Wire.setTimeOut(1500);
    g_initialised = true;
  }

  // Always re-sync T=1' and re-select on every se_init call —
  // this is the path that runs after wake-from-sleep or after
  // an error-recovery reset.
  g_ready = false;
  g_pin_session_open = false;   // V1 policy: session never survives a reset
  g_session_obj = 0;
  mbedtls_platform_zeroize(g_session_id, 8);
  g_t1_seq = 0;

  if (!t1TrySync()) {
    Serial.println("[SE051] FAIL: t1 sync");
    return false;
  }
  if (!selectIoTApplet()) {
    Serial.println("[SE051] FAIL: select applet");
    return false;
  }

  se_print_variant();   // DIAG: print authoritative OEF ID (A vs C variant)

  g_ready = true;
  Serial.println("[SE051] OK");

  // Door-1 PCR. Persistent (see pcrCreateLocked), so it normally already
  // exists here and holds whatever state it was left in — including
  // "unlocked" after an unclean power-down. This processor cannot reset it
  // anonymously (only the daily session may), so an unlocked PCR at boot is
  // corrected at the next PIN entry. Firmware still refuses Nostr ops before
  // PIN entry (g_pin_session_open), and the G0 has no K_SE-less path, so the
  // exposure is RCE-only and bounded by the next lock. Create it only if it is
  // missing (first onboarding, or after a wipe).
  computePcrAtRest();   // v5.1: the unlocked value needs the daily PIN (door1ReadX)
  if (se_object_exists(SE_OBJ_PIN_DAILY)) {
    if (!se_pcr_ensure_exists())
      Serial.println("[SE051] WARN: Door-1 PCR could not be (re)created at init");
  }
  return true;
}

// ── se_is_ready ──────────────────────────────────────────────
bool se_is_ready() {
  return g_ready;
}

// -----------------------------------------------------------------------------
// se_transceive_raw - opaque APDU passthrough for the G0 blind relay.
//
// This is the ONLY SE entry point that does not parse its payload, and that is
// deliberate. The frames it carries are SCP03-protected end-to-end between the
// G0 and the SE, so this processor must not - and cannot - interpret them.
// Tampering is caught by the CMAC inside the G0, not here.
//
// The status word is returned verbatim as part of the response; it is the G0's
// to interpret, not ours.
// -----------------------------------------------------------------------------
bool se_transceive_raw(const uint8_t *apdu, size_t apdu_len,
                       uint8_t *resp, size_t resp_cap, size_t *resp_len) {
  if (!g_ready || !apdu || !resp || !resp_len) return false;
  if (apdu_len == 0 || apdu_len > 512) return false;

  int n = sendAPDU(apdu, apdu_len, resp, resp_cap);
  if (n < 2) return false;          // no SW available - transport fault
  *resp_len = (size_t)n;
  return true;
}

// ── se_power_down ────────────────────────────────────────────
// Put the SE051 into Power-down mode before the host deep-sleeps.
//
// WHY: deep sleep only powers down the ESP32 core. The SE051 rail is fed
// permanently on this board, so without this the SE sits at its idle current
// FOREVER while the device is "off". Per the SE050 data sheet (rev 3.8) §5.1
// and Table 12, Power-down mode drops it to ~450 uA typ / 500 uA max, with
// CPU registers and RAM retained.
//
// HOW: Power-down is entered by sending an "End of APDU session request"
// S-block over T=1 over I2C (UM11225) — subtype 0x05. That is the SAME
// mechanism t1TrySync() uses for RESYNCH (subtype 0x00), so the whole frame
// path already exists; this just picks a different subtype.
//
// WAKE: a falling edge on I2C_SDA wakes it (data sheet Table 14: tWKPD ~97 us).
// Any subsequent I2C transaction therefore wakes it implicitly. Because the
// device REBOOTS out of deep sleep and se_init() re-runs from scratch, no
// explicit wake call is needed here. If a light-sleep path is ever added, the
// first APDU after wake may need a retry — the SE answers with an R-block
// requesting retransmission if it was still waking (data sheet Table 14 [4]).
//
// NOTE: Deep Power-down (<5 uA) is NOT reachable from firmware — it needs the
// ENA pad pulled low, plus the Vin/Vout supply arrangement described in §5.2.
// That is a board-level change, not a software one.
//
// Returns true if the SE acknowledged the request with an S-block response.
// Fail-soft: a false return only means we could not confirm; the caller should
// sleep regardless rather than block on it.
bool se_power_down() {
  if (!g_ready) return false;

  bool acked = false;
  if (g_busLock) g_busLock();

  // S-block request, subtype 0x05 = end of APDU session.
  if (t1SendSBlock(0x05, false, nullptr, 0)) {
    uint8_t pcb;
    uint8_t inf[64];
    int n = t1RecvRawFrame(&pcb, inf, sizeof(inf));
    // Expect an S-block RESPONSE (the 0x20 bit set) echoing the subtype.
    if (n >= 0 && pcb_is_sblock(pcb) && !pcb_is_sblock_request(pcb)) {
      acked = true;
    }
  }

  if (g_busUnlock) g_busUnlock();

  // Whether or not it acked, treat the SE as not-ready: any later call must
  // re-establish state rather than assume a live session. g_t1_seq is reset so
  // a future t1TrySync() starts clean.
  g_ready   = false;
  g_t1_seq  = 0;

  Serial.printf("[SE051] power-down request %s\n", acked ? "ACKed" : "NOT acked");
  return acked;
}

// ── se_object_exists ─────────────────────────────────────────
// FIXED: previously used readObjectShallow(), which tries to READ the object.
// That works for readable binary blobs (the Nostr scalar) but FALSELY reports
// "empty" for non-readable objects — PIN/UserID auth objects and AES key
// objects — because the SE refuses to read out a secret. A stuck PIN object at
// 0x70000003 therefore read as "empty" while still blocking WriteUserID (6985).
// Now uses the SE051 CheckObjectExists management APDU, which reports presence
// WITHOUT reading contents, so it is correct for every object type.
//   APDU: CLA=80 INS=04(MGMT) P1=00 P2=0x27(EXIST), data = TAG_1 || objId(4)
//   Result TLV value: 0x01 = exists, 0x02 = does not exist; SW 0x9000.
bool se_object_exists(uint32_t obj_id) {
  if (!g_ready) return false;
  uint8_t payload[8]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(obj_id >> 24), (uint8_t)(obj_id >> 16),
    (uint8_t)(obj_id >>  8), (uint8_t) obj_id
  };
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  uint8_t apdu[32];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_MGMT, P1_DEFAULT, 0x27 /* P2_EXIST */,
                              payload, p, true);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (n < 2) return false;
  uint16_t sw = (resp[n-2] << 8) | resp[n-1];
  if (sw != 0x9000) return false;
  // R-APDU body (AN12543 Table 146): TLV[TAG_1] = 1-byte Result.
  // Layout: TAG_1(0x41) len(0x01) value(0x01=exists / 0x02=not) then SW.
  // Parse the TLV explicitly — do NOT scan for 0x01, because the length
  // byte is itself 0x01 and would false-match.
  //   resp[0]=0x41 (TAG_1), resp[1]=0x01 (len), resp[2]=result value.
  int bodyLen = n - 2;
  if (bodyLen >= 3 && resp[0] == TAG_1 && resp[1] == 0x01) {
    return resp[2] == 0x01;   // RESULT_SUCCESS = exists
  }
  // Fallback: if the body is a bare 1-byte result without the TLV wrapper.
  if (bodyLen >= 1) {
    return resp[bodyLen - 1] == 0x01;
  }
  return false;
}

// ── se_aes_wrap_block / se_aes_unwrap_block ──────────────────
// Two-door: keyed variants take the explicit wrap-key object. The legacy
// (unkeyed) names default to the SEED key (spend-bound), preserving the
// seed_store / seed_unwrap_to_ram call sites without edits.
bool se_aes_wrap_block_keyed(uint32_t keyObjId, const uint8_t plaintext[32],
                             const uint8_t iv[16], uint8_t ct_out[32]) {
  if (!g_ready) return false;
  return aesOneShot(keyObjId, P2_ENCRYPT_ONESHOT, plaintext, iv, ct_out);
}

bool se_aes_unwrap_block_keyed(uint32_t keyObjId, const uint8_t ciphertext[32],
                               const uint8_t iv[16], uint8_t pt_out[32]) {
  if (!g_ready) return false;
  return aesOneShot(keyObjId, P2_DECRYPT_ONESHOT, ciphertext, iv, pt_out);
}

bool se_aes_wrap_block(const uint8_t plaintext[32], const uint8_t iv[16],
                       uint8_t ct_out[32]) {
  return se_aes_wrap_block_keyed(SE_OBJ_AES_WRAP_SEED, plaintext, iv, ct_out);
}

bool se_aes_unwrap_block(const uint8_t ciphertext[32], const uint8_t iv[16],
                         uint8_t pt_out[32]) {
  return se_aes_unwrap_block_keyed(SE_OBJ_AES_WRAP_SEED, ciphertext, iv, pt_out);
}

// ── se_pair_wrap_block / se_pair_unwrap_block (Path-A, cold) ──
// Anonymous CipherOneShot under SE_OBJ_PAIR_WRAP. No PIN session required —
// these are the device-identity primitive used by deviceIdentityInit() to
// derive g_dDevice on a cold boot. See aesOneShotAnon for the security model.
bool se_pair_wrap_block(const uint8_t plaintext[32], const uint8_t iv[16],
                        uint8_t ct_out[32]) {
  if (!g_ready) return false;
  return aesOneShotAnon(P2_ENCRYPT_ONESHOT, plaintext, iv, ct_out);
}

bool se_pair_unwrap_block(const uint8_t ciphertext[32], const uint8_t iv[16],
                          uint8_t pt_out[32]) {
  if (!g_ready) return false;
  return aesOneShotAnon(P2_DECRYPT_ONESHOT, ciphertext, iv, pt_out);
}

bool se_pair_wrap_exists() {
  return se_object_exists(SE_OBJ_PAIR_WRAP);
}


// ── PIN session (M5 — real hardware PIN check) ─────────────────────
//
// Step 6 (M5 port): replaces the Step 2 permissive stub with the
// real SE PIN verification flow. The SE has a hardware retry counter
// on the PIN object — wrong PIN decrements it; after PIN_MAX_ATTEMPTS
// the PIN object locks permanently and the device requires seed
// restore.
//
// Session lifecycle:
//   open  → CreateSession + VerifySessionUserID (PIN check)
//   work  → SE crypto operations proceed (signing, unwrap, etc)
//   close → CloseSession (releases session handle)
//
// V1 policy: session never persists across power cycles. se_init()
// clears g_pin_session_open on every call.
bool se_pin_session_open_obj(uint32_t pinObjId, const char *pin) {
  if (!g_ready) {
    Serial.println("[SE051] se_pin_session_open: SE not ready");
    return false;
  }
  if (!pin) {
    Serial.println("[SE051] se_pin_session_open: null pin");
    return false;
  }

  // Idempotent ONLY for the same object. If a session is already open against
  // the SAME PIN object, treat as no-op success (preserves the legacy daily
  // behaviour, and lets se_pin_destroy reuse a live unlock session without
  // burning the retry counter). But if a session is open against a DIFFERENT
  // object (e.g. daily is open and we're opening SPEND at TX time), we MUST
  // close it and open the requested one — otherwise the wrap key's
  // spend-bound policy would be checked against the daily session and fail
  // (6985/6986). This is the crux of the two-door session model.
  if (g_pin_session_open) {
    if (g_session_obj == pinObjId) {
      return true;
    }
    // Different door requested — tear down the existing session first.
    Serial.printf("[SE051] se_pin_session_open: switching session obj 0x%08X -> 0x%08X\n",
                  (unsigned)g_session_obj, (unsigned)pinObjId);
    se_pin_session_close();
  }

  // v5.1 Door-1 boot lock, retried here if the boot-time attempt did not land:
  // the G0 refuses every Nostr fetch until it has locked Door 1 this life, and
  // it needs its OWN SE session, so this must run before ours is created.
  // 2 Nov 2026 (review L3): the passkey PIN retries it too. A PASSKEY life has
  // no daily PIN, and K_PKN's G0 entry is gated on Door 1 reading unlocked.
  if ((pinObjId == SE_OBJ_PIN_DAILY || pinObjId == SE_OBJ_PIN_PASSKEY) && g0_present() && !g0_door1_locked_this_boot() &&
      se_object_exists(SE_AUTH_OBJ_G0)) {
    g0_door1_lock();
  }

  // Create the session handle against the requested PIN auth object.
  uint8_t sid[8];
  if (!createSession(pinObjId, sid)) {
    Serial.printf("[SE051] se_pin_session_open: CreateSession failed (obj 0x%08X)\n", (unsigned)pinObjId);
    return false;
  }

  // Verify the PIN against the session.
  size_t pin_len = strlen(pin);
  if (!verifySessionUserID(sid, (const uint8_t*)pin, pin_len)) {
    // Wrong PIN — close the session immediately so we don't hold a
    // dangling handle. The SE's retry counter has already decremented.
    Serial.println("[SE051] se_pin_session_open: PIN verify failed");
    closeSessionInternal(sid);
    return false;
  }

  // Success — store the session id, flag, and which object it auths.
  memcpy(g_session_id, sid, 8);
  g_pin_session_open = true;
  g_session_obj      = pinObjId;

  // Door-1 -> isolated signer. The daily PIN is the ONLY thing that may move
  // the PCR, and the scalar is readable by the G0's session ONLY while the PCR
  // holds the unlocked value. So: PIN verified => extend. If this fails the
  // session still opens (Bitcoin, settings, everything else works) but every
  // Nostr operation fails closed on the SE side until the next PIN entry.
  if (pinObjId == SE_OBJ_PIN_DAILY) {
    uint8_t x[32];
    if (!se_object_exists(SE_OBJ_DOOR1_SECRET) || !door1ReadX(g_session_id, x)) {
      Serial.println("[SE051] WARN: Door-1 secret absent/unreadable (not onboarded, or onboarded before v5.1) - Nostr stays locked");
    } else if (!se_pcr_ensure_exists()) {
      Serial.println("[SE051] WARN: Door-1 PCR absent and not creatable - Nostr stays locked");
    } else if (!pcrUnlockInSession(g_session_id, x)) {
      Serial.println("[SE051] WARN: Door-1 PCR extend failed - Nostr stays locked");
    } else {
      Serial.println("[SE051] Door-1 PCR extended - isolated signer unlocked");
      // NOTE: no session test here. On RAM-only keys (pre step-5) a reboot is
      // the only way back to this hook, and a reboot wipes the G0 keys, so an
      // unlock-time test always reports keys MISSING. The step-3 self-test runs
      // at the end of se_provision_nostr_scalar instead — the one moment keys,
      // PCR-unlock and sealed scalar all coexist without a reboot.
    }
    mbedtls_platform_zeroize(x, sizeof(x));
  }
  return true;
}

// Legacy wrapper: targets the daily PIN. Existing callers are unchanged.
bool se_pin_session_open(const char *pin) {
  return se_pin_session_open_obj(SE_OBJ_PIN_DAILY, pin);
}

void se_pin_session_close() {
  if (g_pin_session_open) {
    // Lock / timeout / spend-door switch: reset the PCR BEFORE the session
    // goes away, because only this session may. A failed reset leaves the
    // signer unlocked until power loss - log loudly, but there is nothing
    // more this side can do (the SE would refuse an anonymous reset too).
    if (g_session_obj == SE_OBJ_PIN_DAILY && se_object_exists(SE_OBJ_PCR_UNLOCK)) {
      if (pcrLockInSession(g_session_id))
        Serial.println("[SE051] Door-1 PCR reset - isolated signer locked");
      else
        Serial.println("[SE051] WARN: Door-1 PCR reset FAILED - signer stays unlocked until SE power-cycle");
    }
    closeSessionInternal(g_session_id);
    mbedtls_platform_zeroize(g_session_id, 8);
    g_pin_session_open = false;
    g_session_obj      = 0;
  }
}

bool se_pin_session_is_open() {
  return g_pin_session_open;
}

uint32_t se_pin_session_obj() {
  return g_pin_session_open ? g_session_obj : 0;
}

// ── se_pin_provision (M5 — write the user PIN object) ──────────────
//
// Called once during onboarding when the user picks their PIN.
// Idempotent: deletes any existing PIN object first.
//
// Two-door (V1.x): the object-ID-aware core writes either PIN. The policy
// differs by object:
//   - SE_OBJ_PIN_DAILY: self R/W/D (as today) — only its own session deletes.
//   - SE_OBJ_PIN_SPEND: self R/W/D only. (v5.1: the anonymous DELETE entry
//     it used to carry was a PIN reset - see below. Not benign after all.)
bool se_pin_provision_obj(uint32_t pinObjId, const uint8_t *pin, size_t pin_len) {
  if (!g_ready) {
    Serial.println("[SE051] se_pin_provision: SE not ready");
    return false;
  }
  if (!pin || pin_len == 0 || pin_len > 32) {
    Serial.println("[SE051] se_pin_provision: invalid pin");
    return false;
  }

  // Delete any existing PIN object so this is idempotent (re-provisioning
  // during PIN change or new-device-after-restore). Anonymous delete may
  // fail if the existing PIN was provisioned with a restrictive policy
  // (legacy bench units); the subsequent WriteUserID will then fail with
  // 6985, and the user needs to use factory reset or a fresh slot.
  // v5.1: no delete-first. Onboarding runs on a FRESH generation, so the id
  // is empty; if it is not, refuse rather than reuse an object whose policy
  // and attempt counter we did not set.
  if (se_object_exists(pinObjId)) {
    Serial.printf("[SE051] se_pin_provision: 0x%08X already exists - refusing (v5.1: fresh generation expected)\n", (unsigned)pinObjId);
    return false;
  }

  // Self-policy: PIN object grants R/W/D to its own authenticated session.
  // Without this, the SE applies a restrictive default that refuses
  // self-deletion — every PIN provision would orphan the previous one
  // on re-onboard or PIN change. M5 bringup verified this exact pattern.
  uint8_t policy[32]; size_t pp = 0;
  uint32_t arSelf = POLICY_OBJ_ALLOW_READ
                  | POLICY_OBJ_ALLOW_WRITE
                  | POLICY_OBJ_ALLOW_DELETE;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), pinObjId, arSelf);
  // v5.1 (15 Oct 2026): NOTHING ELSE. Until v5 the spend PIN carried an
  // anonymous DELETE entry and both PINs a RECOVER DELETE entry. Deleting a
  // PIN frees its id; recreating it there with a known value satisfies every
  // policy that names the id - the seed key's DEC, MODE_PCR's WRITE - so it
  // was a PIN RESET for anyone on the I2C bus (spend PIN) or anyone with the
  // G0's flash (both, via K_RECOVER). A wipe now leaves the PIN objects in
  // place as dead weight; the next onboarding uses the next generation.
  const bool anonDelete = false;

  if (!writeUserIDWithPolicy(pinObjId,
                              pin, pin_len,
                              PIN_MAX_ATTEMPTS,
                              policy, pp)) {
    Serial.println("[SE051] se_pin_provision: WriteUserID failed");
    return false;
  }

  Serial.printf("[SE051] PIN object 0x%08X provisioned (max_attempts=%u, self-delete OK%s)\n",
                (unsigned)pinObjId, PIN_MAX_ATTEMPTS,
                anonDelete ? " + anon-delete" : "");
  return true;
}

// Legacy wrapper: targets the daily PIN. Existing onboarding callers unchanged.
bool se_pin_provision(const uint8_t *pin, size_t pin_len) {
  return se_pin_provision_obj(SE_OBJ_PIN_DAILY, pin, pin_len);
}

// ── se_pin_destroy (authenticated PIN deletion) ──────────────────
//
// Opens a session against SE_OBJ_USER_PIN, verifies with the supplied
// current_pin, then deletes the PIN object from inside the session.
// The SE permits this because the session is authenticated against
// the same object being deleted.
//
// Returns true if the PIN object is gone after the call. False if:
//   - current_pin was wrong (SE retry counter decremented)
//   - the PIN object doesn't exist (treat as success — slot is clear)
//   - any APDU error during session/delete
bool se_pin_destroy(const char *current_pin) {
  if (!g_ready) {
    Serial.println("[SE051] se_pin_destroy: SE not ready");
    return false;
  }

  // The PIN (UserID auth object) and the AES wrap key are provisioned with
  // policies that grant R/W/DELETE to the PIN's OWN AUTHENTICATED SESSION —
  // NOT anonymously. Anonymous DeleteSecureObject on them returns 6986
  // ("no current session"). So we must delete them FROM WITHIN an open PIN
  // session. The Nostr scalar is a plain binary blob and deletes either way.
  //
  // We open (or reuse) the PIN session ONCE. se_pin_session_open is idempotent
  // — if a session is already open (the unlock session), it is reused and the
  // PIN retry counter is NOT touched. Only if no session is open do we verify
  // the PIN to create one (a correct PIN here does not burn the counter).
  bool had_session = g_pin_session_open;
  if (!g_pin_session_open) {
    if (!current_pin || !se_pin_session_open(current_pin)) {
      Serial.println("[SE051] se_pin_destroy: could not open PIN session — cannot delete session-bound objects");
      // Best effort: the scalar is anonymous-deletable, try it so we don't
      // leave the existence marker behind.
      bool sc = tryDeleteObject_internal(SE_OBJ_NOSTR_SCALAR);
      // v5.1: the spend PIN no longer carries an anonymous-delete entry (that
      // was a PIN reset); this attempt is refused and the object stays dead.
      bool sp = tryDeleteObject_internal(SE_OBJ_PIN_SPEND);
      // The pair-wrap key has a NO-AUTH delete policy, so it deletes without a
      // session — clear it too so a stale device identity never survives a wipe.
      bool pw = tryDeleteObject_internal(SE_OBJ_PAIR_WRAP);
      Serial.printf("[SE051] se_pin_destroy: no-session path (scalar=%d spend_pin=%d pair_wrap=%d, daily-pin/wrap NOT deleted)\n", sc, sp, pw);
      return false;
    }
  }
  (void)had_session;

  // Delete order: dependent objects FIRST, the PIN auth object LAST — because
  // deleting the PIN object tears down the very session we are deleting
  // through. (Matches the two-door spec ordering rule.)
  bool scalar_gone = deleteInSession(g_session_id, SE_OBJ_NOSTR_SCALAR);
  // Isolated-signer objects. The scalar and daily key reference these in
  // their policies, so they go AFTER the scalar and before the PIN. Both are
  // deletable from the daily session by policy. The G0's own copy of the keys
  // is wiped best-effort; the SE objects are the ones that matter.
  if (se_object_exists(SE_OBJ_NSEC_IMPORT)) deleteInSession(g_session_id, SE_OBJ_NSEC_IMPORT);
  // Two-door (V1.x): there are now TWO wrap keys.
  //   - SEED key  (SE_OBJ_AES_WRAP_SEED, spend-bound): the daily session can
  //     still DELETE it because its policy grants DELETE to the daily PIN
  //     (the second policy entry added at provisioning). It cannot ENC/DEC
  //     with it — only destroy it. That's exactly the wipe path.
  //   - DAILY key (SE_OBJ_AES_WRAP_DAILY, daily-bound): deletes normally in
  //     this daily session.
  // tryDeleteObject in-session is tolerant of absence, so on a pre-split
  // single-PIN board (no daily key yet) the daily-key delete is a no-op.
  bool wrap_gone      = deleteInSession(g_session_id, SE_OBJ_AES_WRAP_SEED);
  bool wrapdaily_gone = deleteInSession(g_session_id, SE_OBJ_AES_WRAP_DAILY);
  // 19 Oct 2026 (review finding 3): the latch is no longer deleted here.
  // Neither PIN holds DELETE on it and the G0's MODEDEL is retired: a latch
  // that can be deleted can be re-created already reading BTC. It goes in
  // the G0's WIPEALL below (RECOVER right), and only after the seed wrap key
  // is gone. A re-onboard does not need it removed: it takes a new object
  // generation, so it creates a new latch with the current policy.
#ifdef FAVILLA_PASSKEY_DOOR
  se_passkey_wipe_credentials();   // 30 Oct 2026: passkey credential keys (anonymous DELETE by policy)
#endif
  bool mode_gone   = !se_object_exists(SE_OBJ_PCR_MODE_FWD);   // re-read after WIPEALL below
  mode_btc_value_erase();   // 16 Sep 2026: the S-derived BTC value belongs to the wallet being wiped
  bool g0auth_gone = !se_object_exists(SE_AUTH_OBJ_G0) || deleteInSession(g_session_id, SE_AUTH_OBJ_G0);
  bool pcr_gone    = !se_object_exists(SE_OBJ_PCR_UNLOCK) || deleteInSession(g_session_id, SE_OBJ_PCR_UNLOCK);
  bool d1sec_gone  = !se_object_exists(SE_OBJ_DOOR1_SECRET) || deleteInSession(g_session_id, SE_OBJ_DOOR1_SECRET);   // v5.1
  (void)d1sec_gone;
  // v4.1: the recovery auth object is self-only, so only the G0 can remove
  // it. WIPEALL over K_RECOVER deletes it (and anything the daily session
  // could not) BEFORE the G0 forgets K_SE below. One SE session at a time:
  // close ours, let the G0 work, reopen for the PIN delete that follows.
  if (se_object_exists(SE_AUTH_OBJ_RECOVER) && g0_present()) {
    se_pin_session_close();
    uint16_t done = 0, missing = 0;
    bool wall = g0_wipe_all(&done, &missing);
    Serial.printf("[SE051] se_pin_destroy: G0 WIPEALL %s (done %04X missing %04X) - recovery object %s\n",
                  wall ? "ok" : "FAILED", done, missing, se_object_exists(SE_AUTH_OBJ_RECOVER) ? "STILL PRESENT" : "gone");
    if (!(current_pin && se_pin_session_open(current_pin))) {
      Serial.println("[SE051] se_pin_destroy: daily session not reopened after WIPEALL (PIN object may already be gone)");
    }
  }
  if (g0_present()) g0_wipe_keys();
  mode_gone = mode_gone || !se_object_exists(SE_OBJ_PCR_MODE_FWD);   // 19 Oct 2026: WIPEALL's job now
  // 19 Oct 2026: these two were read before WIPEALL and logged stale (g0auth=0
  // after a wipe that had removed it). Re-read like mode_gone.
  g0auth_gone = g0auth_gone || !se_object_exists(SE_AUTH_OBJ_G0);
  pcr_gone    = pcr_gone    || !se_object_exists(SE_OBJ_PCR_UNLOCK);
  Serial.printf("[SE051] se_pin_destroy: g0auth=%d pcr=%d mode=%d\n", g0auth_gone, pcr_gone, mode_gone);
  // Two-door (V1.x): the SPEND PIN object is a USER credential — a wallet
  // reset must destroy BOTH PIN objects (deleteSlot future-proofing rule).
  // It is provisioned with an ANONYMOUS-delete policy (auth-obj 0x00000000),
  // so it deletes from this daily session — OR with no session at all — which
  // is exactly what makes "either PIN wipes both" work: the user only ever
  // has the DAILY session open at Delete-Key time, never the spend session.
  // tryDeleteObject_internal is tolerant of absence (returns true on 6A82 /
  // object-not-found via checkSW), so on this single-PIN board — where the
  // spend PIN does not yet exist — this is a harmless no-op. CRITICAL: this
  // is the SAFETY NET. It must exist BEFORE any onboard can create a spend
  // PIN, so that a half-finished two-door onboard can always be recovered by
  // Delete Key rather than stranding 0x70000005 on a chip with no DeleteAll.
  bool spendpin_gone = !se_object_exists(SE_OBJ_PIN_SPEND) || tryDeleteObject_internal(SE_OBJ_PIN_SPEND);   // v4.1: WIPEALL may have taken it
  // Pair-wrap key (device identity) — NO-AUTH delete policy, so anonymous
  // delete works; do it here so a recovery-wipe / re-onboard mints a fresh
  // identity rather than inheriting the old dev_pair_pub.
  bool pairwrap_gone = !se_object_exists(SE_OBJ_PAIR_WRAP) || tryDeleteObject_internal(SE_OBJ_PAIR_WRAP);
  // v5.1: the daily PIN object is NOT deleted. Freeing its id while any
  // object that names it survived an earlier failed delete would let anyone
  // recreate it with a known PIN. The generation is dead once the G0 has
  // forgotten its keys (above); the next onboarding takes a fresh one.
  bool pin_gone    = false;   // never deleted (see above); kept for the log lines below

  // The session's auth object is gone (or we are done with it) — drop our
  // handle. Don't call closeSessionInternal: if the PIN object was deleted the
  // session is already invalid; just clear local state.
  if (g_pin_session_open) closeSessionInternal(g_session_id);   // v5.1: the PIN object survives, so close properly
  g_pin_session_open = false;
  g_session_obj      = 0;
  mbedtls_platform_zeroize(g_session_id, 8);

  // v4.1: after a WIPEALL the earlier per-object flags may read "failed" for
  // objects the G0 has since removed; re-read the ones that matter.
  scalar_gone = scalar_gone || !se_object_exists(SE_OBJ_NOSTR_SCALAR);
  wrap_gone   = wrap_gone   || !se_object_exists(SE_OBJ_AES_WRAP_SEED);
  if (scalar_gone && wrap_gone) {
    Serial.printf("[SE051] wallet objects destroyed (PIN object left in place, unused by firmware; scalar + seed-wrap; daily-wrap=%d spend_pin=%d pair_wrap=%d)\n",
                  wrapdaily_gone, spendpin_gone, pairwrap_gone);
  } else {
    Serial.printf("[SE051] se_pin_destroy: partial wipe (pin=%d scalar=%d seed_wrap=%d daily_wrap=%d spend_pin=%d pair_wrap=%d)\n",
                  pin_gone, scalar_gone, wrap_gone, wrapdaily_gone, spendpin_gone, pairwrap_gone);
  }
  // v5.1: true once the secrets are gone. The PIN object stays: the SE would
  // still verify the old PIN against it, but no secret of any live wallet
  // names it, and this firmware never uses that generation again.
  return scalar_gone && wrap_gone;
}

// ── se_factory_reset (applet-wide wipe) ─────────────────────────────
//
// SE051 IoT Applet DeleteAll command. Wipes every object in the SE
// namespace. The applet itself survives. After this returns, the SE
// is in factory-fresh state — same as a brand-new SE051 chip.
//
// Also clears the favilla_se NVS namespace flags so se_first_boot_setup
// will reprovision the AES wrap key on the next call.
// Does RESERVED_ID_FACTORY_RESET (0x7FFF0205) exist on this chip? DeleteAll is
// only permitted from a session authenticated as that object (AN12543 3.2.4.1.1.5
// + Tab.339 notes). If it is absent, DeleteAll is simply not available here.
bool se_factory_reset_probe() {
  constexpr uint32_t RESERVED_ID_FACTORY_RESET = 0x7FFF0205u;
  bool present = se_object_exists(RESERVED_ID_FACTORY_RESET);
  Serial.printf("[SE051] RESERVED_ID_FACTORY_RESET (0x7FFF0205): %s\n",
                present ? "PRESENT (DeleteAll may be usable via a session as this object)"
                        : "ABSENT (DeleteAll unavailable on this chip)");
  return present;
}

bool se_factory_reset() {
  if (!g_ready) {
    Serial.println("[SE051] se_factory_reset: SE not ready");
    return false;
  }

  // DeleteAll APDU: CLA=80 INS=04 P1=00 P2=06, no data, no Le
  uint8_t apdu[8];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_MGMT, P1_DEFAULT, P2_DELETE_ALL,
                              nullptr, 0, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (!checkSW(resp, n, "DeleteAll")) return false;

  Serial.println("[SE051] applet namespace wiped");

  // Close any session we were tracking (it's gone now anyway)
  g_pin_session_open = false;
  g_session_obj      = 0;
  mbedtls_platform_zeroize(g_session_id, 8);

  // Clear the NVS first-boot flag so se_first_boot_setup re-runs
  Preferences prefs;
  if (prefs.begin(NVS_NS, false, NVSPART_SEC)) {
    prefs.remove("wrapkey_done");
    // Also clear any seed blob — it was wrapped with the now-destroyed AES key
    prefs.remove(NVS_KEY_SEED);
    prefs.remove(NVS_KEY_SEEDKIND);   // v4
    prefs.end();
    Serial.println("[SE051] NVS flags cleared (wrapkey_done, seed_blob)");
  }

  return true;
}

// ── se_random (SE TRNG → host buffer) ───────────────────────────────
//
// GetRandom APDU per AN12543 §4.x:
//   CLA = 0x80
//   INS = INS_MGMT (0x04)
//   P1  = P1_DEFAULT (0x00)
//   P2  = P2_RANDOM (0x49)
//   Data = TAG_1 + (2-byte BE length)
//   Le  = 0x00
//
// Response: TAG_1 + (2-byte BE length) + random bytes + SW
bool se_random(uint8_t *out, size_t len) {
  if (!out) return false;
  if (len == 0 || len > 256) {
    Serial.printf("[SE051] se_random: invalid len %u\n", (unsigned)len);
    if (out && len > 0) mbedtls_platform_zeroize(out, len);
    return false;
  }
  if (!g_ready) {
    Serial.println("[SE051] se_random: SE not ready");
    mbedtls_platform_zeroize(out, len);
    return false;
  }

  // Build payload: TAG_1 + 2-byte BE length.
  uint8_t lenBytes[2] = { (uint8_t)((len >> 8) & 0xFF), (uint8_t)(len & 0xFF) };
  uint8_t payload[8]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, lenBytes, 2);

  uint8_t apdu[16];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_MGMT, P1_DEFAULT, P2_RANDOM,
                              payload, p, true);

  // Response can be up to 256 + TLV overhead + 2 SW bytes
  uint8_t resp[264];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  if (!checkSW(resp, n, "GetRandom")) {
    mbedtls_platform_zeroize(out, len);
    return false;
  }

  size_t bodyLen = (size_t)n - 2;
  if (bodyLen < 2 || resp[0] != TAG_1) {
    Serial.println("[SE051] se_random: malformed response");
    mbedtls_platform_zeroize(out, len);
    return false;
  }

  size_t valOffset;
  int valLen = parseTLVLength(resp, bodyLen, &valOffset);
  if (valLen != (int)len) {
    Serial.printf("[SE051] se_random: response len %d (expected %u)\n",
                  valLen, (unsigned)len);
    mbedtls_platform_zeroize(out, len);
    return false;
  }

  memcpy(out, resp + valOffset, len);
  // Zero the response buffer's random bytes — they shouldn't linger.
  mbedtls_platform_zeroize(resp + valOffset, len);
  return true;
}

// ── Seed storage (Step 2 — Strategy A) ─────────────────────────────

// Shared tail of seed_store / seed_store_entropy: SE-wrap the two halves of a
// G0-sealed 64-byte inner ciphertext, write the 96-byte blob + kind tag.
static bool seed_blob_store(uint8_t inner[64], uint8_t kind) {
  uint8_t blob[SEED_BLOB_LEN];

  uint8_t iv_lo[16]; freshIV(iv_lo);
  uint8_t ct_lo[32];
  if (!se_aes_wrap_block(inner + 0, iv_lo, ct_lo)) {
    Serial.println("[SE051] seed_store: SE wrap (lo) failed");
    mbedtls_platform_zeroize(inner, 64);
    return false;
  }
  memcpy(blob + 0,  iv_lo, 16);
  memcpy(blob + 16, ct_lo, 32);

  uint8_t iv_hi[16]; freshIV(iv_hi);
  uint8_t ct_hi[32];
  if (!se_aes_wrap_block(inner + 32, iv_hi, ct_hi)) {
    Serial.println("[SE051] seed_store: SE wrap (hi) failed");
    mbedtls_platform_zeroize(blob, SEED_BLOB_LEN);
    mbedtls_platform_zeroize(inner, 64);
    return false;
  }
  memcpy(blob + 48, iv_hi, 16);
  memcpy(blob + 64, ct_hi, 32);
  uint8_t ihash[32];
  mbedtls_sha256(inner, 64, ihash, 0);
  mbedtls_platform_zeroize(inner, 64);

  // v5.1 (15 Oct 2026): the blob goes to the G0's write-once seed page, never
  // to this chip's flash. The G0 binds it to the inner layer it sealed in this
  // power-on life (by hash) and refuses a second store until a wipe, so code
  // on this chip can neither swap in a seed of its choosing nor delete it.
  uint8_t g0hash[32] = {0}, rc = 0xFF;
  bool ok = g0_seed_store(kind, blob, g0hash, &rc);
  mbedtls_platform_zeroize(blob, SEED_BLOB_LEN);
  if (!ok) {
    Serial.printf("[SE051] seed_store: the G0 did not store the blob (rc %02X) - seed NOT stored\n", rc);
    return false;
  }
  if (memcmp(g0hash, ihash, 32) != 0) {
    Serial.println("[SE051] seed_store: G0 stored a different inner hash than this seal - refusing");
    return false;
  }
  seed_erase_from_nvs();   // a pre-v5.1 NVS copy, if any, must not linger
  Serial.printf("[SE051] %s stored on the G0 (double-wrapped: G0 inner layer + SE outer layer; write-once)\n",
                kind == SEED_KIND_ENTROPY ? "entropy container" : "seed");
  return true;
}

bool seed_store(const uint8_t seed[64]) {
  if (!g_ready) {
    Serial.println("[SE051] seed_store: SE not ready");
    return false;
  }
  uint8_t inner[64];
  if (!g0_seed_seal(seed, inner)) {
    Serial.println("[SE051] seed_store: G0 inner seal FAILED - seed NOT stored (G0 keys missing or G0 absent)");
    return false;
  }
  return seed_blob_store(inner, SEED_KIND_SEED);
}

// v4: per-session passphrase wallet. The G0 builds and seals the container
// ("FENT" | wc | entropy); this chip only ever sees its ciphertext afterwards.
bool seed_store_entropy(const uint8_t* entropy, int word_count) {
  if (!g_ready) {
    Serial.println("[SE051] seed_store_entropy: SE not ready");
    return false;
  }
  if (!(word_count == 12 || word_count == 24)) return false;
  uint8_t inner[64];
  if (!g0_ent_seal(entropy, word_count, inner)) {
    Serial.println("[SE051] seed_store_entropy: G0 inner seal FAILED - entropy NOT stored");
    return false;
  }
  return seed_blob_store(inner, SEED_KIND_ENTROPY);
}

uint8_t seed_blob_kind() {
  // v5.1: the kind is part of the G0's seed record.
  uint8_t k = SEED_KIND_SEED;
  if (!g0_seed_get(&k, nullptr, nullptr)) return SEED_KIND_SEED;
  return (k == SEED_KIND_ENTROPY) ? SEED_KIND_ENTROPY : SEED_KIND_SEED;
}

// v5 (15 Oct 2026): strip the SE's outer layer of the 96-byte seed blob
// INSIDE an open, SE-verified SPEND PIN session, while MODE_PCR == BTC (the
// key policy enforces both). The result is the G0's inner layer, 64 bytes of
// AES-256 ciphertext under K_SEEDWRAP: useless to this processor, and handed
// to the G0 as the SEED_IN/ENT_IN inner packet. A 6986 here on a KEY
// onboarded before v5 means the seed key still carries the old policy (DEC
// for the G0, none for the spend PIN): that KEY must be wiped and re-onboarded.
bool seed_inner_from_blob_in_open_session(const uint8_t blob[SEED_BLOB_LEN], uint8_t inner_out[64]) {
  if (!g_pin_session_open || g_session_obj != SE_OBJ_PIN_SPEND) {
    Serial.println("[SE051] seed inner: refused - needs an open SPEND PIN session");
    return false;
  }
  bool ok = se_aes_unwrap_block_keyed(SE_OBJ_AES_WRAP_SEED, blob + 16, blob + 0,  inner_out + 0)
         && se_aes_unwrap_block_keyed(SE_OBJ_AES_WRAP_SEED, blob + 64, blob + 48, inner_out + 32);
  if (!ok) {
    mbedtls_platform_zeroize(inner_out, 64);
    Serial.println("[SE051] seed inner: SE refused DEC (latch not BTC, or a pre-v5 seed key policy - wipe and re-onboard)");
  }
  return ok;
}

bool seed_unwrap_to_ram(uint8_t seed_out[64]) {
  // v3 (16 Sep 2026): PERMANENTLY DISABLED. v5: the seed's SE layer is
  // stripped only inside a spend-PIN session (seed_inner_from_blob_in_open_
  // session), which yields the inner layer, and the inner layer only by the
  // G0's K_SEEDWRAP.
  // This processor has no path to a plaintext seed after onboarding. Every
  // former caller now goes through g0_door_keys() / g0_btc_sign(). Kept as a
  // hard stop so any stray call fails loudly rather than silently.
  (void)seed_out;
  Serial.println("[SE051] seed_unwrap_to_ram: DISABLED (v3) - the seed lives on the G0; use g0_door_keys / g0_btc_sign");
  mbedtls_platform_zeroize(seed_out, 64);
  return false;
}

// Read the 96-byte seed blob (ciphertext: SE layer over the G0 layer) from
// the G0 (v5.1). No session needed: the bytes are useless without a verified
// spend PIN (outer, v5) and the G0's K_SEEDWRAP (inner). kind/ihash optional.
bool seed_blob_read(uint8_t blob[SEED_BLOB_LEN], uint8_t* kind, uint8_t ihash[32]) {
  bool known = false;
  if (!g0_seed_get(kind, blob, ihash, &known)) {
    Serial.printf("[SE051] seed_blob_read: %s\n", known ? "no seed stored on the G0" : "G0 did not answer");
    mbedtls_platform_zeroize(blob, SEED_BLOB_LEN);
    return false;
  }
  return true;
}

bool seed_is_provisioned() {
  return g0_seed_get(nullptr, nullptr, nullptr);   // v5.1: the G0 holds it or nobody does
}

bool seed_erase_from_nvs() {
  Preferences prefs;
  if (!prefs.begin(NVS_NS, false, NVSPART_SEC)) {
    Serial.println("[SE051] seed_erase: NVS open failed");
    return false;
  }
  // remove returns true on success or if the key didn't exist.
  bool ok = prefs.remove(NVS_KEY_SEED);
  prefs.remove(NVS_KEY_SEEDKIND);   // v4
  prefs.end();
  if (!ok) {
    // Some ESP-IDF versions return false when the key wasn't there.
    // Re-check by querying length; if it's now zero, treat as success.
    if (!seed_is_provisioned()) ok = true;
  }
  if (ok) Serial.println("[SE051] seed blob erased from NVS");
  return ok;
}

// ============================================================
// Provisioning (M7 Step 6)
//
// Three onboarding paths converge here. Each is idempotent —
// any existing object at the target slot is deleted first, then
// the new value is wrapped and written. Caller must zero the
// input scalar after the call returns.
//
// All three require the SE to be ready and an open PIN session
// (same fail-closed invariant as signing). The AES wrap key
// provisioning is the exception — it runs before any user PIN
// exists, so it doesn't gate on the session.
// ============================================================

// Generic helper: delete then write a BinaryFile with the wrapped scalar.
// Used by both Nostr scalar and imported-nsec provisioning. NOT public —
// callers go through se_provision_nostr_scalar or se_provision_imported_nsec.

// Two-door core: provision a wrap key at `keyObjId`, binding ENC/DEC to
// `bindObjId`'s session. If `grantDailyDelete`, also grant DELETE-only to the
// DAILY PIN (used for the spend-bound SEED key so "either PIN wipes both"
// works). PRECONDITION: a session against bindObjId must be open.
// modeGate: 0 = none, 1 = require MODE==NOSTR on the G0-DEC entry (daily key),
//           2 = require MODE==BTC on the bind-PIN ENC/DEC entry (seed key).
bool se_provision_wrap_key_core(uint32_t keyObjId, uint32_t bindObjId,
                                bool grantDailyDelete, bool grantG0Decrypt = false,
                                int modeGate = 0) {
  if (!g_ready) {
    Serial.println("[SE051] se_provision_wrap_key: SE not ready");
    return false;
  }
  // The key's ENC/DEC + WRITE bind to bindObjId's session — the SE enforces it
  // in silicon. PRECONDITION: a session AGAINST bindObjId must be open, so the
  // WRITE permission is satisfied and the policy's referenced object exists.
  if (!g_pin_session_open) {
    Serial.println("[SE051] se_provision_wrap_key: no PIN session "
                   "(policy requires the bind PIN object to exist + its session)");
    return false;
  }
  // modeGate 2 (seed key): the WRITE/ENC/DELETE holder is the DAILY PIN (see
  // below), so the key must be written inside a DAILY session even though its
  // DEC binds to the spend PIN.
  const uint32_t writeObj = (modeGate == 2) ? SE_OBJ_PIN_DAILY : bindObjId;
  if (g_session_obj != writeObj) {
    Serial.printf("[SE051] se_provision_wrap_key: open session is obj 0x%08X "
                  "but key must be written from 0x%08X — WRITE will be refused\n",
                  (unsigned)g_session_obj, (unsigned)writeObj);
    return false;
  }

  // Generate the AES-256 key host-side using ESP32 hardware RNG, then write
  // it via WriteSymmKey. The key never leaves the SE again.
  uint8_t key[32];
  for (int i = 0; i < 32; i += 4) {
    uint32_t r = esp_random();
    key[i+0] = (r      ) & 0xFF;
    key[i+1] = (r >>  8) & 0xFF;
    key[i+2] = (r >> 16) & 0xFF;
    key[i+3] = (r >> 24) & 0xFF;
  }

  // Delete any prior key at this slot first (idempotent re-provisioning).
  // A policy is fixed at object creation: overwriting an existing key keeps
  // its OLD policy, silently. So the delete must actually succeed — and an
  // anonymous delete is refused (6985) on any policied object, so do it from
  // the open session (which holds DELETE on this key by policy). If the
  // object is still there afterwards, refuse rather than provision a key
  // whose policy is not what this code says it is.
  tryDeleteObject_internal(keyObjId);            // harmless if absent/unpoliced
  if (se_object_exists(keyObjId)) deleteInSession(g_session_id, keyObjId);
  if (se_object_exists(keyObjId)) {
    Serial.printf("[SE051] se_provision_wrap_key: 0x%08X still exists after delete - "
                  "refusing to overwrite (policy would be stale). Wipe first.\n",
                  (unsigned)keyObjId);
    mbedtls_platform_zeroize(key, 32);
    return false;
  }

  // Policy: bindObjId's session may ENC/DEC + WRITE + DELETE. Any explicit
  // policy disables the permissive default (AN12543 Table 17), so anonymous
  // CipherOneShot is denied.
  uint8_t policy[128]; size_t pp = 0;
  uint32_t arBind = POLICY_OBJ_ALLOW_ENC | POLICY_OBJ_ALLOW_DEC
                  | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE;
  if (modeGate == 2) {
    // ── Two-door SEED key: DEC gated on MODE==BTC, ENC ungated ────────────
    // The threat is seed EXTRACTION, which is a DECRYPT. Wrapping the seed at
    // onboarding is an ENCRYPT and is harmless, so ENC carries no mode clause
    // and onboarding needs only ONE mode transition (-> NOSTR), which the G0's
    // single per-boot reset can supply.
    //
    // SILICON FINDING (11 Sep 2026, fourth AN12413 divergence): TWO POLICY
    // ENTRIES FOR THE SAME AUTH OBJECT ARE NOT OR'D. The applet resolves the
    // session's auth object to ONE entry (the first) and evaluates only that.
    // The previous encoding — spend:ENC|WRITE|DELETE then spend:DEC+PCR(BTC) —
    // set MODE->BTC byte-exact and was still refused DEC with 6986, because
    // only the first spend entry was ever consulted. Entries for DIFFERENT
    // auth objects ARE OR'd (proven July 2026, test 4), so the two rights are
    // split across two objects instead:
    //   * DAILY PIN : ENC | WRITE | DELETE, no mode clause — wraps the seed at
    //                 onboarding, re-provisions, wipes. It can never DEC, so a
    //                 phished daily PIN yields no seed. (It could already DELETE
    //                 this key, so ENC adds no new destructive power.)
    //   * SPEND PIN : DEC only, and only while MODE_PCR == BTC — the one
    //                 operation that can leak the seed, reachable only by
    //                 extending from the G0-produced neutral.
    // Consequence for onboarding: this key and seed_store() now run inside
    // the DAILY session (the spend session only has to create the spend PIN
    // object and MODE_PCR beforehand).
    if (!g_mode_vals_valid) modeComputeValues();
    if (!se_object_exists(SE_OBJ_PCR_MODE_FWD)) {
      Serial.println("[SE051] se_provision_wrap_key: MODE_PCR missing - set mode first");
      mbedtls_platform_zeroize(key, 32);
      return false;
    }
    // 16 Sep 2026: the DEC gate must reference the S-derived BTC value, never
    // the legacy public-label one — otherwise the ESP32 could still extend to
    // it. mode_btc_secret_begin() must have run in this onboarding session.
    // v3: onboarding now delivers S to the G0 (se_provision_g0_identity, which
    // then forgets the pending copy) BEFORE this key is created, so the value
    // must be S-derived AND either still pending or already delivered.
    if (!g_mode_btc_from_g0 || !(g_mode_secret_pending_valid || g_mode_secret_delivered)) {
      Serial.println("[SE051] se_provision_wrap_key: BTC value is not G0-secret-derived (or S never reached the G0) - call mode_btc_secret_begin() then se_provision_g0_identity() first");
      mbedtls_platform_zeroize(key, 32);
      return false;
    }
    // v5 (15 Oct 2026): the DEC right belongs to the SPEND PIN again, gated
    // on MODE_PCR == BTC. v3 had moved it to the G0's auth object, and that
    // made the PIN optional for anyone holding the G0's secrets: with K_SE
    // (open a session as the G0), S (reset + extend the latch to BTC, both
    // G0 rights on MODE_PCR) and K_G0 (strip the inner layer), a G0 readout
    // or an I2C tap during SETKEYS gave the whole seed with NO PIN, because
    // "a PIN armed the door" was checked only by the G0's firmware. Now the
    // SE itself refuses the only operation that opens the seed unless a
    // verified spend-PIN session asks for it, AND the latch reads BTC, which
    // only S can produce. What the spend session gets back is still the
    // G0's INNER layer (AES-256 under K_SEEDWRAP), so this processor still
    // has no path to a plaintext seed: it hands the inner layer to the G0,
    // which re-checks the latch over its own session, burns it, and strips.
    // The G0 auth object still has to exist first (onboarding order: G0
    // identity, which delivers S, BEFORE the seed key).
    if (!se_object_exists(SE_AUTH_OBJ_G0)) {
      Serial.println("[SE051] se_provision_wrap_key: G0 auth object missing - provision the G0 identity BEFORE the seed key (v3)");
      mbedtls_platform_zeroize(key, 32);
      return false;
    }
    // entry 1: DAILY PIN — ENC + WRITE + DELETE, no mode clause
    pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_DAILY,
                          POLICY_OBJ_ALLOW_ENC | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
    // entry 2: SPEND PIN — DEC only, and only while MODE_PCR == BTC.
    // (One entry per auth object: the spend PIN has no other right here.)
    // The G0 auth object has NO entry on this key any more (v5).
    pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), SE_OBJ_PIN_SPEND,
                             POLICY_OBJ_ALLOW_DEC, SE_OBJ_PCR_MODE_FWD, g_mode_btc);
    (void)bindObjId;
    // The daily entry above already carries DELETE; a second daily entry would
    // be another same-object duplicate and must NOT be added (see finding).
    grantDailyDelete = false;
  } else {
    pp = buildPolicyEntry(policy, pp, sizeof(policy), bindObjId, arBind);
  }

  if (grantDailyDelete) {
    // Second entry: DELETE-only to the DAILY PIN, so a wipe from the daily
    // session can destroy this key without being able to ENC/DEC with it.
    pp = buildPolicyEntry(policy, pp, sizeof(policy),
                          SE_OBJ_PIN_DAILY, POLICY_OBJ_ALLOW_DELETE);
  }

  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);   // v4.1: recovery wipe
  if (grantG0Decrypt) {
    // DAILY key only. The scalar is stored AES(K_DAILY, AES(K_G0, scalar)); the
    // G0 must strip the outer K_DAILY layer from ITS session, so its auth
    // object gets DEC — and ONLY DEC, and ONLY while the Door-1 PCR says
    // unlocked. It cannot encrypt, write or delete with this key.
    if (!se_object_exists(SE_AUTH_OBJ_G0) || !g_pcr_unlocked_valid) {
      Serial.println("[SE051] se_provision_wrap_key: G0 auth object missing - provision the G0 identity first");
      mbedtls_platform_zeroize(key, 32);
      return false;
    }
    if (modeGate == 1) {
      // Two-door: the G0 may strip the outer wrap ONLY while MODE_PCR == NOSTR.
      // MODE==NOSTR can only be set by the daily PIN this power-on life and
      // cannot be forged (anon writes refused, proven), so this single gate
      // already implies "daily PIN entered + Nostr door chosen". It REPLACES
      // the Door-1 (SE_OBJ_PCR_UNLOCK) gate on this entry — one PCR per entry.
      if (!g_mode_vals_valid) modeComputeValues();
      if (!se_object_exists(SE_OBJ_PCR_MODE_FWD)) {
        Serial.println("[SE051] se_provision_wrap_key: MODE_PCR missing - set mode first");
        mbedtls_platform_zeroize(key, 32);
        return false;
      }
      pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), SE_AUTH_OBJ_G0,
                               POLICY_OBJ_ALLOW_DEC, SE_OBJ_PCR_MODE_FWD, g_mode_nostr);
    } else {
      pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), SE_AUTH_OBJ_G0,
                               POLICY_OBJ_ALLOW_DEC, SE_OBJ_PCR_UNLOCK, g_pcr_unlocked);
    }
  }

  // WriteSymmKey APDU: CLA=80 INS=01 P1=0x03 (AES) P2=0x00
  uint8_t payload[160]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(keyObjId >> 24), (uint8_t)(keyObjId >> 16),
    (uint8_t)(keyObjId >>  8), (uint8_t) keyObjId
  };
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, key, 32);

  uint8_t apdu[192];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_WRITE, 0x03 /* P1_AES */, P2_DEFAULT,
                              payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));

  mbedtls_platform_zeroize(key, 32);

  if (!checkSW(resp, n, "WriteSymmKey(PIN-bound)")) return false;
  Serial.printf("[SE051] AES wrap key 0x%08X provisioned (ENC/DEC bound to 0x%08X%s)\n",
                (unsigned)keyObjId, (unsigned)bindObjId,
                grantDailyDelete ? ", DELETE also granted to daily PIN" : "");
  return true;
}

// Two-door entry points:
//   SEED key  → bound to SPEND, dual-delete (daily can wipe). Requires an open
//               SPEND session.
//   DAILY key → bound to DAILY, single policy. Requires an open DAILY session.
bool se_provision_aes_wrap_key_seed() {
  // Two-door: the SEED (BTC) wrap key is usable ONLY while MODE_PCR == BTC.
  // MODE->BTC is committed inside the spend session in bitcoin_menu.inc
  // (airgapPsbtConfirmAndSign) right after the spend PIN opens it and before
  // seed_unwrap_to_ram — so the unwrap is satisfied during a real spend, and
  // refused (6986) in NOSTR mode. Onboarding also sets MODE->BTC in the spend
  // session before creating this key, so the seed wrap at onboarding works.
  // Requires an open DAILY session (the daily PIN holds ENC/WRITE/DELETE; the
  // spend PIN holds DEC gated on MODE==BTC — see the modeGate==2 policy).
  return se_provision_wrap_key_core(SE_OBJ_AES_WRAP_SEED, SE_OBJ_PIN_SPEND,
                                    /*grantDailyDelete=*/false,   // folded into entry 1
                                    /*grantG0Decrypt=*/false,
                                    /*modeGate=*/2);   // DEC only while MODE==BTC
}
bool se_provision_aes_wrap_key_daily() {
  // Third policy entry: the G0 may DECRYPT with this key, PCR-gated. That is
  // how the SE strips the outer wrap for the G0 without ever handing the key
  // or the plaintext to this processor.
  return se_provision_wrap_key_core(SE_OBJ_AES_WRAP_DAILY, SE_OBJ_PIN_DAILY,
                                    /*grantDailyDelete=*/false,
                                    /*grantG0Decrypt=*/true,
                                    /*modeGate=*/1);   // G0-DEC only while MODE==NOSTR
}

// Legacy/compat: bind the SEED wrap key to an arbitrary PIN object. Kept so the
// single-PIN wrapper below still works. New two-door code uses the explicit
// seed/daily entry points above.
bool se_provision_aes_wrap_key_bound(uint32_t bindObjId) {
  return se_provision_wrap_key_core(SE_OBJ_AES_WRAP_SEED, bindObjId,
                                    /*grantDailyDelete=*/(bindObjId == SE_OBJ_PIN_SPEND));
}

// Legacy wrapper: binds to the daily PIN (single-PIN behaviour). The spend
// session is not involved; existing single-PIN onboarding is unchanged.
bool se_provision_aes_wrap_key() {
  return se_provision_aes_wrap_key_bound(SE_OBJ_PIN_DAILY);
}

// ── se_provision_pair_wrap_key (Path-A device identity) ──────
// Writes the NO-AUTH AES-256 device-identity wrap key at SE_OBJ_PAIR_WRAP.
//
// Policy model: a SINGLE policy entry whose auth-object id is 0x00000000 (the
// SE051 "no session / anybody" reference) granting ONLY ENC|DEC, plus self
// WRITE|DELETE so the slot can be re-provisioned (mirrors the wrap-key fix at
// se_provision_aes_wrap_key). Setting an explicit policy disables the permissive
// default (AN12543 Table 17), so the key can do NOTHING except ENC/DEC and
// rewrite-itself — it cannot be read, and it is not bound to the PIN, which is
// exactly the point: deviceIdentityInit() can exercise it while LOCKED.
//
// Unlike the PIN-bound wrap key this needs NO open PIN session (the policy
// references no PIN object). We still typically call it with a session open
// (onboarding / first on-device unlock) so the key is created while the user is
// physically authenticated, but that is a policy/operational choice, not an SE
// requirement.
//
// SECURITY NOTE: the worst case if this key leaks is that an attacker can
// decrypt an ECDH/session envelope addressed to the device identity. It can
// NEVER sign, spend, or unwrap the BIP-39 seed / Nostr scalar — those remain on
// the PIN-bound SE_OBJ_AES_WRAP path. See the HANDOVER threat analysis.
bool se_provision_pair_wrap_key() {
  if (!g_ready) {
    Serial.println("[SE051] se_provision_pair_wrap_key: SE not ready");
    return false;
  }

  uint8_t key[32];
  for (int i = 0; i < 32; i += 4) {
    uint32_t r = esp_random();
    key[i+0] = (r      ) & 0xFF;
    key[i+1] = (r >>  8) & 0xFF;
    key[i+2] = (r >> 16) & 0xFF;
    key[i+3] = (r >> 24) & 0xFF;
  }

  // Idempotent: delete any prior pair-wrap key first. The self WRITE|DELETE
  // policy below permits this on a re-provision.
  tryDeleteObject_internal(SE_OBJ_PAIR_WRAP);

  // NO-AUTH policy: auth-object id 0x00000000 ⇒ rights apply with no session.
  // Grant ONLY ENC|DEC (the identity-derivation primitive) plus self
  // WRITE|DELETE so the slot is re-provisionable on a factory reset / reonboard.
  uint8_t policy[32]; size_t pp = 0;
  uint32_t arNoAuth = POLICY_OBJ_ALLOW_ENC | POLICY_OBJ_ALLOW_DEC
                    | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL, arNoAuth);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);   // v4.1: recovery wipe

  uint8_t payload[80]; size_t p = 0;
  uint8_t objId[4] = {
    (uint8_t)(SE_OBJ_PAIR_WRAP >> 24), (uint8_t)(SE_OBJ_PAIR_WRAP >> 16),
    (uint8_t)(SE_OBJ_PAIR_WRAP >>  8), (uint8_t) SE_OBJ_PAIR_WRAP
  };
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, key, 32);

  uint8_t apdu[100];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                              0x80, INS_WRITE, 0x03 /* P1_AES */, P2_DEFAULT,
                              payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));

  mbedtls_platform_zeroize(key, 32);

  if (!checkSW(resp, n, "WriteSymmKey(no-auth pair)")) return false;
  Serial.println("[SE051] Pair wrap key provisioned (no-auth, cold-capable)");
  return true;
}


// ── Isolated-signer provisioning ─────────────────────────────────────────
bool se_pcr_ensure_exists() {
  if (!g_ready) return false;
  if (se_object_exists(SE_OBJ_PCR_UNLOCK)) return true;
  if (!se_object_exists(SE_OBJ_PIN_DAILY)) {
    Serial.println("[SE051] PCR: daily PIN object absent - cannot create (policy references it)");
    return false;
  }
  if (!se_object_exists(SE_AUTH_OBJ_G0)) {   // v5.1: the policy names the G0 (extend) too
    Serial.println("[SE051] PCR: G0 auth object absent - created later by se_provision_g0_identity");
    return false;
  }
  bool ok = pcrCreateLocked();
  Serial.printf("[SE051] Door-1 PCR %s (persistent, locked)\n", ok ? "created" : "CREATE FAILED");
  return ok;
}

bool se_pcr_is_unlocked() {
  if (!g_ready || !g_pin_session_open || g_session_obj != SE_OBJ_PIN_DAILY) return false;
  uint8_t v[32];
  if (!pcrReadInSession(g_session_id, v)) return false;
  return g_pcr_unlocked_valid && memcmp(v, g_pcr_unlocked, 32) == 0;
}

bool se_g0_objects_present() {
  return g_ready && se_object_exists(SE_AUTH_OBJ_G0);
}

// v4.1: K_SE is generated by se_provision_recovery_auth() (which must run
// before any policy names the recovery object) and parked here for
// se_provision_g0_identity(). Zeroised once delivered to the G0.
static uint8_t g_kse_pending[G0_KSE_LEN];
static bool    g_kse_pending_valid = false;

static void deriveRecoverKey(const uint8_t kse[G0_KSE_LEN], uint8_t kr[16]) {
  static const uint8_t label[] = "favilla-recover-key";
  uint8_t h[32];
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, kse, G0_KSE_LEN); mbedtls_sha256_update(&c, label, sizeof(label) - 1);
  mbedtls_sha256_finish(&c, h); mbedtls_sha256_free(&c);
  memcpy(kr, h, 16); mbedtls_platform_zeroize(h, 32);
}

bool se_recovery_auth_exists() { return se_object_exists(SE_AUTH_OBJ_RECOVER); }

bool se_provision_recovery_auth() {
  if (!g_ready) { Serial.println("[SE051] recovery auth: SE not ready"); return false; }
  if (se_object_exists(SE_AUTH_OBJ_RECOVER)) {
    // Its policy is self-only, so nothing here can remove it; only the G0's
    // WIPEALL can. A leftover means the previous wipe did not finish.
    Serial.println("[SE051] recovery auth: object already exists - run the recovery wipe first");
    return false;
  }
  uint8_t kse[G0_KSE_LEN], kr[16];
  if (!se_random(kse, sizeof(kse))) { Serial.println("[SE051] recovery auth: TRNG failed"); return false; }
  deriveRecoverKey(kse, kr);
  // Self-only policy: DELETE (so WIPEALL can remove it last) + WRITE. No
  // anonymous entry - anyone able to delete and recreate this object would
  // hold DELETE on everything, and a PIN object deleted on its own is a PIN
  // reset. Only the G0, in WIPEALL's fixed order, ever uses this credential.
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER,
                        POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  uint8_t id[4] = { (uint8_t)(SE_AUTH_OBJ_RECOVER >> 24), (uint8_t)(SE_AUTH_OBJ_RECOVER >> 16),
                    (uint8_t)(SE_AUTH_OBJ_RECOVER >>  8), (uint8_t) SE_AUTH_OBJ_RECOVER };
  uint8_t payload[64]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, kr, 16);
  uint8_t apdu[96];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                             0x80, (uint8_t)(INS_WRITE | INS_AUTH_OBJECT), P1_AES, P2_DEFAULT,
                             payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  mbedtls_platform_zeroize(payload, sizeof(payload));
  mbedtls_platform_zeroize(apdu, sizeof(apdu));
  mbedtls_platform_zeroize(kr, sizeof(kr));
  bool ok = checkSW(resp, n, "WriteSymmKey(recovery auth object)");
  if (ok) {
    memcpy(g_kse_pending, kse, G0_KSE_LEN); g_kse_pending_valid = true;
    Serial.println("[SE051] recovery auth object provisioned (K_RECOVER from K_SE; DELETE-only credential for G0 WIPEALL)");
  }
  mbedtls_platform_zeroize(kse, sizeof(kse));
  return ok;
}

bool se_provision_g0_identity() {
  if (!g_ready) { Serial.println("[SE051] g0 identity: SE not ready"); return false; }
  if (!g_pin_session_open || g_session_obj != SE_OBJ_PIN_DAILY) {
    Serial.println("[SE051] g0 identity denied: daily PIN session not open");
    return false;
  }
  if (!g0_present()) {
    Serial.println("[SE051] g0 identity: G0 signer not present - refusing (no fallback)");
    return false;
  }
  computePcrAtRest();

  if (g_gen == SE_GEN_NONE) {
    Serial.println("[SE051] g0 identity: no object generation chosen - call se_begin_new_generation() first (v5.1)");
    return false;
  }
  if (!g_mode_secret_pending_valid) {
    Serial.println("[SE051] g0 identity: no pending BTC secret - call mode_btc_secret_begin() first");
    return false;
  }
  // Both keys from the SE's certified TRNG. The G0B1 has no TRNG of its own
  // (which is also why S is generated HERE and delivered, not made in the G0).
  uint8_t kse[G0_KSE_LEN], kg0[G0_KG0_LEN];
  // v4.1: K_SE was generated by se_provision_recovery_auth() so that
  // K_RECOVER (derived from it) already guards every object written since.
  if (!g_kse_pending_valid) {
    Serial.println("[SE051] g0 identity: no parked K_SE - call se_provision_recovery_auth() FIRST (v4.1)");
    return false;
  }
  memcpy(kse, g_kse_pending, G0_KSE_LEN);
  mbedtls_platform_zeroize(g_kse_pending, sizeof(g_kse_pending)); g_kse_pending_valid = false;
  if (!se_random(kg0, sizeof(kg0))) {
    Serial.println("[SE051] g0 identity: TRNG failed");
    mbedtls_platform_zeroize(kse, sizeof(kse)); mbedtls_platform_zeroize(kg0, sizeof(kg0));
    return false;
  }

  bool ok = false;
  do {
    // 1. SE side: the G0's AESKey auth object, on this fresh generation.
    //    v5.1: self WRITE (the holder may rotate its own key). Until v5 the
    //    daily PIN held WRITE|DELETE: a daily-PIN holder could delete it and
    //    recreate it under a key of their own, then act as "the G0" towards
    //    the SE. The daily PIN holds nothing on it now.
    //    20 Oct 2026 (N2): RECOVER holds DELETE again, for the G0's WIPEALL
    //    only, where it is deleted last-but-one and only once every object
    //    whose policy names it is gone (g0w src/main.c, wipe_order). This adds
    //    no capability: K_RECOVER is derived from K_SE, so whoever holds it
    //    already IS this object's key holder. Without it every wipe left the
    //    old generation's auth object on the SE for good (g0auth=0 in the
    //    wipe log) and SE object storage filled a little with each re-onboard.
    if (se_object_exists(SE_AUTH_OBJ_G0)) {
      Serial.println("[SE051] g0 identity: auth object already exists on this generation - refusing");
      break;
    }
    uint8_t policy[32]; size_t pp = 0;
    pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_G0, POLICY_OBJ_ALLOW_WRITE);
    pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);   // N2: WIPEALL, last-but-one
    uint8_t id[4] = { (uint8_t)(SE_AUTH_OBJ_G0 >> 24), (uint8_t)(SE_AUTH_OBJ_G0 >> 16),
                      (uint8_t)(SE_AUTH_OBJ_G0 >>  8), (uint8_t) SE_AUTH_OBJ_G0 };
    uint8_t payload[64]; size_t p = 0;
    p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
    p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
    p = appendTLV(payload, p, sizeof(payload), TAG_3, kse, G0_KSE_LEN);
    uint8_t apdu[96];
    // INS 0x41 = WRITE | AUTH_OBJECT (same as the PIN's WriteUserID), P1 = AES.
    size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                               0x80, (uint8_t)(INS_WRITE | INS_AUTH_OBJECT), P1_AES, P2_DEFAULT,
                               payload, p, false);
    uint8_t resp[16];
    int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
    mbedtls_platform_zeroize(payload, sizeof(payload));
    mbedtls_platform_zeroize(apdu, sizeof(apdu));
    if (!checkSW(resp, n, "WriteSymmKey(G0 auth object)")) break;

    // 2. v5.1: a fresh Door-1 secret, then the PCR DELETED and RECREATED so
    //    its policy is the current one (DAILY rwd + G0 extend, nothing for
    //    RECOVER): a PCR left by an earlier wallet or firmware keeps whatever
    //    policy it was born with. Created locked, then extended with X.
    {
      uint8_t x[32];
      bool d1 = door1MintSecret(g_session_id, x);
      if (d1 && se_object_exists(SE_OBJ_PCR_UNLOCK) && !deleteInSession(g_session_id, SE_OBJ_PCR_UNLOCK)) {
        Serial.println("[SE051] g0 identity: could not delete the previous Door-1 PCR");
        d1 = false;
      }
      if (d1 && !se_pcr_ensure_exists()) { Serial.println("[SE051] g0 identity: PCR create failed"); d1 = false; }
      if (d1 && !pcrUnlockInSession(g_session_id, x)) { Serial.println("[SE051] g0 identity: PCR extend failed"); d1 = false; }
      mbedtls_platform_zeroize(x, sizeof(x));
      if (!d1) break;
    }

    // 3. G0 side. Must acknowledge with SHA256(K_SE||K_G0||S).
    if (!g0_set_keys(kse, kg0, g_mode_secret_pending, g_gen)) {   // v5.1: + the generation these objects live in
      Serial.println("[SE051] g0 identity: G0 did not confirm keys");
      break;
    }
    ok = true;
    g_mode_secret_delivered = true;   // v3: the seed key may now be created against this value
    Serial.println("[SE051] G0 identity provisioned (SE auth object + PCR + G0 keys + BTC secret S)");
  } while (0);

  // Any failure after the auth object was written: take it back out, so the
  // SE never holds an auth key that nothing can use (and a re-run starts clean).
  // v5.1: no rollback delete (nobody holds DELETE on the auth object). A
  // failed onboarding leaves it dead; the retry runs on the next generation.

  mbedtls_platform_zeroize(kse, sizeof(kse));
  mbedtls_platform_zeroize(kg0, sizeof(kg0));
  modeBtcSecretForget();   // S has left this chip (or the attempt failed and must be regenerated)
  return ok;
}

bool se_provision_nostr_scalar(const uint8_t scalar[32]) {
  // -------------------------------------------------------------------------
  // DOUBLE WRAP AT ONBOARDING
  //
  // The scalar is sealed under K_G0 (a key that exists only inside the G0,
  // behind RDP Level 2) BEFORE the SE ever sees it. The SE then wraps that
  // ciphertext under its own daily key, so the stored object is:
  //
  //     AES(K_DAILY, AES(K_G0, scalar))
  //
  // Consequence: the SE unwraps only its own layer, so what leaves the SE at
  // signing time is still ciphertext. The SE never emits a plaintext scalar,
  // and the ESP32 - which physically relays every G0<->SE frame - never has
  // anything it could use even if the session channel were absent.
  //
  // The caller's plaintext scalar is in ESP32 RAM at this moment. That is
  // acceptable ONLY because onboarding runs air-gapped with the radios down.
  // The caller MUST zeroize it immediately after this returns, on every path.
  // -------------------------------------------------------------------------
  if (!g_ready) return false;

  if (!g0_present()) {
    // Never store a scalar the G0 cannot later open - that would brick the
    // identity on first use.
    Serial.println("[SE051] provision: G0 signer unavailable - refusing");
    return false;
  }

  // The G0 returns exactly 32 bytes of ciphertext. Its IV is derived
  // deterministically from K_G0 inside the chip, so nothing extra needs
  // storing - which means the existing SE wrap path is unchanged.
  uint8_t sealed[G0_SEALED_BLOB_LEN];   // 32
  if (!g0_seal_scalar(scalar, sealed)) {
    Serial.println("[SE051] provision: G0 seal failed");
    mbedtls_platform_zeroize(sealed, sizeof(sealed));
    return false;
  }

  // Store the SEALED 32 bytes under the SE daily wrap key. provisionScalarInto
  // is untouched - it still wraps 32 bytes into IV(16)||CT(32). Only the
  // meaning of those 32 bytes has changed: ciphertext, not a raw scalar.
  bool ok = provisionScalarInto(SE_OBJ_NOSTR_SCALAR, sealed,
                                "se_provision_nostr_scalar(sealed)");

  mbedtls_platform_zeroize(sealed, sizeof(sealed));

#if G0_SESSION_TEST_ON_UNLOCK
  // Step-3 bring-up on RAM-only keys: this is the ONLY moment in an onboarding
  // where the G0 holds K_SE/K_G0, the Door-1 PCR is unlocked, and the scalar is
  // sealed in 0x20000002 — and it needs no reboot (a reboot would wipe the
  // RAM keys). So prove the whole SE fetch path here. Remove with the flag once
  // step 5 moves the keys into flash.
  if (ok && g0_present()) {
    Serial.println("[SE051] onboarding complete - running G0 session self-test");
    g0_session_test();
  }
#endif
  return ok;
}

bool se_provision_imported_nsec(const uint8_t scalar[32]) {
  return provisionScalarInto(SE_OBJ_NSEC_IMPORT, scalar, "se_provision_imported_nsec");
}

// ============================================================
// First-boot setup
//
// Generates the AES wrap key on the very first boot of a virgin
// device. Uses a NVS-stored flag to know whether this has run
// before. The wrap key is the precondition for every other SE
// operation, so this MUST succeed before onboarding starts.
//
// Idempotent: calling multiple times is a no-op after the first
// successful run.
//
// Returns true if (a) the flag was already set, or (b) the key
// was just provisioned. Returns false if provisioning failed —
// caller should treat this as a hard error.
// ============================================================
bool se_first_boot_setup() {
  // V1 Path-1 change: the AES wrap key is no longer created at first boot.
  // A PIN-bound wrap key must be written AFTER the PIN object exists, so
  // provisioning moved into onboarding (see se_provision_aes_wrap_key, called
  // from the onboarding flow right after se_pin_session_open). This function
  // is retained as a no-op for call-site compatibility.
  //
  // The legacy "wrapkey_done" NVS flag is intentionally no longer consulted;
  // the wrap key's existence is now implied by a completed onboarding (PIN +
  // scalar + seed all present). The boot-time consistency check in the main
  // sketch (PIN-exists-but-no-seed -> force re-onboard) handles partial state.
  (void)g_ready;
  return true;
}

// ============================================================
// Other operations
// ============================================================

// ── se_get_nostr_scalar (M7 Step 6 — direct scalar access for ECDH) ──
//
// Reads the wrapped scalar at SE_OBJ_NOSTR_SCALAR and AES-unwraps to RAM.
// Replaces getUnmaskedKey (ATECC) for the ECDH paths. The scalar must be
// zeroed by the caller immediately after use — typically within tens of
// milliseconds of the ecdh_raw call that consumes it.
//
// Why this exists separately from se_schnorr_sign: the architecture
// (security architecture §8.3) keeps ECDH in software RAM for V1, which
// means the scalar genuinely needs to escape the SE for that one
// operation. se_schnorr_sign keeps the scalar internal; this function
// is the deliberate, audited way to expose it for the ECDH legitimate
// use case.
bool se_get_nostr_scalar(uint8_t out[32]) {
  // -------------------------------------------------------------------------
  // PERMANENTLY DISABLED — the scalar cannot be retrieved to this processor.
  //
  // The Nostr scalar is stored double-wrapped: AES(K_DAILY, AES(K_G0, scalar)).
  // The SE will strip its own outer layer, but the inner layer is sealed under
  // K_G0, which exists only inside the isolated signer and is protected by RDP
  // Level 2. There is no code path — here or on the signer — that returns the
  // plaintext scalar to the ESP32.
  //
  // This is not an oversight and must not be "fixed". Every operation that
  // used to need the scalar now has a dedicated signer command that returns a
  // result instead of the key:
  //
  //     signing        -> se_schnorr_sign()  -> G0 SIGN
  //     NIP-04/44 DMs  -> nostr_ecdh()       -> G0 ECDH   (hook in secp256k1.h)
  //     public key     -> g0_get_pubkey()    -> G0 PUBKEY
  //     PWA cache key  -> g0_get_cache_key() -> G0 CACHEKEY  (HKDF, one-way)
  //
  // Adding a signer command that returns the scalar would make the key
  // retrievable by any compromised ESP32 and would collapse the entire
  // isolation model. Do not add one.
  //
  // Retained as a hard stop rather than deleted so that any forgotten caller
  // fails loudly and closed instead of silently receiving uninitialised RAM.
  // -------------------------------------------------------------------------
  if (out) mbedtls_platform_zeroize(out, 32);
  Serial.println("[SE051] se_get_nostr_scalar: DISABLED - key is sealed in the "
                 "isolated signer and cannot be exported");
  return false;
}

// ── se_schnorr_sign (isolated signer — Nostr signing on the STM32G0) ──
//
// Signs `msg32` under the Nostr scalar sealed in the G0. Steps:
//
//   1. PIN session check (UX only; the SE enforces the real gate)
//   2. G0 present check (fail-closed, no RAM fallback)
//   3. g0_schnorr_sign(): hash out over I2C, N blind-relayed session frames
//      between the G0 and the SE, 64-byte signature back
//
// The old M7 Step 3 path (ReadObject -> SE unwrap -> schnorr_sign in RAM)
// is gone. Returns true on success. sig_out is the 64-byte BIP-340
// signature (r || s); signatures are public values.
bool se_schnorr_sign(const uint8_t msg32[32], uint8_t sig_out[SCHNORR_SIG_LEN]) {
  // -------------------------------------------------------------------------
  // ISOLATED SIGNER PATH
  //
  // This function used to unwrap the Nostr scalar into a local uint8_t[32] and
  // call schnorr_sign() here, in ESP32 RAM. That local was the exposure: this
  // processor runs the radios and every parser (JSON, UR, PSBT, QR), so a
  // memory-safety flaw anywhere in that surface could yield RCE and a permanent,
  // unrecoverable theft of a long-lived identity key.
  //
  // The scalar now lives on the STM32G0 and is unwrapped, used, and zeroized
  // there. This processor sees the 32-byte hash going out and the 64-byte
  // signature coming back. Nothing else.
  //
  // Do not reintroduce a local scalar buffer in this function.
  // -------------------------------------------------------------------------

  // UX short-circuit only. The real Door-1 enforcement happens on the SE (the
  // PCR AND-gate on the scalar object's policy), checked by the G0 over its own
  // session. This flag is advisory — a compromised ESP32 can skip it trivially,
  // and that is fine, because it cannot skip the SE's.
  if (!g_pin_session_open) {
    Serial.println("[SE051] se_schnorr_sign denied: no PIN session");
    return false;
  }
  if (!g_ready) {
    Serial.println("[SE051] se_schnorr_sign: SE not ready");
    return false;
  }

  // FAIL CLOSED. If the isolated signer is missing we refuse to sign rather
  // than falling back to signing in RAM. A fallback would silently undo this
  // entire architecture the first time the G0 failed to answer.
  if (!g0_present()) {
    Serial.println("[SE051] se_schnorr_sign: G0 signer unavailable - refusing");
    return false;
  }

  // The G0 fetches the wrapped object itself over the blind relay, because only
  // the G0 holds K_G0 and can open the inner wrap. This processor no longer
  // reads SE_OBJ_NOSTR_SCALAR on the signing path at all.
  // 27 Oct 2026: two round trips with a host-contributed nonce; the result is
  // checked against the G0's commitment and verified here before it is used.
  bool ok = g0_schnorr_sign(msg32, sig_out);
  if (!ok && g0_antiexfil_faulted()) dispAntiExfilFaultForever();   // never returns
  return ok;
}

bool se_ecdh(const uint8_t /*peer_pubkey33*/[33],
             uint8_t /*shared_x_out*/[ECDH_SHARED_LEN]) {
  // Identity-key ECDH now runs on the isolated signer (G0 ECDH) via the
  // nostr_ecdh() hook in secp256k1.h, installed by g0_init(). This 33-byte
  // compressed-pubkey entry point was never implemented and has no callers;
  // it stays as a fail-closed stub so the API surface is stable.
  Serial.println("[SE051] se_ecdh: unused - identity ECDH is routed to the G0 via nostr_ecdh()");
  return false;
}

// ── Device attestation (SE-native P-256) ─────────────────────────────────────
// Compiled here, INSIDE namespace favilla and AFTER the anonymous-namespace
// helpers (buildAPDU/sendAPDU/checkSW/buildPolicyEntry), because those helpers
// have internal linkage and are only reachable from within this translation
// unit. Defines favilla::se_attest_exists/provision/pubkey/sign/selftest.
#include "se_attest.inc"

// ── Two-door mode latch (NOSTR/BTC) — provisioning + selftest ──────────────
// Same linkage rationale as se_attest.inc: needs the anonymous-namespace
// helpers and g_session_id, so it is included here inside namespace favilla.
#include "mode_pcr.inc"

// Passkey door bench check 1 (29 Oct 2026): EC-key PCR gate probe. Compiles
// to nothing unless FAVILLA_BENCH_PROBES is defined (bench env only).
#include "ec_gate_probe.inc"

// Passkey door (30 Oct 2026, step 3b): credential keys, the login sequence
// and the passkey PIN. Compiles to nothing unless FAVILLA_PASSKEY_DOOR.
#include "passkey_door.inc"

// Restorable passkeys (30 Oct 2026): master + scratch objects. Compiles to
// nothing unless FAVILLA_PK_RESTORABLE.
#include "pk_restorable.inc"

#ifdef FAVILLA_BENCH_PROBES
// ═════════════════════════════════════════════════════════════════════════════
// RCE SIM probes (19 Oct 2026) - bench env only, NEVER in a release build.
// Each one does what code execution on this chip could do in a live Nostr life
// and returns the SE's raw status word, so the RCE sim page (rce_sim.h) can
// show BLOCKED / OPEN against the review finding-3 attack chain:
//   delete MODE_PCR  ->  re-create it at the public BTC value  ->  spend-PIN DEC
// 0x9000 means the SE did it. 0x0000 = not attempted (precondition missing).
// ═════════════════════════════════════════════════════════════════════════════
static uint16_t benchSW(const uint8_t* r, int n) {
  return (n >= 2) ? (uint16_t)((r[n - 2] << 8) | r[n - 1]) : 0xFFFF;
}
bool se_bench_mode_exists() { return g_ready && se_object_exists(SE_OBJ_PCR_MODE); }
bool se_bench_daily_session_open() { return g_pin_session_open && g_session_obj == SE_OBJ_PIN_DAILY; }
// Latch class as the open daily session reads it. 1 NEUTRAL 2 NOSTR 3 BTC
// 4 SPENT 5 other, 0xFE absent, 0xFF unreadable / no session.
uint8_t se_bench_mode_class() {
  if (!g_ready) return 0xFF;
  if (!se_object_exists(SE_OBJ_PCR_MODE)) return 0xFE;
  if (!se_bench_daily_session_open()) return 0xFF;
  if (!g_mode_vals_valid) modeComputeValues();
  uint8_t cur[32], spent[32];
  if (!modePcrReadInSession(g_session_id, cur)) return 0xFF;
  modeExt(g_mode_btc, MODE_CONST_SPENT, spent);
  if (!memcmp(cur, g_mode_neutral, 32)) return 1;
  if (!memcmp(cur, g_mode_nostr, 32))   return 2;
  if (!memcmp(cur, g_mode_btc, 32))     return 3;
  if (!memcmp(cur, spent, 32))          return 4;
  return 5;
}
// Step A: DeleteSecureObject(MODE_PCR) from the open DAILY session.
// Fixed policy: 6986. Pre-fix policy: 9000 (and the latch is gone).
uint16_t se_bench_mode_delete_daily() {
  if (!g_ready || !se_bench_daily_session_open()) return 0x0000;
  if (!se_object_exists(SE_OBJ_PCR_MODE)) return 0x6A88;
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[8]; size_t p = appendTLV(payload, 0, sizeof(payload), TAG_1, id, 4);
  uint8_t inner[32];
  size_t innerLen = buildAPDU(inner, sizeof(inner), 0x80, INS_MGMT, P1_DEFAULT, P2_DELETE_OBJECT, payload, p, false);
  uint8_t resp[32];
  int n = processSessionCmd(g_session_id, inner, innerLen, resp, sizeof(resp));
  return benchSW(resp, n);
}
// Step B: ANONYMOUS WritePCR create of the MODE_PCR id, no policy, initial
// value = the public BTC value. Only attempted when the id is free (a live
// object is the fix holding: nothing to re-create).
uint16_t se_bench_mode_recreate_btc() {
  if (!g_ready) return 0x0000;
  if (se_object_exists(SE_OBJ_PCR_MODE)) return 0x0000;
  if (!g_mode_vals_valid) modeComputeValues();
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[64]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, g_mode_btc, 32);
  uint8_t apdu[96];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return benchSW(resp, n);
}
// Step C: what the whole chain is for. Close the daily session, open the
// SPEND session with the PIN given, and ask for CipherOneShot DECRYPT with
// the seed wrap key (on zeros: only the status word matters). 9000 = the SE
// would unwrap the seed's outer layer in this life. Leaves NO session open.
// 0xFFFE = the spend PIN was refused (that costs one SE attempt).
uint16_t se_bench_seed_dec_spend(const char* spendPin) {
  if (!g_ready || !spendPin) return 0x0000;
  se_pin_session_close();
  if (!se_pin_session_open_obj(SE_OBJ_PIN_SPEND, spendPin)) return 0xFFFE;
  uint8_t zero[32] = {0}, iv[16] = {0};
  uint8_t objId[4] = { (uint8_t)(SE_OBJ_AES_WRAP_SEED >> 24), (uint8_t)(SE_OBJ_AES_WRAP_SEED >> 16),
                       (uint8_t)(SE_OBJ_AES_WRAP_SEED >> 8),  (uint8_t) SE_OBJ_AES_WRAP_SEED };
  uint8_t mode = AES_CBC_NOPAD;
  uint8_t payload[128]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, objId, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, &mode, 1);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, zero, 32);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, iv, 16);
  uint8_t inner[160];
  size_t innerLen = buildAPDU(inner, sizeof(inner), 0x80, INS_CRYPTO, P1_CIPHER, P2_DECRYPT_ONESHOT, payload, p, true);
  uint8_t resp[80];
  int n = processSessionCmd(g_session_id, inner, innerLen, resp, sizeof(resp));
  uint16_t sw = benchSW(resp, n);
  mbedtls_platform_zeroize(resp, sizeof(resp));
  se_pin_session_close();
  return sw;
}
#endif  // FAVILLA_BENCH_PROBES

} // namespace favilla
