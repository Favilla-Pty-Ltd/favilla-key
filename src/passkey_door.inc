// =============================================================================
// passkey_door.inc — the PASSKEY door, SE side (30 Oct 2026, step 3b)
// =============================================================================
// Passkey door spec v1.0, sections 5 and 6. Replaces the step 2 bench door
// (EG_PIN / EG_PCR / a simulated mint) with the real objects:
//   * the passkey PIN, SE_OBJ_PIN_PASSKEY (third UserID, made at onboarding);
//   * the real MODE_PCR, which the passkey PIN may READ and WRITE (arm, burn);
//   * the real G0 mint, MODEDOOR, which puts the latch at V_3 only in a life
//     the G0 holds as PASSKEY, and only from a value a PIN session ARMed.
// Credential keys use the policy shape proven in bench check 1:
//   passkey PIN : SIGN, only while MODE_PCR == V_3   (one entry, one PCR)
//   anonymous   : READ | DELETE | GEN                (public key, wipe, keygen)
// One login (same order as the BTC door, spec section 6 item 5):
//   open passkey session -> ARM the latch -> close -> G0 MODEDOOR (its own SE
//   session) -> reopen -> latch must read V_3 -> ECDSASign -> burn (extend
//   SPENT) with readback -> close.
// Callers hold the I2C lock (main.cpp wrappers). Included INSIDE namespace
// favilla in se_signer.cpp after mode_pcr.inc and se_attest.inc.
// =============================================================================
#ifdef FAVILLA_PASSKEY_DOOR

static constexpr uint32_t PK_CRED_BASE = 0x2000E200u;   // + slot; middle byte 0xE2 sits above every generation's range
static constexpr int      PK_CRED_MAX  = 20;            // bench check 2: 25 fit; fido_hid.h keeps a free-memory reserve too

static uint16_t pkSW(const uint8_t* r, int n) { return n >= 2 ? (uint16_t)((r[n-2] << 8) | r[n-1]) : 0xFFFF; }

bool se_passkey_ready() {
  if (!g_ready) return false;
  if (!g_mode_vals_valid) modeComputeValues();
  return g_mode_pk_valid && se_object_exists(SE_OBJ_PIN_PASSKEY) && se_object_exists(SE_OBJ_PCR_MODE);
}

bool se_passkey_pin_provision(const uint8_t* pin, size_t len) {
  return se_pin_provision_obj(SE_OBJ_PIN_PASSKEY, pin, len);
}

// 1 = the SE accepted the PIN (the session is closed again), 0 = refused.
// A refusal costs one of the SE's attempts; the caller keeps its own budget.
int se_passkey_pin_check(const char* pin) {
  if (!g_ready || !pin) return 0;
  if (g_pin_session_open) se_pin_session_close();
  bool ok = se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin);
  if (ok) se_pin_session_close();
  return ok ? 1 : 0;
}

static uint16_t pkKeyCreate(uint32_t id) {
  uint8_t policy[96]; size_t pp = 0;
  pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), SE_OBJ_PIN_PASSKEY, POLICY_OBJ_ALLOW_SIGN, SE_OBJ_PCR_MODE, g_mode_pk);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_DELETE | POLICY_OBJ_ALLOW_GEN);
  uint8_t data[128]; size_t dl = 0; uint8_t oid[4]; obj_be(id, oid);
  dl += put_tlv(data + dl, TAG_POLICY, policy, pp);
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t curve = ECCURVE_NIST_P256;
  dl += put_tlv(data + dl, TAG_2, &curve, 1);
  uint8_t apdu[160];
  size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE, (uint8_t)(P1_KEY_PAIR | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  return pkSW(r, n);
}
static bool pkPub(uint32_t id, uint8_t pub65[65]) {
  uint8_t oid[4]; obj_be(id, oid);
  uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ, P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t r[128]; int n = sendAPDU(apdu, al, r, sizeof(r));
  if (pkSW(r, n) != 0x9000) return false;
  for (int i = 0; i + 65 <= n - 2; i++) if (r[i] == 0x04) { memcpy(pub65, r + i, 65); return true; }
  return false;
}
// ECDSASign inside the open passkey session; the DER signature as the SE gave it.
static uint16_t pkSignDer(uint32_t id, const uint8_t h[32], uint8_t* der, size_t* derN) {
  *derN = 0;
  uint8_t oid[4]; obj_be(id, oid);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256; dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = processSessionCmd(g_session_id, apdu, al, r, sizeof(r));
  uint16_t sw = pkSW(r, n);
  if (sw != 0x9000) return sw;
  for (int i = 0; i + 2 <= n - 2; i++) if (r[i] == 0x30) {
    size_t L = (size_t)r[i + 1] + 2;
    if (r[i + 1] < 0x80 && i + (int)L <= n - 2 && L <= 72) { memcpy(der, r + i, L); *derN = L; return sw; }
    break;
  }
  return 0xFFFD;   // 9000 but no DER signature found
}
int se_passkey_free() {
  uint8_t t = 0x01;   // persistent memory
  uint8_t pl[8]; size_t p = appendTLV(pl, 0, sizeof(pl), TAG_1, &t, 1);
  uint8_t apdu[24]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_MGMT, P1_DEFAULT, 0x22, pl, p, true);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  if (pkSW(r, n) != 0x9000 || n < 4 || r[0] != TAG_1) return -1;
  size_t off = 0; int len = parseTLVLength(r, (size_t)n - 2, &off);
  if (len == 2 && off + 2 <= (size_t)n - 2) return (r[off] << 8) | r[off + 1];
  if (len == 4 && off + 4 <= (size_t)n - 2) return (int)(((uint32_t)r[off] << 24) | ((uint32_t)r[off+1] << 16) | (r[off+2] << 8) | r[off+3]);
  return -1;
}

// Latch values of the passkey door, from V_3.
static void pkSpent(uint8_t out[32]) { modeExt(g_mode_pk, MODE_CONST_SPENT, out); }

// Review, 30 Oct 2026: V_3 must never be left in the latch. If a burn cannot
// be confirmed the door is WEDGED: every later login this boot is refused and
// passkey_life.inc holds a restart screen (a power cycle is the G0's reset).
static bool g_pkWedged = false;
bool se_passkey_wedged() { return g_pkWedged; }
// Burn inside the OPEN passkey session: extend SPENT_CONST from V_3, readback.
static bool pkBurnInSession(const uint8_t spent[32]) {
  uint8_t v[32];
  if (!modePcrReadInSession(g_session_id, v)) return false;
  if (!memcmp(v, spent, 32)) return true;               // already burned
  if (memcmp(v, g_mode_pk, 32)) return true;            // not V_3: nothing open to burn
  if (!modePcrExtendInSession(g_session_id, MODE_CONST_SPENT)) return false;
  return modePcrReadInSession(g_session_id, v) && !memcmp(v, spent, 32);
}

bool se_passkey_keygen(uint32_t obj, uint8_t pub65[65], uint16_t* sw) {
  *sw = 0;
  if (!se_passkey_ready()) { Serial.println("[PASSKEY-SE] not provisioned on this unit (no passkey PIN or no V_3) - re-onboard"); return false; }
  if (obj < PK_CRED_BASE || obj >= PK_CRED_BASE + PK_CRED_MAX) return false;
  if (g_pin_session_open) se_pin_session_close();
  if (se_object_exists(obj)) tryDeleteObject_internal(obj);   // a slot left over from an earlier wallet
  *sw = pkKeyCreate(obj);
  if (*sw != 0x9000) return false;
  return pkPub(obj, pub65);
}

// One login. pin = the passkey PIN held for this life (entered on the KEY at
// the door).
bool se_passkey_sign(uint32_t obj, const char* pin, const uint8_t hash32[32], uint8_t* der, size_t* derN, uint16_t* sw) {
  *sw = 0; *derN = 0;
  if (g_pkWedged) { Serial.println("[PASSKEY-SE] refused: an earlier burn was not confirmed - restart the key"); return false; }
  if (!se_passkey_ready() || !pin) { Serial.println("[PASSKEY-SE] not ready"); return false; }
  if (obj < PK_CRED_BASE || obj >= PK_CRED_BASE + PK_CRED_MAX) return false;
  uint32_t t0 = millis();
  // 1. ARM inside a passkey-PIN session (the G0 mints only from an ARMed value)
  if (!se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin)) { Serial.println("[PASSKEY-SE] passkey PIN session refused"); return false; }
  uint8_t cur[32], spent[32];
  pkSpent(spent);
  bool armed = false, ok = modePcrReadInSession(g_session_id, cur);
  if (ok) {
    uint8_t a[32];
    modeExt(g_mode_neutral, MODE_CONST_ARM, a); if (!memcmp(cur, a, 32)) armed = true;
    modeExt(spent,          MODE_CONST_ARM, a); if (!memcmp(cur, a, 32)) armed = true;
    modeExt(g_mode_pk,      MODE_CONST_ARM, a); if (!memcmp(cur, a, 32)) armed = true;
    if (!armed) {
      bool base = !memcmp(cur, g_mode_neutral, 32) || !memcmp(cur, spent, 32) || !memcmp(cur, g_mode_pk, 32);
      if (!base) {
        Serial.printf("[PASSKEY-SE] latch is %s - not a PASSKEY life value, power cycle required\n",
                      !memcmp(cur, g_mode_nostr, 32) ? "NOSTR" : !memcmp(cur, g_mode_btc, 32) ? "BTC" : "another value");
        ok = false;
      } else {
        ok = mode_pcr_arm_in_open_session();
      }
    }
  }
  se_pin_session_close();
  if (!ok) { Serial.println("[PASSKEY-SE] could not ARM the latch"); return false; }
  uint32_t tArm = millis();
  // 2. the G0 mints V_3 (refused unless it holds PASSKEY for this power-on life)
  if (!g0_mode_door()) { Serial.println("[PASSKEY-SE] the G0 did not mint the PASSKEY value"); return false; }
  uint32_t tMint = millis();
  // 3. reopen, check, sign, burn. The latch now reads V_3: from here every
  // exit burns it, and a burn that cannot be confirmed wedges the door.
  bool opened = false;
  for (int t = 0; t < 3 && !opened; t++) { opened = se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin); if (!opened) delay(20); }
  if (!opened) {
    Serial.println("[PASSKEY-SE] passkey PIN session refused on reopen - V_3 left open: door WEDGED until a power cycle");
    g_pkWedged = true; return false;
  }
  ok = modePcrReadInSession(g_session_id, cur) && !memcmp(cur, g_mode_pk, 32);
  if (!ok) Serial.println("[PASSKEY-SE] latch does not read V_3 after the mint - not signing");
  if (ok) { *sw = pkSignDer(obj, hash32, der, derN); ok = (*sw == 0x9000 && *derN > 0); }
  bool burned = false;
  for (int t = 0; t < 3 && !burned; t++) burned = pkBurnInSession(spent);
  se_pin_session_close();
  if (!burned) { g_pkWedged = true; Serial.println("[PASSKEY-SE] burn NOT confirmed after 3 tries - door WEDGED until a power cycle"); }
  Serial.printf("[PASSKEY-SE] login %s | arm %lu ms, G0 mint %lu ms, sign+burn %lu ms\n", ok ? "signed" : "FAILED",
                (unsigned long)(tArm - t0), (unsigned long)(tMint - tArm), (unsigned long)(millis() - tMint));
  return ok && burned;
}

void se_passkey_delete(uint32_t obj) {
  if (obj < PK_CRED_BASE || obj >= PK_CRED_BASE + PK_CRED_MAX) return;
  if (se_object_exists(obj)) tryDeleteObject_internal(obj);
}
void se_passkey_wipe_credentials() {
  int n = 0;
  for (int i = 0; i < PK_CRED_MAX; i++) {
    uint32_t id = PK_CRED_BASE + i;
    if (se_object_exists(id)) { tryDeleteObject_internal(id); n++; }   // anonymous DELETE by policy, session or not
  }
  if (n) Serial.printf("[PASSKEY-SE] wipe: %d credential key(s) deleted\n", n);
}

// ---------------------------------------------------------------------------
// Passkey window (2 Nov 2026, Vault spec v0.25 section 1b, phase 2b).
// The G0 may decrypt the PASSKEY copy of the passkey master only while the
// latch reads V_3, so every G0 PKSIGN / VAULT in a PASSKEY life runs inside a
// window: ARM (passkey-PIN session), the G0 mints V_3, the op, then the burn.
// open(..., keepSession = false) leaves no ESP32 session open (the G0 runs its
// own); keepSession = true reopens the passkey session at V_3 for SE work done
// here (the first-login copies, opening the gate). close() always burns, and a
// burn that cannot be confirmed wedges the door, as a login does.
// ---------------------------------------------------------------------------
static bool pkArmInOpenSession() {
  uint8_t cur[32], spent[32]; pkSpent(spent);
  if (!modePcrReadInSession(g_session_id, cur)) return false;
  uint8_t a[32];
  modeExt(g_mode_neutral, MODE_CONST_ARM, a); if (!memcmp(cur, a, 32)) return true;
  modeExt(spent,          MODE_CONST_ARM, a); if (!memcmp(cur, a, 32)) return true;
  modeExt(g_mode_pk,      MODE_CONST_ARM, a); if (!memcmp(cur, a, 32)) return true;
  bool base = !memcmp(cur, g_mode_neutral, 32) || !memcmp(cur, spent, 32) || !memcmp(cur, g_mode_pk, 32);
  if (!base) {
    Serial.printf("[PASSKEY-SE] latch is %s - not a PASSKEY life value, power cycle required\n",
                  !memcmp(cur, g_mode_nostr, 32) ? "NOSTR" : !memcmp(cur, g_mode_btc, 32) ? "BTC" : "another value");
    return false;
  }
  return mode_pcr_arm_in_open_session();
}
bool se_pk_window_open(const char* pin, bool keepSession) {
  if (g_pkWedged) { Serial.println("[PASSKEY-SE] window refused: the door is wedged - restart the key"); return false; }
  if (!se_passkey_ready() || !pin) return false;
  if (g_pin_session_open) se_pin_session_close();
  if (!se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin)) { Serial.println("[PASSKEY-SE] window: passkey PIN session refused"); return false; }
  bool ok = pkArmInOpenSession();
  se_pin_session_close();
  if (!ok) { Serial.println("[PASSKEY-SE] window: could not ARM the latch"); return false; }
  if (!g0_mode_door()) { Serial.println("[PASSKEY-SE] window: the G0 did not mint the PASSKEY value"); se_pk_window_close(pin); return false; }   // review (L1): it may have minted; burn
  if (!keepSession) return true;
  bool opened = false;
  for (int t = 0; t < 3 && !opened; t++) { opened = se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin); if (!opened) delay(20); }
  if (!opened) { g_pkWedged = true; Serial.println("[PASSKEY-SE] window: session refused on reopen - V_3 left open: door WEDGED until a power cycle"); return false; }
  uint8_t cur[32];
  if (!modePcrReadInSession(g_session_id, cur) || memcmp(cur, g_mode_pk, 32)) { Serial.println("[PASSKEY-SE] window: latch does not read V_3 after the mint"); return true; }   // close() still burns
  return true;
}
bool se_pk_window_close(const char* pin) {
  if (!g_pin_session_open) {
    bool opened = false;
    for (int t = 0; t < 3 && !opened; t++) { opened = pin && se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin); if (!opened) delay(20); }
    if (!opened) { g_pkWedged = true; Serial.println("[PASSKEY-SE] window: no session to burn with - door WEDGED until a power cycle"); return false; }
  }
  uint8_t spent[32]; pkSpent(spent); bool burned = false;
  for (int t = 0; t < 3 && !burned; t++) burned = pkBurnInSession(spent);
  se_pin_session_close();
  if (!burned) { g_pkWedged = true; Serial.println("[PASSKEY-SE] window: burn NOT confirmed after 3 tries - door WEDGED until a power cycle"); }
  return burned;
}

#ifdef FAVILLA_PK_RESTORABLE
// ---------------------------------------------------------------------------
// Phase 2b objects (Vault spec v0.25 section 1b, rulings S1 to S4).
// ---------------------------------------------------------------------------
bool se_pkr_ready_passkey() { return g_ready && se_object_exists(SE_OBJ_PK_MASTER_P); }
bool se_pk2b_keys_present() { return g_ready && se_object_exists(SE_OBJ_K_PK); }
// v19 (13 Nov 2026, docs/DOOR_KEY_RULE.md): an earlier generation made K_PKN (and
// a 48-byte PASSKEY copy) at onboarding. A v19 G0 cannot use it: set the KEY up again.
bool se_pk_old_generation() { return g_ready && (se_object_exists(SE_OBJ_K_PKN) || se_object_exists(SE_OBJ_PK_MASTER)); }

static bool pk2bKeyCreate(uint32_t id, const uint8_t* policy, size_t pp, const char* what) {
  if (se_object_exists(id)) { Serial.printf("[PK2B] %s 0x%08X already exists - refusing (a policy is fixed at creation; wipe first)\n", what, (unsigned)id); return false; }
  uint8_t key[32]; esp_fill_random(key, 32);
  uint8_t payload[200]; size_t p = 0; uint8_t oid[4]; obj_be(id, oid);
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, oid, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, key, 32);
  uint8_t apdu[240]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, 0x03 /* P1_AES */, P2_DEFAULT, payload, p, false);
  uint8_t r[16]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(key, 32); mbedtls_platform_zeroize(payload, sizeof(payload)); mbedtls_platform_zeroize(apdu, sizeof(apdu));
  uint16_t sw = pkSW(r, n);
  Serial.printf("[PK2B] %s 0x%08X: %s (SW %04X)\n", what, (unsigned)id, sw == 0x9000 ? "created" : "FAILED", sw);
  return sw == 0x9000;
}
// Onboarding, after the passkey PIN, MODE_PCR and the G0 identity exist.
// v19: K_PK only, and no G0 entry. The passkey PIN's session at V_3 is the one
// thing that decrypts the master, so a full read of the G0's flash opens nothing.
bool se_pk2b_create_keys() {
  if (!g_ready) return false;
  if (!g_mode_vals_valid) modeComputeValues();
  if (!g_mode_pk_valid || !se_object_exists(SE_OBJ_PIN_PASSKEY) || !se_object_exists(SE_OBJ_PCR_MODE)) { Serial.println("[PK2B] keys: passkey PIN / V_3 / MODE_PCR missing"); return false; }
  uint8_t pol[160]; size_t pp = 0;
  // K_PK: passkey PIN ENC|DEC|WRITE|DELETE at V_3; RECOVER DELETE. No daily entry, no G0 entry.
  pp = buildPolicyEntryPcr(pol, pp, sizeof(pol), SE_OBJ_PIN_PASSKEY, POLICY_OBJ_ALLOW_ENC | POLICY_OBJ_ALLOW_DEC | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE, SE_OBJ_PCR_MODE, g_mode_pk);
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);
  bool ok = pk2bKeyCreate(SE_OBJ_K_PK, pol, pp, "K_PK");
  mbedtls_platform_zeroize(pol, sizeof(pol));
  return ok;
}
// v19: the PASSKEY copy is IV16 || AES-CBC(K_PK, inner || tag), 80 bytes. Two
// 32-byte one-shots chained by hand: the second block's IV is the first block's
// last ciphertext block, which is plain CBC over the 64 bytes.
static constexpr size_t PKM_COPY_LEN = 16 + 64;
static bool pkmCbc(uint8_t p2, const uint8_t iv[16], const uint8_t in[64], uint8_t out[64]) {
  if (p2 == P2_ENCRYPT_ONESHOT) {
    return aesOneShot(SE_OBJ_K_PK, p2, in, iv, out) && aesOneShot(SE_OBJ_K_PK, p2, in + 32, out + 16, out + 32);
  }
  return aesOneShot(SE_OBJ_K_PK, p2, in, iv, out) && aesOneShot(SE_OBJ_K_PK, p2, in + 32, in + 16, out + 32);
}
// A fresh 80-byte binary with its policy (the create is top level, as for every
// other binary; the old one was deleted in the session first).
static bool pkmBinWrite(const uint8_t blob[PKM_COPY_LEN], const uint8_t* pol, size_t pp) {
  uint8_t payload[200]; size_t p = 0; uint8_t oid[4]; obj_be(SE_OBJ_PK_MASTER_P, oid);
  uint8_t fileSize[2] = { 0x00, (uint8_t)PKM_COPY_LEN };
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, pol, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, oid, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, fileSize, 2);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, blob, PKM_COPY_LEN);
  uint8_t apdu[240]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_BINARY, P2_DEFAULT, payload, p, false);
  uint8_t r[16]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(payload, sizeof(payload)); mbedtls_platform_zeroize(apdu, sizeof(apdu));
  return pkSW(r, n) == 0x9000;
}
// First PASSKEY login, in a window with the session kept: inner || tag from
// PKMASTER (64 bytes, kept in nvs_sec since onboarding) under K_PK.
// Policy: passkey PIN READ|WRITE|DELETE, RECOVER DELETE. No G0 entry.
bool se_pk2b_write_copies(const uint8_t pkm64[64]) {
  if (!g_pin_session_open || g_session_obj != SE_OBJ_PIN_PASSKEY) return false;
  if (se_object_exists(SE_OBJ_PK_MASTER_P) && !deleteInSession(g_session_id, SE_OBJ_PK_MASTER_P)) { Serial.println("[PK2B] PASSKEY copy: could not remove the old one"); return false; }
  uint8_t blob[PKM_COPY_LEN]; esp_fill_random(blob, 16);
  if (!pkmCbc(P2_ENCRYPT_ONESHOT, blob, pkm64, blob + 16)) { mbedtls_platform_zeroize(blob, sizeof blob); Serial.println("[PK2B] PASSKEY copy: K_PK encrypt refused (not at V_3?)"); return false; }
  uint8_t pol[96]; size_t pp = 0;
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_OBJ_PIN_PASSKEY, POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);
  bool ok = pkmBinWrite(blob, pol, pp);
  mbedtls_platform_zeroize(blob, sizeof(blob));
  Serial.printf("[PK2B] PASSKEY copy (80 B): %s\n", ok ? "written" : "FAILED");
  return ok;
}
// Each window (v19): READ the PASSKEY copy in the open passkey session at V_3
// and strip K_PK. out64 = inner || tag, which the G0 checks before it uses it.
bool se_pk_master_read(uint8_t out64[64]) {
  if (!g_pin_session_open || g_session_obj != SE_OBJ_PIN_PASSKEY) return false;
  uint8_t oid[4]; obj_be(SE_OBJ_PK_MASTER_P, oid);
  uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ, P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t r[112]; int n = processSessionCmd(g_session_id, apdu, al, r, sizeof(r));
  if (pkSW(r, n) != 0x9000) { Serial.println("[PK2B] master: the PASSKEY copy could not be read"); return false; }
  size_t off = 0; int L = parseTLVLength(r, (size_t)n - 2, &off);
  if (r[0] != TAG_1 || L != (int)PKM_COPY_LEN) { mbedtls_platform_zeroize(r, sizeof(r)); Serial.printf("[PK2B] master: PASSKEY copy is %d bytes, not 80 (an earlier generation: set the KEY up again)\n", L); return false; }
  bool ok = pkmCbc(P2_DECRYPT_ONESHOT, r + off, r + off + 16, out64);
  mbedtls_platform_zeroize(r, sizeof(r));
  if (!ok) { mbedtls_platform_zeroize(out64, 64); Serial.println("[PK2B] master: K_PK refused (not at V_3?)"); }
  return ok;
}
// Phase 3, v19: the vault backup publishing key copy. sealed32 is k_pub under
// K_G0 (G0 VAULT PUBSEAL, PASSKEY life, kept in nvs_sec until now). Written in
// the NOSTR life inside the daily session with the Nostr key's policy: G0 READ
// only while Door 1 is unlocked, daily PIN DELETE, RECOVER DELETE. VSIGN strips
// the daily layer and then K_G0.
bool se_vpub_present() { return g_ready && se_object_exists(SE_OBJ_VPUB); }
bool se_vpub_write(const uint8_t sealed32[32]) {
  return provisionScalarInto(SE_OBJ_VPUB, sealed32, "vault backup publishing key (daily layer)");
}
// ---------------------------------------------------------------------------
// v19: K_IXN is no longer made (no NOSTR copies); present/delete stay so an
// older object is still removed. P4-10 (3 Nov 2026, Vault spec): the site index key K_IDX. The index of site
// names lives in nvs_vault under AES-GCM with K_IDX; K_IDX is stored only
// wrapped: under K_PK for the PASSKEY life (passkey session at V_3) and under
// K_IXN for the NOSTR life (daily session DEC). K_IXN exists only while the
// gate is open: it is made when the gate opens and deleted when it closes, so
// a NOSTR life with the gate closed cannot unwrap even a rolled-back wrap.
// The daily PIN may DEC and DELETE it, never ENC or WRITE (the 1b reasoning).
// ---------------------------------------------------------------------------
bool se_idx_kixn_present() { return g_ready && se_object_exists(SE_OBJ_K_IXN); }
bool se_idx_kixn_delete_in_session() {
  if (!g_pin_session_open) return false;
  if (!se_object_exists(SE_OBJ_K_IXN)) return true;
  bool ok = deleteInSession(g_session_id, SE_OBJ_K_IXN);
  Serial.printf("[PK2B] K_IXN %s\n", ok ? "deleted" : "delete FAILED");
  return ok && !se_object_exists(SE_OBJ_K_IXN);
}
bool se_idx_wrap(uint32_t keyId, const uint8_t k[32], uint8_t out48[48]) {
  if (!g_pin_session_open) return false;
  esp_fill_random(out48, 16);
  bool ok = aesOneShot(keyId, P2_ENCRYPT_ONESHOT, k, out48, out48 + 16);
  if (!ok) { mbedtls_platform_zeroize(out48, 48); Serial.printf("[PK2B] index key wrap under 0x%08X refused\n", (unsigned)keyId); }
  return ok;
}
bool se_idx_unwrap(uint32_t keyId, const uint8_t in48[48], uint8_t k[32]) {
  if (!g_pin_session_open) return false;
  bool ok = aesOneShot(keyId, P2_DECRYPT_ONESHOT, in48 + 16, in48, k);
  if (!ok) { mbedtls_platform_zeroize(k, 32); Serial.printf("[PK2B] index key unwrap under 0x%08X refused\n", (unsigned)keyId); }
  return ok;
}
#endif  // FAVILLA_PK_RESTORABLE

#ifdef FAVILLA_BENCH_PROBES
// ---------------------------------------------------------------------------
// bench pkprobe (2 Nov 2026, Vault spec v0.24 section 1b, the L2 silicon
// probe). Checks the new policy shapes on THIS chip with throwaway objects:
//   T_PK  (AES): passkey PIN ENC|DEC|WRITE|DELETE only at V_3; G0 DEC only at
//                V_3; RECOVER DELETE                       (K_PK's shape)
//   T_PKN (AES): passkey PIN ENC|WRITE|DELETE only at V_3; RECOVER DELETE;
//                no daily entry                              (K_PKN's shape)
//   T_BIN (48 B binary): G0 READ; passkey PIN WRITE|DELETE; RECOVER DELETE
// Every check prints PASS or FAIL. Objects are deleted at the end (inside a
// V_3 window, since their DELETE needs it); free SE memory before and after.
// ---------------------------------------------------------------------------
static const uint32_t PROBE_PK = 0x2000E2F0u, PROBE_PKN = 0x2000E2F1u, PROBE_BIN = 0x2000E2F2u;
static int g_probeFail = 0;
static void probeCheck(bool ok, const char* what) { Serial.printf("[PKPROBE] %s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) g_probeFail++; }
static bool probeAesCreate(uint32_t id, const uint8_t* policy, size_t pp) {
  uint8_t key[32]; esp_fill_random(key, 32);
  uint8_t payload[200]; size_t p = 0; uint8_t oid[4]; obj_be(id, oid);
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, oid, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, key, 32);
  uint8_t apdu[240]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, 0x03, P2_DEFAULT, payload, p, false);
  uint8_t r[16]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(key, 32);
  uint16_t sw = pkSW(r, n); if (sw != 0x9000) Serial.printf("[PKPROBE]   create 0x%08X: SW %04X\n", (unsigned)id, sw);
  return sw == 0x9000;
}
// CipherOneShot, in the open session when inSession, else as a top-level APDU. Returns the SW.
static uint16_t probeCipher(uint32_t id, uint8_t p2, bool inSession, const uint8_t in[32], uint8_t out[32]) {
  uint8_t payload[96]; size_t p = 0; uint8_t oid[4]; obj_be(id, oid);
  uint8_t mode = AES_CBC_NOPAD, iv[16] = {0};
  p = appendTLV(payload, p, sizeof(payload), TAG_1, oid, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, &mode, 1);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, in, 32);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, iv, 16);
  uint8_t apdu[160]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_CRYPTO, P1_CIPHER, p2, payload, p, true);
  uint8_t r[80]; int n = inSession ? processSessionCmd(g_session_id, apdu, al, r, sizeof(r)) : sendAPDU(apdu, al, r, sizeof(r));
  uint16_t sw = pkSW(r, n);
  if (sw == 0x9000 && out) { size_t off; int L = parseTLVLength(r, (size_t)n - 2, &off); if (r[0] == TAG_1 && L == 32) memcpy(out, r + off, 32); else sw = 0xFFFE; }
  return sw;
}
// WriteBinary (create or overwrite), in the open session or top level. Returns the SW.
static uint16_t probeBinWrite(uint32_t id, bool inSession, const uint8_t* policy, size_t pp) {
  uint8_t data[48]; esp_fill_random(data, 48);
  uint8_t payload[200]; size_t p = 0; uint8_t oid[4]; obj_be(id, oid); uint8_t sz[2] = {0, 48};
  if (policy && pp) p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, oid, 4);
  if (policy) p = appendTLV(payload, p, sizeof(payload), TAG_3, sz, 2);
  p = appendTLV(payload, p, sizeof(payload), TAG_4, data, 48);
  uint8_t apdu[240]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_BINARY, P2_DEFAULT, payload, p, false);
  uint8_t r[16]; int n = inSession ? processSessionCmd(g_session_id, apdu, al, r, sizeof(r)) : sendAPDU(apdu, al, r, sizeof(r));
  return pkSW(r, n);
}
static uint16_t probeBinRead(uint32_t id) {
  uint8_t oid[4]; obj_be(id, oid); uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ, P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t r[96]; int n = sendAPDU(apdu, al, r, sizeof(r)); return pkSW(r, n);
}
// ARM in a passkey session, the G0 mints V_3, reopen the session. true = the latch reads V_3 and the session is open.
static bool probeWindowOpen(const char* pin) {
  if (!se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin)) return false;
  bool ok = mode_pcr_arm_in_open_session();
  se_pin_session_close();
  if (!ok || !g0_mode_door()) return false;
  if (!se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin)) { g_pkWedged = true; return false; }
  uint8_t cur[32];
  return modePcrReadInSession(g_session_id, cur) && !memcmp(cur, g_mode_pk, 32);
}
static bool probeWindowClose() {
  uint8_t spent[32]; pkSpent(spent); bool burned = false;
  for (int t = 0; t < 3 && !burned; t++) burned = pkBurnInSession(spent);
  se_pin_session_close();
  if (!burned) { g_pkWedged = true; Serial.println("[PKPROBE] burn NOT confirmed - door WEDGED until a power cycle"); }
  return burned;
}

int se_pkprobe(const char* pin) {
  g_probeFail = 0;
  if (g_pkWedged || !se_passkey_ready() || !pin) { Serial.println("[PKPROBE] needs a PASSKEY life with the passkey PIN entered"); return -1; }
  if (g_pin_session_open) se_pin_session_close();
  int free0 = se_passkey_free();
  Serial.printf("[PKPROBE] start | SE free %d bytes\n", free0);
  if (se_object_exists(PROBE_PK) || se_object_exists(PROBE_PKN) || se_object_exists(PROBE_BIN)) {
    Serial.println("[PKPROBE] objects left from an earlier run: deleting them inside a V_3 window first");
    if (probeWindowOpen(pin)) { deleteInSession(g_session_id, PROBE_PK); deleteInSession(g_session_id, PROBE_PKN); deleteInSession(g_session_id, PROBE_BIN); probeWindowClose(); }
    if (se_object_exists(PROBE_PK) || se_object_exists(PROBE_PKN) || se_object_exists(PROBE_BIN)) { Serial.println("[PKPROBE] could not clear them - stopping"); return -1; }
  }

  uint8_t pol[200]; size_t pp;
  // 1. create the three objects post-setup, as anonymous top-level writes (as the provisioning code does)
  pp = 0;
  pp = buildPolicyEntryPcr(pol, pp, sizeof(pol), SE_OBJ_PIN_PASSKEY, POLICY_OBJ_ALLOW_ENC | POLICY_OBJ_ALLOW_DEC | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE, SE_OBJ_PCR_MODE, g_mode_pk);
  pp = buildPolicyEntryPcr(pol, pp, sizeof(pol), SE_AUTH_OBJ_G0, POLICY_OBJ_ALLOW_DEC, SE_OBJ_PCR_MODE, g_mode_pk);
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);
  probeCheck(probeAesCreate(PROBE_PK, pol, pp), "1a create K_PK-shaped key after setup (passkey PIN + G0 entries, both V_3-gated)");
  pp = 0;
  pp = buildPolicyEntryPcr(pol, pp, sizeof(pol), SE_OBJ_PIN_PASSKEY, POLICY_OBJ_ALLOW_ENC | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE, SE_OBJ_PCR_MODE, g_mode_pk);
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);
  probeCheck(probeAesCreate(PROBE_PKN, pol, pp), "1b create K_PKN-shaped key after setup (no daily entry)");
  pp = 0;
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_AUTH_OBJ_G0, POLICY_OBJ_ALLOW_READ);
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_OBJ_PIN_PASSKEY, POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  pp = buildPolicyEntry(pol, pp, sizeof(pol), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);
  uint16_t sw = probeBinWrite(PROBE_BIN, false, pol, pp);
  probeCheck(sw == 0x9000, "1c create the master-copy-shaped binary object");
  mbedtls_platform_zeroize(pol, sizeof(pol));

  uint8_t a[32], b[32], c[32]; esp_fill_random(a, 32);
  // 2. anonymous: everything refused
  probeCheck(probeCipher(PROBE_PKN, P2_ENCRYPT_ONESHOT, false, a, b) != 0x9000, "2a anonymous ENC under K_PKN refused");
  probeCheck(probeCipher(PROBE_PK, P2_DECRYPT_ONESHOT, false, a, b) != 0x9000, "2b anonymous DEC under K_PK refused");
  probeCheck(probeBinRead(PROBE_BIN) != 0x9000, "2c anonymous READ of the binary object refused");
  probeCheck(probeBinWrite(PROBE_BIN, false, nullptr, 0) != 0x9000, "2d anonymous overwrite of the binary object refused");
  // 3. passkey PIN session, latch NOT at V_3: the V_3-gated rights refused
  bool s = se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin);
  probeCheck(s, "3a passkey PIN session opens");
  if (s) {
    probeCheck(probeCipher(PROBE_PKN, P2_ENCRYPT_ONESHOT, true, a, b) != 0x9000, "3b passkey PIN, latch not V_3: ENC under K_PKN refused");
    probeCheck(probeCipher(PROBE_PK, P2_ENCRYPT_ONESHOT, true, a, b) != 0x9000, "3c passkey PIN, latch not V_3: ENC under K_PK refused");
    probeCheck(probeBinWrite(PROBE_BIN, true, nullptr, 0) == 0x9000, "3d passkey PIN, no PCR clause: overwrite of the binary object allowed");
    se_pin_session_close();
  }
  // 4. inside a V_3 window: allowed
  uint32_t t0 = millis();
  bool w = probeWindowOpen(pin);
  uint32_t tOpen = millis() - t0;
  probeCheck(w, "4a ARM + G0 mint + reopen: latch reads V_3");
  if (w) {
    probeCheck(probeCipher(PROBE_PKN, P2_ENCRYPT_ONESHOT, true, a, b) == 0x9000, "4b at V_3: ENC under K_PKN allowed");
    probeCheck(probeCipher(PROBE_PKN, P2_DECRYPT_ONESHOT, true, b, c) != 0x9000, "4c at V_3: DEC under K_PKN refused (no DEC right for the passkey PIN)");
    bool e = probeCipher(PROBE_PK, P2_ENCRYPT_ONESHOT, true, a, b) == 0x9000;
    bool d = e && probeCipher(PROBE_PK, P2_DECRYPT_ONESHOT, true, b, c) == 0x9000 && !memcmp(a, c, 32);
    probeCheck(e && d, "4d at V_3: ENC then DEC under K_PK round-trips");
    uint32_t t1 = millis();
    probeWindowClose();
    Serial.printf("[PKPROBE] timing: window open %lu ms, close (burn) %lu ms\n", (unsigned long)tOpen, (unsigned long)(millis() - t1));
  }
  // 5. after the burn (SPENT): refused again, in a fresh session
  s = se_pin_session_open_obj(SE_OBJ_PIN_PASSKEY, pin);
  if (s) {
    probeCheck(probeCipher(PROBE_PKN, P2_ENCRYPT_ONESHOT, true, a, b) != 0x9000, "5a after the burn: ENC under K_PKN refused");
    probeCheck(probeCipher(PROBE_PK, P2_DECRYPT_ONESHOT, true, b, c) != 0x9000, "5b after the burn: DEC under K_PK refused");
    se_pin_session_close();
  }
  mbedtls_platform_zeroize(a, 32); mbedtls_platform_zeroize(b, 32); mbedtls_platform_zeroize(c, 32);
  // 6. clean up inside a second window (DELETE on the keys needs V_3), then check they are gone
  bool cleaned = false;
  if (probeWindowOpen(pin)) {
    bool d1 = deleteInSession(g_session_id, PROBE_PK), d2 = deleteInSession(g_session_id, PROBE_PKN), d3 = deleteInSession(g_session_id, PROBE_BIN);
    probeWindowClose();
    cleaned = d1 && d2 && d3;
  }
  probeCheck(cleaned && !se_object_exists(PROBE_PK) && !se_object_exists(PROBE_PKN) && !se_object_exists(PROBE_BIN), "6 passkey PIN at V_3 deletes all three; none left");
  int free1 = se_passkey_free();
  Serial.printf("[PKPROBE] done: %d FAIL | SE free %d -> %d bytes | door %s\n", g_probeFail, free0, free1, g_pkWedged ? "WEDGED (power cycle)" : "ok");
  Serial.println("[PKPROBE] not covered here: the G0's DEC at V_3 (needs a G0 build), the daily PIN's delete rights (daily PIN not held in a PASSKEY life)");
  return g_probeFail;
}
#endif  // FAVILLA_BENCH_PROBES

#endif  // FAVILLA_PASSKEY_DOOR
