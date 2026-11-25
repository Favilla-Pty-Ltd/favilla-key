// =============================================================================
// ec_gate_probe.inc — passkey door, bench check 1 (29 Oct 2026). BENCH ONLY.
// =============================================================================
// Question: does this SE051 ENFORCE a POLICY_OBJ_REQUIRE_PCR_VALUE clause on
// an EC SIGNING key at ECDSASign time? The latch rule is proven on AES keys,
// but the chip has diverged from AN12413/AN12543 four times (transient objects,
// fresh-PCR extend base, PIN-object PCR clause accepted but not evaluated,
// same-object policy entries not OR'd), so the passkey door is not designed on
// the spec's word.
//
// Self-contained: it builds three throwaway objects, touches NOTHING real
// (not MODE_PCR, not the Door-1 PCR, not any wallet key), and deletes them:
//   EG_PCR  0x2000E0A0  persistent PCR, NO policy (anyone may reset/extend/read)
//   EG_PIN  0x7000E0A1  UserID "424242", 10 attempts, self R/W/D + anonymous DELETE
//   EG_KEY  0x2000E0A2  on-chip NIST P-256 key. Policy, exactly the passkey shape:
//             EG_PIN : SIGN, only while EG_PCR == V      (one entry, one PCR)
//             anon   : READ | DELETE | GEN               (pubkey, cleanup, keygen)
// The 0xE0 middle byte sits far above every generation's range (gen <= 63).
//
// Tests (each prints the SE status word):
//   A  anonymous sign, PCR at base          want REFUSED  (no SIGN for anon)
//   B  EG_PIN session sign, PCR at base     want REFUSED  <-- THE QUESTION
//   C  EG_PIN session sign, PCR == V        want 9000 + signature verifies
//   D  EG_PIN session sign, PCR extended    want REFUSED  (the burn works)
//      past V
//   E  anonymous sign, PCR == V             want REFUSED  (the gate is per auth object)
// VERDICT: PASS = A,B,D,E refused and C signed + verified. If B or D SIGNS,
// the SE accepts the clause on EC keys but does not enforce it: the passkey
// door must then wrap its credential keys under an AES key that carries the
// latch rule (proven on silicon) instead of gating the EC keys directly.
//
// Session note: opening the EG_PIN session closes any session already open
// (one session at a time on this SE). Run it from the lock screen; a daily
// session that was open is closed, so unlock again afterwards.
// Included INSIDE namespace favilla in se_signer.cpp, after se_attest.inc
// (uses its EC constants, put_tlv/obj_be and der_ecdsa_to_raw).
// =============================================================================
#ifdef FAVILLA_BENCH_PROBES

bool ecgate_verify_p256(const uint8_t pub65[65], const uint8_t hash32[32], const uint8_t sig64[64]);   // ec_gate_verify.cpp

static constexpr uint32_t EG_PCR = 0x2000E0A0u;
static constexpr uint32_t EG_PIN = 0x7000E0A1u;
static constexpr uint32_t EG_KEY = 0x2000E0A2u;
static const char* EG_PIN_VAL = "424242";

static uint16_t egSW(const uint8_t* r, int n) { return n >= 2 ? (uint16_t)((r[n-2] << 8) | r[n-1]) : 0xFFFF; }
static bool egRefused(uint16_t sw) { return sw != 0x9000; }

// Send an APDU plain, or inside the open PIN session when one is open.
static int egSend(bool inSession, const uint8_t* apdu, size_t len, uint8_t* resp, size_t max) {
  if (inSession) return processSessionCmd(g_session_id, apdu, len, resp, max);
  return sendAPDU(apdu, len, resp, max);
}

static uint16_t egPcrCreate() {
  uint8_t id[4]; obj_be(EG_PCR, id);
  uint8_t pl[48]; size_t p = 0;
  p = appendTLV(pl, p, sizeof(pl), TAG_1, id, 4);
  p = appendTLV(pl, p, sizeof(pl), TAG_2, PCR_INITIAL, 32);
  uint8_t apdu[64]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, pl, p, false);
  uint8_t r[16]; int n = sendAPDU(apdu, al, r, sizeof(r));
  return egSW(r, n);
}
// ext == nullptr -> reset to initial (6985 = already at initial, counted as ok)
static uint16_t egPcrWrite(bool sess, const uint8_t* ext) {
  uint8_t id[4]; obj_be(EG_PCR, id);
  uint8_t pl[48]; size_t p = 0;
  p = appendTLV(pl, p, sizeof(pl), TAG_1, id, 4);
  if (ext) p = appendTLV(pl, p, sizeof(pl), TAG_3, ext, 32);   // TAG_3 = extend data (TAG_2 on an existing PCR -> 6A80)
  uint8_t apdu[64]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, pl, p, false);
  uint8_t r[32]; int n = egSend(sess, apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n);
  if (!ext && sw == 0x6985) sw = 0x9000;
  return sw;
}
static bool egPcrRead(bool sess, uint8_t out[32]) {
  uint8_t id[4]; obj_be(EG_PCR, id);
  uint8_t pl[8]; size_t p = appendTLV(pl, 0, sizeof(pl), TAG_1, id, 4);
  uint8_t apdu[24]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_READ, P1_DEFAULT, P2_DEFAULT, pl, p, true);
  uint8_t r[96]; int n = egSend(sess, apdu, al, r, sizeof(r));
  if (egSW(r, n) != 0x9000) return false;
  size_t body = (size_t)n - 2, off = 0;
  if (body < 2 || r[0] != TAG_1) return false;
  int len = parseTLVLength(r, body, &off);
  if (len != 32 || off + 32 > body) return false;
  memcpy(out, r + off, 32); return true;
}
static uint16_t egKeyCreate(const uint8_t want[32]) {
  uint8_t policy[96]; size_t pp = 0;
  pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), EG_PIN, POLICY_OBJ_ALLOW_SIGN, EG_PCR, want);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_DELETE | POLICY_OBJ_ALLOW_GEN);
  uint8_t data[128]; size_t dl = 0;
  uint8_t oid[4]; obj_be(EG_KEY, oid);
  dl += put_tlv(data + dl, TAG_POLICY, policy, pp);
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t curve = ECCURVE_NIST_P256;
  dl += put_tlv(data + dl, TAG_2, &curve, 1);
  uint8_t apdu[160];
  size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE, (uint8_t)(P1_KEY_PAIR | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  return egSW(r, n);
}
static bool egPub(uint8_t pub65[65]) {
  uint8_t oid[4]; obj_be(EG_KEY, oid);
  uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ, P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t r[128]; int n = sendAPDU(apdu, al, r, sizeof(r));
  if (egSW(r, n) != 0x9000) return false;
  for (int i = 0; i + 65 <= n - 2; i++) if (r[i] == 0x04) { memcpy(pub65, r + i, 65); return true; }
  return false;
}
static uint16_t egSign(bool sess, const uint8_t h[32], uint8_t sig64[64], bool* gotSig) {
  *gotSig = false;
  uint8_t oid[4]; obj_be(EG_KEY, oid);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256;
  dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = egSend(sess, apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n);
  if (sw == 0x9000) {
    for (int i = 0; i < n - 2; i++) if (r[i] == 0x30) { *gotSig = der_ecdsa_to_raw(r + i, n - 2 - i, sig64); break; }
  }
  return sw;
}
static void egHex(const char* label, const uint8_t* b, size_t n) {
  Serial.printf("[ECGATE] %s ", label); for (size_t i = 0; i < n; i++) Serial.printf("%02x", b[i]); Serial.println();
}
static void egCleanup() {
  tryDeleteObject_internal(EG_KEY);
  tryDeleteObject_internal(EG_PIN);
  tryDeleteObject_internal(EG_PCR);
}

void se_bench_ec_gate_probe() {
  Serial.println("========== [ECGATE] passkey door bench check 1 ==========");
  Serial.println("[ECGATE] does the SE enforce REQUIRE_PCR_VALUE on a P-256 SIGN key?");
  if (g_pin_session_open) { Serial.println("[ECGATE] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  egCleanup();   // leftovers from an interrupted run

  static const uint8_t EXT_A[32] = { 'F','A','V','I','L','L','A','-','E','C','G','A','T','E','-','A' };
  static const uint8_t EXT_B[32] = { 'F','A','V','I','L','L','A','-','E','C','G','A','T','E','-','B' };
  uint8_t base[32], V[32], cur[32], pub[65], sig[64];
  uint8_t h[32]; { const char* m = "favilla ecgate test message"; mbedtls_sha256((const uint8_t*)m, strlen(m), h, 0); }
  uint16_t sw; bool got;
  bool A=false, B=false, C=false, D=false, E=false, setup=false;

  do {
    // 1. the gate PCR: create, reset (fresh-PCR extend-base quirk), learn V, back to base
    sw = egPcrCreate();                                 Serial.printf("[ECGATE] create PCR %08lX: SW %04X\n", (unsigned long)EG_PCR, sw);
    if (sw != 0x9000) break;
    if ((sw = egPcrWrite(false, nullptr)) != 0x9000) { Serial.printf("[ECGATE] reset SW %04X\n", sw); break; }
    if ((sw = egPcrWrite(false, EXT_A)) != 0x9000)  { Serial.printf("[ECGATE] extend A SW %04X\n", sw); break; }
    if (!egPcrRead(false, V)) { Serial.println("[ECGATE] read V failed"); break; }
    if ((sw = egPcrWrite(false, nullptr)) != 0x9000) { Serial.printf("[ECGATE] reset SW %04X\n", sw); break; }
    if (!egPcrRead(false, base) || !memcmp(base, V, 32)) { Serial.println("[ECGATE] base unreadable or equal to V"); break; }
    egHex("V    =", V, 32); egHex("base =", base, 32);

    // 2. the PIN and the gated key
    { uint8_t pol[32]; size_t pp = 0;
      pp = buildPolicyEntry(pol, pp, sizeof(pol), EG_PIN, POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
      pp = buildPolicyEntry(pol, pp, sizeof(pol), 0x00000000UL, POLICY_OBJ_ALLOW_DELETE);
      bool ok = writeUserIDWithPolicy(EG_PIN, (const uint8_t*)EG_PIN_VAL, strlen(EG_PIN_VAL), 10, pol, pp);
      Serial.printf("[ECGATE] create PIN %08lX: %s\n", (unsigned long)EG_PIN, ok ? "OK" : "FAILED");
      if (!ok) break; }
    sw = egKeyCreate(V);                                Serial.printf("[ECGATE] create P-256 key %08lX gated on PCR==V: SW %04X\n", (unsigned long)EG_KEY, sw);
    if (sw != 0x9000) { Serial.println("[ECGATE] the SE refused the policy or the keygen - note the SW; the clause may be rejected outright on EC keys"); break; }
    if (!egPub(pub)) { Serial.println("[ECGATE] pubkey read failed"); break; }
    egHex("pub  =", pub, 65);
    setup = true;

    // A. anonymous sign, PCR at base
    sw = egSign(false, h, sig, &got);  A = egRefused(sw);
    Serial.printf("[ECGATE] A anon sign, PCR=base:      SW %04X  %s\n", sw, A ? "refused (ok)" : "SIGNED - anon has no SIGN right, unexpected");

    // open the EG_PIN session
    if (!se_pin_session_open_obj(EG_PIN, EG_PIN_VAL)) { Serial.println("[ECGATE] EG_PIN session did not open"); break; }

    // B. session sign, PCR at base  <-- the question
    if (!egPcrRead(true, cur) || memcmp(cur, base, 32)) Serial.println("[ECGATE] WARN: PCR not at base before B");
    sw = egSign(true, h, sig, &got);   B = egRefused(sw);
    Serial.printf("[ECGATE] B PIN sign, PCR=base:       SW %04X  %s\n", sw, B ? "refused (ok) - GATE ENFORCED" : "SIGNED - GATE NOT ENFORCED ON EC KEYS");

    // C. extend to V, session sign
    if ((sw = egPcrWrite(true, EXT_A)) != 0x9000) { Serial.printf("[ECGATE] extend to V in session SW %04X\n", sw); break; }
    if (!egPcrRead(true, cur) || memcmp(cur, V, 32)) { Serial.println("[ECGATE] PCR did not land on V"); egHex("cur  =", cur, 32); break; }
    sw = egSign(true, h, sig, &got);
    bool ver = got && ecgate_verify_p256(pub, h, sig);
    C = (sw == 0x9000) && ver;
    Serial.printf("[ECGATE] C PIN sign, PCR=V:          SW %04X  sig %s, verify %s\n", sw, got ? "parsed" : "none", ver ? "OK" : "FAILED");
    if (got) egHex("sig  =", sig, 64);

    // D. extend past V (the burn), session sign
    if ((sw = egPcrWrite(true, EXT_B)) != 0x9000) { Serial.printf("[ECGATE] burn extend SW %04X\n", sw); break; }
    sw = egSign(true, h, sig, &got);   D = egRefused(sw);
    Serial.printf("[ECGATE] D PIN sign, PCR burned:     SW %04X  %s\n", sw, D ? "refused (ok)" : "SIGNED - burn does not close the gate");

    // E. back to V, anonymous sign
    se_pin_session_close();
    egPcrWrite(false, nullptr); egPcrWrite(false, EXT_A);
    if (!egPcrRead(false, cur) || memcmp(cur, V, 32)) Serial.println("[ECGATE] WARN: PCR not at V before E");
    sw = egSign(false, h, sig, &got);  E = egRefused(sw);
    Serial.printf("[ECGATE] E anon sign, PCR=V:         SW %04X  %s\n", sw, E ? "refused (ok)" : "SIGNED - the gate is not tied to the PIN session");
  } while (0);

  if (g_pin_session_open && g_session_obj == EG_PIN) se_pin_session_close();
  egCleanup();
  Serial.printf("[ECGATE] cleanup: key gone=%d pin gone=%d pcr gone=%d\n",
                !se_object_exists(EG_KEY), !se_object_exists(EG_PIN), !se_object_exists(EG_PCR));
  if (!setup)                    Serial.println("[ECGATE] VERDICT: INCOMPLETE - setup failed, see the SW above");
  else if (A && B && C && D && E) Serial.println("[ECGATE] VERDICT: PASS - the latch rule is enforced on P-256 signing keys. Gate the credential keys directly.");
  else if (!B || !D)             Serial.println("[ECGATE] VERDICT: FAIL - clause accepted but NOT enforced on EC keys. Fall back to AES-wrapped credentials.");
  else                           Serial.println("[ECGATE] VERDICT: MIXED - read the A..E lines");
  Serial.println("========== [ECGATE end] ==========");
}


// =============================================================================
// Bench check 2 (29 Oct 2026): how many passkey-shaped P-256 keys fit?
// Creates keys of EXACTLY the section 5 policy shape (passkey PIN: SIGN gated on
// a PCR value; anonymous: READ | DELETE | GEN) at 0x2000E100 + i until the SE
// refuses one or the cap is reached, reports persistent free memory before,
// during and after, then deletes every key it made. The count is on top of
// whatever this unit already holds (wallet objects, old generations), so read
// it together with the "free before" figure.
// =============================================================================
static constexpr uint32_t EF_BASE = 0x2000E100u;
static constexpr int      EF_CAP  = 200;
// GetFreeMemory (AN12413: INS_MGMT, P2_MEMORY 0x22, TAG_1 = 1-byte type,
// 1 = persistent). The SE caps the answer at 0x7FFF.
static int egFreePersistent() {
  uint8_t t = 0x01;
  uint8_t pl[8]; size_t p = appendTLV(pl, 0, sizeof(pl), TAG_1, &t, 1);
  uint8_t apdu[24]; size_t al = buildAPDU(apdu, sizeof(apdu), 0x80, INS_MGMT, P1_DEFAULT, 0x22, pl, p, true);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  if (egSW(r, n) != 0x9000 || n < 4 || r[0] != TAG_1) return -1;
  size_t off = 0; int len = parseTLVLength(r, (size_t)n - 2, &off);
  if (len == 2 && off + 2 <= (size_t)n - 2) return (r[off] << 8) | r[off + 1];
  if (len == 4 && off + 4 <= (size_t)n - 2) return (int)(((uint32_t)r[off] << 24) | ((uint32_t)r[off+1] << 16) | (r[off+2] << 8) | r[off+3]);
  return -1;
}
static uint16_t efKeyCreate(uint32_t id, const uint8_t want[32]) {
  uint8_t policy[96]; size_t pp = 0;
  pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), EG_PIN, POLICY_OBJ_ALLOW_SIGN, EG_PCR, want);
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
  return egSW(r, n);
}

void se_bench_ec_fill_probe() {
  Serial.println("========== [ECFILL] passkey door bench check 2 ==========");
  if (g_pin_session_open) { Serial.println("[ECFILL] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  // leftovers from an interrupted run
  for (int i = 0; i < EF_CAP; i++) { if (se_object_exists(EF_BASE + i)) tryDeleteObject_internal(EF_BASE + i); esp_task_wdt_reset(); }
  egCleanup();
  int free0 = egFreePersistent();
  Serial.printf("[ECFILL] persistent free before: %d bytes%s\n", free0, free0 == 0x7FFF ? " (SE caps the report at 32767)" : free0 < 0 ? " (GetFreeMemory not answered)" : "");
  // the policy needs a real PCR id and auth object id to point at; values only
  static const uint8_t VDUMMY[32] = { 'F','A','V','I','L','L','A','-','E','C','F','I','L','L' };
  int made = 0; uint16_t last = 0x9000; uint32_t t0 = millis(), worst = 0;
  for (int i = 0; i < EF_CAP; i++) {
    uint32_t t1 = millis();
    last = efKeyCreate(EF_BASE + i, VDUMMY);
    uint32_t dt = millis() - t1; if (dt > worst) worst = dt;
    esp_task_wdt_reset();
    if (last != 0x9000) break;
    made++;
    if (made % 10 == 0) Serial.printf("[ECFILL] %3d keys, persistent free %d, last keygen %lu ms\n", made, egFreePersistent(), (unsigned long)dt);
  }
  int freeFull = egFreePersistent();
  Serial.printf("[ECFILL] stopped at %d keys: %s (SW %04X) | free now %d | %lu ms total, worst keygen %lu ms\n",
                made, made == EF_CAP ? "cap reached, SE still accepting" : "SE refused the next key", last, freeFull,
                (unsigned long)(millis() - t0), (unsigned long)worst);
  int gone = 0;
  for (int i = 0; i < made; i++) { if (tryDeleteObject_internal(EF_BASE + i)) gone++; esp_task_wdt_reset(); }
  int left = 0;
  for (int i = 0; i < made; i++) { if (se_object_exists(EF_BASE + i)) left++; esp_task_wdt_reset(); }
  int free1 = egFreePersistent();
  Serial.printf("[ECFILL] cleanup: deleted %d, still present %d | persistent free after: %d (before %d)\n", gone, left, free1, free0);
  if (made > 0 && free0 > 0 && freeFull >= 0 && free0 != 0x7FFF)
    Serial.printf("[ECFILL] about %d bytes per passkey-shaped key\n", (free0 - freeFull) / made);
  Serial.printf("[ECFILL] RESULT: %d passkey credentials fit on this unit as it stands%s\n", made, made == EF_CAP ? " (at least)" : "");
  Serial.println("========== [ECFILL end] ==========");
}


// =============================================================================
// Bench check 4 (29 Oct 2026): how long does one passkey login take on the SE
// side? Builds the check-1 objects, then runs 10 logins of the section 7 shape
// (PIN-once mode, so no ARM):
//   open PIN session -> close -> [G0 MODEDOOR] -> reopen -> verify latch == V
//   -> ECDSASign -> burn (extend past V) -> close
// The G0 step does not exist yet (MODEDOOR is a freeze item), so it is
// SIMULATED by a plain reset + extend of the test PCR; its real cost is the
// G0's own SCP03 open + read + reset + extend, measured on the BTC door today.
// Add that figure to the total printed here. Touches no real object.
// =============================================================================
void se_bench_ec_time_probe() {
  Serial.println("========== [ECTIME] passkey door bench check 4 ==========");
  if (g_pin_session_open) { Serial.println("[ECTIME] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  egCleanup();
  static const uint8_t EXT_A[32] = { 'F','A','V','I','L','L','A','-','E','C','G','A','T','E','-','A' };
  static const uint8_t EXT_B[32] = { 'F','A','V','I','L','L','A','-','E','C','G','A','T','E','-','B' };
  uint8_t V[32], cur[32], pub[65], sig[64], h[32];
  bool ok = false;
  do {
    if (egPcrCreate() != 0x9000) { Serial.println("[ECTIME] PCR create failed"); break; }
    egPcrWrite(false, nullptr); egPcrWrite(false, EXT_A);
    if (!egPcrRead(false, V)) { Serial.println("[ECTIME] read V failed"); break; }
    egPcrWrite(false, nullptr);
    { uint8_t pol[32]; size_t pp = 0;
      pp = buildPolicyEntry(pol, pp, sizeof(pol), EG_PIN, POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
      pp = buildPolicyEntry(pol, pp, sizeof(pol), 0x00000000UL, POLICY_OBJ_ALLOW_DELETE);
      if (!writeUserIDWithPolicy(EG_PIN, (const uint8_t*)EG_PIN_VAL, strlen(EG_PIN_VAL), 10, pol, pp)) { Serial.println("[ECTIME] PIN create failed"); break; } }
    if (egKeyCreate(V) != 0x9000 || !egPub(pub)) { Serial.println("[ECTIME] key create failed"); break; }
    ok = true;
  } while (0);

  const int N = 10;
  const char* names[7] = { "open session (PIN verify)", "close", "G0 step (SIMULATED)", "reopen session", "read + check latch", "ECDSASign", "burn + close" };
  uint32_t mn[7], mx[7], sum[7]; for (int k = 0; k < 7; k++) { mn[k] = 0xFFFFFFFF; mx[k] = 0; sum[k] = 0; }
  uint32_t tmin = 0xFFFFFFFF, tmax = 0, tsum = 0; int good = 0, verified = 0;
  for (int it = 0; ok && it < N; it++) {
    uint32_t t[8]; bool fine = true; bool got = false;
    t[0] = millis();
    fine = se_pin_session_open_obj(EG_PIN, EG_PIN_VAL);                    t[1] = millis();
    se_pin_session_close();                                                t[2] = millis();
    egPcrWrite(false, nullptr); egPcrWrite(false, EXT_A);                  t[3] = millis();
    fine = fine && se_pin_session_open_obj(EG_PIN, EG_PIN_VAL);            t[4] = millis();
    fine = fine && egPcrRead(true, cur) && !memcmp(cur, V, 32);            t[5] = millis();
    { char m[24]; snprintf(m, sizeof m, "login %d", it); mbedtls_sha256((const uint8_t*)m, strlen(m), h, 0); }
    uint16_t sw = egSign(true, h, sig, &got);                              t[6] = millis();
    egPcrWrite(true, EXT_B); se_pin_session_close();                       t[7] = millis();
    esp_task_wdt_reset();
    if (!fine || sw != 0x9000 || !got) { Serial.printf("[ECTIME] login %d failed (sw %04X)\n", it, sw); continue; }
    if (ecgate_verify_p256(pub, h, sig)) verified++;
    good++;
    for (int k = 0; k < 7; k++) { uint32_t d = t[k+1] - t[k]; sum[k] += d; if (d < mn[k]) mn[k] = d; if (d > mx[k]) mx[k] = d; }
    uint32_t tot = t[7] - t[0]; tsum += tot; if (tot < tmin) tmin = tot; if (tot > tmax) tmax = tot;
  }
  if (g_pin_session_open && g_session_obj == EG_PIN) se_pin_session_close();
  egCleanup();
  if (good) {
    for (int k = 0; k < 7; k++)
      Serial.printf("[ECTIME] %-26s min %4lu  avg %4lu  max %4lu ms\n", names[k], (unsigned long)mn[k], (unsigned long)(sum[k] / good), (unsigned long)mx[k]);
    Serial.printf("[ECTIME] SE side, whole login:    min %4lu  avg %4lu  max %4lu ms  (%d/%d logins, %d signatures verified)\n",
                  (unsigned long)tmin, (unsigned long)(tsum / good), (unsigned long)tmax, good, N, verified);
    Serial.println("[ECTIME] Add the real G0 step (its own SCP03 open + read + reset + extend) to get the full login.");
  } else {
    Serial.println("[ECTIME] no login completed - see the lines above");
  }
  Serial.printf("[ECTIME] cleanup: key gone=%d pin gone=%d pcr gone=%d\n",
                !se_object_exists(EG_KEY), !se_object_exists(EG_PIN), !se_object_exists(EG_PCR));
  Serial.println("========== [ECTIME end] ==========");
}


// =============================================================================
// Restorable passkeys, bench check 2 (30 Oct 2026): `se ecimport`
// =============================================================================
// Option B signs with a key the G0 COMPUTED and writes into a scratch object.
// The enterprise door only ever used keys GENERATED inside the SE, so the import
// path is unproven on this applet. This probe answers, with throwaway objects:
//   1. does WriteECKey accept an imported P-256 key pair (TAG_3 priv, TAG_4 pub),
//      and/or the private key alone (P1_PRIVATE)?
//   2. does the SE then sign with it, and does the signature verify against the
//      public key we computed (proving it really used OUR key)?
//   3. time per write / sign / delete over 20 cycles, and SE free memory before
//      and after (no leak from the write-sign-delete pattern).
// Sent in the clear here (no session): the real design sends the same APDUs
// inside the G0's encrypted SCP03 session. Endurance is NOT measured here; that
// figure comes from NXP's datasheet.
static constexpr uint32_t EI_OBJ = 0x2000E0B0u;
bool ecgate_make_p256(uint8_t priv32[32], uint8_t pub65[65]);
static uint16_t eiWrite(uint8_t p1, const uint8_t priv[32], const uint8_t* pub65) {
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL,
                        POLICY_OBJ_ALLOW_SIGN | POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_DELETE);
  uint8_t data[160]; size_t dl = 0; uint8_t oid[4]; obj_be(EI_OBJ, oid);
  dl += put_tlv(data + dl, TAG_POLICY, policy, pp);
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t curve = ECCURVE_NIST_P256;
  dl += put_tlv(data + dl, TAG_2, &curve, 1);
  dl += put_tlv(data + dl, TAG_3, priv, 32);
  if (pub65) dl += put_tlv(data + dl, TAG_4, pub65, 65);
  uint8_t apdu[200];
  size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE, (uint8_t)(p1 | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(data, sizeof(data)); mbedtls_platform_zeroize(apdu, sizeof(apdu));
  return egSW(r, n);
}
static uint16_t eiSign(const uint8_t h[32], uint8_t sig64[64], bool* got) {
  *got = false;
  uint8_t oid[4]; obj_be(EI_OBJ, oid);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256; dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = sendAPDU(apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n);
  if (sw == 0x9000) for (int i = 0; i < n - 2; i++) if (r[i] == 0x30) { *got = der_ecdsa_to_raw(r + i, n - 2 - i, sig64); break; }
  return sw;
}
// One variant: write, sign, verify, delete. Returns true if the SE signed with OUR key.
static bool eiOnce(uint8_t p1, bool withPub, uint32_t* tW, uint32_t* tS, uint32_t* tD, uint16_t* swW) {
  uint8_t priv[32], pub[65], h[32], sig[64]; bool got = false;
  if (!ecgate_make_p256(priv, pub)) { Serial.println("[ECIMPORT] could not make a test key"); return false; }
  esp_fill_random(h, 32);
  if (se_object_exists(EI_OBJ)) tryDeleteObject_internal(EI_OBJ);
  uint32_t t0 = millis();
  *swW = eiWrite(p1, priv, withPub ? pub : nullptr);
  uint32_t t1 = millis();
  mbedtls_platform_zeroize(priv, sizeof(priv));
  if (*swW != 0x9000) return false;
  uint16_t swS = eiSign(h, sig, &got);
  uint32_t t2 = millis();
  bool ok = (swS == 0x9000) && got && ecgate_verify_p256(pub, h, sig);
  if (swS != 0x9000) Serial.printf("[ECIMPORT]   sign SW %04X\n", swS);
  tryDeleteObject_internal(EI_OBJ);
  uint32_t t3 = millis();
  *tW = t1 - t0; *tS = t2 - t1; *tD = t3 - t2;
  return ok;
}
void se_bench_ec_import_probe() {
  Serial.println("========== [ECIMPORT] restorable passkeys bench check 2 ==========");
  if (g_pin_session_open) { Serial.println("[ECIMPORT] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  if (se_object_exists(EI_OBJ)) tryDeleteObject_internal(EI_OBJ);
  int free0 = egFreePersistent();
  Serial.printf("[ECIMPORT] SE persistent free before: %d bytes\n", free0);
  uint32_t tW, tS, tD; uint16_t sw;
  bool pairOk = eiOnce(P1_KEY_PAIR, true, &tW, &tS, &tD, &sw);
  Serial.printf("[ECIMPORT] A key pair import (priv + pub): write SW %04X -> %s (write %lu ms, sign %lu, delete %lu)\n",
                sw, pairOk ? "SIGNED WITH OUR KEY, verified" : "no", (unsigned long)tW, (unsigned long)tS, (unsigned long)tD);
  bool privOk = eiOnce(0x40 /* P1_PRIVATE */, false, &tW, &tS, &tD, &sw);
  Serial.printf("[ECIMPORT] B private key only: write SW %04X -> %s (write %lu ms, sign %lu, delete %lu)\n",
                sw, privOk ? "SIGNED WITH OUR KEY, verified" : "no", (unsigned long)tW, (unsigned long)tS, (unsigned long)tD);
  uint8_t p1 = pairOk ? P1_KEY_PAIR : 0x40; bool wp = pairOk;
  if (pairOk || privOk) {
    uint32_t sw_ = 0, ss = 0, sd = 0, worst = 0; int good = 0;
    const int N = 20;
    for (int i = 0; i < N; i++) {
      esp_task_wdt_reset();
      if (eiOnce(p1, wp, &tW, &tS, &tD, &sw)) good++;
      sw_ += tW; ss += tS; sd += tD; uint32_t all = tW + tS + tD; if (all > worst) worst = all;
    }
    int free1 = egFreePersistent();
    Serial.printf("[ECIMPORT] %d cycles (%s): %d signed + verified | mean write %lu ms, sign %lu ms, delete %lu ms | worst cycle %lu ms\n",
                  N, pairOk ? "key pair" : "private only", good, (unsigned long)(sw_ / N), (unsigned long)(ss / N), (unsigned long)(sd / N), (unsigned long)worst);
    Serial.printf("[ECIMPORT] SE persistent free after: %d bytes (before %d) -> %s\n", free1, free0,
                  free1 == free0 ? "no leak" : "CHANGED - look again");
  }
  if (se_object_exists(EI_OBJ)) tryDeleteObject_internal(EI_OBJ);
  Serial.printf("[ECIMPORT] VERDICT: %s\n", (pairOk || privOk) ? "the SE accepts an imported P-256 key and signs with it - option B is open"
                                                                : "the SE REFUSED the import (see SWs) - option B is closed, measure option A");
  Serial.println("========== [ECIMPORT end] ==========");
}

// =============================================================================
// Restorable passkeys, bench check 2b (30 Oct 2026): `se ecoverwrite`
// =============================================================================
// `se ecimport` showed delete costs ~700 ms of a ~900 ms cycle. Question: will
// the SE take a NEW key written over an EXISTING key object (no delete)? If so a
// login is: write the site key over the slot, sign, write a random junk key over
// it, and the site key lives in the SE only for one sign-in.
//   1. create the slot (policy: anonymous SIGN | READ | WRITE | DELETE) with key 1
//   2. write key 2 over it, without a policy TLV, then with one (which form the
//      SE accepts on an existing object), sign, verify against key 2 (proves the
//      key really changed, not just a 9000)
//   3. 20 cycles of: write real key, sign + verify, write junk key; timings and
//      free memory before and after
static constexpr uint32_t EO_OBJ = 0x2000E0B1u;
static int g_eoForm = -1;   // the rewrite form that worked (2c), -1 = the 2a/2b eoWrite forms
// form bits for rewrites (bench check 2c): which TLVs go with a write to an EXISTING object
static constexpr int EO_POLICY = 1, EO_CURVE = 2, EO_PUB = 4, EO_PRIVONLY_P1 = 8;
static uint16_t eoWriteForm(const uint8_t priv[32], const uint8_t pub65[65], int form) {
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL,
                        POLICY_OBJ_ALLOW_SIGN | POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  uint8_t data[160]; size_t dl = 0; uint8_t oid[4]; obj_be(EO_OBJ, oid);
  if (form & EO_POLICY) dl += put_tlv(data + dl, TAG_POLICY, policy, pp);
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  if (form & EO_CURVE) { uint8_t curve = ECCURVE_NIST_P256; dl += put_tlv(data + dl, TAG_2, &curve, 1); }
  dl += put_tlv(data + dl, TAG_3, priv, 32);
  if (form & EO_PUB) dl += put_tlv(data + dl, TAG_4, pub65, 65);
  uint8_t p1 = (form & EO_PRIVONLY_P1) ? 0x40 /* P1_PRIVATE */ : P1_KEY_PAIR;
  uint8_t apdu[200];
  size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE, (uint8_t)(p1 | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(data, sizeof(data)); mbedtls_platform_zeroize(apdu, sizeof(apdu));
  return egSW(r, n);
}
static uint16_t eoWrite(const uint8_t priv[32], const uint8_t pub65[65], bool withPolicy) {
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL,
                        POLICY_OBJ_ALLOW_SIGN | POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  uint8_t data[160]; size_t dl = 0; uint8_t oid[4]; obj_be(EO_OBJ, oid);
  if (withPolicy) dl += put_tlv(data + dl, TAG_POLICY, policy, pp);
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t curve = ECCURVE_NIST_P256;
  dl += put_tlv(data + dl, TAG_2, &curve, 1);
  dl += put_tlv(data + dl, TAG_3, priv, 32);
  dl += put_tlv(data + dl, TAG_4, pub65, 65);
  uint8_t apdu[200];
  size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE, (uint8_t)(P1_KEY_PAIR | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(data, sizeof(data)); mbedtls_platform_zeroize(apdu, sizeof(apdu));
  return egSW(r, n);
}
static bool eoSignVerify(const uint8_t pub65[65], uint16_t* swOut) {
  uint8_t oid[4]; obj_be(EO_OBJ, oid);
  uint8_t h[32], sig[64]; esp_fill_random(h, 32);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256; dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = sendAPDU(apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n); if (swOut) *swOut = sw;
  if (sw != 0x9000) return false;
  bool got = false;
  for (int i = 0; i < n - 2; i++) if (r[i] == 0x30) { got = der_ecdsa_to_raw(r + i, n - 2 - i, sig); break; }
  return got && ecgate_verify_p256(pub65, h, sig);
}
void se_bench_ec_overwrite_probe() {
  Serial.println("========== [ECOVERWRITE] restorable passkeys bench check 2b/2c ==========");
  g_eoForm = -1;
  if (g_pin_session_open) { Serial.println("[ECOVERWRITE] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  if (se_object_exists(EO_OBJ)) tryDeleteObject_internal(EO_OBJ);
  int free0 = egFreePersistent();
  Serial.printf("[ECOVERWRITE] SE persistent free before: %d bytes\n", free0);
  uint8_t k1[32], p1[65], k2[32], p2[65]; uint16_t sw;
  if (!ecgate_make_p256(k1, p1) || !ecgate_make_p256(k2, p2)) { Serial.println("[ECOVERWRITE] could not make test keys"); return; }
  sw = eoWrite(k1, p1, true);
  bool s1 = (sw == 0x9000) && eoSignVerify(p1, nullptr);
  Serial.printf("[ECOVERWRITE] 1 create with key 1: SW %04X, signs with key 1: %s\n", sw, s1 ? "yes" : "no");
  bool form = false, viaPolicy = false;
  if (s1) {
    uint32_t t0 = millis();
    sw = eoWrite(k2, p2, false);
    uint32_t t1 = millis();
    bool s2 = (sw == 0x9000) && eoSignVerify(p2, nullptr);
    bool still1 = !s2 && eoSignVerify(p1, nullptr);
    Serial.printf("[ECOVERWRITE] 2a overwrite with key 2, no policy TLV: SW %04X (%lu ms), signs with key 2: %s%s\n",
                  sw, (unsigned long)(t1 - t0), s2 ? "YES" : "no", still1 ? " (still key 1)" : "");
    form = s2;
    if (!s2) {
      sw = eoWrite(k2, p2, true);
      s2 = (sw == 0x9000) && eoSignVerify(p2, nullptr);
      Serial.printf("[ECOVERWRITE] 2b overwrite with key 2, policy TLV included: SW %04X, signs with key 2: %s\n", sw, s2 ? "YES" : "no");
      form = s2; viaPolicy = s2;
    }
    // 2c (30 Oct 2026): 6A80 on both - try without the curve id, which an
    // existing object already has.
    static const struct { int f; const char* nm; } F[] = {
      { EO_PUB,                  "key pair, no policy, NO curve" },
      { 0,                       "private only (P1 key pair), no policy, no curve, no pub" },
      { EO_PRIVONLY_P1,          "P1_PRIVATE, private only, no policy, no curve" },
      { EO_PRIVONLY_P1 | EO_CURVE, "P1_PRIVATE, private only, curve, no policy" },
    };
    for (unsigned i = 0; !form && i < sizeof F / sizeof F[0]; i++) {
      uint32_t a = millis(); sw = eoWriteForm(k2, p2, F[i].f); uint32_t b = millis();
      bool ok = (sw == 0x9000) && eoSignVerify(p2, nullptr);
      Serial.printf("[ECOVERWRITE] 2c.%u overwrite, %s: SW %04X (%lu ms), signs with key 2: %s\n", i + 1, F[i].nm, sw, (unsigned long)(b - a), ok ? "YES" : "no");
      if (ok) { form = true; g_eoForm = F[i].f; }
    }
  }
  mbedtls_platform_zeroize(k1, 32); mbedtls_platform_zeroize(k2, 32);
  if (form) {
    const int N = 20; int good = 0; uint32_t tw = 0, ts = 0, tj = 0, worst = 0;
    for (int i = 0; i < N; i++) {
      esp_task_wdt_reset();
      uint8_t k[32], p[65], jk[32], jp[65];
      if (!ecgate_make_p256(k, p) || !ecgate_make_p256(jk, jp)) continue;
      uint32_t a = millis(); uint16_t w = g_eoForm >= 0 ? eoWriteForm(k, p, g_eoForm) : eoWrite(k, p, viaPolicy); uint32_t b = millis();
      bool ok = (w == 0x9000) && eoSignVerify(p, nullptr); uint32_t c = millis();
      uint16_t j = g_eoForm >= 0 ? eoWriteForm(jk, jp, g_eoForm) : eoWrite(jk, jp, viaPolicy); uint32_t d = millis();
      bool junkOk = (j == 0x9000) && !eoSignVerify(p, nullptr);   // the site key must be gone
      mbedtls_platform_zeroize(k, 32); mbedtls_platform_zeroize(jk, 32);
      if (ok && junkOk) good++;
      tw += b - a; ts += c - b; tj += d - c; if (d - a > worst) worst = d - a;
    }
    int free1 = egFreePersistent();
    Serial.printf("[ECOVERWRITE] %d cycles (write site key, sign, write junk): %d good (signed with the site key, then the site key gone)\n", N, good);
    Serial.printf("[ECOVERWRITE] mean write %lu ms, sign+verify %lu ms, junk write %lu ms | worst cycle %lu ms\n",
                  (unsigned long)(tw / N), (unsigned long)(ts / N), (unsigned long)(tj / N), (unsigned long)worst);
    Serial.printf("[ECOVERWRITE] SE persistent free after: %d bytes (before %d)\n", free1, free0);
  }
  if (se_object_exists(EO_OBJ)) tryDeleteObject_internal(EO_OBJ);
  Serial.printf("[ECOVERWRITE] VERDICT: %s\n", form ? (g_eoForm >= 0 ? "overwrite in place works (see the 2c line that said YES for the form)" : viaPolicy ? "overwrite in place works (the SE wants the policy TLV on every write)" : "overwrite in place works (no policy TLV on rewrites)")
                                                     : "the SE does NOT overwrite a key in place - keep delete + write (~0.9 s)");
  Serial.println("========== [ECOVERWRITE end] ==========");
}

// =============================================================================
// Restorable passkeys, bench check 2d (30 Oct 2026): `se ecprivonly`
// =============================================================================
// The overwrite that worked (2c.1) sends the KEY PAIR, so whoever writes it must
// know the public key k*G. Under option B the G0 has no P-256 code and the ESP32
// must never see k. So option B without new curve code needs the SE to take the
// PRIVATE key alone, work out the public key itself, and hand it back. Tests:
//   1. create a slot from the private key alone (P1_PRIVATE): SW, and does a
//      ReadObject then return a public key - and is it k*G (compared with the
//      public key computed here)?
//   2. overwrite that slot with ONLY a new private key, every form without the
//      curve id (P1_PRIVATE, and P1_KEY_PAIR with no TAG_4): SW, does it then
//      sign with the new key, and does ReadObject return the NEW public key?
static constexpr uint32_t EP_OBJ = 0x2000E0B2u;
static uint16_t epWrite(uint8_t p1, const uint8_t priv[32], bool create) {
  uint8_t policy[32]; size_t pp = 0;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL,
                        POLICY_OBJ_ALLOW_SIGN | POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  uint8_t data[128]; size_t dl = 0; uint8_t oid[4]; obj_be(EP_OBJ, oid);
  if (create) dl += put_tlv(data + dl, TAG_POLICY, policy, pp);
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  if (create) { uint8_t curve = ECCURVE_NIST_P256; dl += put_tlv(data + dl, TAG_2, &curve, 1); }
  dl += put_tlv(data + dl, TAG_3, priv, 32);
  uint8_t apdu[160];
  size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE, (uint8_t)(p1 | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t r[32]; int n = sendAPDU(apdu, al, r, sizeof(r));
  mbedtls_platform_zeroize(data, sizeof(data)); mbedtls_platform_zeroize(apdu, sizeof(apdu));
  return egSW(r, n);
}
// ReadObject on the slot: SW, and the 65-byte uncompressed point if one comes back.
static uint16_t epReadPub(uint8_t pub65[65], bool* got) {
  *got = false;
  uint8_t oid[4]; obj_be(EP_OBJ, oid);
  uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ, P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t r[128]; int n = sendAPDU(apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n);
  if (sw == 0x9000) for (int i = 0; i + 65 <= n - 2; i++) if (r[i] == 0x04) { memcpy(pub65, r + i, 65); *got = true; break; }
  return sw;
}
static bool epSignVerify(const uint8_t pub65[65]) {
  uint8_t oid[4]; obj_be(EP_OBJ, oid);
  uint8_t h[32], sig[64]; esp_fill_random(h, 32);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256; dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = sendAPDU(apdu, al, r, sizeof(r));
  if (egSW(r, n) != 0x9000) return false;
  bool got = false;
  for (int i = 0; i < n - 2; i++) if (r[i] == 0x30) { got = der_ecdsa_to_raw(r + i, n - 2 - i, sig); break; }
  return got && ecgate_verify_p256(pub65, h, sig);
}
void se_bench_ec_privonly_probe() {
  Serial.println("========== [ECPRIVONLY] restorable passkeys bench check 2d ==========");
  if (g_pin_session_open) { Serial.println("[ECPRIVONLY] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  if (se_object_exists(EP_OBJ)) tryDeleteObject_internal(EP_OBJ);
  uint8_t k1[32], p1[65], k2[32], p2[65], rp[65]; bool got; uint16_t sw;
  if (!ecgate_make_p256(k1, p1) || !ecgate_make_p256(k2, p2)) { Serial.println("[ECPRIVONLY] could not make test keys"); return; }
  // 1. create from the private key alone, then read the public key back
  sw = epWrite(0x40 /* P1_PRIVATE */, k1, true);
  Serial.printf("[ECPRIVONLY] 1 create, private key only: SW %04X\n", sw);
  bool pubOk = false;
  if (sw == 0x9000) {
    uint16_t rs = epReadPub(rp, &got);
    pubOk = got && !memcmp(rp, p1, 65);
    Serial.printf("[ECPRIVONLY] 1 ReadObject: SW %04X, public key returned: %s%s\n", rs, got ? "yes" : "no",
                  got ? (pubOk ? " and it IS k*G" : " but it is NOT k*G") : "");
    Serial.printf("[ECPRIVONLY] 1 signs with key 1: %s\n", epSignVerify(p1) ? "yes" : "no");
  }
  // 2. overwrite with only a new private key
  bool ovOk = false, ovPub = false; const char* ovForm = "none";
  if (sw == 0x9000) {
    static const struct { uint8_t p1; const char* nm; } F[] = { { 0x40, "P1_PRIVATE, private only" }, { P1_KEY_PAIR, "P1_KEY_PAIR, private only (no TAG_4)" } };
    for (unsigned i = 0; i < 2 && !ovOk; i++) {
      uint32_t a = millis(); uint16_t w = epWrite(F[i].p1, k2, false); uint32_t b = millis();
      bool signs2 = (w == 0x9000) && epSignVerify(p2);
      bool rpub = false;
      if (signs2) { uint16_t rs = epReadPub(rp, &got); rpub = (rs == 0x9000) && got && !memcmp(rp, p2, 65); }
      Serial.printf("[ECPRIVONLY] 2.%u overwrite, %s: SW %04X (%lu ms), signs with key 2: %s, ReadObject gives key 2's public key: %s\n",
                    i + 1, F[i].nm, w, (unsigned long)(b - a), signs2 ? "YES" : "no", rpub ? "YES" : "no");
      if (signs2) { ovOk = true; ovPub = rpub; ovForm = F[i].nm; }
    }
  }
  mbedtls_platform_zeroize(k1, 32); mbedtls_platform_zeroize(k2, 32);
  if (se_object_exists(EP_OBJ)) tryDeleteObject_internal(EP_OBJ);
  if (pubOk && ovOk && ovPub)
    Serial.printf("[ECPRIVONLY] VERDICT: option B needs NO curve code on the G0 - the SE takes the private key alone (%s) and gives back the public key\n", ovForm);
  else if (pubOk && ovOk)
    Serial.println("[ECPRIVONLY] VERDICT: private-only works but the public key is not re-read after an overwrite - registration can still read it from a fresh create");
  else
    Serial.println("[ECPRIVONLY] VERDICT: the SE does not give back the public key from a private key alone - the G0 would need P-256 point multiplication for registration");
  Serial.println("========== [ECPRIVONLY end] ==========");
}

// Restorable passkeys bench check 2e (30 Oct 2026). 2d showed the SE keeps no
// public key for a private-only key, and registration must send one. Fix under
// test: the SE signs two FIXED hashes with the site key and the public key is
// recovered from (r, s, hash), which is public data. So: no P-256 code on the
// G0, and the ESP32 never holds k. Per cycle on the 2d slot (EP_OBJ):
//   write site key (P1_PRIVATE) -> sign h1, h2 -> recover -> compare with k*G
//   computed here (bench only) -> sign a login hash, verify with the RECOVERED
//   key -> write junk -> confirm the recovered key no longer verifies.
bool ecgate_recover_pair(const uint8_t h1[32], const uint8_t s1[64],
                         const uint8_t h2[32], const uint8_t s2[64], uint8_t pub65[65]);
static uint16_t epSignRaw(const uint8_t h[32], uint8_t sig64[64]) {
  uint8_t oid[4]; obj_be(EP_OBJ, oid);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256; dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = sendAPDU(apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n);
  if (sw != 0x9000) return sw;
  for (int i = 0; i < n - 2; i++) if (r[i] == 0x30) return der_ecdsa_to_raw(r + i, n - 2 - i, sig64) ? 0x9000 : 0x6F00;
  return 0x6F00;
}
void se_bench_ec_recover_probe() {
  Serial.println("========== [ECRECOVER] restorable passkeys bench check 2e ==========");
  if (g_pin_session_open) { Serial.println("[ECRECOVER] closing the open PIN session first (unlock again afterwards)"); se_pin_session_close(); }
  if (se_object_exists(EP_OBJ)) tryDeleteObject_internal(EP_OBJ);
  uint8_t k[32], p[65], q[65], h1[32], h2[32], hl[32], s1[64], s2[64], sl[64];
  mbedtls_sha256((const uint8_t*)"FAVILLA-PK-RECOVER-1", 20, h1, 0);
  mbedtls_sha256((const uint8_t*)"FAVILLA-PK-RECOVER-2", 20, h2, 0);
  if (!ecgate_make_p256(k, p)) { Serial.println("[ECRECOVER] could not make a test key"); return; }
  uint16_t sw = epWrite(0x40 /* P1_PRIVATE */, k, true);
  Serial.printf("[ECRECOVER] create slot, private key only (junk): SW %04X\n", sw);
  if (sw != 0x9000) { Serial.println("[ECRECOVER] VERDICT: could not create the slot"); return; }
  const int N = 20; int good = 0, loginOk = 0, junkOk = 0;
  uint32_t tW = 0, tS = 0, tR = 0, tL = 0, tJ = 0;
  for (int c = 0; c < N; c++) {
    if (!ecgate_make_p256(k, p)) break;
    uint32_t a = millis(); uint16_t w = epWrite(0x40, k, false); uint32_t b = millis();
    uint16_t x1 = epSignRaw(h1, s1), x2 = epSignRaw(h2, s2); uint32_t d = millis();
    bool rec = (w == 0x9000 && x1 == 0x9000 && x2 == 0x9000) && ecgate_recover_pair(h1, s1, h2, s2, q);
    uint32_t e = millis();
    bool match = rec && !memcmp(q, p, 65);
    esp_fill_random(hl, 32);
    uint32_t f = millis(); bool login = match && epSignRaw(hl, sl) == 0x9000 && ecgate_verify_p256(q, hl, sl); uint32_t g = millis();
    uint8_t junk[32], jp[65]; ecgate_make_p256(junk, jp);
    uint32_t i0 = millis(); uint16_t wj = epWrite(0x40, junk, false); uint32_t i1 = millis();
    mbedtls_platform_zeroize(junk, 32);
    esp_fill_random(hl, 32);
    bool gone = wj == 0x9000 && epSignRaw(hl, sl) == 0x9000 && !ecgate_verify_p256(q, hl, sl);
    tW += b - a; tS += d - b; tR += e - d; tL += g - f; tJ += i1 - i0;
    good += match; loginOk += login; junkOk += gone;
    if (c < 3 || !match || !login || !gone)
      Serial.printf("[ECRECOVER] cycle %2d: write %04X, sign %04X/%04X, recovered key = k*G: %s, login verifies with recovered key: %s, junk write %04X, site key gone: %s\n",
                    c + 1, w, x1, x2, match ? "YES" : "no", login ? "YES" : "no", wj, gone ? "YES" : "no");
  }
  mbedtls_platform_zeroize(k, 32);
  if (se_object_exists(EP_OBJ)) tryDeleteObject_internal(EP_OBJ);
  Serial.printf("[ECRECOVER] %d cycles: key recovered %d, login verified %d, cleared by junk %d\n", N, good, loginOk, junkOk);
  Serial.printf("[ECRECOVER] mean ms: write %lu, two signs %lu, recovery on ESP32 %lu, login sign+verify %lu, junk write %lu\n",
                (unsigned long)(tW / N), (unsigned long)(tS / N), (unsigned long)(tR / N), (unsigned long)(tL / N), (unsigned long)(tJ / N));
  if (good == N && loginOk == N && junkOk == N)
    Serial.println("[ECRECOVER] VERDICT: public key recovery works on silicon - option B needs no curve code on the G0");
  else
    Serial.println("[ECRECOVER] VERDICT: recovery did NOT hold every cycle - see the cycle lines");
  Serial.println("========== [ECRECOVER end] ==========");
}

// =============================================================================
// Passkey step 2 backend (30 Oct 2026, FIDO env). Bench door only: the
// throwaway PIN EG_PIN and latch EG_PCR from the probes stand in for the
// passkey PIN and the PASSKEY door, and the G0's mint is SIMULATED by an
// anonymous reset + extend of EG_PCR (MODEDOOR is a freeze item). Credential
// keys use exactly the check-1 policy: EG_PIN may SIGN only while EG_PCR == V.
// Callers hold the I2C lock (main.cpp wrappers). Each call closes any PIN
// session that was open, so keep the KEY on the lock screen while testing.
// =============================================================================
static const uint8_t FK_EXT_A[32] = { 'F','A','V','I','L','L','A','-','E','C','G','A','T','E','-','A' };
static const uint8_t FK_EXT_B[32] = { 'F','A','V','I','L','L','A','-','E','C','G','A','T','E','-','B' };
// Make sure the bench door objects exist and learn V (the "open" latch value).
static bool fkDoor(uint8_t V[32]) {
  if (g_pin_session_open) se_pin_session_close();
  if (!se_object_exists(EG_PCR)) {
    uint16_t sw = egPcrCreate();
    if (sw != 0x9000) { Serial.printf("[FIDO-SE] bench latch create SW %04X\n", sw); return false; }
  }
  if (!se_object_exists(EG_PIN)) {
    uint8_t pol[32]; size_t pp = 0;
    pp = buildPolicyEntry(pol, pp, sizeof(pol), EG_PIN, POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
    pp = buildPolicyEntry(pol, pp, sizeof(pol), 0x00000000UL, POLICY_OBJ_ALLOW_DELETE);
    if (!writeUserIDWithPolicy(EG_PIN, (const uint8_t*)EG_PIN_VAL, strlen(EG_PIN_VAL), 10, pol, pp)) { Serial.println("[FIDO-SE] bench PIN create failed"); return false; }
  }
  if (egPcrWrite(false, nullptr) != 0x9000 || egPcrWrite(false, FK_EXT_A) != 0x9000 || !egPcrRead(false, V)) { Serial.println("[FIDO-SE] could not learn V"); return false; }
  egPcrWrite(false, nullptr);   // back to base: nothing signs until a login mints V again
  return true;
}
static bool fkPub(uint32_t id, uint8_t pub65[65]) {
  uint8_t oid[4]; obj_be(id, oid);
  uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ, P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t r[128]; int n = sendAPDU(apdu, al, r, sizeof(r));
  if (egSW(r, n) != 0x9000) return false;
  for (int i = 0; i + 65 <= n - 2; i++) if (r[i] == 0x04) { memcpy(pub65, r + i, 65); return true; }
  return false;
}
// ECDSASign inside the open PIN session; returns the DER signature as the SE gave it.
static uint16_t fkSignDer(uint32_t id, const uint8_t h[32], uint8_t* der, size_t* derN) {
  *derN = 0;
  uint8_t oid[4]; obj_be(id, oid);
  uint8_t data[64]; size_t dl = 0;
  dl += put_tlv(data + dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256; dl += put_tlv(data + dl, TAG_2, &algo, 1);
  dl += put_tlv(data + dl, TAG_3, h, 32);
  uint8_t apdu[96]; size_t al = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t r[160]; int n = processSessionCmd(g_session_id, apdu, al, r, sizeof(r));
  uint16_t sw = egSW(r, n);
  if (sw != 0x9000) return sw;
  for (int i = 0; i + 2 <= n - 2; i++) if (r[i] == 0x30) {
    size_t L = (size_t)r[i + 1] + 2;
    if (r[i + 1] < 0x80 && i + (int)L <= n - 2 && L <= 72) { memcpy(der, r + i, L); *derN = L; return sw; }
    break;
  }
  return 0xFFFD;   // 9000 but no DER signature found
}

bool se_fido_keygen(uint32_t obj, uint8_t pub65[65], uint16_t* sw) {
  uint8_t V[32]; *sw = 0;
  if (!fkDoor(V)) return false;
  if (se_object_exists(obj)) tryDeleteObject_internal(obj);
  *sw = efKeyCreate(obj, V);
  if (*sw != 0x9000) return false;
  return fkPub(obj, pub65);
}
// One login: (simulated) mint -> open bench PIN session -> check latch == V ->
// sign -> burn -> close. Same sequence as bench check 4.
bool se_fido_sign(uint32_t obj, const uint8_t hash32[32], uint8_t* der, size_t* derN, uint16_t* sw) {
  uint8_t V[32], cur[32]; *sw = 0; *derN = 0;
  if (!fkDoor(V)) return false;
  egPcrWrite(false, nullptr); egPcrWrite(false, FK_EXT_A);                     // SIMULATED G0 mint
  if (!se_pin_session_open_obj(EG_PIN, EG_PIN_VAL)) { Serial.println("[FIDO-SE] bench PIN session did not open"); return false; }
  bool ok = egPcrRead(true, cur) && !memcmp(cur, V, 32);
  if (ok) { *sw = fkSignDer(obj, hash32, der, derN); ok = (*sw == 0x9000 && *derN > 0); }
  else Serial.println("[FIDO-SE] latch not at V before sign");
  egPcrWrite(true, FK_EXT_B);                                                  // burn
  se_pin_session_close();
  return ok;
}
void se_fido_delete(uint32_t obj) { if (se_object_exists(obj)) tryDeleteObject_internal(obj); }
int  se_fido_free() { return egFreePersistent(); }

#endif  // FAVILLA_BENCH_PROBES
