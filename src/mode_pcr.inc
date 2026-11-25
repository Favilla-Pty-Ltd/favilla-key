// =============================================================================
// mode_pcr.inc — two-door mode latch (NOSTR / BTC) — provisioning + selftest
// =============================================================================
// Included INSIDE namespace favilla in se_signer.cpp, AFTER the anonymous-
// namespace helpers (buildAPDU/sendAPDU/checkSW/buildPolicyEntry/appendTLV/
// processSessionCmd/g_session_id), because those have internal linkage.
//
// See TWO_DOOR_MODE_SPEC.md. This file provisions SE_OBJ_PCR_MODE and proves,
// on silicon, the four properties the design rests on:
//   P1  a PIN-gated persistent PCR can be created
//   P2  the daily PIN session can reset->extend it to NOSTR (atomic mode set)
//   P3  an ANONYMOUS (no-PIN) write/reset is REFUSED (the security crux — this
//       is the thing the bench probe could NOT show because its PCR had no
//       policy; here the policy is the real two-PIN gate)
//   P4  it survives soft reboot + power cycle already known from the probe;
//       the selftest re-reads AS-FOUND so you can eyeball persistence too
//
// mode_pcr_selftest(dailyPin) is the public entry point (declared in se_signer.h).
// It is a BENCH/bring-up routine — safe to leave compiled, call from a serial
// command or a temporary setup() hook. It does NOT gate any real asset yet;
// wiring the NOSTR/BTC require-PCR clauses onto the wrap keys is the next step,
// only after this proves green.
// =============================================================================

// ---- ids & constants -------------------------------------------------------
// SE_OBJ_PCR_MODE_FWD, MODE_CONST_NOSTR/BTC, g_mode_neutral/nostr/btc,
// g_mode_vals_valid and modeComputeValues() are all DEFINED in se_signer.cpp
// (near PCR_INITIAL), because the wrap-key provisioner and se_pin_destroy —
// which appear earlier in that file — need them. This file only adds the
// APDU-level create/extend/read/set functions on top of them.
static uint32_t& SE_OBJ_PCR_MODE = SE_OBJ_PCR_MODE_FWD;   // v5.1: per generation

// ---- create MODE_PCR with the two-PIN policy (spec §3.1) -------------------
// Persistent (INS_WRITE, NOT transient — transient is unusable on this SE051).
// Write+Delete granted to BOTH the daily and spend PIN objects; ALLOW_READ
// granted to the daily PIN so the ESP32 can read the value inside a session.
// NO anonymous entry — an unauthenticated command can neither extend nor reset.
static bool modePcrCreate() {
  uint8_t policy[64]; size_t pp = 0;
  // ── THE POWER-CYCLE WITNESS POLICY ──────────────────────────────────────
  // The PINs may EXTEND the latch (neutral -> NOSTR / neutral -> BTC) and READ
  // it. They may NOT reset it. Only SE_AUTH_OBJ_G0 may reset.
  //
  // Why this exact split is the whole mechanism: a PCR is extend-only
  // (new = SHA256(old || const)), so from NOSTR you cannot reach BTC by
  // extending — you would land on a third value that matches no gate. The ONLY
  // route from one door to the other is a reset to neutral first. Since reset
  // belongs solely to the G0, and the G0 performs it only once per PHYSICAL
  // boot (one-shot armed in its main(), NRST wired only to TC2030 so the ESP32
  // cannot reboot it), BTC mode is unreachable without a real power cycle.
  // Give a PIN the reset right and that guarantee is gone: a resident RCE in a
  // daily session could neutralise and re-open the BTC door without a cycle.
  // 19 Oct 2026 (review finding 3): NO PIN holds DELETE. DO NOT RE-ADD.
  // The old reasoning was "deleting the latch bricks both doors". It does not:
  // a deleted id can be re-created (anonymously, per the v5.1 Door-1 silicon
  // notes) with any INITIAL value, and the BTC value is public (it is in the
  // seed wrap key's policy and in nvs_sec "btcval"). Delete + re-create at
  // BTC = a latch that reads BTC with no S, i.e. the SE opens the seed key to
  // the spend PIN in a Nostr life. Same hole as the v5.1 Door-1 PCR.
  // Only SE_AUTH_OBJ_RECOVER deletes it now, inside the G0's WIPEALL, which
  // refuses to touch it while the seed wrap key still exists. Re-provisioning
  // a policy never needs a delete: every onboarding takes a new generation.
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_DAILY,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_SPEND,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE);
  // The G0: READ (to verify) + DELETE (= WritePCR reset) + WRITE (extend with
  // its secret S -> BTC, 16 Sep 2026). Nobody else resets, and nobody else can
  // reach BTC: the PINs' WRITE right cannot land on SHA256(NEUTRAL || S)
  // without S, which only the G0 holds.
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_G0,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE);
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_AUTH_OBJ_RECOVER, POLICY_OBJ_ALLOW_DELETE);   // v4.1: recovery wipe
#ifdef FAVILLA_PASSKEY_DOOR
  // 30 Oct 2026 (passkey door spec v1.0 s.5): the passkey PIN arms and burns
  // the latch exactly like the other two PINs. No reset, no delete. Its
  // credential keys sign only at V_3, which only the G0 can mint.
  pp = buildPolicyEntry(policy, pp, sizeof(policy), SE_OBJ_PIN_PASSKEY,
                        POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE);
#endif
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[128]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_POLICY, policy, pp);
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_2, PCR_INITIAL, 32);
  uint8_t apdu[192];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu),
                             0x80, INS_WRITE /* persistent */, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return checkSW(resp, n, "WritePCR(create MODE, persistent, 2-PIN policy)");
}

// ---- in-session extend / reset / read of MODE_PCR --------------------------
static bool modePcrExtendInSession(const uint8_t sid[8], const uint8_t ext[32]) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[48]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, ext, 32);
  uint8_t inner[64];
  size_t innerLen = buildAPDU(inner, sizeof(inner), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[32];
  int n = processSessionCmd(sid, inner, innerLen, resp, sizeof(resp));
  return checkSW(resp, n, "WritePCR(extend MODE)");
}
// Reset MODE_PCR to its initial value. A TAG_1-only WritePCR reset on a PCR
// that is ALREADY at initial is refused with 6985 (observed on this SE for
// Door-1 too) — that is NOT an error for us, it means "already at base". We
// return true on 9000 OR 6985, false on anything else. Callers always reset
// before extend so the extend chains from a known base (a freshly-CREATED PCR
// reads neutral but extends from a different internal base than a RESET one —
// this is the fix for that).
static bool modePcrResetInSession(const uint8_t sid[8]) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[8]; size_t p = appendTLV(payload, 0, sizeof(payload), TAG_1, id, 4);
  uint8_t inner[24];
  size_t innerLen = buildAPDU(inner, sizeof(inner), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[32];
  int n = processSessionCmd(sid, inner, innerLen, resp, sizeof(resp));
  uint16_t sw = (n >= 2) ? (uint16_t)((resp[n-2] << 8) | resp[n-1]) : 0xFFFF;
  if (sw == 0x9000 || sw == 0x6985) return true;   // 6985 = already at initial
  Serial.printf("[MODEPCR] WritePCR(reset MODE) SW %04X\n", sw);
  return false;
}
static bool modePcrReadInSession(const uint8_t sid[8], uint8_t out[32]) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[8]; size_t p = appendTLV(payload, 0, sizeof(payload), TAG_1, id, 4);
  uint8_t inner[24];
  size_t innerLen = buildAPDU(inner, sizeof(inner), 0x80, INS_READ, P1_DEFAULT, P2_DEFAULT, payload, p, true);
  uint8_t resp[96];
  int n = processSessionCmd(sid, inner, innerLen, resp, sizeof(resp));
  if (!checkSW(resp, n, "ReadObject(MODE)")) return false;
  size_t bodyLen = (size_t)n - 2, off = 0;
  if (bodyLen < 2 || resp[0] != TAG_1) return false;
  int len = parseTLVLength(resp, bodyLen, &off);
  if (len != 32 || off + 32 > bodyLen) return false;
  memcpy(out, resp + off, 32);
  return true;
}

// Atomic "set mode" inside an OPEN PIN session (spec §3.2): read; reset to
// NEUTRAL only if not already there (a TAG_1-only reset on an at-initial PCR
// is refused 6985 — same silicon quirk as Door-1); then extend to target.
// The caller must have a matching PIN session open (daily->NOSTR, spend->BTC).
// Set the mode by EXTENDING from neutral. PIN sessions no longer hold the reset
// right (see modePcrCreate), so this can only succeed when the latch is already
// at the canonical neutral base — i.e. after the G0 has done its once-per-
// physical-boot reset. Extending from a non-neutral value would land on a third
// value matching no gate, so we refuse rather than silently wedge the latch.
static bool modeSetInSession(const uint8_t sid[8], const uint8_t target[32]) {
  uint8_t cur[32];
  if (!modePcrReadInSession(sid, cur)) return false;
  if (memcmp(cur, g_mode_neutral, 32) != 0) {
    const char *w = !memcmp(cur, g_mode_nostr, 32) ? "NOSTR"
                  : !memcmp(cur, g_mode_btc,   32) ? "BTC" : "non-canonical";
    Serial.printf("[MODEPCR] refuse set: latch is %s, not neutral — needs a real power cycle\n", w);
    return false;
  }
  return modePcrExtendInSession(sid, target);
}

// ---- ANONYMOUS (no-session) write attempt — for the P3 security test -------
// Tries a plain WritePCR(reset) with NO session wrapper. On a correctly-policed
// MODE_PCR this MUST fail (6985). If it ever returns 9000, the policy is wrong.
static uint16_t modePcrAnonResetSW() {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[8]; size_t p = appendTLV(payload, 0, sizeof(payload), TAG_1, id, 4);
  uint8_t apdu[24];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return (n >= 2) ? (uint16_t)((resp[n-2] << 8) | resp[n-1]) : 0xFFFF;
}
static uint16_t modePcrAnonExtendSW(const uint8_t ext[32]) {
  uint8_t id[4] = { (uint8_t)(SE_OBJ_PCR_MODE >> 24), (uint8_t)(SE_OBJ_PCR_MODE >> 16),
                    (uint8_t)(SE_OBJ_PCR_MODE >> 8),  (uint8_t) SE_OBJ_PCR_MODE };
  uint8_t payload[48]; size_t p = 0;
  p = appendTLV(payload, p, sizeof(payload), TAG_1, id, 4);
  p = appendTLV(payload, p, sizeof(payload), TAG_3, ext, 32);
  uint8_t apdu[64];
  size_t apduLen = buildAPDU(apdu, sizeof(apdu), 0x80, INS_WRITE, P1_PCR, P2_DEFAULT, payload, p, false);
  uint8_t resp[16];
  int n = sendAPDU(apdu, apduLen, resp, sizeof(resp));
  return (n >= 2) ? (uint16_t)((resp[n-2] << 8) | resp[n-1]) : 0xFFFF;
}

// Run the in-session mode set on an ALREADY-OPEN daily session (g_session_id
// live). Use this from the post-unlock hook where the session is already up —
// it must NOT open/close its own session. Sets MODE -> NOSTR and verifies.
bool mode_pcr_set_nostr_in_open_session() {
  if (!g_mode_vals_valid) modeComputeValues();
  if (!se_object_exists(SE_OBJ_PCR_MODE)) {
    if (!modePcrCreate()) { Serial.println("[MODEPCR] set-NOSTR: create failed"); return false; }
  }
  uint8_t cur[32];
  if (!modePcrReadInSession(g_session_id, cur)) {
    Serial.println("[MODEPCR] set-NOSTR: cannot read latch");
    return false;
  }
  // Already in the NOSTR door for this power-on life? Nothing to do. Extending
  // again would chain SHA256(NOSTR || const) and land on a value matching NO
  // gate, wedging the latch until the next battery cycle — which is exactly the
  // bug seen on silicon (afterExt 35EE016F..., pubkey fetch then failed).
  if (memcmp(cur, g_mode_nostr, 32) == 0) {
    Serial.println("[MODEPCR] already NOSTR for this power cycle - no change");
    return true;
  }
  // Only a latch at the canonical NEUTRAL may be extended. Neutral comes ONLY
  // from the G0's once-per-physical-boot reset; PIN sessions cannot reset (6986
  // by policy). Anything else means the door is already chosen (or the latch is
  // wedged) and the correct answer is to refuse, not to extend blindly.
  if (memcmp(cur, g_mode_neutral, 32) != 0) {
    const char *w = !memcmp(cur, g_mode_btc, 32) ? "BTC" : "non-canonical (wedged)";
    Serial.printf("[MODEPCR] set-NOSTR refused: latch is %s, not neutral - power cycle required\n", w);
    return false;
  }
  if (!modePcrExtendInSession(g_session_id, MODE_CONST_NOSTR)) {
    Serial.println("[MODEPCR] set-NOSTR: extend failed");
    return false;
  }
  uint8_t v[32];
  bool ok = modePcrReadInSession(g_session_id, v) && !memcmp(v, g_mode_nostr, 32);
  Serial.printf("[MODEPCR] mode -> NOSTR: %s\n", ok ? "ok" : "MISMATCH after extend");
  return ok;
}

// (modePcrEnsureAndSet removed 16 Sep 2026: its only remaining caller was the
// BTC setter, which no longer exists — the G0 extends to BTC, not the ESP32.)

// Create MODE_PCR if absent, WITHOUT setting any mode. Onboarding calls this
// before provisioning the wrap keys, because their policies reference the PCR
// by id and the provisioner refuses if the object does not exist yet. Creating
// it leaves the latch at its initial value; only the G0 can produce the
// canonical NEUTRAL base, and only a PIN can extend from there.
bool mode_pcr_ensure_exists() {
  if (!g_mode_vals_valid) modeComputeValues();
  if (se_object_exists(SE_OBJ_PCR_MODE)) return true;
  bool ok = modePcrCreate();
  Serial.printf("[MODEPCR] ensure exists: %s\n", ok ? "created" : "CREATE FAILED");
  return ok;
}
static const uint8_t MODE_CONST_SPENT[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','S','P','E','N','T',
  0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
// ── BTC door (16 Sep 2026): the ESP32 no longer extends to BTC ─────────────
// It cannot: BTC = SHA256(NEUTRAL || S) and S lives only in the G0. The door
// sequence is now: open spend session -> mode_pcr_btc_state (must be NEUTRAL,
// or already BTC from a soft reboot inside this BTC life) -> close session ->
// g0_mode_btc() -> reopen spend session -> mode_pcr_verify_btc -> unwrap.
//   returns 0 = latch NEUTRAL, SPENT or a LEFTOVER BTC (ask the G0 to put it
//               at BTC; a found BTC is never trusted — the G0 re-mints it)
//          -1 = anything else (NOSTR / non-canonical: power cycle)
// v2.1: no unwrap without a G0 extend immediately before it. A BTC found
// lying in the latch (crash inside the unwrap window, or anything else) is
// treated exactly like SPENT: the G0 resets it and extends again.
// v2 (16 Sep 2026): BTC is consumed by every unwrap (burned to SPENT at once),
// so SPENT is the NORMAL state between signatures and the G0 re-extends from
// it. NOSTR stays a hard refusal — the G0 will not reset from NOSTR either.
// ── v3 ARM (16 Sep 2026) ────────────────────────────────────────────────────
// Before the G0 will mint BTC it wants proof that the SE verified a PIN since
// the last burn: the latch must read SHA256(x || "FAVILLA-MODE-ARM") with x in
// {NEUTRAL, SPENT, BTC-leftover}. That extend is a PIN-session WRITE, done here
// on the open spend session, verified by readback. The G0 then resets and
// extends S itself. An RCE that skips the spend PIN cannot arm; an RCE that
// has the PIN was always able to sign while the user typed it.
static const uint8_t MODE_CONST_ARM[32] = {
  'F','A','V','I','L','L','A','-','M','O','D','E','-','A','R','M',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
bool mode_pcr_arm_in_open_session() {
  if (!g_mode_vals_valid) modeComputeValues();
  uint8_t cur[32], expect[32], v[32];
  if (!modePcrReadInSession(g_session_id, cur)) { Serial.println("[MODEPCR] arm: cannot read latch"); return false; }
  modeExt(cur, MODE_CONST_ARM, expect);
  if (!modePcrExtendInSession(g_session_id, MODE_CONST_ARM)) { Serial.println("[MODEPCR] arm: extend failed"); return false; }
  bool ok = modePcrReadInSession(g_session_id, v) && memcmp(v, expect, 32) == 0;
  Serial.printf("[MODEPCR] latch ARMed in the open PIN session: %s\n", ok ? "ok" : "READBACK MISMATCH");
  return ok;
}
// v3: also recognise ARMed values when reading the state (a soft reset between
// arm and mint leaves ARM_x in the latch; the G0 still accepts it).
static bool modeIsArmedOf(const uint8_t cur[32], const uint8_t base[32]) {
  uint8_t a[32]; modeExt(base, MODE_CONST_ARM, a); return memcmp(cur, a, 32) == 0;
}

int mode_pcr_btc_state_in_open_session() {
  if (!g_mode_vals_valid) modeComputeValues();
  if (!se_object_exists(SE_OBJ_PCR_MODE)) { Serial.println("[MODEPCR] btc state: no latch object"); return -1; }
  uint8_t cur[32], spent[32];
  if (!modePcrReadInSession(g_session_id, cur)) { Serial.println("[MODEPCR] btc state: cannot read latch"); return -1; }
  modeExt(g_mode_btc, MODE_CONST_SPENT, spent);
  if (memcmp(cur, g_mode_btc, 32) == 0)     { Serial.println("[MODEPCR] latch reads BTC (leftover) - NOT trusted, asking the G0 to re-mint"); return 0; }
  if (memcmp(cur, g_mode_neutral, 32) == 0) { Serial.println("[MODEPCR] latch NEUTRAL - asking the G0"); return 0; }
  if (memcmp(cur, spent, 32) == 0)          { Serial.println("[MODEPCR] latch SPENT - asking the G0 to re-arm"); return 0; }
  if (modeIsArmedOf(cur, g_mode_neutral) || modeIsArmedOf(cur, spent) || modeIsArmedOf(cur, g_mode_btc)) {
    Serial.println("[MODEPCR] latch already ARMed - asking the G0"); return 3; }
  Serial.printf("[MODEPCR] BTC refused: latch is %s - power cycle required\n",
                !memcmp(cur, g_mode_nostr, 32) ? "NOSTR" : "non-canonical");
  return -1;
}
bool mode_pcr_verify_btc_in_open_session() {
  if (!g_mode_vals_valid) modeComputeValues();
  uint8_t cur[32];
  if (!modePcrReadInSession(g_session_id, cur)) { Serial.println("[MODEPCR] verify BTC: cannot read latch"); return false; }
  bool ok = memcmp(cur, g_mode_btc, 32) == 0;
  Serial.printf("[MODEPCR] mode -> BTC (by G0): %s\n", ok ? "ok" : "MISMATCH - G0 secret does not match the provisioned value");
  return ok;
}

// ── Post-spend burn ──────────────────────────────────────────────────────────
// Josh's stated BTC granularity is ONE signing SESSION per power cycle. The
// extend-only latch on its own gives "one DOOR per power cycle": once BTC, it
// stays BTC until the battery is pulled, so a second ceremony in the same
// power-on life would open the seed again (seen on silicon 11 Sep 2026:
// "already BTC for this power cycle - no change", then a second signed tx).
// Closing that is one more extend: BTC || "FAVILLA-MODE-SPENT" lands on a
// value that matches NO key gate, so the seed wrap key's DEC clause can never
// be satisfied again this power cycle. Only the G0's physical-boot reset can
// bring the latch back to neutral. Call it on the live spend session AFTER the
// seed has been unwrapped (and zeroised), before the session closes.
bool mode_pcr_burn_after_spend_in_open_session() {
  if (!g_mode_vals_valid) modeComputeValues();
  uint8_t cur[32];
  if (!modePcrReadInSession(g_session_id, cur)) { Serial.println("[MODEPCR] burn: cannot read latch"); return false; }
  if (memcmp(cur, g_mode_btc, 32) != 0) {
    // Not BTC: either already burned (fine) or never opened (nothing to do).
    Serial.println("[MODEPCR] burn: latch not BTC - nothing to burn");
    return true;
  }
  if (!modePcrExtendInSession(g_session_id, MODE_CONST_SPENT)) { Serial.println("[MODEPCR] burn: extend failed"); return false; }
  uint8_t v[32];
  bool ok = modePcrReadInSession(g_session_id, v)
         && memcmp(v, g_mode_btc, 32) != 0 && memcmp(v, g_mode_nostr, 32) != 0
         && memcmp(v, g_mode_neutral, 32) != 0;
  Serial.printf("[MODEPCR] BTC door burned for this power cycle: %s\n", ok ? "ok" : "READBACK STILL MATCHES A GATE");
  return ok;
}
// (the NOSTR variant below is kept with its diagnostic dump for the bench test)

// Read the current mode from MODE_PCR using an already-open PIN session.
// 0 = neutral/unknown/unreadable, 1 = NOSTR, 2 = BTC. For the header indicator
// after unlock. READ is granted to both PIN objects, so any open session works.
int mode_pcr_current_in_open_session() {
  if (!g_mode_vals_valid) modeComputeValues();
  if (!se_object_exists(SE_OBJ_PCR_MODE)) return 0;
  uint8_t v[32];
  if (!modePcrReadInSession(g_session_id, v)) return 0;
  if (memcmp(v, g_mode_nostr, 32) == 0) return 1;
  if (memcmp(v, g_mode_btc,   32) == 0) return 2;
  return 0;
}

// ---- PIN-GATE PROBE: does REQUIRE_PCR_VALUE gate a PIN at UNLOCK time? ------
// THE question the whole two-door design hinges on. Spec (AN12413 p29/p114) says
// POLICY_OBJ_REQUIRE_PCR_VALUE is allowed on authentication objects and that
// "any access to the object requires a PCR value" — but we have been burned by
// spec-vs-silicon twice (transient objects refused; fresh-PCR extend base). So
// prove it here.
//
// Method: with MODE_PCR at a KNOWN value (call this right after a daily unlock,
// so MODE == NOSTR), create two throwaway PIN objects with the same PIN value:
//   0x70000090  gated REQUIRE_PCR_VALUE(MODE_PCR == BTC)   -> should be REFUSED
//   0x70000091  gated REQUIRE_PCR_VALUE(MODE_PCR == NOSTR) -> should SUCCEED
// Then try to open a session as each and print the result.
//
//   refused / succeed   => the gate works AT UNLOCK. Build the real design:
//                          spend PIN gated on MODE==NEUTRAL, SE refuses the
//                          BTC unlock unless freshly power-cycled.
//   succeed / succeed   => it does NOT gate the unlock; keep the key gate
//                          (seed key requires MODE==BTC), which already works.
//
// Cleans up both test objects afterwards. Does not touch any real object.
// NOTE: this closes the caller's session (opening a test PIN replaces it), so
// call it at a point where that is acceptable — the hook closes and the caller
// should treat its session as gone.
void mode_pcr_pingate_probe() {
  if (!g_mode_vals_valid) modeComputeValues();
  static constexpr uint32_t TEST_PIN_BTC   = 0x70000090u;
  static constexpr uint32_t TEST_PIN_NOSTR = 0x70000091u;
  static const char *TESTPIN = "424242";

  Serial.println("========== [PINGATE probe] ==========");

  // What does MODE_PCR actually read right now? (needs an open session; the
  // caller's daily session is still live at entry.)
  {
    uint8_t v[32];
    if (modePcrReadInSession(g_session_id, v)) {
      const char* w = !memcmp(v,g_mode_nostr,32) ? "NOSTR"
                    : !memcmp(v,g_mode_btc,32)   ? "BTC"
                    : !memcmp(v,g_mode_neutral,32)?"NEUTRAL":"OTHER";
      Serial.printf("[PINGATE] MODE_PCR currently = %s\n", w);
    } else {
      Serial.println("[PINGATE] could not read MODE_PCR (no session?) — run me right after a daily unlock");
    }
  }

  // Build the two gated PIN objects. Policy: self R/W/D (so we can delete them
  // again) PLUS an anonymous DELETE (belt and braces for cleanup), and the
  // REQUIRE_PCR_VALUE extension carrying MODE_PCR + the target value.
  auto makeGatedPin = [&](uint32_t oid, const uint8_t want[32]) -> bool {
    tryDeleteObject_internal(oid);
    uint8_t policy[96]; size_t pp = 0;
    // entry 1: self, all rights, gated on MODE_PCR == want
    pp = buildPolicyEntryPcr(policy, pp, sizeof(policy), oid,
                             POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_WRITE | POLICY_OBJ_ALLOW_DELETE,
                             SE_OBJ_PCR_MODE, want);
    // entry 2: anonymous DELETE so cleanup always works even if the gate blocks us
    pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL, POLICY_OBJ_ALLOW_DELETE);
    bool ok = writeUserIDWithPolicy(oid, (const uint8_t*)TESTPIN, strlen(TESTPIN),
                                    10, policy, pp);
    Serial.printf("[PINGATE] create %08lX gated: %s\n", (unsigned long)oid, ok?"OK":"FAILED");
    return ok;
  };

  bool cb = makeGatedPin(TEST_PIN_BTC,   g_mode_btc);
  bool cn = makeGatedPin(TEST_PIN_NOSTR, g_mode_nostr);

  // Now the actual test: try to OPEN a session as each.
  if (cb) {
    bool opened = se_pin_session_open_obj(TEST_PIN_BTC, TESTPIN);
    Serial.printf("[PINGATE] open PIN gated on MODE==BTC   (MODE is NOSTR): %s  <-- want REFUSED\n",
                  opened ? "OPENED (gate does NOT block unlock)" : "refused");
    if (opened) se_pin_session_close();
  }
  if (cn) {
    bool opened = se_pin_session_open_obj(TEST_PIN_NOSTR, TESTPIN);
    Serial.printf("[PINGATE] open PIN gated on MODE==NOSTR (MODE is NOSTR): %s  <-- want OPENED\n",
                  opened ? "opened" : "REFUSED (gate too strict / other problem)");
    if (opened) se_pin_session_close();
  }

  // Cleanup (anonymous delete entry makes this reliable).
  tryDeleteObject_internal(TEST_PIN_BTC);
  tryDeleteObject_internal(TEST_PIN_NOSTR);
  Serial.printf("[PINGATE] cleanup: btc gone=%d nostr gone=%d\n",
                !se_object_exists(TEST_PIN_BTC), !se_object_exists(TEST_PIN_NOSTR));
  Serial.println("[PINGATE] VERDICT: refused+opened => gate works AT UNLOCK (build the real design)");
  Serial.println("[PINGATE]          opened+opened => no unlock gate; keep the key gate");
  Serial.println("========== [PINGATE end] ==========");
}

// ---- public selftest -------------------------------------------------------
// dailyPin: the device's daily PIN, needed to open the gated session for P2.
// Prints [MODEPCR] lines. Returns true only if the security-critical checks
// (create OK, in-session set OK, anon REFUSED) all pass.
bool mode_pcr_selftest(const char *dailyPin) {
  if (!g_mode_vals_valid) modeComputeValues();
  Serial.println("========== [MODEPCR selftest] ==========");
  bool allGood = true;

  // --- P1: MODE_PCR must exist. Do NOT create it here on a virgin chip: its
  // policy references BOTH PIN objects, so it belongs to onboarding, which
  // creates it via modePcrEnsureAndSet AFTER the PINs exist. Creating it at
  // boot before the PINs would leave a policy pointing at absent objects.
  bool existed = se_object_exists(SE_OBJ_PCR_MODE);
  if (!existed) {
    bool pinsExist = se_object_exists(SE_OBJ_PIN_DAILY) && se_object_exists(SE_OBJ_PIN_SPEND);
    if (!pinsExist) {
      Serial.println("[MODEPCR] P1: absent on un-onboarded chip (expected; onboarding creates it)");
      Serial.println("========== [MODEPCR end] ==========");
      return true;   // nothing to test yet; not a failure
    }
    bool c = modePcrCreate();
    Serial.printf("[MODEPCR] P1 create: %s\n", c ? "OK" : "FAILED");
    allGood &= c;
  } else {
    Serial.println("[MODEPCR] P1: exists");
  }

  // --- P3a: ANONYMOUS reset/extend must be REFUSED (security crux) ---
  // Do this BEFORE opening a session so it's a truly anonymous command.
  uint16_t swR = modePcrAnonResetSW();
  uint16_t swE = modePcrAnonExtendSW(MODE_CONST_BTC);
  bool anonRefused = (swR != 0x9000) && (swE != 0x9000);
  Serial.printf("[MODEPCR] P3 anon reset SW %04X, anon extend SW %04X -> %s\n",
                swR, swE, anonRefused ? "REFUSED (GOOD: 2-PIN policy holds)"
                                      : "ACCEPTED (BAD: policy wrong, RCE could move mode!)");
  allGood &= anonRefused;

  // --- P2: open daily session, set mode to NOSTR, read back ---
  if (!dailyPin || !*dailyPin) {
    Serial.println("[MODEPCR] P2 skipped: no daily PIN supplied");
  } else if (!se_pin_session_open_obj(SE_OBJ_PIN_DAILY, dailyPin)) {
    Serial.println("[MODEPCR] P2 FAILED: could not open daily PIN session");
    allGood = false;
  } else {
    bool setOk = modeSetInSession(g_session_id, g_mode_nostr);
    uint8_t v[32]; bool rd = modePcrReadInSession(g_session_id, v);
    bool isNostr = rd && (memcmp(v, g_mode_nostr, 32) == 0);
    Serial.printf("[MODEPCR] P2 daily-session set NOSTR: setOk=%d readOk=%d value=%s\n",
                  setOk, rd, isNostr ? "NOSTR (ok)" :
                            (rd && !memcmp(v, g_mode_neutral, 32)) ? "NEUTRAL" :
                            (rd && !memcmp(v, g_mode_btc, 32))     ? "BTC" : "OTHER");
    allGood &= (setOk && isNostr);
    se_pin_session_close();
  }

  Serial.printf("[MODEPCR] RESULT: %s\n", allGood ? "PASS (create + in-session set + anon refused)"
                                                  : "FAIL (see lines above)");
  Serial.println("========== [MODEPCR end] ==========");
  return allGood;
}
