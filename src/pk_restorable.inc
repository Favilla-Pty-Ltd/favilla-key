// =============================================================================
// pk_restorable.inc — restorable passkeys, SE side (30 Oct 2026, spec v0.8)
// =============================================================================
// SE_OBJ_PK_MASTER (0x20000038 + gen), binary 48 B: S_pk sealed by the G0's
//   PKMASTER (K_G0, its own IV label; onboarding seal window only) and then
//   wrapped with the daily key by provisionScalarInto, the same policy as the
//   Nostr scalar: G0 READ only while Door 1 is unlocked, daily PIN DELETE,
//   RECOVER DELETE.
// SE_OBJ_PK_SCRATCH (0x20000037 + gen) is NOT made here. The G0 deletes and
//   creates it itself, inside its session, with its own policy (G0 SIGN|WRITE|
//   DELETE, RECOVER DELETE, nothing for this chip), on its first PKSIGN or
//   PKSCRUB of a power-on life. That way a compromised ESP32 cannot plant an
//   object it could sign with.
// The G0's WIPEALL deletes both. Included INSIDE namespace favilla in
// se_signer.cpp. Callers hold the I2C lock.
// =============================================================================
#ifdef FAVILLA_PK_RESTORABLE

bool se_pkr_ready() {
  return g_ready && se_object_exists(SE_OBJ_PK_MASTER);
}

// Store the G0-sealed master (32 B from g0_pk_master). Needs the daily PIN
// session (onboarding has it open), like the Nostr scalar.
bool se_pkr_provision(const uint8_t sealed32[32]) {
  if (!g_ready) return false;
  if (!g_pin_session_open || g_session_obj != SE_OBJ_PIN_DAILY) {
    Serial.println("[PKR] provision denied: no daily PIN session");
    return false;
  }
  return provisionScalarInto(SE_OBJ_PK_MASTER, sealed32, "pkr master (G0-sealed)");
}

#endif  // FAVILLA_PK_RESTORABLE
