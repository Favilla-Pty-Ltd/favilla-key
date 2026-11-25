// ─────────────────────────────────────────────────────────────────────────────
// se_attest.inc — SE051-native device attestation (Favilla KEY)
//
// COMPILED AS PART OF se_signer.cpp:  #include "se_attest.inc" near the end of
// se_signer.cpp, INSIDE `namespace favilla`, AFTER buildAPDU/sendAPDU/checkSW/
// buildPolicyEntry are defined. Those helpers live in se_signer.cpp's ANONYMOUS
// namespace (internal linkage) so they are NOT reachable from a separate .cpp —
// that is why this is an include, not its own translation unit.
//
// All the common SE05x constants (INS_*, P1_DEFAULT, P2_DEFAULT, TAG_1/2/3,
// TAG_POLICY, POLICY_OBJ_ALLOW_READ) are already in scope from se_signer.cpp;
// we define ONLY the EC-specific values it lacks.
//
// APDU values confirmed vs AN12543 Rev 4.5: WriteECKey (Table 115, on-chip
// keygen = P1_KEY_PAIR|P1_EC, key TLVs omitted), ECDSASign (Table 175),
// ReadObject (Table 127), SIG_ECDSA_SHA_256=0x21 (Table 34), NIST_P256=0x03,
// policy SIGN|READ|GEN with DELETE/WRITE omitted = permanent.
//
// Public entry points (declared extern in main.cpp for the bench command):
//   bool se_attest_exists();
//   bool se_attest_provision();          // manufacture: on-chip keygen (once)
//   bool se_attest_pubkey(uint8_t[33]);
//   bool se_attest_sign(const uint8_t[32], uint8_t[64]);
//   void se_attest_selftest();
// ─────────────────────────────────────────────────────────────────────────────

// EC-specific constants NOT already defined in se_signer.cpp:
static const uint8_t CLA_SE             = 0x80;
static const uint8_t P1_EC             = 0x01;  // AN12543 P1_EC
static const uint8_t P1_KEY_PAIR       = 0x60;  // AN12543 P1_KEY_PAIR
static const uint8_t P1_SIGNATURE      = 0x0C;  // AN12543 P1_SIGNATURE
static const uint8_t P2_SIGN           = 0x09;  // AN12543 P2_SIGN
static const uint8_t SIG_ECDSA_SHA_256 = 0x21;  // AN12543 Table 34 (PLAIN unsupported)
static const uint8_t ECCURVE_NIST_P256 = 0x03;  // AN12543 curve id
static const uint32_t POLICY_OBJ_ALLOW_SIGN = 0x10000000UL;  // AN12543
static const uint32_t POLICY_OBJ_ALLOW_GEN  = 0x00080000UL;  // AN12543 (on-chip keygen)

// forward decl (defined below se_attest_sign, used by it)
bool der_ecdsa_to_raw(const uint8_t* der, int len, uint8_t out64[64]);

static size_t put_tlv(uint8_t* p, uint8_t tag, const uint8_t* v, size_t n){
  p[0]=tag; p[1]=(uint8_t)n; memcpy(p+2, v, n); return 2+n;
}
static void obj_be(uint32_t id, uint8_t out[4]){
  out[0]=(id>>24)&0xff; out[1]=(id>>16)&0xff; out[2]=(id>>8)&0xff; out[3]=id&0xff;
}

// ── se_attest_exists ─────────────────────────────────────────────────────────
bool se_attest_exists(){
  return se_object_exists(SE_OBJ_ATTEST_KEY);
}

// ── se_attest_provision (MANUFACTURE ONLY) ───────────────────────────────────
// AN12543 §4.7.1.1 WriteECKey. On-chip keygen: P1 = P1_KEY_PAIR | P1_EC, and
// TAG_3/TAG_4 (priv/pub values) are OMITTED so the SE generates the pair
// internally. Object policy grants SIGN + READ(public) + GEN, and OMITS DELETE
// and WRITE so the key is permanent (survives factory reset) and cannot be
// overwritten. Idempotent guard: refuse if the object already exists.
bool se_attest_provision(){
  if(se_attest_exists()){
    Serial.println("[ATTEST] provision: key already present — refusing to overwrite");
    return false;
  }
  // Policy: SIGN | READ | GEN to the no-auth object (0x00000000); DELETE/WRITE
  // omitted → permanent. GEN is required by WriteECKey for on-chip generation.
  uint8_t policy[32]; size_t pp = 0;
  uint32_t ar = POLICY_OBJ_ALLOW_SIGN | POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_GEN;
  pp = buildPolicyEntry(policy, pp, sizeof(policy), 0x00000000UL, ar);

  uint8_t data[80]; size_t dl=0;
  uint8_t oid[4]; obj_be(SE_OBJ_ATTEST_KEY, oid);
  dl += put_tlv(data+dl, TAG_POLICY, policy, pp);        // TAG_POLICY = 0x11
  dl += put_tlv(data+dl, TAG_1,      oid, 4);            // TAG_1 object id (AN12543: min policy ALLOW_GEN)
  uint8_t curve = ECCURVE_NIST_P256;
  dl += put_tlv(data+dl, TAG_2,      &curve, 1);         // TAG_2 = 1-byte curve id (AN12543 Table 115)
  // TAG_3 (priv) and TAG_4 (pub) DELIBERATELY OMITTED → on-chip generation.

  uint8_t apdu[128];
  size_t alen = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_WRITE,
                          (uint8_t)(P1_KEY_PAIR | P1_EC), P2_DEFAULT, data, dl, false);
  uint8_t resp[32];
  int n = sendAPDU(apdu, alen, resp, sizeof(resp));
  if(!checkSW(resp, n, "attest_provision")) return false;
  Serial.println("[ATTEST] provisioned P-256 attestation key (on-chip, permanent: no DELETE/WRITE)");
  return true;
}

// ── se_attest_pubkey ─────────────────────────────────────────────────────────
// Reads the public key and returns it COMPRESSED (33 bytes: 0x02/0x03 || X).
// The SE typically returns an uncompressed point (0x04 || X || Y); we compress
// on host (compression is public-key math, no secret involved).
bool se_attest_pubkey(uint8_t pk33[33]){
  uint8_t oid[4]; obj_be(SE_OBJ_ATTEST_KEY, oid);
  uint8_t data[8]; size_t dl = put_tlv(data, TAG_1, oid, 4);
  uint8_t apdu[32];
  // AN12543 §4.7.3.1 ReadObject: INS_READ, P1_DEFAULT, P2_DEFAULT, TAG_1=object
  // id. For a key pair the SE returns ONLY the public key (private never leaves
  // — exactly our requirement).
  size_t alen = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_READ,
                          P1_DEFAULT, P2_DEFAULT, data, dl, true);
  uint8_t resp[128];
  int n = sendAPDU(apdu, alen, resp, sizeof(resp));
  if(!checkSW(resp, n, "attest_pubkey")) return false;

  // Expect a TLV wrapping an uncompressed EC point (0x04 || X32 || Y32 = 65B).
  // Find the 0x04 lead byte of a 65-byte point within the response.
  int payload = n - 2; // strip SW
  const uint8_t* q = resp;
  // Skip a leading TLV tag/len if present; locate the 65-byte 0x04 point.
  for(int i=0; i + 65 <= payload; i++){
    if(resp[i]==0x04){
      q = resp + i;
      const uint8_t* X = q + 1;
      const uint8_t* Y = q + 33;
      pk33[0] = (Y[31] & 1) ? 0x03 : 0x02;   // parity of Y → compressed prefix
      memcpy(pk33+1, X, 32);
      return true;
    }
  }
  Serial.println("[ATTEST] pubkey: could not locate EC point in response");
  return false;
}

// ── se_attest_sign ───────────────────────────────────────────────────────────
// In-SE ECDSA over a 32-byte hash. The private scalar never leaves the chip.
// Returns the signature as raw r||s (64 bytes) to match the reference oracle
// (which does raw<->DER conversion). The SE typically returns DER; we convert.
bool se_attest_sign(const uint8_t hash32[32], uint8_t sig64[64]){
  if(!se_attest_exists()){
    Serial.println("[ATTEST] sign: no attestation key");
    return false;
  }
  uint8_t oid[4]; obj_be(SE_OBJ_ATTEST_KEY, oid);
  uint8_t data[64]; size_t dl=0;
  // AN12543 §4.10.1.1 ECDSASign C-APDU (Table 175):
  //   TAG_1 = key object id, TAG_2 = 1-byte ECSignatureAlgo, TAG_3 = hashed input.
  //   The host MUST hash first (SIG_ECDSA_PLAIN is unsupported); we pass the
  //   caller's 32-byte SHA-256 digest with algo SIG_ECDSA_SHA_256.
  dl += put_tlv(data+dl, TAG_1, oid, 4);
  uint8_t algo = SIG_ECDSA_SHA_256;
  dl += put_tlv(data+dl, TAG_2, &algo, 1);
  dl += put_tlv(data+dl, TAG_3, hash32, 32);

  uint8_t apdu[96];
  size_t alen = buildAPDU(apdu, sizeof(apdu), CLA_SE, INS_CRYPTO,
                          P1_SIGNATURE, P2_SIGN, data, dl, true);
  uint8_t resp[128];
  int n = sendAPDU(apdu, alen, resp, sizeof(resp));
  if(!checkSW(resp, n, "attest_sign")) return false;

  // AN12543 Table 176: R-APDU carries TLV[TAG_1] = ASN.1 DER signature. Locate
  // the 0x30 SEQUENCE (inside or after the TLV wrapper) and convert to raw r||s.
  int payload = n - 2;
  int seq = -1;
  for(int i=0;i<payload;i++){ if(resp[i]==0x30){ seq=i; break; } }
  if(seq < 0){ Serial.println("[ATTEST] sign: no DER SEQUENCE in response"); return false; }
  if(!der_ecdsa_to_raw(resp+seq, payload-seq, sig64)){
    Serial.println("[ATTEST] sign: DER→raw failed");
    return false;
  }
  return true;
}

// DER SEQUENCE{ INTEGER r, INTEGER s } → raw r(32)||s(32), left-zero-padded.
// Handles the leading 0x00 sign byte DER adds when the high bit is set.
bool der_ecdsa_to_raw(const uint8_t* der, int len, uint8_t out64[64]){
  if(len < 6 || der[0]!=0x30) return false;
  int pos = 2;                          // skip SEQ tag+len (len assumed 1-byte; sigs are short)
  if(der[1] & 0x80) pos = 2 + (der[1] & 0x7f);  // long-form length (rare for ECDSA)
  auto read_int = [&](uint8_t* dst)->bool{
    if(pos>=len || der[pos]!=0x02) return false;
    int l = der[++pos]; pos++;
    // strip leading zero pad
    while(l>32 && der[pos]==0x00){ pos++; l--; }
    if(l>32) return false;
    memset(dst, 0, 32);
    memcpy(dst + (32-l), der+pos, l);
    pos += l; return true;
  };
  if(!read_int(out64)) return false;        // r
  if(!read_int(out64+32)) return false;     // s
  return true;
}

// ── se_attest_selftest (BENCH GATE) ──────────────────────────────────────────
// Signs the fixed spec test-vector preimage and prints pubkey + sig as hex so
// the host can verify against the reference oracle. Does NOT prove the on-chip
// key matches any allowlist — it proves the SE sign path produces a valid P-256
// ECDSA signature over the exact bytes the verifier will check.
//   Test vector (genuine ctx): preimage SHA256 =
//     967f3b1c35499df87b573e2671e03d29c535b6cec24e391d58ea437f9671ba11
void se_attest_selftest(){
  static const uint8_t TV[32] = {
    0x96,0x7f,0x3b,0x1c,0x35,0x49,0x9d,0xf8,0x7b,0x57,0x3e,0x26,0x71,0xe0,0x3d,0x29,
    0xc5,0x35,0xb6,0xce,0xc2,0x4e,0x39,0x1d,0x58,0xea,0x43,0x7f,0x96,0x71,0xba,0x11
  };
  uint8_t pk[33], sig[64];
  if(!se_attest_pubkey(pk)){ Serial.println("[ATTEST] selftest: no pubkey"); return; }
  if(!se_attest_sign(TV, sig)){ Serial.println("[ATTEST] selftest: sign failed"); return; }
  char hex[131];
  for(int i=0;i<33;i++){ sprintf(hex+i*2,"%02x",pk[i]); } hex[66]=0;
  Serial.printf("[ATTEST] selftest pubkey(c33)=%s\n", hex);
  for(int i=0;i<64;i++){ sprintf(hex+i*2,"%02x",sig[i]); } hex[128]=0;
  Serial.printf("[ATTEST] selftest sig(raw64)=%s\n", hex);
  Serial.println("[ATTEST] verify host-side: ecdsa_verify(pubkey, sig, TV) must PASS");
}
