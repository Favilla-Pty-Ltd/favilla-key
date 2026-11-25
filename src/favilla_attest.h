// ─────────────────────────────────────────────────────────────────────────────
// favilla_attest.h — Favilla KEY device attestation (on-device, non-SE parts)
//
// Implements the firmware half of ATTESTATION_SPEC.md:
//   • parse a FAVC1: challenge QR
//   • build the DOMAIN-SEPARATED signed preimage  (the security-critical bytes)
//   • sign it via the SE (se_attest_sign — SE-native, key never leaves chip)
//   • emit a FAVR1: answer QR
//
// The signed preimage is a plain concatenation (NOT cbor) so the exact bytes
// are trivial to audit and match the reference oracle:
//     msg = SHA256( "FAVILLA-ATTEST-v1\0" || nonce(32) || ctx || aux(32|empty) )
// CBOR is used ONLY for the transport envelopes, with a minimal fixed-schema
// reader/writer below (no external CBOR dependency).
//
// Domain separation (spec §5): P-256 curve + dedicated SE object + this domain
// tag make an attestation signature structurally unusable as a BTC/Nostr sig.
// The FAVC1: prefix routes ONLY here; this handler refuses anything that also
// looks like ur:/FK1:/nsec1/PSBT.
// ─────────────────────────────────────────────────────────────────────────────
#pragma once
#include <Arduino.h>
#include <mbedtls/sha256.h>
#include "pair_qr.h"        // pq_b64u_encode / pq_b64u_decode

// Provided by the SE driver (se_signer) — see step 5. Declared here so this
// header compiles against the interface; the SE-native bodies land in se_signer.
extern bool se_attest_exists();
extern bool se_attest_pubkey(uint8_t pk33[33]);
extern bool se_attest_sign(const uint8_t hash32[32], uint8_t sig64[64]);

// ── constants (MUST match favilla_attest.py byte-for-byte) ───────────────────
static const char ATTEST_DOMAIN[] = "FAVILLA-ATTEST-v1";  // 17 chars; the \0 is
                                                          // appended explicitly
                                                          // below so it's part
                                                          // of the preimage.
#define ATTEST_DOMAIN_LEN 18   // 17 chars + NUL

static const char* ATTEST_CHAL_PREFIX = "FAVC1:";
static const char* ATTEST_ANS_PREFIX  = "FAVR1:";

// Parsed challenge (fixed schema).
struct AttestChallenge {
  uint8_t nonce[32];
  char    ctx[8];         // "genuine" | "cipher"
  bool    hasAux;
  uint8_t aux[32];
  uint32_t iat;
  uint32_t exp;
  // NOTE: the device does NOT verify the CHALLENGE_KEY sig or expiry — the
  // VERIFIER does (spec §6 steps 3/5). The device only needs the fields it
  // signs over. Freshness/authenticity of the challenge is the verifier's job;
  // the device signing a stale nonce is harmless because the verifier rejects
  // it. Keeping the device out of clock/keys here reduces its trusted inputs.
};

// ── CIPHER score attestation (FAVS1) ────────────────────────────────────────
// Domain-separated from FAVC1 device verification: a score signature can never
// be replayed as a verification answer, nor vice versa. VERIFICATION SPEC (for
// favillakey.io/cipher): rebuild the canonical string below from the kind-1888
// event's tags + pubkey + created_at, hash with the domain (NUL included),
// verify the P-256 ECDSA sig from the ["attest", pk33hex, sig64hex] tag, and
// check pk33 against the published registry of provisioned Favilla devices.
//
//   canonical = "<npub_hex64>|<score>|<walked>|<runs>|<lvl>|<created_at>|<nonce_hex32>"
//   preimage  = SHA256( "FAVILLA-CIPHER-SCORE-v1\0" || canonical )
//
// Binding the event pubkey in means a signature can't be lifted onto another
// npub's entry; created_at + nonce make replays distinct and dedupable.
// v2 (current): binds the full stat set the leaderboards rank, so none of them
// is forgeable independent of the signature. v1 (score|walked|runs|lvl only)
// is retained ONLY as a doc note for verifying pre-v2 events on the site.
//
//   FAVS2 canonical (pipe-joined, in THIS order):
//     npub | score | lvl | boss | bots | blocks | dur |
//     walked | runs | lifeHash | lifeBoss | lifeBots | lifeBlocks | embers |
//     a1 | a2 | p1 | p2 | i0 | i1 | i2 | created_at | nonce
//   preimage = SHA256( "FAVILLA-CIPHER-SCORE-v2\0" || canonical )
//
// Per-run: score,lvl,boss,bots,blocks,dur. Account: walked,runs,lifeHash,
// lifeBoss,lifeBots,lifeBlocks,embers. Build: a1,a2 (active skills), p1,p2
// (passives), i0,i1,i2 (equipped item defs per class slot).
static const char SCORE_DOMAIN[] = "FAVILLA-CIPHER-SCORE-v2";
#define SCORE_DOMAIN_LEN 24   // 23 chars + NUL (NUL is part of the preimage)

static void attest_score_hash_v2(const char* npubHex64,
      long score, int lvl, long boss, long bots, long blocks, long dur,
      long walked, long runs, long lifeHash, long lifeBoss, long lifeBots,
      long lifeBlocks, long embers,
      int a1, int a2, int p1, int p2,
      unsigned i0, unsigned i1, unsigned i2,
      long createdAt, const char* nonceHex32, uint8_t out32[32]) {
  char canon[512];   // V-3: enlarged from 384 so long-lived stats don't truncate
  int n = snprintf(canon, sizeof(canon),
    "%s|%ld|%d|%ld|%ld|%ld|%ld|%ld|%ld|%ld|%ld|%ld|%ld|%ld|%d|%d|%d|%d|%u|%u|%u|%ld|%s",
    npubHex64, score, lvl, boss, bots, blocks, dur,
    walked, runs, lifeHash, lifeBoss, lifeBots, lifeBlocks, embers,
    a1, a2, p1, p2, i0, i1, i2, createdAt, nonceHex32);
  mbedtls_sha256_context c; mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, (const uint8_t*)SCORE_DOMAIN, SCORE_DOMAIN_LEN);
  // V-3 fix: snprintf returns the WOULD-BE length; clamp before hashing so a
  // truncated canonical string can't over-read the buffer.
  size_t cn = (n < 0) ? 0 : ((n >= (int)sizeof(canon)) ? sizeof(canon) - 1 : (size_t)n);
  mbedtls_sha256_update(&c, (const uint8_t*)canon, cn);
  mbedtls_sha256_finish(&c, out32);
  mbedtls_sha256_free(&c);
}

// ── the ONE preimage definition (security-critical) ─────────────────────────
static void attest_preimage(const uint8_t nonce[32], const char* ctx,
                            const uint8_t* aux /*32 or nullptr*/,
                            uint8_t out32[32]) {
  mbedtls_sha256_context c; mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  // domain tag INCLUDING the trailing NUL (matches b"...v1\x00" in the oracle)
  mbedtls_sha256_update(&c, (const uint8_t*)ATTEST_DOMAIN, ATTEST_DOMAIN_LEN);
  mbedtls_sha256_update(&c, nonce, 32);
  mbedtls_sha256_update(&c, (const uint8_t*)ctx, strlen(ctx));
  if (aux) mbedtls_sha256_update(&c, aux, 32);
  mbedtls_sha256_finish(&c, out32);
  mbedtls_sha256_free(&c);
}

// ── minimal CBOR reader (fixed schema: a map of the keys we expect) ─────────
// Supports exactly the subset the challenge uses: text-string keys, small
// uints, byte-strings (nonce/aux), text-strings (ctx), and null. Rejects
// anything unexpected. This is deliberately tiny and total — no recursion,
// no allocation — so it can't become a parser-attack surface (audit finding 9
// class). Returns true on a fully-recognised challenge.
struct CborRd {
  const uint8_t* p; const uint8_t* end;
  bool u8(uint8_t& v){ if(p>=end) return false; v=*p++; return true; }
  bool take(uint8_t* dst, size_t n){ if((size_t)(end-p)<n) return false; memcpy(dst,p,n); p+=n; return true; }
};

// read a CBOR "definite-length" header → (major, argument). Handles args
// encoded inline (<24), or in following 1/2/4 bytes.
static bool cbor_hdr(CborRd& r, uint8_t& major, uint64_t& arg){
  uint8_t ib; if(!r.u8(ib)) return false;
  major = ib >> 5; uint8_t ai = ib & 0x1f;
  if(ai < 24){ arg = ai; return true; }
  if(ai == 24){ uint8_t v; if(!r.u8(v)) return false; arg=v; return true; }
  if(ai == 25){ uint8_t b[2]; if(!r.take(b,2)) return false; arg=(b[0]<<8)|b[1]; return true; }
  if(ai == 26){ uint8_t b[4]; if(!r.take(b,4)) return false;
                arg=((uint64_t)b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]; return true; }
  return false; // 8-byte args / indefinite not expected in a challenge
}

// Parse "FAVC1:<b64url(cbor)>" → AttestChallenge. Returns false on ANY
// unexpected structure (fail-closed).
static bool attest_parse_challenge(const String& qr, AttestChallenge& out){
  if(!qr.startsWith(ATTEST_CHAL_PREFIX)) return false;
  // Reject anything that ALSO looks like another payload type (belt-and-braces
  // domain separation — the prefix already guarantees this, but explicit).
  if(qr.indexOf("ur:")==0 || qr.startsWith("FK1:") || qr.startsWith("FK2:") ||
     qr.startsWith("nsec1")) return false;

  String body = qr.substring(strlen(ATTEST_CHAL_PREFIX));
  static uint8_t buf[256];
  int n = pq_b64u_decode(body.c_str(), body.length(), buf, sizeof(buf));
  if(n <= 0) return false;

  CborRd r{ buf, buf + n };
  uint8_t major; uint64_t arg;
  if(!cbor_hdr(r, major, arg) || major != 5) return false;  // must be a map
  uint64_t nkeys = arg;

  memset(&out, 0, sizeof(out));
  bool haveN=false, haveCtx=false;
  for(uint64_t i=0;i<nkeys;i++){
    // key: text string
    if(!cbor_hdr(r, major, arg) || major != 3 || arg > 8) return false;
    char key[9]={0}; if(!r.take((uint8_t*)key, arg)) return false; key[arg]=0;

    if(!strcmp(key,"v")){
      if(!cbor_hdr(r,major,arg) || major!=0 || arg!=1) return false;   // version==1
    } else if(!strcmp(key,"n")){
      if(!cbor_hdr(r,major,arg) || major!=2 || arg!=32) return false;  // 32-byte bstr
      if(!r.take(out.nonce,32)) return false; haveN=true;
    } else if(!strcmp(key,"iat")){
      if(!cbor_hdr(r,major,arg) || major!=0) return false; out.iat=(uint32_t)arg;
    } else if(!strcmp(key,"exp")){
      if(!cbor_hdr(r,major,arg) || major!=0) return false; out.exp=(uint32_t)arg;
    } else if(!strcmp(key,"ctx")){
      if(!cbor_hdr(r,major,arg) || major!=3 || arg>7) return false;
      if(!r.take((uint8_t*)out.ctx, arg)) return false; out.ctx[arg]=0; haveCtx=true;
    } else if(!strcmp(key,"aux")){
      if(!cbor_hdr(r,major,arg)) return false;
      if(major==7 && arg==22){ out.hasAux=false; }                     // null (0xf6)
      else if(major==2 && arg==32){ if(!r.take(out.aux,32)) return false; out.hasAux=true; }
      else return false;
    } else if(!strcmp(key,"sig")){
      // device ignores the challenge sig; skip its 64-byte bstr
      if(!cbor_hdr(r,major,arg) || major!=2) return false;
      if((uint64_t)(r.end - r.p) < arg) return false; r.p += arg;
    } else {
      return false; // unexpected key → fail closed
    }
  }
  if(!haveN || !haveCtx) return false;
  if(strcmp(out.ctx,"genuine") && strcmp(out.ctx,"cipher")) return false;
  // cipher challenges MUST carry aux; genuine MUST NOT
  if(!strcmp(out.ctx,"cipher") && !out.hasAux) return false;
  if(!strcmp(out.ctx,"genuine") && out.hasAux) return false;
  return true;
}

// ── minimal CBOR writer for the fixed answer map ────────────────────────────
static void cbor_wr_hdr(String& s, uint8_t major, uint64_t arg){
  uint8_t m = major<<5;
  if(arg<24){ s += (char)(m|arg); }
  else if(arg<256){ s += (char)(m|24); s += (char)arg; }
  else { s += (char)(m|25); s += (char)((arg>>8)&0xff); s += (char)(arg&0xff); }
}
static void cbor_wr_bstr(String& s, const uint8_t* b, size_t n){
  cbor_wr_hdr(s,2,n); for(size_t i=0;i<n;i++) s += (char)b[i];
}
static void cbor_wr_tstr(String& s, const char* t){
  size_t n=strlen(t); cbor_wr_hdr(s,3,n); s += t;
}

// Build "FAVR1:<b64url(answer_cbor)>". Signs via the SE. Returns "" on failure.
static String attest_build_answer(const AttestChallenge& ch){
  uint8_t pk[33];
  if(!se_attest_pubkey(pk)) return "";
  uint8_t msg[32];
  attest_preimage(ch.nonce, ch.ctx, ch.hasAux ? ch.aux : nullptr, msg);
  uint8_t sig[64];
  if(!se_attest_sign(msg, sig)) return "";   // SE-native ECDSA, key stays on chip

  // map with 6 keys: v, pk, n, ctx, aux, sig  (canonical order by spec)
  String cb;
  cbor_wr_hdr(cb, 5, 6);
  cbor_wr_tstr(cb,"v");   cbor_wr_hdr(cb,0,1);
  cbor_wr_tstr(cb,"pk");  cbor_wr_bstr(cb, pk, 33);
  cbor_wr_tstr(cb,"n");   cbor_wr_bstr(cb, ch.nonce, 32);
  cbor_wr_tstr(cb,"ctx"); cbor_wr_tstr(cb, ch.ctx);
  cbor_wr_tstr(cb,"aux");
  if(ch.hasAux) cbor_wr_bstr(cb, ch.aux, 32); else { cb += (char)0xf6; } // null
  cbor_wr_tstr(cb,"sig"); cbor_wr_bstr(cb, sig, 64);

  String out = String(ATTEST_ANS_PREFIX) +
               pq_b64u_encode((const uint8_t*)cb.c_str(), cb.length());
  return out;
}
