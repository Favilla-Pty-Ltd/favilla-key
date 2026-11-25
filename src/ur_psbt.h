#pragma once
// ============================================================================
// ur_psbt.h — Uniform Resource (UR) decode/encode + finalized-PSBT serializer
//             for airgap Bitcoin signing on the Favilla KEY.
//
// SCOPE (27 May 2026): airgap Bitcoin is IN V1. The device scans an animated
// ur:crypto-psbt from Sparrow/Keystone/Passport/Jade, decodes the PSBT,
// confirms + signs on-device, then displays a finalized ur:crypto-psbt back
// for the coordinator to scan and broadcast.
//
// Every primitive in this file was first written and verified in a standalone
// C++ harness (urtest/ur_test.cpp) against the Blockchain Commons spec test
// vectors:
//   - Bytewords minimal decode  (BCR-2020-012)  → spec hex + CRC c904f40b ✓
//   - UR string parse (single + multipart)                                ✓
//   - multipart part CBOR array(5)  → 850c0818641a12345678450105030305    ✓
//   - CBOR byte-string unwrap (untagged crypto-psbt)                       ✓
//   - full encode→fragment→decode→reassemble round-trip                    ✓
//   - metadata-mismatch splice rejection (security)                        ✓
//
// EMBEDDED CONSTRAINTS:
//   - No STL. Fixed-size static buffers sized to PSBT_MAX_* from psbt.h.
//   - Runs in the clean-heap reboot-to-scan airgap path (WiFi down → clean
//     internal RAM). Do NOT introduce heap pressure during camera operation.
//   - Fountain/XOR (seqNum > seqLen) is DEFERRED. This is the PURE decoder:
//     simple parts seqNum 1..seqLen only. Fountain parts are ignored.
//
// BBQr (Coldcard-native) is a known deferred gap — UR first (broadest cover).
// ============================================================================

#include <stdint.h>
#include <string.h>
#include <stdlib.h>   // atoi
#include <stdio.h>    // snprintf
#include "psbt.h"
#include "psbt_sign.h"

// Largest UR message we will accept/produce. A finalized 1-in/2-out P2WPKH
// PSBT is ~210-260B; a 2-in is larger. 4KB is generous headroom and matches
// the scale of the network path's 16KB psbt buffer being overkill.
#ifndef UR_MAX_MESSAGE
#define UR_MAX_MESSAGE  4096   // was 2048. A 2-in/2-out 2-of-3 P2WSH PSBT from
                               // Sparrow with a cosigner's partial sig is ~1.7KB;
                               // 3 inputs would not fit. NOTE: main.cpp sizes
                               // urPsbt/urFinal at 2048 — raise to UR_MAX_MESSAGE.
#endif
// Max fragments we will reassemble. Bounded by scan patience, not message
// size: at realistic ~96-160B/fragment this covers multi-input PSBTs well past
// 2KB. 12 animated frames is already a long capture for the user.
#ifndef UR_MAX_PARTS
#define UR_MAX_PARTS    32    // was 12: 12 x 96B capped messages at 1152B, so
                              // signed PSBTs of 1153-2048B FAILED to display.
                              // 32 x 80B covers the full UR_MAX_MESSAGE.
#endif
// Per-fragment payload ceiling for ENCODE. Bench: OV2640 reliable read ceiling
// ~v10-11 (271-321 alphanumeric chars). Bytewords doubles byte→2 chars, so a
// 200B CBOR part → 400 char payload. We size the *message* fragment so the
// final UR string lands inside the readable ceiling. ~96B data per fragment
// keeps the QR at ~v9-10 with margin (75-80% of ceiling per handover).
// Display-side fragment size (bytes of message per QR frame). The RECEIVER is a
// phone/webcam reading the KEY's 240px panel (228px usable, ECC L, alnum):
//     80 B -> v7  45 modules 5 px/module   (1.9KB PSBT: 24 frames)
//    160 B -> v10 57 modules 4 px/module   (12 frames)   <- default from 14 Sep 2026
//    240 B -> v12 65 modules 3 px/module   ( 8 frames)   hard ceiling: 640-char frame buffer
// UR_ENCODE_FRAG_MAX sizes the buffers; g_ur_frag_bytes is the runtime value
// (Settings > Device > QR density, when that lands). Never affects decoding.
#ifndef UR_ENCODE_FRAG_MAX
#define UR_ENCODE_FRAG_MAX    240
#endif
#ifndef UR_ENCODE_FRAG_DEFAULT
#define UR_ENCODE_FRAG_DEFAULT 160
#endif
static size_t g_ur_frag_bytes = UR_ENCODE_FRAG_DEFAULT;
static inline void ur_set_frag_bytes(size_t b) {
  if (b < 40) b = 40;
  if (b > UR_ENCODE_FRAG_MAX) b = UR_ENCODE_FRAG_MAX;
  g_ur_frag_bytes = b;
}
#define UR_ENCODE_FRAG_BYTES  UR_ENCODE_FRAG_MAX   // buffer sizing only
// Scratch for bytewords-decoded CBOR of one incoming frame. This is the hard
// ceiling on how big any single readable frame can be after decode.
// Encoder-side part cap (return leg only). Decoupled from UR_MAX_PARTS because
// the decoder pool costs ~2.7KB of internal RAM per part while encode frames
// live in PSRAM (main.cpp: urFrags = ps_malloc(UR_MAX_ENCODE_PARTS*640) —
// NOTE main.cpp currently allocates UR_MAX_PARTS*640; change it with this).
// 64 x 80B covers a 4KB message.
#ifndef UR_MAX_ENCODE_PARTS
#define UR_MAX_ENCODE_PARTS   64
#endif
#ifndef UR_DECODE_CBOR_CAP
#define UR_DECODE_CBOR_CAP    664
#endif
// DECODE-side per-fragment store. Must be >= UR_DECODE_CBOR_CAP so that any
// frame we can decode, we can also store (covers both a large single-part UR
// and any multipart fragment Sparrow/iPhone emits). Each slot is this big ×
// (UR_MAX_PARTS+1).
#ifndef UR_DECODE_FRAG_CAP
#define UR_DECODE_FRAG_CAP    UR_DECODE_CBOR_CAP
#endif

// ────────────────────────────────────────────────────────────────────────
// Bytewords (BCR-2020-012) — 256-word list, minimal = first+last letter.
// ────────────────────────────────────────────────────────────────────────
static const char UR_BW_WORDS[] =
"able acid also apex aqua arch atom aunt away axis back bald barn belt beta bias "
"blue body brag brew bulb buzz calm cash cats chef city claw code cola cook cost "
"crux curl cusp cyan dark data days deli dice diet door down draw drop drum dull "
"duty each easy echo edge epic even exam exit eyes fact fair fern figs film fish "
"fizz flap flew flux foxy free frog fuel fund gala game gear gems gift girl glow "
"good gray grim guru gush gyro half hang hard hawk heat help high hill holy hope "
"horn huts iced idea idle inch inky into iris iron item jade jazz join jolt jowl "
"judo jugs jump junk jury keep keno kept keys kick kiln king kite kiwi knob lamb "
"lava lazy leaf legs liar limp lion list logo loud love luau luck lung main many "
"math maze memo menu meow mild mint miss monk nail navy need news next noon note "
"numb obey oboe omit onyx open oval owls paid part peck play plus poem pool pose "
"puff puma purr quad quiz race ramp real redo rich road rock roof ruby ruin runs "
"rust safe saga scar sets silk skew slot soap solo song stub surf swan taco task "
"taxi tent tied time tiny toil tomb toys trip tuna twin ugly undo unit urge user "
"vast very veto vial vibe view visa void vows wall wand warm wasp wave waxy webs "
"what when whiz wolf work yank yawn yell yoga yurt zaps zero zest zinc zone zoom";

// reverse lookup: (first-'a')*26 + (last-'a')  ->  byte value 0..255, else -1.
// Built once on first use (idempotent).
static int16_t ur_bw_lookup[26*26];
static bool    ur_bw_ready = false;

static void ur_bw_init() {
  if (ur_bw_ready) return;
  for (int i = 0; i < 26*26; i++) ur_bw_lookup[i] = -1;
  const char* p = UR_BW_WORDS;
  int idx = 0;
  while (*p && idx < 256) {
    int key = (p[0]-'a')*26 + (p[3]-'a');
    ur_bw_lookup[key] = (int16_t)idx;
    idx++; p += 4;
    if (*p == ' ') p++;
  }
  ur_bw_ready = true;
}

// forward word lookup for encode: index -> 4-char word (returns into UR_BW_WORDS)
static const char* ur_bw_word(int idx) {
  // words are fixed 4 chars + 1 space stride = 5, except no trailing space
  return UR_BW_WORDS + idx * 5;
}

// ── CRC32 (reflected, poly 0xEDB88320) ──────────────────────────────────
static uint32_t ur_crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int k = 0; k < 8; k++)
      crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
  }
  return crc ^ 0xFFFFFFFFu;
}

// ── Bytewords minimal DECODE → body bytes (checksum stripped + verified) ──
// Returns body length, or -1 on error.
static int ur_bw_decode(const char* s, size_t slen, uint8_t* out, size_t out_cap) {
  ur_bw_init();
  if (slen % 2 != 0) return -1;
  size_t n = slen / 2;
  if (n < 4 || n > out_cap) return -1;
  for (size_t i = 0; i < n; i++) {
    char a = s[i*2], b = s[i*2+1];
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    if (a < 'a' || a > 'z' || b < 'a' || b > 'z') return -1;
    int16_t v = ur_bw_lookup[(a-'a')*26 + (b-'a')];
    if (v < 0) return -1;
    out[i] = (uint8_t)v;
  }
  size_t body_len = n - 4;
  uint32_t calc = ur_crc32(out, body_len);
  uint32_t got  = ((uint32_t)out[body_len]   << 24) |
                  ((uint32_t)out[body_len+1] << 16) |
                  ((uint32_t)out[body_len+2] <<  8) |
                  ((uint32_t)out[body_len+3]);
  if (calc != got) return -1;
  return (int)body_len;
}

// ── Bytewords minimal ENCODE: body bytes + CRC32 → minimal string (lower) ─
// Writes into out (caller buffer). Returns string length (excl NUL).
static size_t ur_bw_encode(const uint8_t* body, size_t len, char* out, size_t out_cap) {
  ur_bw_init();
  uint32_t crc = ur_crc32(body, len);
  size_t total = len + 4;
  if (total*2 + 1 > out_cap) return 0;
  size_t o = 0;
  for (size_t i = 0; i < total; i++) {
    uint8_t b;
    if (i < len) b = body[i];
    else {
      int sh = (3 - (int)(i - len)) * 8;   // big-endian checksum bytes
      b = (uint8_t)((crc >> sh) & 0xFF);
    }
    const char* w = ur_bw_word(b);
    out[o++] = w[0];
    out[o++] = w[3];
  }
  out[o] = 0;
  return o;
}

// ────────────────────────────────────────────────────────────────────────
// Minimal CBOR readers / writers (mt0 uint, mt2 byte string, mt4 array)
// ────────────────────────────────────────────────────────────────────────
typedef struct { const uint8_t* buf; size_t len; size_t pos; } ur_cbor_r;

static bool ur_cbor_uint(ur_cbor_r* r, uint64_t* out) {
  if (r->pos >= r->len) return false;
  uint8_t ib = r->buf[r->pos]; uint8_t mt = ib>>5; uint8_t ai = ib&0x1f;
  if (mt != 0) return false;
  r->pos++;
  if (ai < 24)  { *out = ai; return true; }
  if (ai == 24) { if (r->pos+1 > r->len) return false; *out = r->buf[r->pos++]; return true; }
  if (ai == 25) { if (r->pos+2 > r->len) return false; *out = ((uint64_t)r->buf[r->pos]<<8)|r->buf[r->pos+1]; r->pos+=2; return true; }
  if (ai == 26) { if (r->pos+4 > r->len) return false; *out = ((uint64_t)r->buf[r->pos]<<24)|((uint64_t)r->buf[r->pos+1]<<16)|((uint64_t)r->buf[r->pos+2]<<8)|r->buf[r->pos+3]; r->pos+=4; return true; }
  if (ai == 27) { if (r->pos+8 > r->len) return false; uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|r->buf[r->pos+i]; r->pos+=8; *out=v; return true; }
  return false;
}

static bool ur_cbor_bytes(ur_cbor_r* r, const uint8_t** out_ptr, size_t* out_len) {
  if (r->pos >= r->len) return false;
  uint8_t ib = r->buf[r->pos]; uint8_t mt = ib>>5; uint8_t ai = ib&0x1f;
  if (mt != 2) return false;
  r->pos++;
  uint64_t ln = 0;
  if (ai < 24)       ln = ai;
  else if (ai == 24) { if (r->pos+1>r->len) return false; ln = r->buf[r->pos++]; }
  else if (ai == 25) { if (r->pos+2>r->len) return false; ln = ((uint64_t)r->buf[r->pos]<<8)|r->buf[r->pos+1]; r->pos+=2; }
  else if (ai == 26) { if (r->pos+4>r->len) return false; ln = ((uint64_t)r->buf[r->pos]<<24)|((uint64_t)r->buf[r->pos+1]<<16)|((uint64_t)r->buf[r->pos+2]<<8)|r->buf[r->pos+3]; r->pos+=4; }
  else return false;
  if (r->pos + ln > r->len) return false;
  *out_ptr = r->buf + r->pos; *out_len = (size_t)ln; r->pos += ln;
  return true;
}

static bool ur_cbor_array_hdr(ur_cbor_r* r, uint64_t* n) {
  if (r->pos >= r->len) return false;
  uint8_t ib = r->buf[r->pos]; uint8_t mt = ib>>5; uint8_t ai = ib&0x1f;
  if (mt != 4) return false;
  r->pos++;
  if (ai < 24)  { *n = ai; return true; }
  if (ai == 24) { if (r->pos+1>r->len) return false; *n = r->buf[r->pos++]; return true; }
  return false;
}

static size_t ur_cbor_w_bstr_hdr(uint8_t* out, size_t n) {
  if (n < 24)    { out[0]=0x40|(uint8_t)n; return 1; }
  if (n < 256)   { out[0]=0x58; out[1]=(uint8_t)n; return 2; }
  if (n < 65536) { out[0]=0x59; out[1]=(n>>8)&0xFF; out[2]=n&0xFF; return 3; }
  out[0]=0x5a; out[1]=(n>>24)&0xFF; out[2]=(n>>16)&0xFF; out[3]=(n>>8)&0xFF; out[4]=n&0xFF; return 5;
}
static size_t ur_cbor_w_uint(uint8_t* out, uint64_t v) {
  if (v < 24)    { out[0]=(uint8_t)v; return 1; }
  if (v < 256)   { out[0]=0x18; out[1]=(uint8_t)v; return 2; }
  if (v < 65536) { out[0]=0x19; out[1]=(v>>8)&0xFF; out[2]=v&0xFF; return 3; }
  out[0]=0x1a; out[1]=(v>>24)&0xFF; out[2]=(v>>16)&0xFF; out[3]=(v>>8)&0xFF; out[4]=v&0xFF; return 5;
}

// ────────────────────────────────────────────────────────────────────────
// UR string parse:  ur:type/payload   |   ur:type/seqNum-seqLen/payload
// Writes type into type_out (caller buf), payload bytewords into bw_out.
// ────────────────────────────────────────────────────────────────────────
typedef struct {
  bool   ok;
  bool   multipart;
  int    seqNum, seqLen;
  char   type[24];
  const char* bw;     // pointer into the (mutated) input string
  size_t bw_len;
} ur_parsed_t;

// Parses in place. `s` must be a mutable, NUL-terminated buffer; we lowercase
// it. Returns parsed view with bw pointing into s.
static ur_parsed_t ur_parse(char* s) {
  ur_parsed_t r; memset(&r, 0, sizeof(r));
  size_t L = strlen(s);
  // trim trailing whitespace
  while (L > 0 && (s[L-1]=='\n'||s[L-1]=='\r'||s[L-1]==' ')) s[--L]=0;
  // lowercase
  for (size_t i=0;i<L;i++) if (s[i]>='A'&&s[i]<='Z') s[i]+=32;
  if (L < 4 || strncmp(s, "ur:", 3) != 0) return r;
  char* rest = s + 3;
  // find up to two '/'
  char* slash1 = strchr(rest, '/');
  if (!slash1) return r;
  char* slash2 = strchr(slash1+1, '/');
  // type = rest .. slash1
  size_t tlen = (size_t)(slash1 - rest);
  if (tlen == 0 || tlen >= sizeof(r.type)) return r;
  memcpy(r.type, rest, tlen); r.type[tlen]=0;
  if (!slash2) {
    r.multipart = false;
    r.bw = slash1+1; r.bw_len = strlen(slash1+1);
    if (r.bw_len == 0) return r;
    r.ok = true; return r;
  }
  // multipart: seq between slash1+1 .. slash2
  char seq[24]; size_t sl = (size_t)(slash2 - (slash1+1));
  if (sl == 0 || sl >= sizeof(seq)) return r;
  memcpy(seq, slash1+1, sl); seq[sl]=0;
  char* dash = strchr(seq, '-');
  if (!dash) return r;
  *dash = 0;
  r.seqNum = atoi(seq);
  r.seqLen = atoi(dash+1);
  if (r.seqNum < 1 || r.seqLen < 1) return r;
  r.multipart = true;
  r.bw = slash2+1; r.bw_len = strlen(slash2+1);
  if (r.bw_len == 0) return r;
  r.ok = true; return r;
}

// ────────────────────────────────────────────────────────────────────────
// multipart part = CBOR array(5): [seqNum, seqLen, messageLen, checksum, data]
// ────────────────────────────────────────────────────────────────────────
typedef struct {
  uint64_t seqNum, seqLen, messageLen, checksum;
  const uint8_t* data; size_t data_len;
  bool ok;
} ur_part_t;

static ur_part_t ur_parse_part(const uint8_t* cbor, size_t len) {
  ur_part_t p; memset(&p, 0, sizeof(p));
  ur_cbor_r r = { cbor, len, 0 };
  uint64_t nel;
  if (!ur_cbor_array_hdr(&r, &nel) || nel != 5) return p;
  if (!ur_cbor_uint(&r, &p.seqNum)) return p;
  if (!ur_cbor_uint(&r, &p.seqLen)) return p;
  if (!ur_cbor_uint(&r, &p.messageLen)) return p;
  if (!ur_cbor_uint(&r, &p.checksum)) return p;
  if (!ur_cbor_bytes(&r, &p.data, &p.data_len)) return p;
  p.ok = true;
  return p;
}

// ── FountainDecoder: full UR fountain/XOR decode (Blockchain Commons spec). ──
//    Handles pure parts (seqNum<=seqLen) as a fast path AND fountain/mixed
//    parts (seqNum>seqLen) via Walker-Vose degree selection + Fisher-Yates
//    fragment choice + Gaussian XOR reduction. This is what Sparrow/Specter/
//    Keystone/Passport/Jade emit. Validated byte-exact against bc-ur test.cpp
//    vectors (next_int, RandomSampler, choose_degree, choose_fragments,
//    end-to-end roundtrip incl. pure-starved streams).
//
//    Metadata-mismatch rejection (seqLen/messageLen/checksum/fragLen) is
//    retained and load-bearing: it prevents splicing two PSBTs mid-scan.
//
// State lives in a single static instance (one airgap scan at a time).

#define UR_MAX_MIXED 20

// SHA-256 hook: device uses mbedtls (already linked); STANDALONE host uses
// the trezor shim for the syntax/roundtrip harness.
#ifndef STANDALONE
#include "mbedtls/sha256.h"
static inline void ur_sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context c; mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, in, len);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
}
#else
extern void ur_sha256(const uint8_t* in, size_t len, uint8_t out[32]);
#endif

// ---- Xoshiro256** (seed = SHA-256(bytes) -> 4 BE u64) ----
typedef struct { uint64_t s[4]; } ur_xo_t;
static inline uint64_t ur_rotl(uint64_t v, int k){ return (v<<k)|(v>>(64-k)); }
static void ur_xo_seed(ur_xo_t* x, const uint8_t* b, size_t len){
  uint8_t d[32]; ur_sha256(b, len, d);
  for(int i=0;i<4;i++){ uint64_t v=0; for(int n=0;n<8;n++){ v<<=8; v|=d[i*8+n]; } x->s[i]=v; }
}
static uint64_t ur_xo_next(ur_xo_t* x){
  const uint64_t r = ur_rotl(x->s[1]*5,7)*9;
  const uint64_t t = x->s[1] << 17;
  x->s[2]^=x->s[0]; x->s[3]^=x->s[1]; x->s[1]^=x->s[2]; x->s[0]^=x->s[3];
  x->s[2]^=t; x->s[3]=ur_rotl(x->s[3],45);
  return r;
}
static double ur_xo_dbl(ur_xo_t* x){ return (double)ur_xo_next(x) / 18446744073709551616.0; } // /2^64
static uint64_t ur_xo_int(ur_xo_t* x, uint64_t lo, uint64_t hi){
  return (uint64_t)(ur_xo_dbl(x) * (double)(hi-lo+1)) + lo;
}

// ---- Walker-Vose alias sampler (rebuilt per choose_degree call) ----
typedef struct { int n; double probs[UR_MAX_PARTS]; int aliases[UR_MAX_PARTS]; } ur_sampler_t;
static void ur_sampler_init(ur_sampler_t* rs, const double* probs, int n){
  rs->n=n; double sum=0; for(int i=0;i<n;i++) sum+=probs[i];
  double P[UR_MAX_PARTS]; for(int i=0;i<n;i++) P[i]=probs[i]*(double)n/sum;
  int S[UR_MAX_PARTS],L[UR_MAX_PARTS],Sn=0,Ln=0;
  for(int i=n-1;i>=0;i--){ if(P[i]<1) S[Sn++]=i; else L[Ln++]=i; }
  for(int i=0;i<n;i++){ rs->probs[i]=0; rs->aliases[i]=0; }
  while(Sn>0&&Ln>0){ int a=S[--Sn],g=L[--Ln]; rs->probs[a]=P[a]; rs->aliases[a]=g;
    P[g]+=P[a]-1; if(P[g]<1) S[Sn++]=g; else L[Ln++]=g; }
  while(Ln>0) rs->probs[L[--Ln]]=1;
  while(Sn>0) rs->probs[S[--Sn]]=1;
}
static int ur_sampler_next(const ur_sampler_t* rs, ur_xo_t* rng){
  double r1=ur_xo_dbl(rng), r2=ur_xo_dbl(rng);
  int i=(int)((double)rs->n*r1);
  return r2<rs->probs[i] ? i : rs->aliases[i];
}
static int ur_choose_degree(int seq_len, ur_xo_t* rng){
  double probs[UR_MAX_PARTS]; for(int i=1;i<=seq_len;i++) probs[i-1]=1.0/(double)i;
  ur_sampler_t rs; ur_sampler_init(&rs, probs, seq_len);
  return ur_sampler_next(&rs, rng)+1;
}

// ---- choose_fragments -> uint16_t index bitmask ----
static uint32_t ur_choose_fragments(uint32_t seq_num, int seq_len, uint32_t checksum){ // F-1: uint16_t->uint32_t
  if(seq_num <= (uint32_t)seq_len) return (1u<<(seq_num-1)); // pure (16 Sep 2026: was cast to uint16_t — parts 17..32 got mask 0)
  uint8_t seed[8] = {
    (uint8_t)(seq_num>>24),(uint8_t)(seq_num>>16),(uint8_t)(seq_num>>8),(uint8_t)seq_num,
    (uint8_t)(checksum>>24),(uint8_t)(checksum>>16),(uint8_t)(checksum>>8),(uint8_t)checksum };
  ur_xo_t rng; ur_xo_seed(&rng, seed, 8);
  int degree = ur_choose_degree(seq_len, &rng);
  int rem[UR_MAX_PARTS]; int rn=seq_len; for(int i=0;i<seq_len;i++) rem[i]=i;
  uint32_t mask=0; int taken=0;   // F-1: uint16_t->uint32_t
  while(rn>0){
    int idx=(int)ur_xo_int(&rng,0,rn-1); int item=rem[idx];
    for(int j=idx;j<rn-1;j++) rem[j]=rem[j+1];
    rn--;
    if(taken<degree){ mask|=(uint32_t)(1u<<item); taken++; } else break;   // F-1
  }
  return mask;
}

// ---- decoder pool ----
typedef struct { uint32_t mask; uint8_t data[UR_DECODE_FRAG_CAP]; } ur_pool_part_t;   // F-1: uint16_t->uint32_t

typedef struct {
  bool     have_meta;
  bool     err;
  uint64_t seqLen, messageLen, checksum, fragLen;
  // simple (solved) fragments, indexed 0..seqLen-1
  bool     simple_got[UR_MAX_PARTS];
  uint8_t  simple[UR_MAX_PARTS][UR_DECODE_FRAG_CAP];
  size_t   n_got;                       // # simple fragments solved (UI progress)
  // mixed pool + work queue
  ur_pool_part_t mixed[UR_MAX_MIXED]; int mixed_count;
  ur_pool_part_t queue[UR_MAX_PARTS*2]; int q_head, q_tail;
  bool     done;
  // Multisig (14 Sep 2026): which UR type this sequence carries. Set by
  // ur_feed on the first accepted part; a later part of a different type is a
  // splice and is refused.
  char     ur_type[24];
} ur_decoder_t;

static void ur_decoder_reset(ur_decoder_t* d){ memset(d, 0, sizeof(*d)); }

// 16 Sep 2026: the mask has been uint32_t since F-1 but this still took a
// uint16_t, so any part touching fragments 17..32 counted wrong. With BOTH
// truncations, every sequence longer than 16 parts stalled at 16/N no matter
// how many fountain parts arrived (BlueWallet's 19-part wallet config; a
// 3-input multisig PSBT would have done the same). Sequences <= 16 never
// exercised it, which is why 4- and 12-part scans always worked.
static int ur_popcount32(uint32_t m){ int c=0; while(m){ c+=(int)(m&1u); m>>=1; } return c; }
#define ur_popcount16 ur_popcount32
static void ur_q_push(ur_decoder_t* d, const ur_pool_part_t* p){
  d->queue[d->q_tail]=*p; d->q_tail=(d->q_tail+1)%(UR_MAX_PARTS*2);
}
static int ur_q_empty(ur_decoder_t* d){ return d->q_head==d->q_tail; }
static ur_pool_part_t ur_q_pop(ur_decoder_t* d){
  ur_pool_part_t p=d->queue[d->q_head]; d->q_head=(d->q_head+1)%(UR_MAX_PARTS*2); return p;
}
// a ^= b when b is strict subset of a's index set.
static int ur_reduce(ur_pool_part_t* a, const ur_pool_part_t* b, int frag_len){
  uint32_t am=a->mask, bm=b->mask;   // F-1
  if(((bm&am)==bm) && bm!=am){
    a->mask = am & ~bm;
    for(int i=0;i<frag_len;i++) a->data[i]^=b->data[i];
    return 1;
  }
  return 0;
}
static void ur_process_simple(ur_decoder_t* d, ur_pool_part_t* p){
  int idx=-1; for(int i=0;i<UR_MAX_PARTS;i++) if(p->mask==(uint32_t)(1u<<i)){ idx=i; break; }   // F-1
  if(idx<0) return;
  if(d->simple_got[idx]) return;
  memcpy(d->simple[idx], p->data, d->fragLen);
  d->simple_got[idx]=true; d->n_got++;
  if(d->n_got==(size_t)d->seqLen){ d->done=true; return; }
  for(int m=0;m<d->mixed_count;m++){
    if(ur_reduce(&d->mixed[m], p, (int)d->fragLen)){
      if(ur_popcount16(d->mixed[m].mask)==1){
        ur_pool_part_t np=d->mixed[m]; d->mixed[m]=d->mixed[--d->mixed_count]; m--;
        ur_q_push(d,&np);
      }
    }
  }
}
static void ur_process_mixed(ur_decoder_t* d, ur_pool_part_t* p){
  for(int m=0;m<d->mixed_count;m++) if(d->mixed[m].mask==p->mask) return;
  for(int i=0;i<UR_MAX_PARTS;i++) if(d->simple_got[i]){
    ur_pool_part_t s; s.mask=(uint32_t)(1u<<i); memcpy(s.data,d->simple[i],d->fragLen);   // F-1
    ur_reduce(p,&s,(int)d->fragLen);
  }
  for(int m=0;m<d->mixed_count;m++) ur_reduce(p,&d->mixed[m],(int)d->fragLen);
  if(p->mask==0) return;
  if(ur_popcount16(p->mask)==1){ ur_q_push(d,p); return; }
  for(int m=0;m<d->mixed_count;m++){
    if(ur_reduce(&d->mixed[m], p, (int)d->fragLen)){
      if(ur_popcount16(d->mixed[m].mask)==1){
        ur_pool_part_t np=d->mixed[m]; d->mixed[m]=d->mixed[--d->mixed_count]; m--;
        ur_q_push(d,&np);
      }
    }
  }
  if(d->mixed_count<UR_MAX_MIXED) d->mixed[d->mixed_count++]=*p;
}

// Returns true when the message is complete. Sets d->err on any spec violation.
static bool ur_decoder_receive(ur_decoder_t* d, const ur_part_t* part){
  if(!part->ok){ d->err=true; return false; }
  if(part->seqLen<1 || part->seqLen>UR_MAX_PARTS){ d->err=true; return false; }
  if(part->seqNum<1){ d->err=true; return false; }
  if(part->data_len>UR_DECODE_FRAG_CAP){ d->err=true; return false; }
  if(part->messageLen>UR_MAX_MESSAGE){ d->err=true; return false; }
  if(!d->have_meta){
    d->seqLen=part->seqLen; d->messageLen=part->messageLen;
    d->checksum=part->checksum; d->fragLen=part->data_len;
    d->have_meta=true;
  } else {
    // SECURITY: reject mismatched metadata — prevents splicing two PSBTs.
    if(part->seqLen!=d->seqLen || part->messageLen!=d->messageLen ||
       part->checksum!=d->checksum || part->data_len!=d->fragLen){
      d->err=true; return false;
    }
  }
  if(d->done) return true;
  ur_pool_part_t p; p.mask=ur_choose_fragments((uint32_t)part->seqNum,(int)d->seqLen,(uint32_t)d->checksum);
  memset(p.data,0,UR_DECODE_FRAG_CAP);
  memcpy(p.data, part->data, part->data_len);
  ur_q_push(d,&p);
  while(!d->done && !ur_q_empty(d)){
    ur_pool_part_t cur=ur_q_pop(d);
    if(ur_popcount16(cur.mask)==1) ur_process_simple(d,&cur);
    else ur_process_mixed(d,&cur);
  }
  return d->done;
}

// Assemble the recovered message into out. Returns length, or -1 on error.
static int ur_decoder_result(ur_decoder_t* d, uint8_t* out, size_t out_cap){
  if(!d->have_meta || !d->done) return -1;
  if(d->messageLen>out_cap) return -1;
  size_t o=0;
  for(uint64_t i=0;i<d->seqLen;i++){
    if(!d->simple_got[i]) return -1;
    size_t take=d->fragLen;
    if(o+take>out_cap) take=out_cap-o;
    memcpy(out+o, d->simple[i], take);
    o+=take;
  }
  if(o<d->messageLen) return -1;
  if(ur_crc32(out, d->messageLen)!=d->checksum) return -1;
  return (int)d->messageLen;
}

// ── Top-level: feed a scanned UR string into the decoder ──────────────────
// `ur_string` is mutated (lowercased) in place. Returns:
//    1  = message complete (call ur_decoder_result + ur_extract_psbt)
//    0  = part accepted, need more frames
//   -1  = parse/decode error (caller may keep scanning; consider d->err)
// Accepts any well-formed UR type and records it in d->ur_type on the first
// part; the CALLER decides what to do with the result by type ("crypto-psbt"
// = transaction, "bytes" = multisig wallet config from Sparrow's "Keystone
// Multisig" export; anything else is rejected there). Mixing types inside one
// sequence is refused here (splice defence).
static int ur_feed(ur_decoder_t* d, char* ur_string) {
  ur_parsed_t p = ur_parse(ur_string);
  if (!p.ok) return -1;
  if (d->ur_type[0] == 0) {
    strncpy(d->ur_type, p.type, sizeof(d->ur_type) - 1);
  } else if (strcmp(d->ur_type, p.type) != 0) {
    d->err = true; return -1;
  }

  // bytewords-decode payload → CBOR bytes
  static uint8_t cborbuf[UR_DECODE_CBOR_CAP];
  int cn = ur_bw_decode(p.bw, p.bw_len, cborbuf, sizeof(cborbuf));
  if (cn < 0) return -1;

  if (!p.multipart) {
    // Single-part: CBOR is directly the crypto-psbt byte string. Treat as a
    // 1-of-1 message so the same result/extract path applies.
    { char t[24]; memcpy(t, d->ur_type, sizeof(t)); ur_decoder_reset(d); memcpy(d->ur_type, t, sizeof(t)); }
    if ((size_t)cn > UR_DECODE_FRAG_CAP) return -1;
    d->have_meta = true; d->seqLen = 1; d->n_got = 1; d->done = true;
    d->messageLen = (uint64_t)cn; d->fragLen = (uint64_t)cn;
    d->checksum = ur_crc32(cborbuf, cn);
    memcpy(d->simple[0], cborbuf, cn); d->simple_got[0] = true;
    return 1;
  }

  ur_part_t part = ur_parse_part(cborbuf, cn);
  if (!part.ok) return -1;
  bool complete = ur_decoder_receive(d, &part);
  if (d->err) return -1;
  return complete ? 1 : 0;
}

// ── Unwrap the recovered crypto-psbt CBOR → raw PSBT bytes ────────────────
// crypto-psbt is an UNTAGGED CBOR byte string wrapping the raw PSBT. Validates
// the psbt\xff magic. Returns raw PSBT length, or -1.
static int ur_extract_psbt(const uint8_t* msg, size_t msg_len,
                           uint8_t* out, size_t out_cap) {
  ur_cbor_r r = { msg, msg_len, 0 };
  const uint8_t* p; size_t pl;
  if (!ur_cbor_bytes(&r, &p, &pl)) return -1;
  if (pl < 5 || pl > out_cap) return -1;
  // PSBT magic = 70 73 62 74 ff  (psbt\xff)
  if (!(p[0]==0x70&&p[1]==0x73&&p[2]==0x62&&p[3]==0x74&&p[4]==0xff)) return -1;
  memcpy(out, p, pl);
  return (int)pl;
}

// ── Unwrap a ur:bytes payload → raw bytes (multisig wallet config) ───────
// ur:bytes is an untagged CBOR byte string. No magic to check; the caller
// hands the bytes to ms_config_parse() which validates the text itself.
static int ur_extract_bytes(const uint8_t* msg, size_t msg_len,
                            uint8_t* out, size_t out_cap) {
  ur_cbor_r r = { msg, msg_len, 0 };
  const uint8_t* p; size_t pl;
  if (!ur_cbor_bytes(&r, &p, &pl)) return -1;
  if (pl == 0 || pl > out_cap) return -1;
  memcpy(out, p, pl);
  return (int)pl;
}

// ════════════════════════════════════════════════════════════════════════
// RETURN LEG — finalize signed inputs → minimal crypto-psbt → multipart UR
// ════════════════════════════════════════════════════════════════════════
//
// We finalize on-device (single-sig P2WPKH, all inputs ours). The emitted PSBT
// is minimal: global key 0x00 = unsigned tx; each input carries only
// PSBT_IN_FINAL_SCRIPTWITNESS (0x08) = witness stack [<sig+sighash>, <pubkey>].
// A finalized PSBT needs no witness UTXO / derivation, so the lossy parse view
// is sufficient — we rebuild the unsigned tx from psbt_tx_t and attach sigs.
//
// CONSTRAINT: every input must be signed (we refuse to finalize a PSBT with a
// foreign input — single-sig V1 has none). Caller checks n_sigs == n_inputs.

// varint (Bitcoin CompactSize) writer
static size_t btc_write_varint(uint8_t* o, uint64_t v) {
  if (v < 0xFD)        { o[0]=(uint8_t)v; return 1; }
  if (v <= 0xFFFF)     { o[0]=0xFD; o[1]=v&0xFF; o[2]=(v>>8)&0xFF; return 3; }
  if (v <= 0xFFFFFFFF) { o[0]=0xFE; for(int i=0;i<4;i++) o[1+i]=(v>>(8*i))&0xFF; return 5; }
  o[0]=0xFF; for(int i=0;i<8;i++) o[1+i]=(v>>(8*i))&0xFF; return 9;
}

// Serialize the unsigned tx (BIP-174 global 0x00 value) from psbt_tx_t.
// Inputs have empty scriptSig (unsigned). No witness marker in the unsigned tx.
static size_t btc_serialize_unsigned_tx(const psbt_tx_t* tx, uint8_t* o) {
  size_t p = 0;
  // version (LE)
  o[p++]=tx->version&0xFF; o[p++]=(tx->version>>8)&0xFF;
  o[p++]=(tx->version>>16)&0xFF; o[p++]=(tx->version>>24)&0xFF;
  // input count
  p += btc_write_varint(o+p, tx->n_inputs);
  for (uint8_t i=0;i<tx->n_inputs;i++) {
    const psbt_txin_t* in = &tx->inputs[i];
    memcpy(o+p, in->prev_txid, 32); p+=32;           // txid (already LE on wire)
    o[p++]=in->prev_vout&0xFF; o[p++]=(in->prev_vout>>8)&0xFF;
    o[p++]=(in->prev_vout>>16)&0xFF; o[p++]=(in->prev_vout>>24)&0xFF;
    o[p++]=0x00;                                      // empty scriptSig (varint 0)
    o[p++]=in->n_sequence&0xFF; o[p++]=(in->n_sequence>>8)&0xFF;
    o[p++]=(in->n_sequence>>16)&0xFF; o[p++]=(in->n_sequence>>24)&0xFF;
  }
  // output count
  p += btc_write_varint(o+p, tx->n_outputs);
  for (uint8_t i=0;i<tx->n_outputs;i++) {
    const psbt_txout_t* ot = &tx->outputs[i];
    for (int b=0;b<8;b++) o[p++]=(ot->value>>(8*b))&0xFF;     // value (LE u64)
    p += btc_write_varint(o+p, ot->script_pubkey_len);
    memcpy(o+p, ot->script_pubkey, ot->script_pubkey_len); p+=ot->script_pubkey_len;
  }
  // locktime (LE)
  o[p++]=tx->locktime&0xFF; o[p++]=(tx->locktime>>8)&0xFF;
  o[p++]=(tx->locktime>>16)&0xFF; o[p++]=(tx->locktime>>24)&0xFF;
  return p;
}

// Build a finalized PSBT. Returns total length, or -1 on overflow/mismatch.
// sigs[] must cover every input (sig for input i found by input_index).
static int ur_build_finalized_psbt(const psbt_t* psbt,
                                    const psbt_partial_sig_t* sigs, int n_sigs,
                                    uint8_t* out, size_t out_cap) {
  if (n_sigs != psbt->tx.n_inputs) return -1;   // every input must be ours
  size_t p = 0;
  // magic
  static const uint8_t MAGIC[5]={0x70,0x73,0x62,0x74,0xff};
  if (p+5 > out_cap) return -1;
  memcpy(out+p, MAGIC, 5); p+=5;

  // ── global map: key 0x00 (unsigned tx), then 0x00 separator ──
  // key: len=1, keytype=0x00
  if (p+2 > out_cap) return -1;
  out[p++]=0x01; out[p++]=0x00;
  // value: varint(len) || unsigned tx. Serialize into a scratch first to know len.
  static uint8_t txbuf[1024];
  size_t txlen = btc_serialize_unsigned_tx(&psbt->tx, txbuf);
  uint8_t vh[9]; size_t vhl = btc_write_varint(vh, txlen);
  if (p+vhl+txlen > out_cap) return -1;
  memcpy(out+p, vh, vhl); p+=vhl;
  memcpy(out+p, txbuf, txlen); p+=txlen;
  out[p++]=0x00;                                   // global map separator

  // ── per-input maps: finalized scriptwitness only ──
  for (uint8_t i=0;i<psbt->tx.n_inputs;i++) {
    // find sig for this input
    const psbt_partial_sig_t* sg = nullptr;
    for (int j=0;j<n_sigs;j++) if (sigs[j].input_index==i) { sg=&sigs[j]; break; }
    if (!sg) return -1;

    // PSBT_IN_FINAL_SCRIPTWITNESS (0x08). key: len=1, keytype=0x08
    if (p+2 > out_cap) return -1;
    out[p++]=0x01; out[p++]=0x08;

    // value = witness stack serialization:
    //   varint(num_items=2)
    //   varint(len sig+sighash) || sig || sighashbyte
    //   varint(33) || pubkey
    uint8_t wbuf[160]; size_t w=0;
    w += btc_write_varint(wbuf+w, 2);                       // 2 stack items
    // item 1: DER sig + 1-byte sighash type
    w += btc_write_varint(wbuf+w, sg->der_len + 1);
    memcpy(wbuf+w, sg->der, sg->der_len); w+=sg->der_len;
    wbuf[w++] = sg->sighash_type;                           // e.g. 0x01 SIGHASH_ALL
    // item 2: 33-byte compressed pubkey
    w += btc_write_varint(wbuf+w, 33);
    memcpy(wbuf+w, sg->pubkey, 33); w+=33;

    uint8_t wvh[9]; size_t wvhl = btc_write_varint(wvh, w);
    if (p+wvhl+w+1 > out_cap) return -1;
    memcpy(out+p, wvh, wvhl); p+=wvhl;
    memcpy(out+p, wbuf, w); p+=w;
    out[p++]=0x00;                                          // input map separator
  }

  // ── per-output maps: empty ──
  for (uint8_t i=0;i<psbt->tx.n_outputs;i++) {
    if (p+1 > out_cap) return -1;
    out[p++]=0x00;                                          // empty output map
  }
  return (int)p;
}

// ── Wrap raw PSBT as crypto-psbt CBOR, fragment into multipart UR strings ──
// Produces up to UR_MAX_PARTS uppercase UR strings into out_frags[i][].
// Returns the number of fragments, or -1.
// out_frags must be [UR_MAX_PARTS][cap]; cap should be >= ~600.
// Generic: fragment an already-CBOR-encoded message as ur:<type>. Used by the
// PSBT return leg (crypto-psbt) and the cosigner export (crypto-account).
// Returns the number of frames written: seqLen pure parts + up to seqLen mixed
// (fountain) parts, capped by max_frags. Display them all in a loop.
static int ur_encode_message(const char* ur_type, const uint8_t* msg, size_t msg_len,
                             char out_frags[][640], size_t frag_cap, int max_frags) {
  uint32_t checksum = ur_crc32(msg, msg_len);

  // 2. fragment
  size_t fb = g_ur_frag_bytes ? g_ur_frag_bytes : UR_ENCODE_FRAG_DEFAULT;
  size_t seqLen = (msg_len + fb - 1) / fb;
  if (seqLen < 1) seqLen = 1;
  if ((int)seqLen > max_frags || seqLen > UR_MAX_ENCODE_PARTS) return -1;
  size_t fragLen = (msg_len + seqLen - 1) / seqLen;        // even-ish split

  if (seqLen == 1) {
    // Single-part UR: "ur:<type>/<bytewords(message)>" — the payload is the
    // message itself, NOT a fragment array. (The decoder's single-part path
    // mirrors this.)
    char bw[UR_MAX_MESSAGE * 2 + 16];
    size_t bwl = ur_bw_encode(msg, msg_len, bw, sizeof(bw));
    if (bwl == 0) return -1;
    int n = snprintf(out_frags[0], frag_cap, "ur:%s/%s", ur_type, bw);
    if (n <= 0 || (size_t)n >= frag_cap) return -1;
    for (char* q = out_frags[0]; *q; q++) if (*q >= 'a' && *q <= 'z') *q -= 32;
    return 1;
  }

  // Emit the seqLen PURE parts followed by MIXED (fountain) parts up to
  // max_frags, exactly as hummingbird / bc-ur encoders do. A mixed part is the
  // XOR of the fragments chosen by the spec's PRNG for its seqNum — the SAME
  // chooser the decoder above uses, so any conforming decoder recovers a
  // persistently missed pure frame from the combinations instead of waiting
  // for that one frame to be captured cleanly. Pure-only cycling (what this
  // encoder did until 14 Sep 2026) left BlueWallet parked at 99% whenever the
  // phone's capture rhythm kept landing on the same frame mid-repaint.
  // One pure pass + two mixed passes. Measured against @ngraveio/bc-ur with the
  // 160B default (12 pure parts): one mixed pass recovers every single-frame
  // drop but leaves 2 of 66 two-frame drops unrecoverable; two mixed passes
  // recover all of them. A clean receiver still completes after the pure pass.
  size_t total = seqLen * 3;
  if (total > (size_t)max_frags) total = (size_t)max_frags;
  if (total > UR_MAX_ENCODE_PARTS) total = UR_MAX_ENCODE_PARTS;
  if (total < seqLen) return -1;

  for (size_t i = 0; i < total; i++) {
    uint32_t seqNum = (uint32_t)(i + 1);
    uint8_t frag[UR_ENCODE_FRAG_BYTES + 16];
    memset(frag, 0, fragLen);
    // mask of source fragments: pure parts map 1:1, mixed parts via the chooser
    uint32_t mask = (seqNum <= seqLen) ? (1u << i)
                                       : ur_choose_fragments(seqNum, (int)seqLen, checksum);
    for (size_t k = 0; k < seqLen; k++) {
      if (!(mask & (1u << k))) continue;
      size_t off = k * fragLen;
      size_t copy = (off + fragLen <= msg_len) ? fragLen : (off < msg_len ? msg_len - off : 0);
      for (size_t b = 0; b < copy; b++) frag[b] ^= msg[off + b];
    }

    // build CBOR array(5): [seqNum, seqLen, messageLen, checksum, data]
    uint8_t cbor[UR_ENCODE_FRAG_BYTES + 64]; size_t c = 0;
    cbor[c++] = 0x85;                                       // array(5)
    c += ur_cbor_w_uint(cbor+c, seqNum);
    c += ur_cbor_w_uint(cbor+c, seqLen);
    c += ur_cbor_w_uint(cbor+c, msg_len);
    cbor[c++]=0x1a;                                         // checksum as uint32
    cbor[c++]=(checksum>>24)&0xFF; cbor[c++]=(checksum>>16)&0xFF;
    cbor[c++]=(checksum>>8)&0xFF;  cbor[c++]=checksum&0xFF;
    c += ur_cbor_w_bstr_hdr(cbor+c, fragLen);
    memcpy(cbor+c, frag, fragLen); c += fragLen;

    char bw[ (UR_ENCODE_FRAG_BYTES + 64) * 2 + 4 ];
    size_t bwl = ur_bw_encode(cbor, c, bw, sizeof(bw));
    if (bwl == 0) return -1;

    // "UR:<TYPE>/<seqNum>-<seqLen>/<BW>" — seqNum runs PAST seqLen for mixed
    // parts; that is how the decoder knows to run the chooser. Uppercase for
    // QR alphanumeric mode (5.5 bits/char vs 8): the UR spec requires decoders
    // to be case-insensitive, and every coordinator displays uppercase itself.
    int n = snprintf(out_frags[i], frag_cap, "ur:%s/%u-%u/%s", ur_type, (unsigned)seqNum, (unsigned)seqLen, bw);
    if (n <= 0 || (size_t)n >= frag_cap) return -1;
    for (char* q = out_frags[i]; *q; q++) if (*q>='a'&&*q<='z') *q -= 32;
  }
  return (int)total;
}

static int ur_encode_psbt(const uint8_t* psbt, size_t psbt_len,
                          char out_frags[][640], size_t frag_cap, int max_frags) {
  // wrap as CBOR byte string (the crypto-psbt message), then fragment
  static uint8_t msg[UR_MAX_MESSAGE + 8];
  size_t mh = ur_cbor_w_bstr_hdr(msg, psbt_len);
  if (mh + psbt_len > sizeof(msg)) return -1;
  memcpy(msg + mh, psbt, psbt_len);
  return ur_encode_message("crypto-psbt", msg, mh + psbt_len, out_frags, frag_cap, max_frags);
}
