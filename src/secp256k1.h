#pragma once
// ============================================================
// secp256k1.h  —  native 32-bit field arithmetic  (FIXED)
// Bugs fixed vs previous version:
//   1. sc_add: carry detection was wrong (false carry when s==a[i])
//   2. sc_mul: hi*SC_R upper 4 limbs were silently discarded
//   3. nip44_padded: missing +2 for length prefix (NIP-44 spec compliance)
// ============================================================

#include <stdint.h>
#include <string.h>
#include <Arduino.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>

typedef struct { uint32_t n[8]; } fe;
typedef struct { uint64_t n[4]; } sc;
typedef struct { fe x, y; int inf; } Pt;
typedef struct { fe X, Y, Z; int inf; } JPt;

static const uint32_t FE_P[8] = {
    0xFFFFFC2FUL, 0xFFFFFFFEUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL };
static const uint64_t SC_N[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };
// 2^256 mod n
static const uint64_t SC_R[4] = {
    0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL, 0x1ULL, 0x0ULL };

static inline void fe_from_b32(fe *r, const uint8_t b[32]) {
    for (int i = 0; i < 8; i++)
        r->n[i] = ((uint32_t)b[28-4*i]<<24)|((uint32_t)b[29-4*i]<<16)|
                  ((uint32_t)b[30-4*i]<< 8)|               b[31-4*i];
}
static inline void fe_to_b32(uint8_t b[32], const fe *a) {
    for (int i = 0; i < 8; i++) {
        b[28-4*i] = (a->n[i]>>24)&0xFF; b[29-4*i] = (a->n[i]>>16)&0xFF;
        b[30-4*i] = (a->n[i]>> 8)&0xFF; b[31-4*i] =  a->n[i]     &0xFF;
    }
}
static inline void sc_from_b32(sc *r, const uint8_t b[32]) {
    for (int i = 0; i < 4; i++)
        r->n[i] = ((uint64_t)b[24-8*i]<<56)|((uint64_t)b[25-8*i]<<48)|
                  ((uint64_t)b[26-8*i]<<40)|((uint64_t)b[27-8*i]<<32)|
                  ((uint64_t)b[28-8*i]<<24)|((uint64_t)b[29-8*i]<<16)|
                  ((uint64_t)b[30-8*i]<< 8)|              b[31-8*i];
}
static inline void sc_to_b32(uint8_t b[32], const sc *a) {
    for (int i = 0; i < 4; i++) {
        b[24-8*i]=(a->n[i]>>56)&0xFF; b[25-8*i]=(a->n[i]>>48)&0xFF;
        b[26-8*i]=(a->n[i]>>40)&0xFF; b[27-8*i]=(a->n[i]>>32)&0xFF;
        b[28-8*i]=(a->n[i]>>24)&0xFF; b[29-8*i]=(a->n[i]>>16)&0xFF;
        b[30-8*i]=(a->n[i]>> 8)&0xFF; b[31-8*i]= a->n[i]     &0xFF;
    }
}

static int fe_cmp_raw(const uint32_t a[8], const uint32_t b[8]) {
    for (int i = 7; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}
static void u256_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t t = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)t;
        borrow = (t >> 32) & 1;
    }
}
static void fe_norm(fe *r) {
    if (fe_cmp_raw(r->n, FE_P) >= 0)
        u256_sub(r->n, r->n, FE_P);
}

static void fe_add(fe *r, const fe *a, const fe *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t t = (uint64_t)a->n[i] + b->n[i] + carry;
        r->n[i] = (uint32_t)t; carry = t >> 32;
    }
    if (carry) {
        uint64_t c2 = 977;
        for (int i = 0; i < 8 && c2; i++) {
            uint64_t t2 = (uint64_t)r->n[i] + c2; r->n[i] = (uint32_t)t2; c2 = t2>>32;
        }
        uint64_t c3 = 1;
        for (int i = 1; i < 8 && c3; i++) {
            uint64_t t3 = (uint64_t)r->n[i] + c3; r->n[i] = (uint32_t)t3; c3 = t3>>32;
        }
    }
    fe_norm(r);
}

static void fe_sub(fe *r, const fe *a, const fe *b) {
    uint32_t negb[8]; u256_sub(negb, FE_P, b->n);
    fe nb; memcpy(nb.n, negb, 32);
    fe_add(r, a, &nb);
}

static inline void fe_muladd(uint64_t *lo, uint64_t *hi, uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * b;
    uint64_t old  = *lo;
    *lo += prod;
    if (*lo < old) (*hi)++;
}

static void fe_mul(fe *r, const fe *a, const fe *b) {
    uint64_t t_lo[16] = {0}, t_hi[16] = {0};
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            fe_muladd(&t_lo[i+j], &t_hi[i+j], a->n[i], b->n[j]);
    for (int i = 0; i < 15; i++) {
        uint64_t c_lo = (t_lo[i] >> 32) + (t_hi[i] << 32);
        uint64_t c_hi = t_hi[i] >> 32;
        t_lo[i] &= 0xFFFFFFFF;
        t_hi[i]  = 0;
        uint64_t old = t_lo[i+1];
        t_lo[i+1] += c_lo;
        if (t_lo[i+1] < old) t_hi[i+1]++;
        t_hi[i+1] += c_hi;
    }
    uint64_t acc[9] = {0};
    for (int i = 0; i < 8; i++) {
        acc[i]   += t_lo[i] + t_lo[8+i] * 977ULL;
        acc[i+1] += t_lo[8+i];
    }
    for (int i = 0; i < 8; i++) { acc[i+1] += acc[i]>>32; acc[i] &= 0xFFFFFFFF; }
    if (acc[8]) {
        acc[0] += acc[8] * 977ULL;
        acc[1] += acc[8];
        acc[8]  = 0;
        for (int i = 0; i < 8; i++) { acc[i+1] += acc[i]>>32; acc[i] &= 0xFFFFFFFF; }
    }
    for (int i = 0; i < 8; i++) r->n[i] = (uint32_t)acc[i];
    fe_norm(r);
}

static inline void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

static inline int fe_is_zero(const fe *a) {
    fe t = *a; fe_norm(&t);
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) acc |= t.n[i];
    return acc == 0;
}
static inline int fe_is_odd(const fe *a) {
    fe t = *a; fe_norm(&t); return t.n[0] & 1;
}
static void fe_negate(fe *r, const fe *a) {
    fe z = {0}; fe_sub(r, &z, a);
}

static void fe_inv(fe *r, const fe *a) {
    static const uint32_t PM2[8] = {
        0xFFFFFC2DUL, 0xFFFFFFFEUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL };
    fe result = {0}; result.n[0] = 1;
    fe base   = *a;
    for (int i = 0; i < 256; i++) {
        if ((PM2[i/32] >> (i%32)) & 1) fe_mul(&result, &result, &base);
        fe_sqr(&base, &base);
    }
    *r = result;
}

static void fe_sqrt(fe *r, const fe *a) {
    static const uint32_t EXP[8] = {
        0xBFFFFF0CUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x3FFFFFFFUL };
    fe result = {0}; result.n[0] = 1;
    fe base   = *a;
    for (int i = 0; i < 256; i++) {
        if ((EXP[i/32] >> (i%32)) & 1) fe_mul(&result, &result, &base);
        fe_sqr(&base, &base);
    }
    *r = result;
}

static inline int sc_is_zero(const sc *a) {
    return (a->n[0]|a->n[1]|a->n[2]|a->n[3]) == 0;
}
static inline int sc_get_bit(const sc *a, int i) {
    return (a->n[i/64] >> (i%64)) & 1;
}

static void sc_reduce_once(sc *r) {
    int ge = 1;
    for (int i = 3; i >= 0; i--) {
        if (r->n[i] < SC_N[i]) { ge = 0; break; }
        if (r->n[i] > SC_N[i]) { ge = 1; break; }
    }
    if (ge) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t prev = r->n[i];
            uint64_t sub  = SC_N[i] + borrow;
            r->n[i]       = prev - sub;
            borrow        = (prev < sub) ? 1 : 0;
        }
    }
}

// ── FIX 1: sc_add ────────────────────────────────────────────────────────
static const uint64_t SC_R_LIMBS[4] = {
    0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL, 0x1ULL, 0x0ULL };

static void sc_add(sc *r, const sc *a, const sc *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t ab   = a->n[i] + b->n[i];
        uint64_t ab_c = (ab < a->n[i]) ? 1ULL : 0ULL;
        uint64_t s    = ab + carry;
        uint64_t s_c  = (s < ab) ? 1ULL : 0ULL;
        r->n[i] = s;
        carry = ab_c + s_c;
    }
    if (carry) {
        uint64_t c2 = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t old = r->n[i];
            uint64_t t   = r->n[i] + SC_R_LIMBS[i] + c2;
            c2 = (t < old || (c2 && t == old)) ? 1ULL : 0ULL;
            r->n[i] = t;
        }
    }
    sc_reduce_once(r);
}

static void sc_sub(sc *r, const sc *a, const sc *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t prev = a->n[i];
        uint64_t sub  = b->n[i] + borrow;
        r->n[i]       = prev - sub;
        borrow        = (prev < sub) ? 1 : 0;
    }
    if (borrow) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t ab   = r->n[i] + SC_N[i];
            uint64_t ab_c = (ab < r->n[i]) ? 1ULL : 0ULL;
            uint64_t s    = ab + carry;
            uint64_t s_c  = (s < ab) ? 1ULL : 0ULL;
            r->n[i] = s;
            carry = ab_c + s_c;
        }
    }
}

static inline void mul64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi) {
    uint64_t a_lo = a & 0xFFFFFFFFULL, a_hi = a >> 32;
    uint64_t b_lo = b & 0xFFFFFFFFULL, b_hi = b >> 32;
    uint64_t ll = a_lo * b_lo;
    uint64_t lh = a_lo * b_hi;
    uint64_t hl = a_hi * b_lo;
    uint64_t hh = a_hi * b_hi;
    uint64_t mid  = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
    *lo = (ll & 0xFFFFFFFFULL) | (mid << 32);
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

static inline void sc_accum(uint64_t *acc_lo, uint64_t *acc_h0, uint64_t *acc_h1, int i,
                             uint64_t prod_lo, uint64_t prod_hi) {
    uint64_t old;
    old = acc_lo[i]; acc_lo[i] += prod_lo;
    if (acc_lo[i] < old) acc_h0[i]++;
    old = acc_h0[i]; acc_h0[i] += prod_hi;
    if (acc_h0[i] < old) acc_h1[i]++;
}

// ── FIX 2: sc_mul ────────────────────────────────────────────────────────
static void sc_mul(sc *r, const sc *a, const sc *b) {
    uint64_t t_lo[8]={0}, t_h0[8]={0}, t_h1[8]={0};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            uint64_t plo, phi;
            mul64(a->n[i], b->n[j], &plo, &phi);
            sc_accum(t_lo, t_h0, t_h1, i+j, plo, phi);
        }
    for (int i = 0; i < 7; i++) {
        uint64_t c_lo = t_h0[i];
        uint64_t c_hi = t_h1[i];
        t_h0[i] = 0; t_h1[i] = 0;
        uint64_t old = t_lo[i+1]; t_lo[i+1] += c_lo;
        if (t_lo[i+1] < old) c_hi++;
        t_h0[i+1] += c_hi;
    }

    sc lo, hi;
    for (int i = 0; i < 4; i++) { lo.n[i] = t_lo[i]; hi.n[i] = t_lo[4+i]; }
    sc_reduce_once(&lo);

    sc result = lo;
    while (!sc_is_zero(&hi)) {
        uint64_t t2_lo[8]={0}, t2_h0[8]={0}, t2_h1[8]={0};
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++) {
                uint64_t plo, phi;
                mul64(hi.n[i], SC_R_LIMBS[j], &plo, &phi);
                sc_accum(t2_lo, t2_h0, t2_h1, i+j, plo, phi);
            }
        for (int i = 0; i < 7; i++) {
            uint64_t c_lo = t2_h0[i], c_hi = t2_h1[i];
            t2_h0[i] = 0; t2_h1[i] = 0;
            uint64_t old = t2_lo[i+1]; t2_lo[i+1] += c_lo;
            if (t2_lo[i+1] < old) c_hi++;
            t2_h0[i+1] += c_hi;
        }
        sc contrib_lo, contrib_hi;
        for (int i=0;i<4;i++) { contrib_lo.n[i]=t2_lo[i]; contrib_hi.n[i]=t2_lo[4+i]; }
        sc_reduce_once(&contrib_lo);
        sc_add(&result, &result, &contrib_lo);
        hi = contrib_hi;
    }
    *r = result;
}

static void sc_negate(sc *r, const sc *a) {
    if (sc_is_zero(a)) { *r = *a; return; }
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t sub = a->n[i] + borrow;
        r->n[i]      = SC_N[i] - sub;
        borrow       = (SC_N[i] < sub) ? 1 : 0;
    }
}

static void tagged_hash(const char *tag, const uint8_t *data, size_t dlen, uint8_t out[32]) {
    uint8_t th[32];
    mbedtls_sha256((const uint8_t *)tag, strlen(tag), th, 0);
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, th, 32);
    mbedtls_sha256_update(&ctx, th, 32);
    mbedtls_sha256_update(&ctx, data, dlen);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

static void jpt_dbl(JPt *R, const JPt *P) {
    if (P->inf) { R->inf = 1; return; }
    fe Y2, S, M, t2, X3, Y3, Z3, t;
    fe_sqr(&Y2, &P->Y);
    fe_mul(&S, &P->X, &Y2); fe_add(&S,&S,&S); fe_add(&S,&S,&S);
    fe_sqr(&M, &P->X); t2=M; fe_add(&M,&M,&t2); fe_add(&M,&M,&t2);
    fe_sqr(&X3, &M); fe_sub(&X3,&X3,&S); fe_sub(&X3,&X3,&S);
    fe_sub(&Y3, &S, &X3); fe_mul(&Y3,&M,&Y3);
    fe_sqr(&t, &Y2); fe_add(&t,&t,&t); fe_add(&t,&t,&t); fe_add(&t,&t,&t);
    fe_sub(&Y3, &Y3, &t);
    fe_mul(&Z3, &P->Y, &P->Z); fe_add(&Z3,&Z3,&Z3);
    R->X=X3; R->Y=Y3; R->Z=Z3; R->inf=0;
}

static void jpt_madd(JPt *R, const JPt *P, const Pt *Q) {
    if (P->inf) {
        R->X=Q->x; R->Y=Q->y;
        memset(R->Z.n, 0, 32); R->Z.n[0]=1;
        R->inf = 0; return;
    }
    fe Z2, Z3, U2, S2, H, r2, H2, H3, X3, Y3, Z3r, tmp;
    fe_sqr(&Z2, &P->Z); fe_mul(&Z3,&Z2,&P->Z);
    fe_mul(&U2,&Q->x,&Z2); fe_mul(&S2,&Q->y,&Z3);
    fe_sub(&H,&U2,&P->X);  fe_sub(&r2,&S2,&P->Y);
    if (fe_is_zero(&H)) {
        if (fe_is_zero(&r2)) { jpt_dbl(R, P); }
        else                 { R->inf = 1; }
        return;
    }
    fe_sqr(&H2,&H); fe_mul(&H3,&H2,&H);
    fe_sqr(&X3,&r2);
    fe_sub(&X3,&X3,&H3);
    fe_mul(&tmp,&P->X,&H2); fe_sub(&X3,&X3,&tmp); fe_sub(&X3,&X3,&tmp);
    fe_sub(&Y3,&tmp,&X3); fe_mul(&Y3,&r2,&Y3);
    fe_mul(&tmp,&P->Y,&H3); fe_sub(&Y3,&Y3,&tmp);
    fe_mul(&Z3r,&P->Z,&H);
    R->X=X3; R->Y=Y3; R->Z=Z3r; R->inf=0;
}

static void jpt_to_affine(Pt *r, const JPt *P) {
    if (P->inf) { r->inf=1; return; }
    fe zi, z2i, z3i;
    fe_inv(&zi, &P->Z);
    fe_sqr(&z2i, &zi);
    fe_mul(&z3i, &z2i, &zi);
    fe_mul(&r->x, &P->X, &z2i);
    fe_mul(&r->y, &P->Y, &z3i);
    r->inf = 0;
}

static Pt G_pt;
static bool G_init = false;
static void init_G() {
    if (G_init) return;
    static const uint8_t gx[32] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98 };
    static const uint8_t gy[32] = {
        0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
        0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8 };
    fe_from_b32(&G_pt.x, gx);
    fe_from_b32(&G_pt.y, gy);
    G_pt.inf = 0; G_init = true;
}

static void pt_mul_base(JPt *R, const sc *k) {
    init_G();
    R->inf = 1;
    for (int i = 255; i >= 0; i--) {
        JPt tmp = *R; jpt_dbl(R, &tmp);
        if (sc_get_bit(k, i)) { tmp = *R; jpt_madd(R, &tmp, &G_pt); }
    }
}

static void pt_mul_pt(JPt *R, const sc *k, const Pt *Q) {
    R->inf = 1;
    for (int i = 255; i >= 0; i--) {
        JPt tmp = *R; jpt_dbl(R, &tmp);
        if (sc_get_bit(k, i)) { tmp = *R; jpt_madd(R, &tmp, Q); }
    }
}

inline bool schnorr_sign(const uint8_t priv32[32], const uint8_t msg32[32], uint8_t sig64[64]) {
    sc d; sc_from_b32(&d, priv32);
    sc_reduce_once(&d);
    if (sc_is_zero(&d)) return false;

    JPt Pj; pt_mul_base(&Pj, &d);
    Pt  P;  jpt_to_affine(&P, &Pj);
    if (fe_is_odd(&P.y)) {
        sc_negate(&d, &d);
        pt_mul_base(&Pj, &d);
        jpt_to_affine(&P, &Pj);
    }

    uint8_t db[32]; sc_to_b32(db, &d);
    uint8_t ni[64]; memcpy(ni, db, 32); memcpy(ni+32, msg32, 32);
    uint8_t kb[32]; tagged_hash("BIP0340/nonce", ni, 64, kb);
    sc k; sc_from_b32(&k, kb); sc_reduce_once(&k);
    if (sc_is_zero(&k)) return false;

    JPt Rj; pt_mul_base(&Rj, &k);
    Pt  Ra; jpt_to_affine(&Ra, &Rj);
    if (fe_is_odd(&Ra.y)) { sc_negate(&k, &k); }

    uint8_t rx[32], px[32];
    fe_to_b32(rx, &Ra.x); fe_to_b32(px, &P.x);
    uint8_t ch[96]; memcpy(ch, rx, 32); memcpy(ch+32, px, 32); memcpy(ch+64, msg32, 32);
    uint8_t eb[32]; tagged_hash("BIP0340/challenge", ch, 96, eb);
    sc e; sc_from_b32(&e, eb);

    sc ed; sc_mul(&ed, &e, &d);
    sc s;  sc_add(&s, &k, &ed);

    memcpy(sig64, rx, 32);
    sc_to_b32(sig64+32, &s);
    return true;
}

inline bool bip340_make_key(uint8_t priv32[32], uint8_t pub32[32]) {
    sc d; sc_from_b32(&d, priv32); sc_reduce_once(&d);
    if (sc_is_zero(&d)) return false;
    JPt Pj; pt_mul_base(&Pj, &d);
    Pt  P;  jpt_to_affine(&P, &Pj);
    if (fe_is_odd(&P.y)) {
        sc_negate(&d, &d);
        pt_mul_base(&Pj, &d);
        jpt_to_affine(&P, &Pj);
    }
    sc_to_b32(priv32, &d);
    fe_to_b32(pub32, &P.x);
    return true;
}

static bool ecdh_raw(const uint8_t priv32[32], const uint8_t xpub32[32], uint8_t shared[32]) {
    sc d; sc_from_b32(&d, priv32); sc_reduce_once(&d);
    if (sc_is_zero(&d)) return false;
    fe x, y, t;
    fe_from_b32(&x, xpub32);
    fe_sqr(&t, &x); fe_mul(&t, &t, &x);
    fe c7 = {0}; c7.n[0] = 7; fe_add(&t, &t, &c7);
    fe_sqrt(&y, &t);
    // SEC: invalid-curve check. fe_sqrt is a blind (p+1)/4 exponentiation and
    // returns an arbitrary value when t is a non-residue, i.e. when xpub32 is
    // not the x-coordinate of a secp256k1 point. Without this check we would
    // run a scalar mult with the private key on an attacker-supplied point of
    // unknown group structure. Verify y^2 == x^3 + 7 and fail closed.
    { fe y2, dz; fe_sqr(&y2, &y); fe_sub(&dz, &y2, &t);
      if (!fe_is_zero(&dz)) return false; }
    if (fe_is_odd(&y)) fe_negate(&y, &y);
    Pt Q; Q.x=x; Q.y=y; Q.inf=0;
    JPt Rj; pt_mul_pt(&Rj, &d, &Q);
    if (Rj.inf) return false;
    Pt R; jpt_to_affine(&R, &Rj);
    fe_to_b32(shared, &R.x);
    return true;
}

// 23 Nov 2026 (#61): constant-time ECDH for a LONG-TERM secret scalar.
// ecdh_raw's pt_mul_pt is double-and-add with data-dependent branches, which
// a caller who picks the point can time (the /api/session es term against the
// pairing key g_dDevice). This one runs the scalar multiply in mbedTLS
// (mbedtls_ecp_mul on secp256k1: a fixed comb, with coordinate blinding from
// the RNG). Lifting x to the even-y point and the curve check stay in the code
// above: they only touch the public point. Same answer as ecdh_raw.
#include <mbedtls/ecp.h>
#ifdef ESP_PLATFORM
#include <esp_random.h>
static int ecdh_ct_rng(void*, unsigned char* out, size_t n) { esp_fill_random(out, n); return 0; }
#else
#include <stdlib.h>
static int ecdh_ct_rng(void*, unsigned char* out, size_t n) { for (size_t i = 0; i < n; i++) out[i] = (unsigned char)rand(); return 0; }   // host tests only
#endif
static bool ecdh_ct(const uint8_t priv32[32], const uint8_t xpub32[32], uint8_t shared[32]) {
    // Public half: lift x to the even-y point, fail closed off the curve.
    fe x, y, t;
    fe_from_b32(&x, xpub32);
    fe_sqr(&t, &x); fe_mul(&t, &t, &x);
    fe c7 = {0}; c7.n[0] = 7; fe_add(&t, &t, &c7);
    fe_sqrt(&y, &t);
    { fe y2, dz; fe_sqr(&y2, &y); fe_sub(&dz, &y2, &t);
      if (!fe_is_zero(&dz)) return false; }
    if (fe_is_odd(&y)) fe_negate(&y, &y);
    uint8_t q65[65]; q65[0] = 0x04; fe_to_b32(q65 + 1, &x); fe_to_b32(q65 + 33, &y);
    // Secret half: mbedTLS.
    mbedtls_ecp_group grp; mbedtls_ecp_point Q, R; mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&Q); mbedtls_ecp_point_init(&R); mbedtls_mpi_init(&d);
    bool ok = false;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) == 0 &&
        mbedtls_ecp_point_read_binary(&grp, &Q, q65, sizeof q65) == 0 &&
        mbedtls_ecp_check_pubkey(&grp, &Q) == 0 &&
        mbedtls_mpi_read_binary(&d, priv32, 32) == 0 &&
        mbedtls_mpi_cmp_int(&d, 0) > 0 && mbedtls_mpi_cmp_mpi(&d, &grp.N) < 0 &&
        mbedtls_ecp_mul(&grp, &R, &d, &Q, ecdh_ct_rng, nullptr) == 0 &&
        mbedtls_ecp_is_zero(&R) == 0) {
        uint8_t r65[65]; size_t rl = 0;   // R.X is private in mbedTLS 3: write the point and take x
        if (mbedtls_ecp_point_write_binary(&grp, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &rl, r65, sizeof r65) == 0 && rl == 65) {
            memcpy(shared, r65 + 1, 32); ok = true;
        }
        memset(r65, 0, sizeof r65);
    }
    mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&R); mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp);
    memset(q65, 0, sizeof q65);
    if (!ok) memset(shared, 0, 32);
    return ok;
}

static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static inline int b64v(char c) {
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52;
    if (c=='+') return 62; if (c=='/') return 63; return -1;
}
static String b64_enc(const uint8_t *d, size_t len) {
    String o; o.reserve(((len+2)/3)*4+1);
    for (size_t i=0; i<len; i+=3) {
        uint32_t b=((uint32_t)d[i]<<16)|(i+1<len?(uint32_t)d[i+1]<<8:0)|(i+2<len?d[i+2]:0);
        o+=B64T[(b>>18)&0x3F]; o+=B64T[(b>>12)&0x3F];
        o+=(i+1<len)?B64T[(b>>6)&0x3F]:'=';
        o+=(i+2<len)?B64T[b&0x3F]:'=';
    }
    return o;
}
static size_t b64_dec(const String &in, uint8_t *out, size_t cap) {
    size_t n=in.length(), ol=0;
    for (size_t i=0; i<n; i+=4) {
        int v0=b64v(in[i]), v1=(i+1<n)?b64v(in[i+1]):-1;
        int v2=(i+2<n&&in[i+2]!='=')?b64v(in[i+2]):0;
        int v3=(i+3<n&&in[i+3]!='=')?b64v(in[i+3]):0;
        if (v0<0||v1<0) break;
        uint32_t b=((uint32_t)v0<<18)|((uint32_t)v1<<12)|((uint32_t)v2<<6)|v3;
        if (ol<cap) out[ol++]=(b>>16)&0xFF;
        if (i+2<n&&in[i+2]!='='&&ol<cap) out[ol++]=(b>>8)&0xFF;
        if (i+3<n&&in[i+3]!='='&&ol<cap) out[ol++]=b&0xFF;
    }
    return ol;
}

// -----------------------------------------------------------------------------
// nostr_ecdh — identity-key ECDH, routed to the isolated signer (STM32G0)
//
// Every NIP-04 / NIP-44 operation below used to call ecdh_raw() with the Nostr
// scalar unwrapped into ESP32 RAM. That scalar now never enters this processor:
// it is sealed under K_G0 on the G0, so the shared secret has to be computed
// there. g0_init() (g0_signer.cpp) installs g_nostr_ecdh_hook = g0_ecdh; until
// it does, this FAILS CLOSED rather than falling back to RAM ECDH.
//
// The `priv` argument is kept so the nip04_/nip44_ signatures are unchanged,
// but it is IGNORED — callers pass nullptr. There is deliberately no
// "priv != nullptr -> local ecdh_raw" fallback: that would be a silent RAM path
// for the identity key the moment anyone reintroduced a scalar buffer.
//
// ecdh_raw() itself is untouched and still used for EPHEMERAL keys (session
// pairing in session_sec_http.h), which are correctly handled locally.
// -----------------------------------------------------------------------------
extern bool (*g_nostr_ecdh_hook)(const uint8_t peer_xonly32[32], uint8_t shared[32]);
static inline bool nostr_ecdh(const uint8_t * /*priv_unused*/,
                              const uint8_t xpub32[32], uint8_t shared[32]) {
    if (!g_nostr_ecdh_hook) {
        Serial.println("[ECDH] nostr_ecdh: isolated signer hook not installed - refusing");
        return false;
    }
    return g_nostr_ecdh_hook(xpub32, shared);
}

inline String nip04_encrypt_raw(const uint8_t *priv, const uint8_t *xpub,
                                 const char *pt, const uint8_t *iv16) {
    uint8_t sh[32]; if (!nostr_ecdh(priv,xpub,sh)) return "";
    size_t pl=strlen(pt), pad=((pl/16)+1)*16;
    uint8_t *buf=(uint8_t*)malloc(pad); if (!buf) return "";
    memcpy(buf,pt,pl); uint8_t p=(uint8_t)(pad-pl); memset(buf+pl,p,p);
    uint8_t *ct=(uint8_t*)malloc(pad); if (!ct){free(buf);return"";}
    mbedtls_aes_context aes; mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes,sh,256);
    uint8_t iv2[16]; memcpy(iv2,iv16,16);
    mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_ENCRYPT,pad,iv2,buf,ct);
    mbedtls_aes_free(&aes); free(buf);
    String r=b64_enc(ct,pad)+"?iv="+b64_enc(iv16,16);
    free(ct); return r;
}
inline String nip04_decrypt_raw(const uint8_t *priv, const uint8_t *xpub, const char *ciphertext) {
    String s=ciphertext; int idx=s.indexOf("?iv="); if (idx<0) return "";
    String b64ct=s.substring(0,idx), b64iv=s.substring(idx+4);
    uint8_t iv[16]; if (b64_dec(b64iv,iv,16)<16) return "";
    size_t cap=((b64ct.length()/4)+1)*3;
    uint8_t *c=(uint8_t*)malloc(cap); if (!c) return "";
    size_t cl=b64_dec(b64ct,c,cap);
    if (!cl||cl%16) { free(c); return ""; }
    uint8_t sh[32]; if (!nostr_ecdh(priv,xpub,sh)){free(c);return"";}
    uint8_t *pl=(uint8_t*)malloc(cl+1); if (!pl){free(c);return"";}
    mbedtls_aes_context aes; mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes,sh,256);
    uint8_t iv2[16]; memcpy(iv2,iv,16);
    mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_DECRYPT,cl,iv2,c,pl);
    mbedtls_aes_free(&aes); free(c);
    uint8_t pad=pl[cl-1]; if (pad>16) pad=0;
    pl[cl-pad]=0;
    String res=(char*)pl; free(pl); return res;
}

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define QR(a,b,c,d) \
  a+=b;d^=a;d=ROTL32(d,16);c+=d;b^=c;b=ROTL32(b,12); \
  a+=b;d^=a;d=ROTL32(d,8); c+=d;b^=c;b=ROTL32(b,7);
static void cc20_block(const uint32_t *st, uint8_t *out) {
    uint32_t x[16]; memcpy(x,st,64);
    for (int i=0;i<10;i++){
        QR(x[0],x[4],x[8], x[12]); QR(x[1],x[5],x[9], x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8], x[13]); QR(x[3],x[4],x[9], x[14]);
    }
    for (int i=0;i<16;i++) {
        uint32_t v=x[i]+st[i];
        out[i*4]=(uint8_t)v; out[i*4+1]=(uint8_t)(v>>8);
        out[i*4+2]=(uint8_t)(v>>16); out[i*4+3]=(uint8_t)(v>>24);
    }
}
static void cc20_xor(const uint8_t *key, const uint8_t *n12, uint32_t ctr,
                     const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t st[16];
    st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
    for (int i=0;i<8;i++) st[4+i]=(uint32_t)key[i*4]|((uint32_t)key[i*4+1]<<8)|
                                   ((uint32_t)key[i*4+2]<<16)|((uint32_t)key[i*4+3]<<24);
    st[12]=ctr;
    for (int i=0;i<3;i++) st[13+i]=(uint32_t)n12[i*4]|((uint32_t)n12[i*4+1]<<8)|
                                    ((uint32_t)n12[i*4+2]<<16)|((uint32_t)n12[i*4+3]<<24);
    uint8_t ks[64];
    for (size_t d=0; d<len; d+=64, st[12]++) {
        cc20_block(st,ks);
        size_t c=len-d<64?len-d:64;
        for (size_t j=0;j<c;j++) out[d+j]=in[d+j]^ks[j];
    }
}

static void hmac_sha256(const uint8_t *k,size_t kl,const uint8_t *d,size_t dl,uint8_t *out){
    mbedtls_md_context_t c; mbedtls_md_init(&c);
    mbedtls_md_setup(&c,mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),1);
    mbedtls_md_hmac_starts(&c,k,kl);
    mbedtls_md_hmac_update(&c,d,dl);
    mbedtls_md_hmac_finish(&c,out);
    mbedtls_md_free(&c);
}
static void hkdf_extract(const uint8_t *salt,size_t sl,const uint8_t *ikm,size_t il,uint8_t *prk){
    hmac_sha256(salt,sl,ikm,il,prk);
}
static void hkdf_expand(const uint8_t *prk,size_t pl,const uint8_t *info,size_t il,uint8_t *out,size_t olen){
    uint8_t T[32]={0}; size_t done=0; uint8_t ctr=1;
    mbedtls_md_context_t c; mbedtls_md_init(&c);
    mbedtls_md_setup(&c,mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),1);
    while (done<olen) {
        mbedtls_md_hmac_starts(&c,prk,pl);
        if (ctr>1) mbedtls_md_hmac_update(&c,T,32);
        if (il)    mbedtls_md_hmac_update(&c,info,il);
        mbedtls_md_hmac_update(&c,&ctr,1);
        mbedtls_md_hmac_finish(&c,T);
        size_t cp=olen-done<32?olen-done:32; memcpy(out+done,T,cp);
        done+=cp; ctr++;
    }
    mbedtls_md_free(&c);
}

// nip44_padded: original size (PWA-compatible, used by nip_encrypt/nip_decrypt pair)
static size_t nip44_padded(size_t msglen) {
    // V-2 fix: the padded buffer also carries a 2-byte length prefix, so the
    // returned size must include it (was missing +2 -> 1-2 byte heap overflow
    // when msglen landed on a chunk boundary). Now matches nip44_padded_spec.
    if (msglen<=32) return 34;
    uint32_t v=(uint32_t)(msglen-1); int lz=__builtin_clz(v);
    uint32_t np=1u<<(32-lz); size_t chunk=(np<=256)?32:(size_t)(np/8);
    return chunk*((msglen-1)/chunk+1) + 2;
}

// nip44_padded_spec: NIP-44 v2 spec-compliant size (+2 for length prefix)
// Used by nip44_encrypt_bunker for interop with standard clients (Coracle, Nostrudel etc.)
static size_t nip44_padded_spec(size_t msglen) {
    if (msglen<=32) return 34;
    uint32_t v=(uint32_t)(msglen-1); int lz=__builtin_clz(v);
    uint32_t np=1u<<(32-lz); size_t chunk=(np<=256)?32:(size_t)(np/8);
    return chunk*((msglen-1)/chunk+1) + 2;
}
static bool nip44_conv_key(const uint8_t *op,const uint8_t *tp,uint8_t *ck){
    uint8_t sh[32]; if (!nostr_ecdh(op,tp,sh)) return false;
    const uint8_t salt[]="nip44-v2"; hkdf_extract(salt,8,sh,32,ck); return true;
}
// Set by nip44_decrypt when the last payload carried MORE than the NIP-44
// maximum of 65535 plaintext bytes (the 2-byte length prefix had wrapped).
// Some clients (seen: Nostrich, a 97 KB kind:3 sign_event, 7 Oct 2026) do not
// enforce the limit; the true length is recovered from the ciphertext size.
// The NIP-46 responder reads this to answer such a client in the same dialect.
static bool g_nip44_oversize_rx = false;
inline String nip44_decrypt(const uint8_t *op,const uint8_t *tp,const char *cb64){
    size_t md=((strlen(cb64)/4)+1)*3;
    uint8_t *blob=(uint8_t*)malloc(md); if (!blob) return "";
    size_t bl=b64_dec(String(cb64),blob,md);
    if (bl<99||blob[0]!=0x02){Serial.printf("NIP-44: bad blob len=%d\n",(int)bl);free(blob);return"";}
    uint8_t *nonce=blob+1, *ct=blob+33;
    size_t cl=bl-33-32; uint8_t *mr=blob+bl-32;
    uint8_t ck[32]; if (!nip44_conv_key(op,tp,ck)){free(blob);return"";}
    uint8_t keys[76]; hkdf_expand(ck,32,nonce,32,keys,76);
    uint8_t *ckey=keys, *cnonce=keys+32, *hkey=keys+44;
    uint8_t *mi=(uint8_t*)malloc(32+cl); if (!mi){free(blob);return"";}
    memcpy(mi,nonce,32); memcpy(mi+32,ct,cl);
    uint8_t mc[32]; hmac_sha256(hkey,32,mi,32+cl,mc); free(mi);
    if (memcmp(mc,mr,32)){Serial.println("NIP-44: MAC FAILED");free(blob);return"";}
    uint8_t *plain=(uint8_t*)malloc(cl+1); if (!plain){free(blob);return"";}
    cc20_xor(ckey,cnonce,0,ct,plain,cl); free(blob);
    uint16_t ml=((uint16_t)plain[0]<<8)|plain[1];
    size_t L=ml; g_nip44_oversize_rx=false;
    if (cl-2>65535) {
        // Beyond the spec maximum: the sender wrote (len mod 65536). The spec
        // padding is a function of the real length, so exactly one candidate
        // len = ml + 65536*k reproduces this ciphertext size. Take it.
        for (size_t cand=(size_t)ml+65536; cand<=cl-2; cand+=65536) {
            if (nip44_padded_spec(cand)==cl) { L=cand; g_nip44_oversize_rx=true; break; }
        }
        if (!g_nip44_oversize_rx && ml==0 && cl>6) {
            // Nostrich dialect: 6-byte big-endian length prefix (00 00 LL LL LL LL),
            // then spec chunk padding. Exact-size check before trusting it.
            size_t L6=((size_t)plain[2]<<24)|((size_t)plain[3]<<16)|((size_t)plain[4]<<8)|plain[5];
            if (L6>0 && L6<=cl-6 && nip44_padded_spec(L6)-2+6==cl) {
                g_nip44_oversize_rx=true;
                plain[6+L6]=0; String res=(char*)(plain+6); free(plain);
                Serial.printf("NIP-44: oversize payload cl=%u, 6-byte prefix -> len %u\n",(unsigned)cl,(unsigned)L6);
                return res;
            }
        }
        if (!g_nip44_oversize_rx) {
            // The prefix does not describe this ciphertext (seen: prefix=0,
            // cl=98310 from Nostrich). The MAC has already proven the bytes
            // authentic and every NIP-46 payload is a JSON object, so take the
            // outermost {...} span wherever the sender's library put it.
            Serial.printf("NIP-44: oversize payload cl=%u prefix=%u, head %02x%02x%02x%02x%02x%02x%02x%02x - scanning for JSON\n",
                          (unsigned)cl,(unsigned)ml,plain[0],plain[1],plain[2],plain[3],plain[4],plain[5],plain[6],plain[7]);
            size_t a=0; while (a<cl && plain[a]!='{') a++;
            size_t b=cl; while (b>a && plain[b-1]!='}') b--;
            if (a<cl && b>a) {
                g_nip44_oversize_rx=true;
                plain[b]=0; String res=(char*)(plain+a); free(plain);
                Serial.printf("NIP-44: oversize recovered by scan: json at %u..%u (%u bytes)\n",(unsigned)a,(unsigned)b,(unsigned)(b-a));
                return res;
            }
        } else {
            Serial.printf("NIP-44: oversize payload cl=%u prefix=%u -> len %u (recovered)\n",(unsigned)cl,(unsigned)ml,(unsigned)L);
        }
    }
    if (L>cl-2){Serial.printf("NIP-44: bad len %u\n",(unsigned)L);free(plain);return"";}
    plain[2+L]=0; String res=(char*)(plain+2); free(plain); return res;
}
inline String nip44_encrypt(const uint8_t *op,const uint8_t *tp,const char *pt,const uint8_t *n32){
    uint8_t ck[32]; if (!nip44_conv_key(op,tp,ck)) return "";
    uint8_t keys[76]; hkdf_expand(ck,32,n32,32,keys,76);
    uint8_t *ckey=keys, *cnonce=keys+32, *hkey=keys+44;
    size_t plen=strlen(pt), padded=nip44_padded(plen);
    uint8_t *pad=(uint8_t*)calloc(padded,1); if (!pad) return "";
    pad[0]=(uint8_t)(plen>>8); pad[1]=(uint8_t)plen; memcpy(pad+2,pt,plen);
    uint8_t *cipher=(uint8_t*)malloc(padded); if (!cipher){free(pad);return"";}
    cc20_xor(ckey,cnonce,0,pad,cipher,padded); free(pad);
    uint8_t *mi=(uint8_t*)malloc(32+padded); if (!mi){free(cipher);return"";}
    memcpy(mi,n32,32); memcpy(mi+32,cipher,padded);
    uint8_t mac[32]; hmac_sha256(hkey,32,mi,32+padded,mac); free(mi);
    size_t total=1+32+padded+32;
    uint8_t *blob=(uint8_t*)malloc(total); if (!blob){free(cipher);return"";}
    blob[0]=0x02; memcpy(blob+1,n32,32); memcpy(blob+33,cipher,padded);
    memcpy(blob+33+padded,mac,32); free(cipher);
    String res=b64_enc(blob,total); free(blob); return res;
}

// nip44_encrypt_bunker: spec-compliant NIP-44 v2 for interop with standard clients.
// Uses nip44_padded_spec (+2 for length prefix) instead of nip44_padded.
// Use this for NIP-46 bunker responses. Use nip44_encrypt/nip_encrypt for PWA.
inline String nip44_encrypt_bunker(const uint8_t *op,const uint8_t *tp,const char *pt,const uint8_t *n32){
    uint8_t ck[32]; if (!nip44_conv_key(op,tp,ck)) return "";
    uint8_t keys[76]; hkdf_expand(ck,32,n32,32,keys,76);
    uint8_t *ckey=keys, *cnonce=keys+32, *hkey=keys+44;
    size_t plen=strlen(pt), padded=nip44_padded_spec(plen);
    // Over the NIP-44 maximum (65535): mirror the dialect observed from
    // Nostrich on 7 Oct 2026 — a 6-byte big-endian length prefix, then the
    // spec chunk padding. (Its 98310-byte request decoded as 00 00 00 01 4f f8
    // = 86008, data, zeros to a 16384 boundary.) Only reached when the caller
    // has decided to answer an oversize request in kind.
    size_t hdr = (plen > 65535) ? 6 : 2;
    if (hdr == 6) padded = nip44_padded_spec(plen) - 2 + 6;
    uint8_t *pad=(uint8_t*)calloc(padded,1); if (!pad) return "";
    if (hdr == 6) { pad[0]=0; pad[1]=0; pad[2]=(uint8_t)(plen>>24); pad[3]=(uint8_t)(plen>>16); pad[4]=(uint8_t)(plen>>8); pad[5]=(uint8_t)plen; }
    else          { pad[0]=(uint8_t)(plen>>8); pad[1]=(uint8_t)plen; }
    memcpy(pad+hdr,pt,plen);
    uint8_t *cipher=(uint8_t*)malloc(padded); if (!cipher){free(pad);return"";}
    cc20_xor(ckey,cnonce,0,pad,cipher,padded); free(pad);
    uint8_t *mi=(uint8_t*)malloc(32+padded); if (!mi){free(cipher);return"";}
    memcpy(mi,n32,32); memcpy(mi+32,cipher,padded);
    uint8_t mac[32]; hmac_sha256(hkey,32,mi,32+padded,mac); free(mi);
    size_t total=1+32+padded+32;
    uint8_t *blob=(uint8_t*)malloc(total); if (!blob){free(cipher);return"";}
    blob[0]=0x02; memcpy(blob+1,n32,32); memcpy(blob+33,cipher,padded);
    memcpy(blob+33+padded,mac,32); free(cipher);
    String res=b64_enc(blob,total); free(blob); return res;
}

inline String nip_decrypt(const uint8_t *op,const uint8_t *tp,const char *content){
    if (strstr(content,"?iv=")) return nip04_decrypt_raw(op,tp,content);
    return nip44_decrypt(op,tp,content);
}
inline String nip_encrypt(const uint8_t *op,const uint8_t *tp,const char *pt,const uint8_t *iv){
    return nip44_encrypt(op,tp,pt,iv);
}
