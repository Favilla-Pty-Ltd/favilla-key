#pragma once
// ============================================================
// secp256k1_ecdsa.h — ECDSA signing on secp256k1 for Bitcoin.
//
// Builds on the primitives in secp256k1.h:
//   - sc_* scalar arithmetic mod n (curve order)
//   - fe_* field arithmetic mod p
//   - pt_mul_base for k*G
//   - hmac_sha256 for RFC 6979 nonce derivation
//
// Validated against the BIP-143 P2WPKH published test vector:
//   priv  = 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
//   msg   = c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
//   r     = 3609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a
//   s     = 573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee
//   DER   = 304402203609e17b...0220573a954c...
//
// All Bitcoin signatures since BIP-62 require low-S form. This impl
// always produces low-S signatures (which means RFC 6979 may need to
// iterate; in practice for k*G the first nonce works ~50% of the time
// and we negate s if it's high). The first attempt is what real
// wallets produce because k itself isn't dependent on the result —
// only s is normalised after the fact.
//
// DER encoding follows the strict format Bitcoin Core enforces in
// IsValidSignatureEncoding: 30 LEN 02 RLEN R 02 SLEN S, where R and
// S are encoded as minimal-length, non-negative DER integers (leading
// 0x00 if high bit set, no padding otherwise).
// ============================================================

#include "secp256k1.h"

// ── RFC 6979 deterministic nonce generation ───────────────────────────
//
// Section 3.2 of RFC 6979 prescribes a procedure for deriving k from
// (priv_key, msg_hash) using HMAC-SHA256. Same priv+msg always
// produces same k — so signatures are deterministic, no RNG needed.
//
// Variables follow the RFC's V/K/T notation. We return k as a scalar
// (sc) suitable for pt_mul_base().
//
// Returns false only if the derived candidate is zero or >= n on every
// HMAC iteration, which is cryptographically impossible in practice.
static bool rfc6979_nonce(const uint8_t priv32[32], const uint8_t msg32[32], sc *k_out) {
    uint8_t V[32], K[32], T[32];
    memset(V, 0x01, 32);
    memset(K, 0x00, 32);

    // K = HMAC_K(V || 0x00 || priv || msg)
    {
        uint8_t buf[32 + 1 + 32 + 32];
        memcpy(buf, V, 32);
        buf[32] = 0x00;
        memcpy(buf + 33, priv32, 32);
        memcpy(buf + 65, msg32, 32);
        hmac_sha256(K, 32, buf, sizeof(buf), K);
    }
    // V = HMAC_K(V)
    hmac_sha256(K, 32, V, 32, V);

    // K = HMAC_K(V || 0x01 || priv || msg)
    {
        uint8_t buf[32 + 1 + 32 + 32];
        memcpy(buf, V, 32);
        buf[32] = 0x01;
        memcpy(buf + 33, priv32, 32);
        memcpy(buf + 65, msg32, 32);
        hmac_sha256(K, 32, buf, sizeof(buf), K);
    }
    // V = HMAC_K(V)
    hmac_sha256(K, 32, V, 32, V);

    // Generation loop. RFC says "until a suitable k is produced".
    // Per BIP-340 / Bitcoin convention: k must be in [1, n-1].
    for (int iter = 0; iter < 100; iter++) {
        // T = HMAC_K(V), repeated until we have 32 bytes (always one iter here)
        hmac_sha256(K, 32, V, 32, T);
        memcpy(V, T, 32);

        // Interpret T as candidate k
        sc cand;
        sc_from_b32(&cand, T);
        // k must satisfy 0 < k < n. sc_reduce_once handles k >= n.
        // We accept iff after reduction k is non-zero AND the original
        // T was strictly less than n (otherwise a biased value).
        // The strict-less-than check is implicit in: if the raw T is
        // >= n we discard; the RFC 6979 spec is to re-derive.
        // Bitcoin's libsecp does: accept iff T < n and T != 0.
        // We approximate that by reducing-once and checking non-zero,
        // which is operationally equivalent for n < 2^256 (the chance
        // of reduction being needed is ~2^-128, never seen in practice).
        sc_reduce_once(&cand);
        if (!sc_is_zero(&cand)) {
            *k_out = cand;
            return true;
        }

        // K = HMAC_K(V || 0x00); V = HMAC_K(V); retry
        {
            uint8_t buf[33];
            memcpy(buf, V, 32);
            buf[32] = 0x00;
            hmac_sha256(K, 32, buf, 33, K);
        }
        hmac_sha256(K, 32, V, 32, V);
    }
    return false;
}

// ── ECDSA sign ────────────────────────────────────────────────────────
//
// Inputs:
//   priv32   — 32-byte private key, big-endian
//   msg32    — 32-byte message hash (e.g. BIP-143 sighash), big-endian
//   r_out    — 32-byte output r component
//   s_out    — 32-byte output s component, low-S normalised
//
// Returns false on degenerate inputs (zero key, r=0 — impossible in
// practice, included for safety).
static bool ecdsa_sign(const uint8_t priv32[32], const uint8_t msg32[32],
                       uint8_t r_out[32], uint8_t s_out[32]) {
    sc d;  sc_from_b32(&d, priv32);  sc_reduce_once(&d);
    if (sc_is_zero(&d)) return false;

    sc z;  sc_from_b32(&z, msg32);   sc_reduce_once(&z);

    sc k;
    if (!rfc6979_nonce(priv32, msg32, &k)) return false;
    if (sc_is_zero(&k)) return false;

    // R = k*G; r = R.x mod n
    JPt R_j; pt_mul_base(&R_j, &k);
    Pt R_aff; jpt_to_affine(&R_aff, &R_j);
    if (R_aff.inf) return false;

    // Convert R.x (a field element mod p) to a scalar mod n. This is
    // the well-known step where, with probability ~2^-128, x >= n and
    // x mod n != x. For correctness we must reduce x modulo n. The
    // simplest path: serialise x as 32 bytes, parse as scalar, reduce.
    uint8_t r_bytes[32];
    fe_norm(&R_aff.x);
    fe_to_b32(r_bytes, &R_aff.x);
    sc r;  sc_from_b32(&r, r_bytes);  sc_reduce_once(&r);
    if (sc_is_zero(&r)) return false;

    // s = k^(-1) * (z + r*d) mod n
    sc rd;  sc_mul(&rd, &r, &d);
    sc zrd; sc_add(&zrd, &z, &rd);

    // k^(-1) via Fermat: k^(n-2) mod n
    // Compute n-2 as a scalar to drive the binary ladder
    sc n_minus_2;
    {
        // n = SC_N (constant); n-2 = SC_N with low limb decremented by 2
        // SC_N[0] = 0xBFD25E8CD0364141 — well above 2, so simple subtract
        n_minus_2.n[0] = SC_N[0] - 2;
        n_minus_2.n[1] = SC_N[1];
        n_minus_2.n[2] = SC_N[2];
        n_minus_2.n[3] = SC_N[3];
    }

    // Binary exponentiation: k^(n-2)
    sc k_inv;
    {
        // Result starts at 1
        k_inv.n[0] = 1; k_inv.n[1] = 0; k_inv.n[2] = 0; k_inv.n[3] = 0;
        sc base = k;
        // 256 bits, scan low-to-high
        for (int i = 0; i < 256; i++) {
            int limb = i / 64;
            int bit  = i % 64;
            if ((n_minus_2.n[limb] >> bit) & 1ULL) {
                sc tmp;  sc_mul(&tmp, &k_inv, &base);
                k_inv = tmp;
            }
            sc base_sq; sc_mul(&base_sq, &base, &base);
            base = base_sq;
        }
    }

    sc s;  sc_mul(&s, &k_inv, &zrd);
    if (sc_is_zero(&s)) return false;

    // Low-S normalisation: if s > n/2, set s = n - s.
    // n/2 = (n-1)/2 (since n is odd) = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    // Compare s vs n/2 by serialising and comparing bytes.
    static const uint8_t N_HALF[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D, 0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
    };
    uint8_t s_bytes[32]; sc_to_b32(s_bytes, &s);
    int s_is_high = 0;
    for (int i = 0; i < 32; i++) {
        if (s_bytes[i] > N_HALF[i]) { s_is_high = 1; break; }
        if (s_bytes[i] < N_HALF[i]) { s_is_high = 0; break; }
    }
    if (s_is_high) {
        sc s_neg;
        sc_negate(&s_neg, &s);   // sc_negate computes n - s
        s = s_neg;
    }

    sc_to_b32(r_out, &r);
    sc_to_b32(s_out, &s);
    return true;
}

// ── DER encoding ──────────────────────────────────────────────────────
//
// Bitcoin's strict DER format for ECDSA signatures:
//   30 totallen 02 rlen r... 02 slen s...
// where r and s are encoded as minimal-length non-negative integers:
//   - strip leading 0x00 bytes (except keep one if it would otherwise
//     create a sign-bit-set value)
//   - if the resulting high bit is set, prepend a 0x00 byte
//
// Output buffer must be at least 72 bytes (max possible signature).
// Returns actual length written. Caller appends the sighash type byte
// (e.g. 0x01 for SIGHASH_ALL) after the DER bytes for use in scriptSig
// or witness data.
static int ecdsa_der_encode(const uint8_t r[32], const uint8_t s[32], uint8_t *out) {
    // Encode one integer in DER form. Writes to *cursor and advances it.
    // Returns the total bytes written (including the 02 LEN prefix).
    auto encode_int = [&](const uint8_t *x, uint8_t *dst) -> int {
        // Find first non-zero byte
        int start = 0;
        while (start < 31 && x[start] == 0x00) start++;
        // If the high bit of the first byte is set, prepend 0x00
        int pad = (x[start] & 0x80) ? 1 : 0;
        int len = (32 - start) + pad;
        dst[0] = 0x02;
        dst[1] = (uint8_t)len;
        if (pad) {
            dst[2] = 0x00;
            memcpy(dst + 3, x + start, 32 - start);
        } else {
            memcpy(dst + 2, x + start, 32 - start);
        }
        return 2 + len;
    };

    // Write integer fields into a scratch buffer first so we can compute
    // the outer length prefix.
    uint8_t inner[72];
    int rLen = encode_int(r, inner);
    int sLen = encode_int(s, inner + rLen);
    int innerLen = rLen + sLen;

    out[0] = 0x30;
    out[1] = (uint8_t)innerLen;
    memcpy(out + 2, inner, innerLen);
    return 2 + innerLen;
}
