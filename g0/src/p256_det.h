#pragma once
#include <stdint.h>
#include <stddef.h>
/* Deterministic P-256 ECDSA in the G0 (next G0 version, 7 Nov 2026): p256-m
 * (constant-time, ~3 KB) with RFC 6979 nonces from HMAC-SHA256, since the
 * G0B1 has no hardware RNG and a signer must never repeat or bias a nonce.
 * sig_der gets the DER signature (low-S not forced; WebAuthn accepts either).
 * Returns the DER length, or 0 on failure. priv is wiped by the caller. */
size_t p256_det_sign_der(const uint8_t priv[32], const uint8_t hash[32], uint8_t *sig_der, size_t cap);
/* v18 (7 Nov 2026): hedged. RFC 6979 section 3.6, with 32 bytes of additional
 * data k' (fresh randomness) appended to the K updates in steps d and f, so the
 * same hash and key never give the same nonce twice (a glitched signature next
 * to a good one over the same message is the classic fault attack on
 * deterministic signing). extra == NULL is plain RFC 6979 (the self-check). */
size_t p256_det_sign_der_x(const uint8_t priv[32], const uint8_t hash[32], const uint8_t extra[32], uint8_t *sig_der, size_t cap);
int p256_det_sign_raw_x(const uint8_t priv[32], const uint8_t hash[32], const uint8_t extra[32], uint8_t sig[64]);
/* The same, raw r||s (for tests). 0 ok. */
int p256_det_sign_raw(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[64]);
