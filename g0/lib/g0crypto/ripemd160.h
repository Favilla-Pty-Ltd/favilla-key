#pragma once
#include <stdint.h>
#include <stddef.h>
/* RIPEMD-160 (single-shot) and HASH160 = RIPEMD160(SHA256(x)), for BIP-32
 * fingerprints and the P2WPKH scriptCode. */
void ripemd160(const uint8_t *d, size_t n, uint8_t out[20]);
void hash160(const uint8_t *d, size_t n, uint8_t out[20]);
