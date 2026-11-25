#pragma once
#include <stdint.h>
#include <stddef.h>
/* PBKDF2-HMAC-SHA512, single 64-byte output block (dkLen = 64, so i = 1 only).
 * The HMAC inner/outer states are computed once and cloned per iteration
 * (2 compressions per round instead of 4). This is exactly what BIP-39 needs:
 * seed = PBKDF2(mnemonic, "mnemonic" || passphrase, 2048, 64). */
void pbkdf2_hmac_sha512_64(const uint8_t *pw, size_t pwlen,
                           const uint8_t *salt, size_t saltlen,
                           uint32_t iters, uint8_t out[64]);
