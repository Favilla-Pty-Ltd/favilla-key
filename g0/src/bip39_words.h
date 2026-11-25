#pragma once
#include <stdint.h>
#include <stddef.h>
/* BIP-39 English word list, packed: one NUL-separated string plus a 16-bit
 * offset table. Generated from the ESP32's src/bip39_wordlist.h (24 Sep 2026)
 * so both chips derive from the same table. ~17212 bytes of flash. */
#define BIP39_WORDS 2048
const char *bip39_word(uint16_t idx);
/* entropy (16 or 32 bytes for wc 12/24) -> space-separated mnemonic with the
 * BIP-39 checksum appended. Returns the length written (no NUL counted) or
 * -1 if wc is not 12/24 or cap is too small (max 215 + NUL). */
int bip39_mnemonic_from_entropy(const uint8_t *ent, int wc, char *out, size_t cap);
