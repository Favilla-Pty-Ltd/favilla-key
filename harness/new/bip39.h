#pragma once
// BIP39 + NIP-06 key derivation for Favilla Key
// Requires: bip39_wordlist.h (official 2048-word list)
// Uses: mbedtls (included in ESP32 Arduino core)

#include <stdint.h>
#include <string.h>
#include "shim.h"
#include "bip39_wordlist.h"

// ── BIP39 ─────────────────────────────────────────────────────────────────

// Generate mnemonic from entropy bytes
// entropy: 16 bytes = 12 words, 32 bytes = 24 words
// words_out: array of char[12] pointers, caller provides storage
// returns true on success
bool bip39_entropy_to_words(const uint8_t* entropy, int entropy_len,
                             char words_out[][12], int* word_count_out) {
  // 1. SHA256 checksum
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, entropy, entropy_len);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  int bits = entropy_len * 8;
  int cs_bits = bits / 32;
  int total_bits = bits + cs_bits;
  int word_count = total_bits / 11;
  *word_count_out = word_count;

  // 2. Concatenate entropy + checksum bits into a bit array
  // Max: 264 bits = 33 bytes
  uint8_t data[33] = {0};
  memcpy(data, entropy, entropy_len);
  // Append checksum byte (top cs_bits of hash)
  data[entropy_len] = hash[0];

  // 3. Extract 11-bit groups
  for (int i = 0; i < word_count; i++) {
    int bit_start = i * 11;
    int byte_idx = bit_start / 8;
    int bit_off = bit_start % 8;

    // Read 3 bytes to safely handle 11-bit groups at any bit offset
    // F5: read the third byte only if it exists. For 24 words the final
    // 11-bit group starts at byte 31 of a 33-byte buffer, so an
    // unconditional 3-byte read touches data[33] — one past the end. The
    // value was always shifted away, so there was no functional impact, but
    // it is a genuine out-of-bounds read that ASan flags.
    uint32_t val = ((uint32_t)data[byte_idx] << 16) |
                   ((uint32_t)data[byte_idx + 1] << 8) |
                   ((byte_idx + 2 < (int)sizeof(data)) ? (uint32_t)data[byte_idx + 2] : 0u);
    val = (val >> (13 - bit_off)) & 0x7FF;

    // Copy word from PROGMEM
    strncpy(words_out[i], BIP39_WORDS[val], 11);
    words_out[i][11] = 0;
  }
  return true;
}

// Reverse: words -> entropy (for recovery)
// Returns true if all words found
bool bip39_words_to_entropy(const char* const* words, int word_count,
                             uint8_t* entropy_out, int* entropy_len_out) {
  uint8_t data[33] = {0};
  for (int i = 0; i < word_count; i++) {
    // Find word index
    int idx = -1;
    for (int j = 0; j < 2048; j++) {
      if (strcmp(words[i], BIP39_WORDS[j]) == 0) { idx = j; break; }
    }
    if (idx < 0) return false;

    // Pack 11 bits into data
    int bit_start = i * 11;
    int byte_idx = bit_start / 8;
    int bit_off = bit_start % 8;
    // Exact inverse of the forward extractor. The previous version shifted by
    // (5 - bit_off), which is NEGATIVE (undefined behaviour) for bit_off 6 and
    // 7 -- hit by words 2, 5, 10, 13, 18, 21 -- and never wrote the third
    // byte, which those offsets require. Verified on host: it corrupted 6 of
    // 24 words. Do not "simplify" this back.
    uint32_t v = (uint32_t)idx << (13 - bit_off);   // 11 bits into a 24-bit window
    data[byte_idx]     |= (uint8_t)((v >> 16) & 0xFF);
    data[byte_idx + 1] |= (uint8_t)((v >>  8) & 0xFF);
    if (byte_idx + 2 < (int)sizeof(data))
      data[byte_idx + 2] |= (uint8_t)(v & 0xFF);
  }
  int elen = (word_count == 12) ? 16 : 32;

  // F4: VALIDATE THE BIP-39 CHECKSUM. Without this a mistyped word that
  // happens to exist in the wordlist restores a different, perfectly valid
  // wallet with no error shown — the user sees an empty balance and has no
  // way to tell a typo from a theft. The checksum is the only thing that
  // distinguishes the two.
  {
    uint8_t h[32];
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, data, elen);
    mbedtls_sha256_finish(&c, h);
    mbedtls_sha256_free(&c);

    int cs_bits = (elen * 8) / 32;            // 4 for 12 words, 8 for 24
    uint8_t mask = (uint8_t)(0xFF << (8 - cs_bits));
    bool good = ((data[elen] & mask) == (h[0] & mask));
    mbedtls_platform_zeroize(h, sizeof(h));
    if(!good){
      mbedtls_platform_zeroize(data, sizeof(data));
      return false;
    }
  }

  *entropy_len_out = elen;
  memcpy(entropy_out, data, elen);
  mbedtls_platform_zeroize(data, sizeof(data));
  return true;
}


// Validate a mnemonic's BIP-39 checksum. Returns true only if every word is in
// the wordlist AND the checksum matches.
//
// WHY THIS MATTERS: without it, a mistyped word that happens to exist in the
// wordlist restores a DIFFERENT, PERFECTLY VALID WALLET. The user sees an
// empty balance and cannot distinguish a typo from a theft. The checksum is
// the only thing that separates the two cases, and it is free.
static bool bip39_validate_mnemonic(const char* const* words, int word_count) {
  if (word_count != 12 && word_count != 24) return false;
  uint8_t ent[32]; int elen = 0;
  bool ok = bip39_words_to_entropy(words, word_count, ent, &elen);
  mbedtls_platform_zeroize(ent, sizeof(ent));
  return ok;
}

