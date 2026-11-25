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
    uint32_t val = ((uint32_t)data[byte_idx] << 16) |
                   ((uint32_t)data[byte_idx + 1] << 8) |
                    (uint32_t)data[byte_idx + 2];
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
    data[byte_idx] |= (idx >> (3 + bit_off));
    data[byte_idx + 1] |= (idx << (5 - bit_off));
  }
  *entropy_len_out = (word_count == 12) ? 16 : 32;
  memcpy(entropy_out, data, *entropy_len_out);
  return true;
}

