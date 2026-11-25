#pragma once
// BIP39 + NIP-06 key derivation for Favilla Key
// Requires: bip39_wordlist.h (official 2048-word list)
// Uses: mbedtls (included in ESP32 Arduino core)

#include "mbed_secret.h"   // 2 Nov 2026: secret mbedTLS work stays on-chip
#include <stdint.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"
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
  // 11bl (issue #47 item 2): only the BIP-39 counts (12, 15, 18, 21, 24).
  // data holds 24 words (264 bits); 25 or more wrote past its end.
  if (!words || word_count < 12 || word_count > 24 || word_count % 3) return false;
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

// BIP39 mnemonic -> 64-byte seed via PBKDF2-HMAC-SHA512
// passphrase: empty string for standard BIP39 (no extra passphrase)
bool bip39_mnemonic_to_seed(const char* mnemonic, const char* passphrase,
                             uint8_t seed_out[64]) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  char salt[256] = "mnemonic";
  strncat(salt, passphrase ? passphrase : "", sizeof(salt) - 9);

  // PBKDF2-HMAC-SHA512: 2048 iterations, 64 byte output
  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
    MBEDTLS_MD_SHA512,
    (const uint8_t*)mnemonic, strlen(mnemonic),
    (const uint8_t*)salt, strlen(salt),
    2048, 64, seed_out
  );
  return ret == 0;
}

// ── BIP32 ─────────────────────────────────────────────────────────────────

// HMAC-SHA512
static void hmac_sha512(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out[64]) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md, 1);
  mbedtls_md_hmac_starts(&ctx, key, key_len);
  mbedtls_md_hmac_update(&ctx, data, data_len);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// BIP32 child derivation handled inline in nip06_derive using mbedtls MPI

// ── NIP-06: derive Nostr key from BIP39 seed ─────────────────────────────
// Path: m/44'/1237'/0'/0/0
// Uses mbedtls MPI for safe modular arithmetic
#include "mbedtls/bignum.h"

bool nip06_derive(const uint8_t seed[64], uint8_t nostr_priv_out[32]) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  // secp256k1 order n
  static const uint8_t N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
  };

  // Step 1: Master key — HMAC-SHA512("Bitcoin seed", seed)
  const uint8_t* bip32_key = (const uint8_t*)"Bitcoin seed";
  uint8_t I[64];
  hmac_sha512(bip32_key, 12, seed, 64, I);

  uint8_t key[32], chain[32];
  memcpy(key, I, 32);
  memcpy(chain, I + 32, 32);

  // NIP-06 path: m/44'/1237'/0'/0/0
  // All steps hardened (0x80000000+) per NIP-06 spec
  uint32_t path[5] = {
    0x80000000 + 44,
    0x80000000 + 1237,
    0x80000000 + 0,
    0x80000000 + 0,
    0x80000000 + 0
  };

  // Step 2: Derive each level
  for (int level = 0; level < 5; level++) {
    uint32_t idx = path[level];

    // Build HMAC data: 0x00 || parent_key || index (hardened)
    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, key, 32);
    data[33] = (idx >> 24) & 0xFF;
    data[34] = (idx >> 16) & 0xFF;
    data[35] = (idx >>  8) & 0xFF;
    data[36] =  idx        & 0xFF;

    uint8_t IL[64];
    hmac_sha512(chain, 32, data, 37, IL);

    // child_key = (IL_left + parent_key) mod n  using mbedtls MPI
    mbedtls_mpi mN, mIL, mKey, mChild;
    mbedtls_mpi_init(&mN);
    mbedtls_mpi_init(&mIL);
    mbedtls_mpi_init(&mKey);
    mbedtls_mpi_init(&mChild);

    mbedtls_mpi_read_binary(&mN,   N_BYTES, 32);
    mbedtls_mpi_read_binary(&mIL,  IL,      32);
    mbedtls_mpi_read_binary(&mKey, key,     32);

    // Fail if IL >= n
    if (mbedtls_mpi_cmp_mpi(&mIL, &mN) >= 0) {
      mbedtls_mpi_free(&mN); mbedtls_mpi_free(&mIL);
      mbedtls_mpi_free(&mKey); mbedtls_mpi_free(&mChild);
      return false;
    }

    mbedtls_mpi_add_mpi(&mChild, &mIL, &mKey);
    mbedtls_mpi_mod_mpi(&mChild, &mChild, &mN);

    // Fail if result is zero
    if (mbedtls_mpi_cmp_int(&mChild, 0) == 0) {
      mbedtls_mpi_free(&mN); mbedtls_mpi_free(&mIL);
      mbedtls_mpi_free(&mKey); mbedtls_mpi_free(&mChild);
      return false;
    }

    mbedtls_mpi_write_binary(&mChild, key, 32);
    memcpy(chain, IL + 32, 32);

    mbedtls_mpi_free(&mN); mbedtls_mpi_free(&mIL);
    mbedtls_mpi_free(&mKey); mbedtls_mpi_free(&mChild);
  }

  memcpy(nostr_priv_out, key, 32);
  return true;
}

// ── High-level: generate new mnemonic and derive Nostr key ────────────────
// entropy_bytes: 16 for 12 words, 32 for 24 words
// words_out: char[24][12] — caller provides
// word_count_out: 12 or 24
// nostr_priv_out: 32 bytes Nostr private key
bool bip39_generate_nostr_key(const uint8_t* entropy, int entropy_len,
                               char words_out[][12], int* word_count_out,
                               uint8_t nostr_priv_out[32]) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  // 1. Entropy -> mnemonic words
  if (!bip39_entropy_to_words(entropy, entropy_len, words_out, word_count_out))
    return false;

  // 2. Build mnemonic string
  char mnemonic[300] = {0};
  for (int i = 0; i < *word_count_out; i++) {
    if (i > 0) strcat(mnemonic, " ");
    strcat(mnemonic, words_out[i]);
  }

  // 3. PBKDF2 seed
  uint8_t seed[64];
  if (!bip39_mnemonic_to_seed(mnemonic, "", seed)) return false;

  // 4. NIP-06 derivation
  return nip06_derive(seed, nostr_priv_out);
}
