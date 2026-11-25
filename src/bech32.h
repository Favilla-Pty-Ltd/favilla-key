#ifndef FAVILLA_BECH32_H
#define FAVILLA_BECH32_H

// Bech32 / Bech32m encoding for Bitcoin native SegWit addresses (BIP-173/350)
//
// IMPORTANT: This file uses a `fbtc_` prefix on every symbol to coexist with
// the existing bech32 helpers in nostr_signer_v21.ino (used for npub/nsec
// encoding). The existing implementation is checksum-only bech32 — fine for
// 32-byte Nostr keys, but doesn't support the segwit address format with
// witness-version + bech32-vs-bech32m switching that BIP-84 needs.
//
// Reference: https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
//
// For Favilla KEY V1 we use witness version 0 (P2WPKH, bc1q...).
// Witness version 1 (Taproot, bc1p...) is auto-handled: this code switches
// to bech32m when witver >= 1, so adding P2TR later doesn't touch this file.

#include <stdint.h>
#include <string.h>

static const char FBTC_BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#define FBTC_BECH32_CONST    1UL
#define FBTC_BECH32M_CONST   0x2bc830a3UL

static uint32_t fbtc_bech32_polymod_step(uint32_t pre) {
  uint8_t b = pre >> 25;
  return ((pre & 0x1FFFFFFUL) << 5) ^
         (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
         (-((b >> 1) & 1) & 0x26508e6dUL) ^
         (-((b >> 2) & 1) & 0x1ea119faUL) ^
         (-((b >> 3) & 1) & 0x3d4233ddUL) ^
         (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static size_t fbtc_bech32_convert_8to5(const uint8_t* in, size_t in_len,
                                        uint8_t* out_5bit) {
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;
  for (size_t i = 0; i < in_len; i++) {
    acc = (acc << 8) | in[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out_5bit[n++] = (acc >> bits) & 0x1F;
    }
  }
  if (bits > 0) {
    out_5bit[n++] = (acc << (5 - bits)) & 0x1F;
  }
  return n;
}

// Encode a segwit address.
//   hrp:        "bc" mainnet, "tb" testnet
//   witver:     0 for P2WPKH/P2WSH, 1 for P2TR
//   program:    witness program (20 bytes P2WPKH, 32 bytes P2WSH/P2TR)
//   out:        char buffer, at least 90 bytes
// Returns true on success.
static bool segwit_addr_encode(const char* hrp, int witver,
                                const uint8_t* program, size_t program_len,
                                char* out) {
  if (witver < 0 || witver > 16) return false;
  if (witver == 0 && program_len != 20 && program_len != 32) return false;
  if (program_len < 2 || program_len > 40) return false;

  uint32_t enc_const = (witver == 0) ? FBTC_BECH32_CONST : FBTC_BECH32M_CONST;

  uint8_t data[80];
  data[0] = (uint8_t)witver;
  size_t data_len = 1 + fbtc_bech32_convert_8to5(program, program_len, data + 1);

  uint32_t chk = 1;
  size_t hrp_len = strlen(hrp);
  for (size_t i = 0; i < hrp_len; i++) {
    int c = hrp[i];
    if (c < 33 || c > 126) return false;
    if (c >= 'A' && c <= 'Z') return false;
    chk = fbtc_bech32_polymod_step(chk) ^ (c >> 5);
  }
  chk = fbtc_bech32_polymod_step(chk);
  for (size_t i = 0; i < hrp_len; i++) {
    chk = fbtc_bech32_polymod_step(chk) ^ (hrp[i] & 0x1F);
  }
  for (size_t i = 0; i < data_len; i++) {
    chk = fbtc_bech32_polymod_step(chk) ^ data[i];
  }
  for (int i = 0; i < 6; i++) {
    chk = fbtc_bech32_polymod_step(chk);
  }
  chk ^= enc_const;

  size_t pos = 0;
  for (size_t i = 0; i < hrp_len; i++) out[pos++] = hrp[i];
  out[pos++] = '1';
  for (size_t i = 0; i < data_len; i++) out[pos++] = FBTC_BECH32_CHARSET[data[i]];
  for (int i = 0; i < 6; i++) {
    out[pos++] = FBTC_BECH32_CHARSET[(chk >> ((5 - i) * 5)) & 0x1F];
  }
  out[pos] = 0;
  return true;
}

#endif // FAVILLA_BECH32_H
