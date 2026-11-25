// BIP-380 descriptor checksum (as in Bitcoin Core's DescriptorChecksum).
#pragma once
#include <stdint.h>
#include <string.h>
static const char* DESC_INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
static const char* DESC_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static uint64_t desc_polymod(uint64_t c, int val) {
  uint8_t c0 = (uint8_t)(c >> 35);
  c = ((c & 0x7ffffffffULL) << 5) ^ (uint64_t)val;
  if (c0 & 1)  c ^= 0xf5dee51989ULL;
  if (c0 & 2)  c ^= 0xa9fdca3312ULL;
  if (c0 & 4)  c ^= 0x1bab10e32dULL;
  if (c0 & 8)  c ^= 0x3706b1677aULL;
  if (c0 & 16) c ^= 0x644d626ffdULL;
  return c;
}
// out[9]; returns false on a character outside the descriptor charset.
static bool desc_checksum(const char* s, char out[9]) {
  uint64_t c = 1; int cls = 0, clscount = 0;
  for (const char* p = s; *p; p++) {
    const char* q = strchr(DESC_INPUT_CHARSET, *p);
    if (!q || !*p) return false;
    int pos = (int)(q - DESC_INPUT_CHARSET);
    c = desc_polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    if (++clscount == 3) { c = desc_polymod(c, cls); cls = 0; clscount = 0; }
  }
  if (clscount > 0) c = desc_polymod(c, cls);
  for (int j = 0; j < 8; j++) c = desc_polymod(c, 0);
  c ^= 1;
  for (int j = 0; j < 8; j++) out[j] = DESC_CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
  out[8] = 0;
  return true;
}
