#pragma once
// ============================================================================
// Favilla KEY — QR pairing codec (firmware side)
// Mirrors qr_pair_codec.py (tested reference). The PWA implements the same.
//
//   QR #1 (phone shows, KEY scans):  "FK1:" + b64url(phone_static[32]||phone_eph[32])
//   QR #2 (KEY shows, phone scans):  "FK2:" + b64url(dev_static[32]||dev_eph[32]||pair_id[8])
//   confirm code = first 6 decimal digits of HMAC-SHA256(sk,"favilla-pair-confirm")
//
// base64url, NO padding. Versioned prefix lets the format evolve.
// ============================================================================

#include <Arduino.h>
#include <mbedtls/md.h>

// ── base64url (no padding) ──────────────────────────────────────────────────
static const char PQ_B64U[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static String pq_b64u_encode(const uint8_t* data, size_t len) {
  String out; out.reserve(((len + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= len) {
    uint32_t n = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
    out += PQ_B64U[(n >> 18) & 63];
    out += PQ_B64U[(n >> 12) & 63];
    out += PQ_B64U[(n >> 6) & 63];
    out += PQ_B64U[n & 63];
    i += 3;
  }
  size_t rem = len - i;
  if (rem == 1) {
    uint32_t n = data[i] << 16;
    out += PQ_B64U[(n >> 18) & 63];
    out += PQ_B64U[(n >> 12) & 63];
    // no padding
  } else if (rem == 2) {
    uint32_t n = (data[i] << 16) | (data[i+1] << 8);
    out += PQ_B64U[(n >> 18) & 63];
    out += PQ_B64U[(n >> 12) & 63];
    out += PQ_B64U[(n >> 6) & 63];
  }
  return out;
}

static int pq_b64u_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

// Decode base64url into out (max outMax). Returns decoded length, or -1 on error.
static int pq_b64u_decode(const char* s, size_t slen, uint8_t* out, size_t outMax) {
  uint32_t acc = 0; int bits = 0; size_t o = 0;
  for (size_t i = 0; i < slen; i++) {
    int v = pq_b64u_val(s[i]);
    if (v < 0) return -1;          // any non-b64url char → reject
    acc = (acc << 6) | (uint32_t)v; bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= outMax) return -1;
      out[o++] = (uint8_t)((acc >> bits) & 0xFF);
    }
  }
  return (int)o;
}

// ── FK1 (phone keys) ────────────────────────────────────────────────────────
// Parse "FK1:<b64url(32||32)>" → phone_static, phone_eph. Returns true on success.
static bool pq_decode_fk1(const String& s, uint8_t phone_static[32], uint8_t phone_eph[32]) {
  if (!s.startsWith("FK1:")) return false;
  String body = s.substring(4);
  uint8_t raw[64];
  int n = pq_b64u_decode(body.c_str(), body.length(), raw, sizeof(raw));
  if (n != 64) return false;
  memcpy(phone_static, raw, 32);
  memcpy(phone_eph, raw + 32, 32);
  return true;
}

// ── FK2 (device keys + pair_id) ───────────────────────────────────────────────
// Build "FK2:<b64url(dev_static[32]||dev_eph[32]||pair_id[8])>".
static String pq_encode_fk2(const uint8_t dev_static[32], const uint8_t dev_eph[32],
                            const uint8_t pair_id[8]) {
  uint8_t buf[72];
  memcpy(buf, dev_static, 32);
  memcpy(buf + 32, dev_eph, 32);
  memcpy(buf + 64, pair_id, 8);
  return String("FK2:") + pq_b64u_encode(buf, 72);
}

// ── confirmation code ─────────────────────────────────────────────────────────
// Transcript-bound: first 6 decimal digits of
//   HMAC-SHA256(sk, "favilla-pair-confirm-v2" ‖ devPub(32) ‖ phonePub(32))
// MUST stay byte-identical to sasCodeFromSk() in session_sec_http.h — the SAS
// path (live) and this FK2 QR path (dormant) have to agree or a cross-path
// pairing would show mismatched codes. See the hardening note there.
static void pq_confirm_code(const uint8_t sk[32], const uint8_t devPub[32],
                            const uint8_t phonePub[32], char out[7]) {
  uint8_t msg[23 + 32 + 32];
  memcpy(msg,      "favilla-pair-confirm-v2", 23);
  memcpy(msg + 23, devPub,   32);
  memcpy(msg + 55, phonePub, 32);
  uint8_t mac[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, sk, 32, msg, sizeof(msg), mac);
  uint32_t n = ((uint32_t)mac[0] << 24) | ((uint32_t)mac[1] << 16) |
               ((uint32_t)mac[2] << 8) | (uint32_t)mac[3];
  n %= 1000000UL;
  snprintf(out, 7, "%06lu", (unsigned long)n);
  memset(mac, 0, 32);
  memset(msg, 0, sizeof(msg));
}
