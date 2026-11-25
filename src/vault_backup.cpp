// =============================================================================
// vault_backup.cpp - relay backup logic (2 Nov 2026). See vault_backup.h.
// =============================================================================
#ifdef FAVILLA_PK_RESTORABLE
#include <Arduino.h>
#include <string.h>
#include <stdio.h>
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include <ArduinoJson.h>
#include "vault_backup.h"

namespace favilla {

static void hmac(const uint8_t* k, size_t kl, const uint8_t* m, size_t ml, uint8_t out[32]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, kl, m, ml, out);
}
static bool zero32(const uint8_t* b) { uint8_t a = 0; for (int i = 0; i < 32; i++) a |= b[i]; return a == 0; }

bool vb_derive(const uint8_t spk[32], uint8_t pub32[32], uint8_t chk8[8]) {
  static const char lab[] = "FAVILLA-VAULT-v1";
  uint8_t kv[32], k[32], h[32]; bool ok = false;
  hmac(spk, 32, (const uint8_t*)lab, sizeof(lab) - 1, kv);
  for (int c = 0; c < 256 && !ok; c++) {
    uint8_t m[4] = { 'P', 'U', 'B', (uint8_t)c };
    hmac(kv, 32, m, 4, k);
    ok = !zero32(k) && vbh_xonly_pub(k, pub32);   // a valid secp256k1 secret key (0 < k < n), as secp256k1_ec_seckey_verify
  }
  if (ok) { hmac(kv, 32, (const uint8_t*)"CHK", 3, h); memcpy(chk8, h, 8); }
  mbedtls_platform_zeroize(kv, 32); mbedtls_platform_zeroize(k, 32); mbedtls_platform_zeroize(h, 32);
  return ok;
}

size_t vb_blob(const uint8_t chk8[8], const uint8_t* body, size_t bodyN, uint8_t* out) {
  memcpy(out, "FVB1", 4); out[4] = VB_VER; out[5] = 0; memcpy(out + 6, chk8, 8);
  memcpy(out + VB_HDR, body, bodyN);
  return VB_HDR + bodyN;
}

int vb_blob_parse(const uint8_t* blob, size_t n, const uint8_t chk8[8], const uint8_t** body, size_t* bodyN) {
  if (n < VB_HDR + 4 || memcmp(blob, "FVB1", 4)) return VB_E_FORMAT;
  if (blob[4] != VB_VER) return VB_E_VERSION;
  if (blob[5] & 1) return VB_E_PASS;        // D6: never import a vault that needs a passphrase we cannot ask for
  if (blob[5] & ~1) return VB_E_FORMAT;
  uint8_t d = 0; for (int i = 0; i < 8; i++) d |= (uint8_t)(blob[6 + i] ^ chk8[i]);
  if (d) return VB_E_CHECK;
  *body = blob + VB_HDR; *bodyN = n - VB_HDR;
  return VB_OK;
}

// NIP-01 string escaping (the characters JSON requires).
static void jesc(mbedtls_sha256_context* c, char* out, size_t cap, size_t* o, const char* s, size_t n) {
  auto put = [&](const char* b, size_t l) { if (c) mbedtls_sha256_update(c, (const unsigned char*)b, l); if (out) { if (*o + l < cap) memcpy(out + *o, b, l); *o += l; } };
  size_t run = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)s[i]; const char* e = nullptr; char u[8];
    switch (ch) {
      case '"': e = "\\\""; break; case '\\': e = "\\\\"; break;
      case '\n': e = "\\n"; break; case '\r': e = "\\r"; break; case '\t': e = "\\t"; break;
      case '\b': e = "\\b"; break; case '\f': e = "\\f"; break;
      default: if (ch < 0x20) { snprintf(u, sizeof u, "\\u%04x", ch); e = u; } break;
    }
    if (e) { if (i > run) put(s + run, i - run); put(e, strlen(e)); run = i + 1; }
  }
  if (n > run) put(s + run, n - run);
}

// [0,"pub",created,30078,[["d","favilla-vault"],["alt",alt]],"content"] hashed (or written).
static void serial(mbedtls_sha256_context* c, char* out, size_t cap, size_t* o, const char* pubHex, uint32_t createdAt,
                   const char* const* tagK, const char* const* tagV, const size_t* tagVN, int ntags, const char* content, size_t contentN) {
  char b[96];
  auto put = [&](const char* s, size_t l) { if (c) mbedtls_sha256_update(c, (const unsigned char*)s, l); if (out) { if (*o + l < cap) memcpy(out + *o, s, l); *o += l; } };
  int l = snprintf(b, sizeof b, "[0,\"%.64s\",%lu,30078,[", pubHex, (unsigned long)createdAt); put(b, (size_t)l);
  for (int i = 0; i < ntags; i++) {
    put(i ? ",[\"" : "[\"", i ? 3 : 2); jesc(c, out, cap, o, tagK[i], strlen(tagK[i])); put("\",\"", 3);
    jesc(c, out, cap, o, tagV[i], tagVN[i]); put("\"]", 2);
  }
  put("],\"", 3); jesc(c, out, cap, o, content, contentN); put("\"]", 2);
}

void vb_event_id(const char pubHex[65], uint32_t createdAt, const char* content, size_t contentN, uint8_t id32[32]) {
  const char* k[2] = { "d", "alt" }; const char* v[2] = { VB_D_TAG, VB_ALT }; size_t vn[2] = { strlen(VB_D_TAG), strlen(VB_ALT) };
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  size_t o = 0; serial(&c, nullptr, 0, &o, pubHex, createdAt, k, v, vn, 2, content, contentN);
  mbedtls_sha256_finish(&c, id32); mbedtls_sha256_free(&c);
}

static void hex(const uint8_t* b, size_t n, char* out) { static const char* H = "0123456789abcdef"; for (size_t i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; } out[2*n] = 0; }
static bool unhex(const char* s, size_t n, uint8_t* out) {
  for (size_t i = 0; i < n; i++) {
    int v = 0;
    for (int j = 0; j < 2; j++) { char ch = s[2*i+j]; int d = (ch >= '0' && ch <= '9') ? ch - '0' : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10 : -1; if (d < 0) return false; v = v * 16 + d; }
    out[i] = (uint8_t)v;
  }
  return true;
}

size_t vb_event_json(char* out, size_t cap, const uint8_t id32[32], const char pubHex[65], uint32_t createdAt,
                     const char* content, size_t contentN, const uint8_t sig64[64]) {
  char idh[65], sigh[129]; hex(id32, 32, idh); hex(sig64, 64, sigh);
  size_t o = 0; char b[360];
  auto put = [&](const char* s, size_t l) { if (o + l < cap) memcpy(out + o, s, l); o += l; };
  int l = snprintf(b, sizeof b, "{\"id\":\"%s\",\"pubkey\":\"%.64s\",\"created_at\":%lu,\"kind\":30078,\"tags\":[[\"d\",\"%s\"],[\"alt\",\"%s\"]],\"content\":\"",
                   idh, pubHex, (unsigned long)createdAt, VB_D_TAG, VB_ALT);
  put(b, (size_t)l);
  jesc(nullptr, out, cap, &o, content, contentN);
  l = snprintf(b, sizeof b, "\",\"sig\":\"%s\"}", sigh); put(b, (size_t)l);
  if (o >= cap) return 0;
  out[o] = 0;
  return o;
}

int vb_event_check(const char* json, size_t n, const uint8_t pub32[32], const char** contentAt, size_t* contentN, uint32_t* createdAt) {
  JsonDocument doc;
  if (deserializeJson(doc, json, n)) return VB_E_EVENT;
  JsonObject e = doc.as<JsonObject>();
  if (e.isNull()) return VB_E_EVENT;
  const char* id = e["id"]; const char* pk = e["pubkey"]; const char* sig = e["sig"]; const char* ct = e["content"];
  if (!id || !pk || !sig || !ct || strlen(id) != 64 || strlen(pk) != 64 || strlen(sig) != 128) return VB_E_EVENT;
  if (!e["kind"].is<int>() || e["kind"].as<int>() != 30078) return VB_E_EVENT;
  if (!e["created_at"].is<unsigned long>()) return VB_E_EVENT;
  uint32_t ca = (uint32_t)e["created_at"].as<unsigned long>();
  uint8_t p[32], id32[32], sig64[64], idc[32];
  if (!unhex(pk, 32, p) || memcmp(p, pub32, 32)) return VB_E_EVENT;
  if (!unhex(id, 32, id32) || !unhex(sig, 64, sig64)) return VB_E_EVENT;
  JsonArray tags = e["tags"].as<JsonArray>();
  if (tags.isNull() || tags.size() < 1 || tags.size() > 2) return VB_E_EVENT;
  const char* k[2]; const char* v[2]; size_t vn[2]; int nt = 0; bool haveD = false;
  for (JsonVariant t : tags) {
    JsonArray a = t.as<JsonArray>();
    if (a.isNull() || a.size() != 2 || !a[0].is<const char*>() || !a[1].is<const char*>()) return VB_E_EVENT;
    const char* tk = a[0]; const char* tv = a[1];
    if (!strcmp(tk, "d")) { if (haveD || strcmp(tv, VB_D_TAG)) return VB_E_EVENT; haveD = true; }
    else if (strcmp(tk, "alt") || strlen(tv) > 128) return VB_E_EVENT;
    k[nt] = tk; v[nt] = tv; vn[nt] = strlen(tv); nt++;
  }
  if (!haveD) return VB_E_EVENT;
  char ph[65]; hex(pub32, 32, ph);
  size_t cn = strlen(ct);
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  size_t o = 0; serial(&c, nullptr, 0, &o, ph, ca, k, v, vn, nt, ct, cn);
  mbedtls_sha256_finish(&c, idc); mbedtls_sha256_free(&c);
  if (memcmp(idc, id32, 32)) return VB_E_EVENT;
  if (!vbh_schnorr_verify(pub32, id32, sig64)) return VB_E_EVENT;
  // Point into the caller's JSON: the content string is base64, so it appears
  // there verbatim. Find it after the "content" key.
  const char* q = strstr(json, "\"content\"");
  if (!q) return VB_E_EVENT;
  q = strchr(q + 9, '"'); if (!q) return VB_E_EVENT; q++;
  if ((size_t)(q - json) + cn > n || memcmp(q, ct, cn)) return VB_E_EVENT;   // escaped content: not base64, refuse
  *contentAt = q; *contentN = cn; *createdAt = ca;
  return VB_OK;
}

}  // namespace favilla
#endif  // FAVILLA_PK_RESTORABLE
