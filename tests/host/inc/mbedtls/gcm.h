// Host shim (3 Nov 2026, P4-10 tests): the four mbedTLS GCM calls pk_records
// uses, on OpenSSL. Same signatures and return codes (0 ok, nonzero fail).
#pragma once
#include <openssl/evp.h>
#include <string.h>
#include <vector>
#define MBEDTLS_GCM_ENCRYPT 1
#define MBEDTLS_GCM_DECRYPT 0
typedef enum { MBEDTLS_CIPHER_ID_AES = 2 } mbedtls_cipher_id_t;
typedef struct { unsigned char key[32]; int bits; EVP_CIPHER_CTX* x; int enc; unsigned char iv[12]; std::vector<unsigned char>* ad; std::vector<unsigned char>* pt; } mbedtls_gcm_context;
static inline void mbedtls_gcm_init(mbedtls_gcm_context* c) { memset((void*)c, 0, sizeof *c); }
static inline void mbedtls_gcm_free(mbedtls_gcm_context* c) { if (c->x) EVP_CIPHER_CTX_free(c->x); delete c->ad; delete c->pt; memset((void*)c, 0, sizeof *c); }
static inline int mbedtls_gcm_setkey(mbedtls_gcm_context* c, mbedtls_cipher_id_t, const unsigned char* k, unsigned bits) { if (bits != 256) return -1; memcpy(c->key, k, 32); c->bits = 256; return 0; }
static inline int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context* c, int mode, size_t len, const unsigned char* iv, size_t ivl, const unsigned char* aad, size_t al, const unsigned char* in, unsigned char* out, size_t tl, unsigned char* tag) {
  if (mode != MBEDTLS_GCM_ENCRYPT || ivl != 12) return -1;
  EVP_CIPHER_CTX* x = EVP_CIPHER_CTX_new(); int l = 0, ok = 1;
  ok &= EVP_EncryptInit_ex(x, EVP_aes_256_gcm(), nullptr, c->key, iv);
  if (al) ok &= EVP_EncryptUpdate(x, nullptr, &l, aad, (int)al);
  if (len) ok &= EVP_EncryptUpdate(x, out, &l, in, (int)len);
  ok &= EVP_EncryptFinal_ex(x, out + len, &l);
  ok &= EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, (int)tl, tag);
  EVP_CIPHER_CTX_free(x); return ok ? 0 : -1;
}
static inline int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context* c, size_t len, const unsigned char* iv, size_t ivl, const unsigned char* aad, size_t al, const unsigned char* tag, size_t tl, const unsigned char* in, unsigned char* out) {
  if (ivl != 12) return -1;
  EVP_CIPHER_CTX* x = EVP_CIPHER_CTX_new(); int l = 0, ok = 1;
  ok &= EVP_DecryptInit_ex(x, EVP_aes_256_gcm(), nullptr, c->key, iv);
  if (al) ok &= EVP_DecryptUpdate(x, nullptr, &l, aad, (int)al);
  if (len) ok &= EVP_DecryptUpdate(x, out, &l, in, (int)len);
  ok &= EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, (int)tl, (void*)tag);
  ok &= EVP_DecryptFinal_ex(x, out + len, &l) > 0;
  EVP_CIPHER_CTX_free(x); return ok ? 0 : -1;
}

// Streaming calls (3 Nov 2026: the index is now sealed in 512-byte pieces).
extern int g_gcmFailAt;   // test hook: fail the Nth update call (0 = never)
static inline int mbedtls_gcm_starts(mbedtls_gcm_context* c, int mode, const unsigned char* iv, size_t ivl) {
  if (ivl != 12 || c->bits != 256) return -1;
  if (c->x) EVP_CIPHER_CTX_free(c->x);
  c->x = EVP_CIPHER_CTX_new(); c->enc = mode == MBEDTLS_GCM_ENCRYPT; memcpy(c->iv, iv, 12);
  delete c->ad; delete c->pt; c->ad = new std::vector<unsigned char>(); c->pt = new std::vector<unsigned char>();
  return EVP_CipherInit_ex(c->x, EVP_aes_256_gcm(), nullptr, c->key, iv, c->enc) ? 0 : -1;
}
static inline int mbedtls_gcm_update_ad(mbedtls_gcm_context* c, const unsigned char* a, size_t al) { int l = 0; c->ad->insert(c->ad->end(), a, a + al); return (!al || EVP_CipherUpdate(c->x, nullptr, &l, a, (int)al)) ? 0 : -1; }
static inline int mbedtls_gcm_update(mbedtls_gcm_context* c, const unsigned char* in, size_t n, unsigned char* out, size_t cap, size_t* w) {
  if (g_gcmFailAt > 0 && --g_gcmFailAt == 0) return -0x0014;
  if (cap < n) return -0x0014;
  int l = 0; if (!EVP_CipherUpdate(c->x, out, &l, in, (int)n)) return -1; *w = (size_t)l;
  if (!c->enc) c->pt->insert(c->pt->end(), out, out + l);
  return 0;
}
static inline int mbedtls_gcm_finish(mbedtls_gcm_context* c, unsigned char*, size_t, size_t* w, unsigned char* tag, size_t tl) {
  unsigned char t[16]; int l = 0; *w = 0;
  if (c->enc) { if (!EVP_CipherFinal_ex(c->x, t, &l)) return -1; return EVP_CIPHER_CTX_ctrl(c->x, EVP_CTRL_GCM_GET_TAG, (int)tl, tag) ? 0 : -1; }
  // decrypt: mbedTLS hands back the tag it computed; OpenSSL only verifies, so
  // re-encrypt the plaintext (same key, nonce, AAD -> same ciphertext and tag).
  std::vector<unsigned char> ct(c->pt->size() + 16);
  return mbedtls_gcm_crypt_and_tag(c, MBEDTLS_GCM_ENCRYPT, c->pt->size(), c->iv, 12, c->ad->data(), c->ad->size(), c->pt->data(), ct.data(), tl, tag);
}
