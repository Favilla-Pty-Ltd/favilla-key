/* Sound memory-safety abstraction of lib/aes128 for CBMC: every primitive
 * asserts that the regions it would touch are valid (same reads/writes as the
 * real code) and returns nondeterministic bytes. Memory safety of scp03.c does
 * not depend on cipher values, so this over-approximates the real behaviour. */
#include "aes128.h"
#include <string.h>
static void havoc(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) { uint8_t v; p[i] = v; } }
void aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t mlen, uint8_t mac[16]) {
    __CPROVER_assert(__CPROVER_r_ok(key, 16), "cmac key readable");
    __CPROVER_assert(mlen == 0 || __CPROVER_r_ok(msg, mlen), "cmac msg readable");
    __CPROVER_assert(__CPROVER_w_ok(mac, 16), "cmac mac writable");
    havoc(mac, 16);
}
void AES128_init_ctx(struct AES128_ctx* ctx, const uint8_t* key) { __CPROVER_assert(__CPROVER_r_ok(key,16),"key"); memset(ctx, 0, sizeof *ctx); }
void AES128_init_ctx_iv(struct AES128_ctx* ctx, const uint8_t* key, const uint8_t* iv) { __CPROVER_assert(__CPROVER_r_ok(key,16)&&__CPROVER_r_ok(iv,16),"key/iv"); memset(ctx, 0, sizeof *ctx); }
void AES128_ctx_set_iv(struct AES128_ctx* ctx, const uint8_t* iv) { (void)ctx; __CPROVER_assert(__CPROVER_r_ok(iv,16),"iv"); }
void AES128_ECB_encrypt(const struct AES128_ctx* ctx, uint8_t* buf) { (void)ctx; __CPROVER_assert(__CPROVER_rw_ok(buf,16),"ecb buf"); havoc(buf,16); }
void AES128_ECB_decrypt(const struct AES128_ctx* ctx, uint8_t* buf) { (void)ctx; __CPROVER_assert(__CPROVER_rw_ok(buf,16),"ecb buf"); havoc(buf,16); }
void AES128_CBC_encrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length) { (void)ctx; __CPROVER_assert(length==0||__CPROVER_rw_ok(buf,length),"cbc buf"); havoc(buf,length); }
void AES128_CBC_decrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length) { (void)ctx; __CPROVER_assert(length==0||__CPROVER_rw_ok(buf,length),"cbc buf"); havoc(buf,length); }
