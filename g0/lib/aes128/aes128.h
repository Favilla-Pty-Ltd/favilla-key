#ifndef _AES128_H_
#define _AES128_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef AES128_CBC
  #define AES128_CBC 1
#endif

#ifndef AES128_ECB
  #define AES128_ECB 1
#endif

#ifndef AES128_CTR
  #define AES128_CTR 0
#endif


#define AES128 1   /* Favilla: this copy is AES-128 only, for the SE05x SCP03 session (K_SE). lib/tinyaes is the AES-256 copy for K_G0. */
//#define AES192 1
//#define AES256 1

#define AES128_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES128_KEYLEN 32
    #define AES128_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES128_KEYLEN 24
    #define AES128_keyExpSize 208
#else
    #define AES128_KEYLEN 16   // Key length in bytes
    #define AES128_keyExpSize 176
#endif

struct AES128_ctx
{
  uint8_t RoundKey[AES128_keyExpSize];
#if (defined(AES128_CBC) && (AES128_CBC == 1)) || (defined(AES128_CTR) && (AES128_CTR == 1))
  uint8_t Iv[AES128_BLOCKLEN];
#endif
};

void AES128_init_ctx(struct AES128_ctx* ctx, const uint8_t* key);
#if (defined(AES128_CBC) && (AES128_CBC == 1)) || (defined(AES128_CTR) && (AES128_CTR == 1))
void AES128_init_ctx_iv(struct AES128_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES128_ctx_set_iv(struct AES128_ctx* ctx, const uint8_t* iv);
#endif

#if defined(AES128_ECB) && (AES128_ECB == 1)
// buffer size is exactly AES128_BLOCKLEN bytes; 
// you need only AES128_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES128_ECB_encrypt(const struct AES128_ctx* ctx, uint8_t* buf);
void AES128_ECB_decrypt(const struct AES128_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(AES128_CBC) && (AES128_CBC == 1)
// buffer size MUST be mutile of AES128_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES128_init_ctx_iv() or AES128_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES128_CBC_encrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length);
void AES128_CBC_decrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(AES128_CBC) && (AES128_CBC == 1)


#if defined(AES128_CTR) && (AES128_CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES128_init_ctx_iv() or AES128_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES128_CTR_xcrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(AES128_CTR) && (AES128_CTR == 1)


#endif // _AES128_H_
