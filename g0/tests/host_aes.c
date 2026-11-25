#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "sha256.h"
int main(){ uint8_t k[32]; for(int i=0;i<32;i++)k[i]=i*7+1; uint8_t h[32],iv[16]; sha256_ctx c; sha256_init(&c); sha256_update(&c,k,32); sha256_update(&c,(const uint8_t*)"favilla-g0-wrap-iv",18); sha256_final(&c,h); memcpy(iv,h,16);
 uint8_t p[32]; for(int i=0;i<32;i++)p[i]=0xA0+i; struct AES_ctx a; AES_init_ctx_iv(&a,k,iv); uint8_t ct[32]; memcpy(ct,p,32); AES_CBC_encrypt_buffer(&a,ct,32);
 for(int i=0;i<32;i++)printf("%02x",ct[i]); printf("\n"); return 0;}
