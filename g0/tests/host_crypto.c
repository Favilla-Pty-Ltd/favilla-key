#include <stdio.h>
#include <string.h>
#include "sha256.h"
static void hex(const uint8_t*b,int n){for(int i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(){ uint8_t o[32];
 sha256((const uint8_t*)"abc",3,o); hex(o,32);
 uint8_t big[1000]; for(int i=0;i<1000;i++) big[i]=(uint8_t)i; sha256(big,1000,o); hex(o,32);
 hmac_sha256((const uint8_t*)"key",3,(const uint8_t*)"The quick brown fox jumps over the lazy dog",43,o); hex(o,32);
 uint8_t ikm[32]; for(int i=0;i<32;i++) ikm[i]=(uint8_t)(0x10+i);
 hkdf_sha256_32((const uint8_t*)"favilla-dm-cache",16,ikm,32,(const uint8_t*)"favilla-dm-cache-v2",19,o); hex(o,32);
 return 0;}
