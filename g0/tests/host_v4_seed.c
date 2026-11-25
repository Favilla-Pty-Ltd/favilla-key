#include <stdio.h>
#include <string.h>
#include "bip39_words.h"
#include "pbkdf2.h"
int main(){ uint8_t ent[16]={0}; char mn[224]; int ml=bip39_mnemonic_from_entropy(ent,12,mn,sizeof mn);
 uint8_t salt[8+100]; memcpy(salt,"mnemonic",8); memcpy(salt+8,"TREZOR",6); uint8_t seed[64];
 pbkdf2_hmac_sha512_64((const uint8_t*)mn,ml,salt,14,2048,seed); for(int i=0;i<64;i++) printf("%02x",seed[i]); printf("\n");
 uint8_t e2[32]; memset(e2,0xff,32); ml=bip39_mnemonic_from_entropy(e2,24,mn,sizeof mn);
 pbkdf2_hmac_sha512_64((const uint8_t*)mn,ml,salt,14,2048,seed); for(int i=0;i<64;i++) printf("%02x",seed[i]); printf("\n"); return 0; }
