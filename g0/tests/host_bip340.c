#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_preallocated.h"
#include "bip340_vectors.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);}
static uint8_t buf[512] __attribute__((aligned(16)));
int main(void){
  printf("prealloc size = %zu\n", secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE));
  secp256k1_context *ctx = secp256k1_context_preallocated_create(buf, SECP256K1_CONTEXT_NONE);
  int npass=0,ntotal=0;
  for(size_t i=0;i<BIP340_NVECS;i++){ const bip340_vec_t*v=&BIP340_VECS[i];
    if(v->has_sk){ ntotal++; secp256k1_keypair kp; uint8_t sig[64];
      int ok=secp256k1_keypair_create(ctx,&kp,v->sk)&&secp256k1_schnorrsig_sign32(ctx,sig,v->msg,&kp,v->aux);
      int p = ok && !memcmp(sig,v->sig,64); npass+=p; printf("vec %2d sign   %s\n",v->idx,p?"ok":"FAIL"); }
    ntotal++; secp256k1_xonly_pubkey pk; int parsed=secp256k1_xonly_pubkey_parse(ctx,&pk,v->pk);
    int ok=parsed&&secp256k1_schnorrsig_verify(ctx,v->sig,v->msg,32,&pk);
    int p=((ok?1:0)==v->expect_ok); npass+=p; printf("vec %2d verify %s (expect %d)  %s\n",v->idx,p?"ok":"FAIL",v->expect_ok,v->comment); }
  printf("%d/%d\n",npass,ntotal); return npass==ntotal?0:1; }
