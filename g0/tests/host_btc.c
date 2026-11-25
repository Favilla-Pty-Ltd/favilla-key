/* Host harness for src/btc.c. Usage:
 *   host_btc acct <seed64hex> <purpose>          -> master_fp parent_fp pub33 cc32 statekey
 *   host_btc sign <seed64hex> <req416hex>        -> rc pub33 der sighash
 *   host_btc msg  <seed64hex> <req416hex>        -> rc pub33 sig65 digest
 * Driven by run_btc_test.py, which compares against embit. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "btc.h"
#include "secp256k1_preallocated.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);exit(9);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);exit(9);}
static uint8_t buf[512] __attribute__((aligned(16)));
static int unhex(const char*s,uint8_t*o,size_t n){ if(strlen(s)!=2*n)return -1; for(size_t i=0;i<n;i++){unsigned v; if(sscanf(s+2*i,"%2x",&v)!=1)return -1; o[i]=(uint8_t)v;} return 0;}
static void hex(const uint8_t*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
int main(int argc,char**argv){
  if(argc<2) return 2;
  secp256k1_context *ctx = secp256k1_context_preallocated_create(buf, SECP256K1_CONTEXT_NONE);
  if(!strcmp(argv[1],"rfc6979")){ /* canonical vector: key=1, msg=SHA256("Satoshi Nakamoto") */
    uint8_t k[32]={0}; k[31]=1; uint8_t m[32]; unhex("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e",m,32);
    secp256k1_ecdsa_signature s; uint8_t c[64]; secp256k1_ecdsa_sign(ctx,&s,m,k,NULL,NULL);
    secp256k1_ecdsa_signature_serialize_compact(ctx,c,&s); hex(c,64); printf("\n"); return 0; }
  if(argc<3) return 2;
  uint8_t seed[64]; if(unhex(argv[2],seed,64)) return 2;
  if(!strcmp(argv[1],"acct")){
    btc_xprv a; uint8_t mfp[4],pfp[4],sk[32]; btc_xpub_t x;
    if(btc_account(ctx,seed,atoi(argv[3]),&a,mfp,pfp)) { printf("ERR\n"); return 1; }
    btc_xpub_of(ctx,&a,pfp,&x); btc_state_key(seed,sk);
    hex(mfp,4);printf(" ");hex(pfp,4);printf(" ");hex(x.pub,33);printf(" ");hex(x.cc,32);printf(" ");hex(sk,32);printf("\n");
    return 0;
  }
  if(!strcmp(argv[1],"sign")){
    uint8_t req[BTC_REQ_LEN]; if(unhex(argv[3],req,BTC_REQ_LEN)) return 2;
    uint8_t pub[33],der[BTC_DER_MAX],dl=0,sh[32];
    int rc=btc_sign_request(ctx,seed,req,pub,der,&dl,sh);
    printf("%d ",rc); hex(pub,33);printf(" ");hex(der,dl);printf(" ");hex(sh,32);printf("\n");
    return 0;
  }
  if(!strcmp(argv[1],"msg")){
    uint8_t req[BTC_REQ_LEN]; if(unhex(argv[3],req,BTC_REQ_LEN)) return 2;
    uint8_t pub[33]={0},sig[65]={0},dg[32]={0};
    int rc=btc_sign_message(ctx,seed,req,pub,sig,dg);
    printf("%d ",rc); hex(pub,33);printf(" ");hex(sig,65);printf(" ");hex(dg,32);printf("\n");
    return 0;
  }
  return 2;
}
