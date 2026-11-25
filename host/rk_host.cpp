// Host build of the REAL pk_records.cpp (2 Nov 2026) against a model of the
// G0's VAULT command (the same construction as g03b/src/vault_glue.inc, here
// with OpenSSL): K_vault = HMAC(S_pk, "FAVILLA-VAULT-v1"), ENC / MAC / SITE
// sub-keys, AES-256-CBC + PKCS#7, MAC over hdr||tag||iv||ct, a 32-per-life
// OPEN budget. Shared by every host harness that includes fido_hid.h.
#define FAVILLA_PK_RESTORABLE 1
#define FAVILLA_BENCH_PROBES 1   // g0_signer.h declares the passkey / vault calls in its bench block
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../src/pk_records.cpp"
#include <cstdio>

int g_nvsPutFail = 0, g_nvsMountErr = 0, g_nvsFree = 100000;
int g_gcmFailAt = 0;
std::vector<uint8_t> g_part; int g_partErases = 0;
bool g_vaultPresent = true;
int g_vaultCalls[4] = {0,0,0,0};   // by op
int g_vaultOpenLeft = 32;
int g_vaultFailNext = 0;           // the next N calls: the G0 does not answer
static uint8_t s_spk[32] = { 0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,
                             0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70 };
static void hm(const uint8_t* k, const uint8_t* m, size_t n, uint8_t o[32]){ unsigned int l=32; HMAC(EVP_sha256(), k, 32, m, n, o, &l); }
static void sub(const uint8_t kv[32], const char* lab, const uint8_t* x, size_t xn, uint8_t o[32]){ uint8_t m[300]; size_t l=strlen(lab); memcpy(m,lab,l); if(xn) memcpy(m+l,x,xn); hm(kv,m,l+xn,o); }
bool g0_vault_present(){ return g_vaultPresent; }
bool g_v15 = true; int g_labelUsed = 0, g_labelCalls = 0;   // v15 model
bool g0_v15_present(){ return g_v15; }
bool g0_v17_present(){ return g_v15; }   // 9i: VAULT TOTP (kind 3 records); the host model answers op 7 as an error
bool g0_limit_present(){ return false; }   // 11ep: the host model has the fixed 32 of a G0 before v24 (no VAULT ops 8 and 9)
bool g_impArmed = false, g_impUsed = false; int g_impCalls = 0;   // v15 import window model: armed by a right UVCHECK, the very next VAULT op
bool g0_vault(uint8_t op, const uint8_t* in, size_t n, uint8_t* out, size_t* outN, uint8_t* res, uint8_t* left){
  if(res) *res=0xFF; if(outN) *outN=0;
  if(op>=1&&op<=3) g_vaultCalls[op]++;
  bool armed = g_impArmed; g_impArmed = false;   // any VAULT op spends the arm
  if(g_vaultFailNext>0){ g_vaultFailNext--; return false; }
  uint8_t kv[32], ke[32], km[32], h[32];
  hm(s_spk,(const uint8_t*)"FAVILLA-VAULT-v1",16,kv); sub(kv,"ENC",nullptr,0,ke); sub(kv,"MAC",nullptr,0,km);
  auto done=[&](uint8_t r, size_t l){ if(res)*res=r; if(left)*left=(uint8_t)g_vaultOpenLeft; if(outN)*outN=l; return true; };
  if(n>511) return done(0xE1,0);
  if(op==3){ if(n<1||n>253) return done(0xE1,0); sub(kv,"SITE",in,n,h); memcpy(out,h,8); return done(0,8); }
  if(op==1){
    if(n<15||n-13>431||in[13]==0||1u+in[13]>n-13) return done(0xE1,0);
    size_t pt=n-13, ct=(pt/16+1)*16; uint8_t pad=(uint8_t)(ct-pt);
    memcpy(out,in,13); sub(kv,"SITE",in+14,in[13],h); memcpy(out+13,h,8); RAND_bytes(out+21,16);
    uint8_t buf[512]; memcpy(buf,in+13,pt); memset(buf+pt,pad,pad);
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new(); int l1=0,l2=0; EVP_EncryptInit_ex(c,EVP_aes_256_cbc(),nullptr,ke,out+21); EVP_CIPHER_CTX_set_padding(c,0);
    EVP_EncryptUpdate(c,out+37,&l1,buf,(int)ct); EVP_EncryptFinal_ex(c,out+37+l1,&l2); EVP_CIPHER_CTX_free(c);
    hm(km,out,37+ct,out+37+ct); return done(0,69+ct);
  }
  if(op==2){
    if(n<85||(n-69)%16) return done(0xE1,0);
    if(g_vaultOpenLeft<=0) return done(0xE7,0);
    hm(km,in,n-32,h); if(memcmp(h,in+n-32,32)) return done(0xE6,0);
    size_t ct=n-69; uint8_t buf[512];
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new(); int l1=0,l2=0; EVP_DecryptInit_ex(c,EVP_aes_256_cbc(),nullptr,ke,in+21); EVP_CIPHER_CTX_set_padding(c,0);
    EVP_DecryptUpdate(c,buf,&l1,in+37,(int)ct); EVP_DecryptFinal_ex(c,buf+l1,&l2); EVP_CIPHER_CTX_free(c);
    uint8_t pad=buf[ct-1]; if(pad==0||pad>16) return done(0xE6,0);
    g_vaultOpenLeft--; memcpy(out,in,13); memcpy(out+13,buf,ct-pad); return done(0,13+ct-pad);
  }
  if(op==5){   // v15 IMPORT
    g_impCalls++;
    if(n!=0) return done(0xE1,0);
    if(!armed||g_impUsed) return done(0xEA,0);
    g_impUsed=true; out[0]=1; out[1]=44; out[2]=1; out[3]=44; return done(0,4);   // 300, 300
  }
  if(op==6){   // v15 LABEL: as G0 vault_glue.inc
    g_labelCalls++;
    if(n<85||(n-69)%16||in[12]!=2) return done(0xE1,0);
    if(g_labelUsed>=400) return done(0xEB,0);
    hm(km,in,n-32,h); if(memcmp(h,in+n-32,32)) return done(0xE6,0);
    size_t ct=n-69; uint8_t buf[512];
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new(); int l1=0,l2=0; EVP_DecryptInit_ex(c,EVP_aes_256_cbc(),nullptr,ke,in+21); EVP_CIPHER_CTX_set_padding(c,0);
    EVP_DecryptUpdate(c,buf,&l1,in+37,(int)ct); EVP_DecryptFinal_ex(c,buf+l1,&l2); EVP_CIPHER_CTX_free(c);
    uint8_t pad=buf[ct-1]; if(pad==0||pad>16) return done(0xE6,0);
    size_t pl=ct-pad, k=1u+buf[0]; if(k<pl) k+=1u+buf[k]; else k=pl+1; if(k>pl) return done(0xE6,0);
    g_labelUsed++; int left=400-g_labelUsed; out[0]=(uint8_t)(left>>8); out[1]=(uint8_t)left; memcpy(out+2,in,13); memcpy(out+15,buf,k);
    return done(0,15+k);
  }
  return done(0xE1,0);
}
// test-only: reset the in-RAM index so the next call reloads from "flash" (a reboot of the ESP32)
namespace favilla { void rk_test_reboot(){ std::lock_guard<std::mutex> g(s_mx); s_loaded=false; for(int i=0;i<RK_MAX;i++) if(s_cache[i]){ free(s_cache[i]); s_cache[i]=nullptr; } if(R) memset(R,0,sizeof *R); s_mounted=true; } }
