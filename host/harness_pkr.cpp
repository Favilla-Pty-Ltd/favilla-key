// Restorable passkeys host harness (30 Oct 2026): the REAL fido_hid.h with a
// backend that models the NOSTR life + the G0's PKSIGN (same derivation as
// pk_glue.inc: tag = HMAC(S, "ID"||1||1||nonce||rp)[0:16], k = HMAC(S, "KEY"||ctr||nonce||rp)).
#define FAVILLA_FIDO_PROBE 1
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "../src/fido_hid.h"
#include <fstream>
#include <iterator>
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms=0; unsigned long millis(){ return g_ms+=5; }
static std::vector<int> g_decisions; static size_t g_di = 0;   // per prompt: 2 approve, 3 refuse; 10+k approve picking row k
extern bool g_vaultPresent; extern int g_vaultCalls[4], g_vaultOpenLeft, g_vaultFailNext, g_nvsPutFail;
namespace favilla { void rk_test_reboot(); }
static int g_prompts = 0, g_warns = 0;
// 2 Nov 2026: model of g0_window_batch_* (PASSKEY life). Each G0-backed call
// is one op; outside a batch it gets its own window, inside one it shares it.
static bool g_batchOn = false; static int g_bDepth = 0, g_bOpen = 0, g_windows = 0, g_badWait = 0, g_refused = 0;
static void winOp(){ if(g_bDepth > 0){ if(!g_bOpen){ g_bOpen = 1; g_windows++; } } else g_windows++; }
static void bBegin(){ g_bDepth++; }
static void bEnd(){ if(g_bDepth > 0 && --g_bDepth == 0) g_bOpen = 0; }
QueueHandle_t xQueueCreate(int,int){ return (void*)1; } BaseType_t xQueueSend(QueueHandle_t,const void*,TickType_t){return 1;}
BaseType_t xQueueReceive(QueueHandle_t,void*,TickType_t){
  if(fido::g_up.state==1){ g_prompts++; if(g_bDepth > 0) g_badWait++; if(fido::g_up.kind==1) g_warns++;
    fprintf(stderr,"PROMPT kind=%d what=%s rp=%s\n",fido::g_up.kind,fido::g_up.what,fido::g_up.rp);
    if(fido::g_up.kind==3){ fprintf(stderr,"PICK n=%d", fido::g_pick.n); for(int i=0;i<fido::g_pick.n;i++) fprintf(stderr," [%s|%s]", fido::g_pick.name[i], fido::g_pick.sub[i]); fprintf(stderr,"\n"); }
    int d = g_di < g_decisions.size() ? g_decisions[g_di++] : 2;
    if(d >= 10){ fido::g_pick.sel = (uint8_t)(d - 10); d = 2; }
    fido::g_up.state = d; }
  return 0; }
#ifndef pdPASS
#define pdPASS 1
#endif
int xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int){return 1;}
static void dl(uint32_t){} static int fr(){ return 10000; }
static bool g_doorOpenH = false; static bool dop(){ return g_doorOpenH; } static uint8_t gn(){ return 1; }
static bool g_pkrOpen = true, g_acked = false; static uint8_t S_[32]; static int g_signs = 0, g_regs = 0;
static void hm(const uint8_t* m, size_t n, uint8_t out[32]){ unsigned int l=32; HMAC(EVP_sha256(), S_, 32, m, n, out, &l); }
static void tagOf(const uint8_t nonce[16], const uint8_t rp[32], uint8_t tag[16]){ uint8_t m[52], h[32]; m[0]='I';m[1]='D';m[2]=1;m[3]=1; memcpy(m+4,nonce,16); memcpy(m+20,rp,32); hm(m,52,h); memcpy(tag,h,16); }
static EC_KEY* keyOf(const uint8_t nonce[16], const uint8_t rp[32]){
  uint8_t m[52], k[32]; m[0]='K';m[1]='E';m[2]='Y'; memcpy(m+4,nonce,16); memcpy(m+20,rp,32);
  BIGNUM* n=BN_new(); EC_GROUP* g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); EC_GROUP_get_order(g,n,nullptr);
  BIGNUM* d=nullptr; for(int c=0;c<256;c++){ m[3]=c; hm(m,52,k); d=BN_bin2bn(k,32,d); if(!BN_is_zero(d) && BN_cmp(d,n)<0) break; }
  EC_KEY* key=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_set_private_key(key,d);
  EC_POINT* P=EC_POINT_new(g); EC_POINT_mul(g,P,d,nullptr,nullptr,nullptr); EC_KEY_set_public_key(key,P);
  EC_POINT_free(P); BN_free(d); BN_free(n); EC_GROUP_free(g); return key; }
static bool pOpen(){ return g_pkrOpen; }
static int pReg(const uint8_t rp[32], uint8_t id[34], uint8_t pub[65]){
  g_regs++; winOp(); uint8_t nonce[16]; for(int i=0;i<16;i++) nonce[i]=rand(); uint8_t tag[16]; tagOf(nonce,rp,tag);
  id[0]=1; id[1]=1; memcpy(id+2,nonce,16); memcpy(id+18,tag,16);
  EC_KEY* k=keyOf(nonce,rp); EC_POINT_point2oct(EC_KEY_get0_group(k),EC_KEY_get0_public_key(k),POINT_CONVERSION_UNCOMPRESSED,pub,65,nullptr); EC_KEY_free(k); return 0; }
static int pSign(const uint8_t rp[32], const uint8_t id[34], const uint8_t h[32], uint8_t* der, size_t* n){
  g_signs++; winOp(); uint8_t tag[16]; tagOf(id+2,rp,tag); if(memcmp(tag,id+18,16)) return 0xE4;
  EC_KEY* k=keyOf(id+2,rp); ECDSA_SIG* s=ECDSA_do_sign(h,32,k); unsigned char* p=der; *n=i2d_ECDSA_SIG(s,&p); ECDSA_SIG_free(s); EC_KEY_free(k); return 0; }
static bool pAcked(){ return g_acked; } static void pAck(){ g_acked = true; }
static bool g_uvFresh = true; static bool uvF(){ return g_uvFresh; }
static bool rkR(){ return favilla::rk_ready(); } static int rkC(){ return favilla::rk_count(); }
static int rkF(const char* s, size_t n, favilla::RkAcct* o, int m){ winOp(); return favilla::rk_find(s, n, o, m); }
static int rkS(const char* s, size_t n, const uint8_t* h, size_t hn, const char* nm, size_t nn, const char* d, size_t dn, const uint8_t id[34]){ winOp(); return favilla::rk_save(s, n, h, hn, nm, nn, d, dn, id); }
int main(int argc, char** argv){
  for(int i=0;i<32;i++) S_[i]=0x40+i;
  fido::Backend b = {}; b.keygen=nullptr; b.sign=nullptr; b.del=dl; b.freeBytes=fr; b.doorOpen=dop; b.gen=gn;
  b.pkrOpen=pOpen; b.pkrRegister=pReg; b.pkrSign=pSign; b.pkrAcked=pAcked; b.pkrAck=pAck; b.uvFresh=uvF;
  b.rkReady=rkR; b.rkCount=rkC; b.rkFind=rkF; b.rkSave=rkS; b.rkRoom=[](const char* s, size_t n, const uint8_t* h, size_t hn){ winOp(); return favilla::rk_room(s,n,h,hn); };
  b.refused=[](){ g_refused++; }; favilla::rk_mount();
  fido::setBackend(b); fido::start();
  for(int a=1;a<argc;a++){
    std::string arg=argv[a];
    if(arg.rfind("decide=",0)==0){ g_decisions.clear(); g_di=0; for(char c: arg.substr(7)) g_decisions.push_back(c=='r'?3:c=='w'?5:(c>='0'&&c<='7')?10+(c-'0'):2); continue; }
    if(arg=="rkoff"){ g_vaultPresent=false; continue; } if(arg=="rkon"){ g_vaultPresent=true; continue; }
    if(arg=="lock"){ favilla::rk_forget_cache(); continue; } if(arg=="reboot"){ favilla::rk_test_reboot(); continue; }
    if(arg=="powercycle"){ favilla::rk_test_reboot(); g_vaultOpenLeft=32; continue; }
    if(arg.rfind("budget=",0)==0){ g_vaultOpenLeft=atoi(arg.c_str()+7); continue; }
    if(arg.rfind("vfail=",0)==0){ g_vaultFailNext=atoi(arg.c_str()+6); continue; }
    if(arg.rfind("putfail=",0)==0){ g_nvsPutFail=atoi(arg.c_str()+8); continue; }
    if(arg.rfind("fill=",0)==0){ int n=atoi(arg.c_str()+5); for(int i=0;i<n;i++){ char site[32]; snprintf(site,sizeof site,"fill%02d.example",i); uint8_t h[1]={(uint8_t)i}, id[34]={1,1}; id[2]=(uint8_t)i;
        int e=favilla::rk_save(site,strlen(site),h,1,"f",1,"",0,id); if(e) fprintf(stderr,"FILL %d failed %d\n",i,e); g_vaultOpenLeft=32; favilla::rk_forget_cache(); } continue; }
    if(arg=="wipe"){ favilla::rk_wipe_all(); continue; }
    if(arg=="tamper"){ for(auto& kv: g_nvs) if(kv.first.rfind("nvs_vault/pkrec/r",0)==0 && kv.second.size()>40){ kv.second[40]^=1; break; } continue; }
    if(arg=="rkstats"){ fprintf(stderr,"RKSTATS records=%d openleft=%d tags=%d opens=%d seals=%d\n",favilla::rk_count(),g_vaultOpenLeft,g_vaultCalls[3],g_vaultCalls[2],g_vaultCalls[1]); continue; }
    if(arg=="pkrclosed"){ g_pkrOpen=false; continue; } if(arg=="uvstale"){ g_uvFresh=false; continue; } if(arg=="uvfresh"){ g_uvFresh=true; continue; } if(arg=="pkropen"){ g_pkrOpen=true; continue; } if(arg=="dooropen"){ g_doorOpenH=true; continue; }
    if(arg=="batch"){ fido::Backend b2 = fido::g_be; b2.batchBegin=bBegin; b2.batchEnd=bEnd; fido::setBackend(b2); continue; }
    if(arg=="winstats"){ fprintf(stderr,"WINSTATS windows=%d depth=%d badwait=%d refused=%d\n",g_windows,g_bDepth,g_badWait,g_refused); g_windows=0; continue; }
    if(arg=="stats"){ fprintf(stderr,"STATS prompts=%d warns=%d regs=%d signs=%d acked=%d\n",g_prompts,g_warns,g_regs,g_signs,(int)g_acked); continue; }
    std::vector<uint8_t> body; std::ifstream f(arg, std::ios::binary); body.assign(std::istreambuf_iterator<char>(f), {});
    uint8_t p[64]; memset(p,0,64); p[3]=1; p[4]=0x90; p[5]=body.size()>>8; p[6]=body.size()&0xff;
    size_t k=body.size()<57?body.size():57; memcpy(p+7,body.data(),k); fido::onPacket(p); size_t off=k; uint8_t seq=0;
    while(off<body.size()){ memset(p,0,64); p[3]=1; p[4]=seq++; size_t m=body.size()-off<59?body.size()-off:59; memcpy(p+5,body.data()+off,m); off+=m; fido::onPacket(p); }
    printf("END\n");
  }
}
