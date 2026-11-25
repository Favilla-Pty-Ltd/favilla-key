#define FAVILLA_FIDO_PROBE 1
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include "../src/fido_hid.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms=0; unsigned long millis(){ return g_ms+=5; }
QueueHandle_t xQueueCreate(int,int){ return (void*)1; } BaseType_t xQueueSend(QueueHandle_t,const void*,TickType_t){return 1;}
BaseType_t xQueueReceive(QueueHandle_t,void*,TickType_t){ if(fido::g_up.state==1){ if(fido::g_up.kind==3) fido::g_pick.sel=(uint8_t)(rand()%10); fido::g_up.state=(uint8_t)(2 + (rand()%4==0) + (rand()%8==0 ? 2 : 0)); } return 0; }
extern bool g_vaultPresent; extern int g_vaultOpenLeft, g_vaultFailNext, g_nvsPutFail;
#ifndef pdPASS
#define pdPASS 1
#endif
int xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int){return 1;}
static bool kg(uint32_t, uint8_t pub[65], uint16_t* sw){ memset(pub,0x04,65); *sw=0x9000; return true; }
static bool sg(uint32_t, const uint8_t*, uint8_t* der, size_t* n, uint16_t* sw){ memset(der,0x30,70); *n=70; *sw=0x9000; return true; }
static void dl(uint32_t){} static int fr(){ return 10000; }
// 30 Oct 2026: PKR=1 fuzzes the restorable (NOSTR life) path instead.
static int preg(const uint8_t*, uint8_t id[34], uint8_t pub[65]){ memset(id,0,34); id[0]=1; id[1]=1; for(int i=2;i<34;i++) id[i]=rand(); memset(pub,0x04,65); return (rand()%5)?0:0xE6; }
static int psig(const uint8_t*, const uint8_t* id, const uint8_t*, uint8_t* der, size_t* n){ if(id[2]&1) return 0xE4; memset(der,0x30,70); *n=70; return (rand()%7)?0:0xE7; }
static bool g_ack=false;
int main(int argc, char** argv){
  fido::Backend b={kg,sg,dl,fr,[]{return true;},[]()->uint8_t{return 1;}};
  b.uvFresh=[]{ return (rand()%2)==0; };   // 31 Oct 2026: UV paths too
  if(getenv("PKR")){ b.doorOpen=[]{return false;}; b.pkrOpen=[]{return true;}; b.pkrRegister=preg; b.pkrSign=psig; b.pkrAcked=[]{return g_ack;}; b.pkrAck=[]{g_ack=!g_ack;}; }
  if(getenv("RK")){   // 2 Nov 2026: the REAL record store (rk_host.cpp: sealed records, budget, cache) behind the restorable path
    b.rkReady=[]{ return favilla::rk_ready(); }; b.rkCount=[]{ return favilla::rk_count(); };
    b.rkFind=[](const char* s, size_t n, favilla::RkAcct* o, int m){ return favilla::rk_find(s,n,o,m); };
    b.rkSave=[](const char* s, size_t n, const uint8_t* h, size_t hn, const char* nm, size_t nn, const char* d, size_t dn, const uint8_t id[34]){ return favilla::rk_save(s,n,h,hn,nm,nn,d,dn,id); };
    b.rkRoom=[](const char* s, size_t n, const uint8_t* h, size_t hn){ return favilla::rk_room(s,n,h,hn); };
    favilla::rk_mount(); }
  static int s_depth; s_depth = 0;   // 2 Nov 2026: every batch must end (window closed) by the time a message is done
  b.batchBegin=[]{ s_depth++; }; b.batchEnd=[]{ if(--s_depth < 0) abort(); }; b.refused=[]{};
  fido::setBackend(b); fido::start();
  std::vector<std::vector<uint8_t>> seeds;
  for(int a=1;a<argc;a++){ std::ifstream f(argv[a], std::ios::binary); seeds.emplace_back(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()); }
  srand(1234); long runs = 200000;
  for(long r=0;r<runs;r++){
    std::vector<uint8_t> m = seeds[r % seeds.size()];
    int nm = 1 + rand()%8;
    for(int k=0;k<nm;k++){ int op=rand()%4; size_t pos = m.empty()?0:rand()%m.size();
      if(op==0 && !m.empty()) m[pos]^= (1<<(rand()%8));
      else if(op==1 && !m.empty()) m[pos]=rand();
      else if(op==2 && m.size()<1000) m.insert(m.begin()+pos, rand());
      else if(op==3 && m.size()>1) m.erase(m.begin()+pos); }
    if(m.size()>fido::MAX_MSG) m.resize(fido::MAX_MSG);
    if(m.empty()) continue;
    fido::handle(1, fido::CMD_CBOR, m.data(), m.size());
    if(s_depth != 0){ fprintf(stderr,"batch left open: depth %d\n", s_depth); abort(); }
    { uint8_t p[64]; for(int q=0;q<64;q++) p[q]=rand(); if(rand()%2){ p[0]=p[1]=p[2]=0; p[3]=1; } fido::onPacket(p); }
    if((r & 0xFFF)==0) fido::wipe();                 // keep slots cycling
    if(getenv("RK")){ if((r & 0x3FF)==0) favilla::rk_forget_cache(); if((r & 0x7FF)==0){ g_vaultOpenLeft = 32; } if((r % 3001)==0) g_vaultFailNext = 1; if((r % 5003)==0) g_nvsPutFail = 1; if((r & 0x3FFF)==0) favilla::rk_wipe_all(); }
  }
  fprintf(stderr,"fuzz done: %ld runs, made %lu signed %lu, records %d\n", runs, (unsigned long)fido::g_made, (unsigned long)fido::g_signed, getenv("RK") ? favilla::rk_count() : -1);
}
