#define FAVILLA_FIDO_PROBE 1
#ifndef pdPASS
#define pdPASS 1   // 11ak: the task starts check their result
#endif
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include "../src/fido_hid.h"
#include <fstream>
#include <iterator>
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms=0; unsigned long millis(){ return g_ms+=5; }
static int g_approve = 2;   // 2 approve, 3 refuse
QueueHandle_t xQueueCreate(int,int){ return (void*)1; } BaseType_t xQueueSend(QueueHandle_t,const void*,TickType_t){return 1;}
BaseType_t xQueueReceive(QueueHandle_t,void*,TickType_t){ if(fido::g_up.state==1) fido::g_up.state=g_approve; return 0; }
int xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int){return 1;}
static EC_KEY* g_keys[64];
static bool kg(uint32_t obj, uint8_t pub[65], uint16_t* sw){ int i=obj-fido::SLOT_OBJ_BASE; EC_KEY* k=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(k); g_keys[i]=k;
  EC_POINT_point2oct(EC_KEY_get0_group(k),EC_KEY_get0_public_key(k),POINT_CONVERSION_UNCOMPRESSED,pub,65,nullptr); *sw=0x9000; return true; }
static bool sg(uint32_t obj, const uint8_t h[32], uint8_t* der, size_t* n, uint16_t* sw){ int i=obj-fido::SLOT_OBJ_BASE; if(!g_keys[i]) return false; ECDSA_SIG* s=ECDSA_do_sign(h,32,g_keys[i]); unsigned char* p=der; *n=i2d_ECDSA_SIG(s,&p); ECDSA_SIG_free(s); *sw=0x9000; return true; }
static void dl(uint32_t){} static int fr(){ return 10000; }
static bool g_open = true; static bool dop(){ return g_open; } static uint8_t gn(){ return 1; }
int main(int argc, char** argv){
  fido::Backend b={kg,sg,dl,fr,dop,gn}; fido::setBackend(b); fido::start();
  // each arg: file with a full CTAPHID message body for CMD_CBOR on channel 1, or "init", or "refuse"
  for(int a=1;a<argc;a++){
    std::string arg=argv[a];
    if(arg=="refuse"){ g_approve=3; continue; } if(arg=="approve"){ g_approve=2; continue; }
    if(arg=="closed"){ g_open=false; continue; } if(arg=="open"){ g_open=true; continue; }
    std::vector<uint8_t> body;
    if(arg=="init"){ uint8_t p[64]={0xff,0xff,0xff,0xff,0x86,0,8,1,2,3,4,5,6,7,8}; fido::onPacket(p); printf("END\n"); continue; }
    std::ifstream f(arg, std::ios::binary); body.assign(std::istreambuf_iterator<char>(f), {});
    // packetise into CTAPHID frames on channel 1 and feed through the reassembler
    uint8_t p[64]; memset(p,0,64); p[0]=0;p[1]=0;p[2]=0;p[3]=1; p[4]=0x90; p[5]=body.size()>>8; p[6]=body.size()&0xff;
    size_t k=body.size()<57?body.size():57; memcpy(p+7,body.data(),k); fido::onPacket(p); size_t off=k; uint8_t seq=0;
    while(off<body.size()){ memset(p,0,64); p[3]=1; p[4]=seq++; size_t m=body.size()-off<59?body.size()-off:59; memcpy(p+5,body.data()+off,m); off+=m; fido::onPacket(p); }
    printf("END\n");
  }
}
