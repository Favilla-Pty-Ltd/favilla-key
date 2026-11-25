// libFuzzer (9u): CTAP2 into the KEY's FIDO stack (src/fido_hid.h), the
// parser behind both the USB passkey and the Bluetooth app channel's CTAP 0x35.
// The scaffold is host/fuzz.cpp's (the earlier random-mutation fuzzer), with the
// REAL record store (host/rk_host.cpp) behind the restorable path.
//   FZ_PKR=1 (build flag): the NOSTR-life restorable path (G0 passkeys) instead of the SE051 door.
// Input: [byte 0: the user's answer to any prompt][CTAP message].
#define FAVILLA_FIDO_PROBE 1
#ifndef pdPASS
#define pdPASS 1   // 11ak: the task starts check their result
#endif
#include "../src/fido_hid.h"
#include <cstdlib>
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms = 0; unsigned long millis(){ return g_ms += 5; }
static uint8_t g_answer = 0;
QueueHandle_t xQueueCreate(int,int){ return (void*)1; } BaseType_t xQueueSend(QueueHandle_t,const void*,TickType_t){ return 1; }
BaseType_t xQueueReceive(QueueHandle_t,void*,TickType_t){ if(fido::g_up.state == 1){ if(fido::g_up.kind == 3) fido::g_pick.sel = g_answer % 10; fido::g_up.state = (uint8_t)(2 + (g_answer & 1) + ((g_answer & 6) == 6 ? 2 : 0)); } return 0; }
int xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int){ return 1; }
extern bool g_vaultPresent; extern int g_vaultOpenLeft, g_vaultFailNext, g_nvsPutFail;
static bool kg(uint32_t, uint8_t pub[65], uint16_t* sw){ memset(pub, 0x04, 65); *sw = 0x9000; return true; }
static bool sg(uint32_t, const uint8_t*, uint8_t* der, size_t* n, uint16_t* sw){ memset(der, 0x30, 70); *n = 70; *sw = 0x9000; return true; }
static void dl(uint32_t){} static int fr(){ return 10000; }
static int preg(const uint8_t*, uint8_t id[34], uint8_t pub[65]){ memset(id, 0, 34); id[0] = 1; id[1] = 1; for(int i = 2; i < 34; i++) id[i] = (uint8_t)(g_ms + i); memset(pub, 0x04, 65); return 0; }
static int psig(const uint8_t*, const uint8_t* id, const uint8_t*, uint8_t* der, size_t* n){ if(id[2] & 1) return 0xE4; memset(der, 0x30, 70); *n = 70; return 0; }
static bool g_ack = false; static int s_depth = 0;
extern "C" int LLVMFuzzerInitialize(int*, char***){
  fido::Backend b = { kg, sg, dl, fr, []{ return true; }, []() -> uint8_t { return 1; } };
  b.uvFresh = []{ return (g_answer & 8) != 0; };
#ifdef FZ_PKR
  b.doorOpen = []{ return false; }; b.pkrOpen = []{ return true; }; b.pkrRegister = preg; b.pkrSign = psig; b.pkrAcked = []{ return g_ack; }; b.pkrAck = []{ g_ack = !g_ack; };
  b.rkReady = []{ return favilla::rk_ready(); }; b.rkCount = []{ return favilla::rk_count(); };
  b.rkFind = [](const char* s, size_t n, favilla::RkAcct* o, int m){ return favilla::rk_find(s, n, o, m); };
  b.rkSave = [](const char* s, size_t n, const uint8_t* h, size_t hn, const char* nm, size_t nn, const char* d, size_t dn, const uint8_t id[34]){ return favilla::rk_save(s, n, h, hn, nm, nn, d, dn, id); };
  b.rkRoom = [](const char* s, size_t n, const uint8_t* h, size_t hn){ return favilla::rk_room(s, n, h, hn); };
  favilla::rk_mount();
#endif
  b.batchBegin = []{ s_depth++; }; b.batchEnd = []{ if(--s_depth < 0) abort(); }; b.refused = []{};
  fido::setBackend(b); fido::start();
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  if(n < 2 || n - 1 > fido::MAX_MSG) return 0;
  g_answer = d[0];
  static long runs = 0;
  fido::handle(1, fido::CMD_CBOR, d + 1, n - 1);
  if(s_depth != 0) abort();   // every batch window must be closed when a message is done
  if((++runs & 0xFFF) == 0) fido::wipe();
#ifdef FZ_PKR
  if((runs & 0x3FF) == 0) favilla::rk_forget_cache();
  if((runs & 0x7FF) == 0) g_vaultOpenLeft = 32;
  if((runs & 0x3FFF) == 0) favilla::rk_wipe_all();
#endif
  return 0;
}
