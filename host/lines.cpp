#define FAVILLA_FIDO_PROBE 1
#include "../src/fido_hid.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs; unsigned long millis(){return 0;}
QueueHandle_t xQueueCreate(int,int){return 0;} BaseType_t xQueueSend(QueueHandle_t,const void*,TickType_t){return 1;} BaseType_t xQueueReceive(QueueHandle_t,void*,TickType_t){return 0;} #ifndef pdPASS
#define pdPASS 1
#endif
int xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int){return 1;}
static void seq(const char* name, std::vector<std::pair<int,int>> v){ fido::g_toLoader=false; memset(fido::g_hist,0xFF,4); for(auto&x:v) fido::onLineState(x.first,x.second); printf("%-34s -> %s\n", name, fido::g_toLoader?"LOADER":"no"); }
int main(){
  // esptool ClassicReset: setDTR(F) setRTS(T) setDTR(T) setRTS(F) setDTR(F), starting from an open port (1,1) or (0,0)
  seq("esptool classic (from 1,1)", {{1,1},{0,1},{0,1},{1,1},{1,0},{0,0}});
  seq("esptool classic (from 0,0)", {{0,0},{0,0},{0,1},{1,1},{1,0},{0,0}});
  // esptool USBJTAGSerialReset: RTS F, DTR F, DTR T, RTS F, RTS T, DTR F, RTS T, DTR F, RTS F
  seq("esptool usb-jtag reset", {{0,0},{0,0},{1,0},{1,0},{1,1},{0,1},{0,1},{0,1},{0,0}});
  seq("monitor open/close (1,1)->(0,0)", {{1,1},{0,0}});
  seq("monitor dtr only", {{1,0},{0,0},{1,0},{0,0}});
  seq("1200 baud touch style", {{1,1},{0,0},{1,1},{0,0}});
}
