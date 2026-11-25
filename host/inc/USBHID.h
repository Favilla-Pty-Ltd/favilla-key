#pragma once
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <cstdio>
#include <cstdarg>
typedef const char* esp_event_base_t;
#define ARDUINO_USB_CDC_LINE_STATE_EVENT 1
struct arduino_usb_cdc_event_data_t { struct { bool dtr; bool rts; } line_state; };
struct S{ void enableReboot(bool){} void flush(){} void onEvent(int, void(*)(void*,esp_event_base_t,int32_t,void*)){}  void printf(const char* f, ...){ va_list a; va_start(a,f); vfprintf(stderr,f,a); va_end(a);} void println(const char* s){ fprintf(stderr,"%s\n",s);} };
extern S Serial;
unsigned long millis();
class USBHIDDevice { public: virtual uint16_t _onGetDescriptor(uint8_t*){return 0;} virtual void _onOutput(uint8_t, const uint8_t*, uint16_t){} virtual ~USBHIDDevice(){} };
class USBHID { public: static bool addDevice(USBHIDDevice*, uint16_t){return true;} void begin(){} bool ready(){return true;} bool SendReport(uint8_t, const void* d, size_t n, uint32_t=100){ const uint8_t* b=(const uint8_t*)d; printf("PKT "); for(size_t i=0;i<n;i++) printf("%02x",b[i]); printf("\n"); return true;} };
