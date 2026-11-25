// Host stub for the firmware's Arduino.h surface used by the crypto headers.
// Harness only — never compiled on device.
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string>
#define PROGMEM
#define IRAM_ATTR
struct HostSerial {
  int printf(const char* f, ...) { va_list a; va_start(a,f); int n=vfprintf(stderr,f,a); va_end(a); return n; }
  void println(const char* s){ fprintf(stderr,"%s\n",s); }
  void println(const std::string& s){ fprintf(stderr,"%s\n",s.c_str()); }
  void print(const char* s){ fputs(s,stderr); }
};
static HostSerial Serial;
// Minimal Arduino String on top of std::string — enough for the helpers in secp256k1.h.
class String : public std::string {
public:
  String() {}
  String(const char* s) : std::string(s?s:"") {}
  String(const std::string& s) : std::string(s) {}
  size_t length() const { return size(); }
  char charAt(size_t i) const { return (*this)[i]; }
  const char* c_str() const { return std::string::c_str(); }
  String& operator+=(char c){ push_back(c); return *this; }
  String& operator+=(const char* s){ append(s); return *this; }
  String& operator+=(const String& s){ append(s); return *this; }
  void reserve(size_t n){ std::string::reserve(n); }
  int indexOf(char c) const { size_t i=find(c); return i==npos?-1:(int)i; }
  int indexOf(const char* c) const { size_t i=find(c); return i==npos?-1:(int)i; }
  String substring(size_t a) const { return String(substr(a)); }
  String substring(size_t a, size_t b) const { return String(substr(a,b-a)); }
};
static inline uint32_t esp_random(void){ return (uint32_t)rand(); }
static inline unsigned long millis(void){ return 0; }
