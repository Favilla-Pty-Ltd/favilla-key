// Host shim for the fuzzers (9u): just enough Arduino (String, Serial) for the
// Bitcoin headers the UR decoder pulls in. Not used by the code under test.
#pragma once
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
class String {
 public:
  std::string s;
  String() {}
  String(const char* c) : s(c ? c : "") {}
  String(const std::string& x) : s(x) {}
  String(char c) : s(1, c) {}
  String(int v) : s(std::to_string(v)) {}
  String(unsigned v) : s(std::to_string(v)) {}
  void reserve(size_t n) { s.reserve(n); }
  size_t length() const { return s.size(); }
  const char* c_str() const { return s.c_str(); }
  int indexOf(const char* x) const { size_t p = s.find(x); return p == std::string::npos ? -1 : (int)p; }
  int indexOf(char x) const { size_t p = s.find(x); return p == std::string::npos ? -1 : (int)p; }
  String substring(size_t a) const { return a >= s.size() ? String() : String(s.substr(a)); }
  String substring(size_t a, size_t b) const { if (a >= s.size() || b <= a) return String(); return String(s.substr(a, b - a)); }
  bool concat(const char* c, size_t n) { s.append(c, n); return true; }
  char operator[](size_t i) const { return i < s.size() ? s[i] : 0; }
  String& operator+=(const String& o) { s += o.s; return *this; }
  String& operator+=(const char* c) { s += c; return *this; }
  String& operator+=(char c) { s += c; return *this; }
  bool operator==(const char* c) const { return s == c; }
  bool startsWith(const char* c) const { return s.rfind(c, 0) == 0; }
};
inline String operator+(const String& a, const String& b) { return String(a.s + b.s); }
inline String operator+(const String& a, const char* b) { return String(a.s + b); }
struct FzSerial {
  int printf(const char*, ...) { return 0; }
  size_t println(const char*) { return 0; } size_t println(const String&) { return 0; } size_t println() { return 0; }
  size_t print(const char*) { return 0; }
};
static FzSerial Serial;
