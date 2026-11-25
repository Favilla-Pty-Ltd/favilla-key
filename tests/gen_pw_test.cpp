// 11bi (issue #38): GEN_PW's rules parser (chan_proto.h parseGenPw), the rules
// generator (pwgen.h generateRules) and PW_SAVE's optional flags byte
// (parsePwSave). Built and run by CI:
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -Ihost/inc -Isrc tests/gen_pw_test.cpp -lcrypto -o /tmp/gp && /tmp/gp
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <set>
#include "chan_proto.h"
#include "pwgen.h"   // host/inc/mbedtls/sha256.h stands in for mbedtls, kbd_layout.h is the real one

static int pass = 0, fail = 0;
static void check(bool c, const char* m) { (c ? pass : fail)++; if (!c) printf("FAIL %s\n", m); }

static std::vector<uint8_t> rules(uint8_t kind, uint8_t mn, uint8_t mx, uint8_t req, uint8_t alw, const char* sp) {
  std::vector<uint8_t> b = { kind, mn, mx, req, alw, (uint8_t)strlen(sp) };
  b.insert(b.end(), sp, sp + strlen(sp));
  return b;
}
static bool parse(const std::vector<uint8_t>& b, chan::GenPwRules* r) { return chan::parseGenPw(b.data(), b.size(), r); }

int main() {
  chan::GenPwRules R;
  // ---- the parser ----
  check(parse(rules(1, 20, 20, 0x0F, 0x0F, ""), &R) && R.sN == strlen(chan::GEN_DEFAULT_SPECIALS) && !strcmp(R.specials, chan::GEN_DEFAULT_SPECIALS), "no rules: the default specials");
  check(parse(rules(1, 8, 64, 0x07, 0x0F, "!!@@#"), &R) && R.sN == 3 && !strcmp(R.specials, "!@#"), "duplicate specials dropped");
  check(parse(rules(1, 12, 30, 0x07, 0x07, "!@"), &R) && R.sN == 0 && R.specials[0] == 0, "specials ignored when the special class is not allowed");
  check(parse(rules(2, 20, 20, 0x0F, 0x0F, "!"), &R) && R.required == 0x07 && R.allowed == 0x07 && R.sN == 0, "kind 2: letters and digits only");
  check(!parse(rules(3, 20, 20, 0x07, 0x0F, ""), &R), "kind 3 refused");
  check(!parse(rules(1, 7, 20, 0x07, 0x0F, ""), &R), "min length 7 refused");
  check(!parse(rules(1, 20, 65, 0x07, 0x0F, ""), &R), "max length 65 refused");
  check(!parse(rules(1, 21, 20, 0x07, 0x0F, ""), &R), "min above max refused");
  check(!parse(rules(1, 20, 20, 0x08, 0x07, ""), &R), "required outside allowed refused");
  check(!parse(rules(1, 20, 20, 0x08, 0x08, "!"), &R), "only specials allowed refused");
  check(!parse(rules(1, 20, 20, 0x10, 0x1F, ""), &R), "unknown class bits refused");
  check(!parse(rules(1, 20, 20, 0x07, 0x0F, "a!"), &R), "a letter as a special refused");
  check(!parse(rules(1, 20, 20, 0x07, 0x0F, "5"), &R), "a digit as a special refused");
  check(!parse(rules(1, 20, 20, 0x07, 0x0F, " "), &R), "a space as a special refused");
  { auto b = rules(1, 20, 20, 0x07, 0x0F, "!"); b.push_back('#'); check(!parse(b, &R), "a byte past the specials refused"); }
  { auto b = rules(1, 20, 20, 0x07, 0x0F, "!#"); b.pop_back(); check(!parse(b, &R), "specials cut short refused"); }
  { std::string sp(33, '!'); for (int i = 0; i < 33; i++) sp[i] = (char)(0x21 + i % 15); check(!parse(rules(1, 20, 20, 0x07, 0x0F, sp.c_str()), &R), "33 specials refused"); }
  check(!chan::parseGenPw(nullptr, 0, &R) && !chan::parseGenPw((const uint8_t*)"\x01\x14\x14\x07\x0F", 5, &R), "short bodies refused");

  // ---- the generator, against the rules ----
  struct Case { uint8_t kind, mn, mx, req, alw; const char* sp; };
  const Case cases[] = {
    {1, 20, 20, 0x0F, 0x0F, ""}, {1, 8, 8, 0x0F, 0x0F, "!"}, {1, 64, 64, 0x0F, 0x0F, ""}, {2, 20, 20, 0x07, 0x07, ""},
    {1, 12, 16, 0x05, 0x05, ""}, {1, 8, 64, 0x04, 0x04, ""}, {1, 16, 16, 0x09, 0x0B, "_."}, {1, 10, 32, 0x00, 0x0F, "$"},
  };
  int made = 0;
  for (const Case& c : cases) {
    check(parse(rules(c.kind, c.mn, c.mx, c.req, c.alw, c.sp), &R), "case parses");
    int len = 20; if (len < R.minLen) len = R.minLen; if (len > R.maxLen) len = R.maxLen;
    std::set<std::string> seen;
    for (int t = 0; t < 400; t++) {
      uint8_t seed[32]; { uint8_t m[8] = {'G','E','N',(uint8_t)c.mn,(uint8_t)c.alw,(uint8_t)c.req,(uint8_t)(t >> 8),(uint8_t)t}; mbedtls_sha256(m, sizeof m, seed, 0); }
      char out[pwgen::MAX_LEN + 1];
      const bool ok = pwgen::generateRules(seed, len, R.required, R.allowed, R.specials, out);
      if (!ok) { check(false, "generated"); continue; }
      made++;
      bool good = (int)strlen(out) == len, triple = false;
      uint32_t got = 0;
      for (int i = 0; i < len; i++) {
        const char x = out[i];
        uint32_t cl = (x >= 'a' && x <= 'z') ? 1 : (x >= 'A' && x <= 'Z') ? 2 : (x >= '0' && x <= '9') ? 4 : 8;
        if (!(cl & R.allowed)) good = false;
        if (cl == 8 && !strchr(R.specials, x)) good = false;
        got |= cl;
        if (i >= 2 && out[i] == out[i - 1] && out[i] == out[i - 2]) triple = true;
      }
      if ((got & R.required) != R.required) good = false;
      check(good, "only allowed characters, every required class, the right length");
      check(!triple, "never three of a character in a row");
      seen.insert(out);
    }
    check(seen.size() >= 395, "different seeds give different passwords");
  }
  { uint8_t seed[32] = {1}; char a[65], b[65];
    pwgen::generateRules(seed, 20, 0x0F, 0x0F, "-!", a); pwgen::generateRules(seed, 20, 0x0F, 0x0F, "-!", b);
    check(!strcmp(a, b), "the same seed gives the same password (the stream is the seed's)"); }
  { bool typeable = true;   // the default specials can be typed later by the KEY's keyboard (US layout)
    for (int t = 0; t < 2000; t++) { uint8_t seed[32]; for (int k = 0; k < 32; k++) seed[k] = (uint8_t)(t + k * 13); char o[65]; char bad[8];
      if (pwgen::generateRules(seed, 20, 0x0F, 0x0F, chan::GEN_DEFAULT_SPECIALS, o) && kbd::untypable(o, 20, bad, sizeof bad)) typeable = false; }
    check(typeable, "every default special can be typed by the KEY"); }
  { uint8_t seed[32] = {2}; char o[65];
    check(!pwgen::generateRules(seed, 7, 0x07, 0x07, "", o), "length 7 refused");
    check(!pwgen::generateRules(seed, 20, 0x08, 0x07, "", o), "required outside allowed refused");
    check(!pwgen::generateRules(seed, 20, 0x00, 0x0F, "", o), "special class with no specials refused"); }

  // ---- PW_SAVE's flags byte ----
  {
    std::vector<uint8_t> b(8, 0x11); const char* f[4] = { "github.com", "alice", "new pass", "" };
    for (auto s : f) { b.push_back((uint8_t)strlen(s)); b.insert(b.end(), s, s + strlen(s)); }
    uint8_t id[8], fl = 9; char site[200], user[129], pw[129], note[129];
    check(chan::parsePwSave(b.data(), b.size(), id, site, user, pw, note, &fl) && fl == 0, "PW_SAVE without the flags byte: flags 0");
    b.push_back(0x01);
    check(chan::parsePwSave(b.data(), b.size(), id, site, user, pw, note, &fl) && fl == chan::PW_KEEP_OLD && !strcmp(pw, "new pass"), "PW_SAVE with flags bit0");
    check(chan::parsePwSave(b.data(), b.size(), id, site, user, pw, note), "PW_SAVE with flags, the old call still parses");
    b.back() = 0x02;
    check(!chan::parsePwSave(b.data(), b.size(), id, site, user, pw, note, &fl), "PW_SAVE with an unknown flag refused");
    b.back() = 0x01; b.push_back(0x01);
    check(!chan::parsePwSave(b.data(), b.size(), id, site, user, pw, note, &fl), "PW_SAVE with two trailing bytes refused");
  }
  printf("gen_pw: %d checks, %d failures, %d passwords made\n", pass + fail, fail, made);
  return fail ? 1 : 0;
}
