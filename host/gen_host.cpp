// Phase 4 host test (3 Nov 2026): the password generator (pwgen.h, the real file).
#include "../src/pwgen.h"
#include <cstdio>
#include <cmath>
#include <set>
#include <string>
static int pass = 0, fail = 0;
static void check(bool c, const char* m) { (c ? pass : fail)++; printf("%s %s\n", c ? "PASS" : "FAIL", m); }
static void seedOf(uint32_t i, uint8_t s[32]) { uint8_t m[8] = {'S','E','E','D',(uint8_t)(i>>24),(uint8_t)(i>>16),(uint8_t)(i>>8),(uint8_t)i}; mbedtls_sha256(m, 8, s, 0); }
int main() {
  using namespace pwgen;
  const uint32_t ALL = CL_LOWER | CL_UPPER | CL_DIGIT | CL_SYMBOL, NOSYM = CL_LOWER | CL_UPPER | CL_DIGIT;
  char abc[100]; size_t an = alphabet(ALL, abc), an2 = alphabet(NOSYM, abc);
  check(an == 86 && an2 == 62, "alphabets: 86 with symbols (26+26+10+24), 62 without");
  char pw[MAX_LEN + 1]; uint8_t s[32];
  bool ok = true, typeable = true, classes = true; std::set<std::string> seen;
  for (uint32_t i = 0; i < 20000; i++) {
    seedOf(i, s); int len = (int[]){16, 20, 32}[i % 3]; uint32_t cl = (i % 4 == 3) ? NOSYM : ALL;
    if (!generate(s, len, cl, pw) || (int)strlen(pw) != len) ok = false;
    char bad[8]; if (kbd::untypable(pw, len, bad, sizeof bad)) typeable = false;
    if (classesOf(pw, len) != cl) classes = false;
    seen.insert(pw);
  }
  check(ok, "20,000 passwords at 16, 20 and 32: the right length every time");
  check(classes, "each has every class asked for, and no symbol when symbols are off");
  check(typeable, "every generated password types (P4-5 invariant)");
  check(seen.size() == 20000, "no repeats in 20,000");
  { uint8_t a[32]; seedOf(7, a); char p1[33], p2[33]; generate(a, 32, ALL, p1); generate(a, 32, ALL, p2);
    uint8_t b[32]; seedOf(8, b); char p3[33]; generate(b, 32, ALL, p3);
    check(!strcmp(p1, p2) && strcmp(p1, p3), "deterministic for a seed, different for another (the randomness is all in the seed)"); }
  { // uniformity: chi-square over the 86 characters, 1,000,000 draws
    static long cnt[128] = {0}; long total = 0; (void)abc;
    for (uint32_t i = 0; i < 31250; i++) { seedOf(100000 + i, s); generate(s, 32, ALL, pw); for (int k = 0; k < 32; k++) { cnt[(uint8_t)pw[k]]++; total++; } }
    // The class rule (every class present) redraws about 2% of 32-character
    // passwords (most of them for want of a digit), which lifts the rarer
    // classes very slightly overall; WITHIN each class every character must
    // be equally likely. Chi-square per class against the 0.1% critical value.
    struct C { char a, b; const char* set; double crit; const char* nm; } cls[4] = {{'a','z',nullptr,54.1,"lower"},{'A','Z',nullptr,54.1,"upper"},{'0','9',nullptr,27.9,"digit"},{0,0,kbd::kGenSymbols,49.7,"symbol"}};
    bool uni = true;
    for (auto& c : cls) {
      std::string chars; if (c.set) chars = c.set; else for (char x = c.a; x <= c.b; x++) chars += x;
      long sum = 0; for (char x : chars) sum += cnt[(uint8_t)x];
      double e = (double)sum / chars.size(), chi = 0; for (char x : chars) { double d = cnt[(uint8_t)x] - e; chi += d * d / e; }
      printf("INFO %s: chi-square %.1f over %zu df (0.1%% critical %.1f), share %.4f of characters (ideal %.4f)\n", c.nm, chi, chars.size() - 1, c.crit, (double)sum / total, (double)chars.size() / 86);
      if (chi > c.crit) uni = false;
    }
    check(uni, "within each class every character is equally likely (chi-square, 1,000,000 characters)"); }
  check(!generate(s, 7, ALL, pw) && !generate(s, 65, ALL, pw) && !generate(s, 20, CL_SYMBOL, pw), "refused: too short, too long, symbols only");
  check(policy(20, ALL) == (20u | (0xFu << 8) | POLICY_V1) && ((policy(20, ALL) | POLICY_PENDING) >> 31) == 1, "policy word: length, classes, version, pending bit");
  printf("\n%s (%d passed, %d failed)\n", fail ? "SOME FAILED" : "ALL PASS", pass, fail);
  return fail ? 1 : 0;
}
