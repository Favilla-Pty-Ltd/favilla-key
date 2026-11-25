// Phase 4 stage 2a host test (3 Nov 2026): the KEY's US layout table and the
// check before typing (kbd_layout.h, the real file).
#include "../src/kbd_layout.h"
#include <cstdio>
#include <set>
static int pass = 0, fail = 0;
static void check(bool c, const char* m) { (c ? pass : fail)++; printf("%s %s\n", c ? "PASS" : "FAIL", m); }
int main() {
  int typeable = 0; std::set<int> combos; bool unique = true;
  for (int c = 0x20; c <= 0x7E; c++) { kbd::Key k = kbd::keyFor((char)c); if (k.usage) { typeable++; int x = k.usage * 2 + k.shift; if (!combos.insert(x).second) unique = false; } }
  check(typeable == 95, "every printable ASCII character (95) has a key");
  check(unique, "no two characters share a key and shift state");
  check(kbd::keyFor('\t').usage == 0x2B && kbd::keyFor('\n').usage == 0x28, "Tab and Enter");
  check(kbd::keyFor('a').usage == 0x04 && !kbd::keyFor('a').shift && kbd::keyFor('Z').usage == 0x1D && kbd::keyFor('Z').shift, "a and Z: HID usages 0x04 and 0x1D, shift only on Z");
  check(kbd::keyFor('1').usage == 0x1E && kbd::keyFor('0').usage == 0x27 && kbd::keyFor('!').usage == 0x1E && kbd::keyFor('!').shift, "1, 0 and ! (shift + 1)");
  { bool ok = true; for (const char* p = kbd::kGenSymbols; *p; p++) if (!kbd::keyFor(*p).usage) ok = false;
    for (char c = 'a'; c <= 'z'; c++) if (!kbd::keyFor(c).usage) ok = false;
    for (char c = 'A'; c <= 'Z'; c++) if (!kbd::keyFor(c).usage) ok = false;
    for (char c = '0'; c <= '9'; c++) if (!kbd::keyFor(c).usage) ok = false;
    check(ok, "invariant (P4-5): every character the generator can produce types"); }
  { bool ok = true; for (const char* p = "\"@#~\\|`"; *p; p++) for (const char* q = kbd::kGenSymbols; *q; q++) if (*p == *q) ok = false;
    check(ok, "the generator leaves out the symbols that move on a UK host (\" @ # ~ \\ | `)"); }
  char bad[16];
  check(kbd::untypable("Correct-Horse_9!", 16, bad, sizeof bad) == 0 && bad[0] == 0, "a normal password: nothing refused");
  check(kbd::untypable("caf\xC3\xA9 \xC3\xA8", 8, bad, sizeof bad) == 1 && !strcmp(bad, "?"), "UTF-8 letters: one '?' entry, refused");
  check(kbd::untypable("a\x01" "b\x01\x7F", 5, bad, sizeof bad) == 2 && bad[0] == 1 && bad[1] == 0x7F, "control bytes: each named once (DEL included)");
  check(kbd::untypable("\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18", 21, bad, 8) == 21 && strlen(bad) == 7, "many refused: counted in full, the list cut to fit");
  printf("\n%s (%d passed, %d failed)\n", fail ? "SOME FAILED" : "ALL PASS", pass, fail);
  return fail ? 1 : 0;
}
