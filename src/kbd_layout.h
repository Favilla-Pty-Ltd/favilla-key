// =============================================================================
// kbd_layout.h - the KEY's keyboard layout table (3 Nov 2026, Vault spec 7f,
// P4-5 ruled A: US first, and a check before typing). Pure code, no USB: the
// host tests include it as it is.
//
// One table maps every character the KEY will ever type to a HID usage and a
// shift flag. Anything not in the table is refused BEFORE anything is typed,
// and the refusal names the characters, so the entry can be edited. US layout
// is also right for UK and AU for the characters a generated password uses
// (letters, digits and the symbols in kbd_gen_symbols); a few symbols differ on
// a UK host (" @ # ~ \ |): those are typed as US and the owner sees the wrong
// character, which is why the generator's symbol set leaves them out.
//
// Invariant (P4-5): every character the generator can produce types (host
// test checks it).
// =============================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace kbd {

struct Key { uint8_t usage; uint8_t shift; };   // usage 0 = cannot type

// US layout, ASCII 0x20..0x7E, plus Tab and Enter. HID usage IDs (USB HID
// Usage Tables, keyboard page 0x07).
inline Key keyFor(char ch) {
  uint8_t c = (uint8_t)ch;
  if (c >= 'a' && c <= 'z') return {(uint8_t)(0x04 + (c - 'a')), 0};
  if (c >= 'A' && c <= 'Z') return {(uint8_t)(0x04 + (c - 'A')), 1};
  if (c >= '1' && c <= '9') return {(uint8_t)(0x1E + (c - '1')), 0};
  switch (c) {
    case '0': return {0x27, 0};
    case '\n': return {0x28, 0};   // Enter
    case '\t': return {0x2B, 0};   // Tab
    case ' ': return {0x2C, 0};
    case '!': return {0x1E, 1}; case '@': return {0x1F, 1}; case '#': return {0x20, 1}; case '$': return {0x21, 1};
    case '%': return {0x22, 1}; case '^': return {0x23, 1}; case '&': return {0x24, 1}; case '*': return {0x25, 1};
    case '(': return {0x26, 1}; case ')': return {0x27, 1};
    case '-': return {0x2D, 0}; case '_': return {0x2D, 1};
    case '=': return {0x2E, 0}; case '+': return {0x2E, 1};
    case '[': return {0x2F, 0}; case '{': return {0x2F, 1};
    case ']': return {0x30, 0}; case '}': return {0x30, 1};
    case '\\': return {0x31, 0}; case '|': return {0x31, 1};
    case ';': return {0x33, 0}; case ':': return {0x33, 1};
    case '\'': return {0x34, 0}; case '"': return {0x34, 1};
    case '`': return {0x35, 0}; case '~': return {0x35, 1};
    case ',': return {0x36, 0}; case '<': return {0x36, 1};
    case '.': return {0x37, 0}; case '>': return {0x37, 1};
    case '/': return {0x38, 0}; case '?': return {0x38, 1};
    default: return {0, 0};
  }
}

// The generator's symbols (Vault spec 6 policy): typeable on US, UK and AU
// hosts alike (no " @ # ~ \ | `).
static const char kGenSymbols[] = "!$%^&*()-_=+[]{};:,.<>/?";

// Check a string before typing. Returns how many distinct characters cannot be
// typed, and writes them (each once, in order of first appearance) to bad, a
// NUL-terminated list of up to badCap-1 bytes. A character outside ASCII (a
// UTF-8 byte) is reported as '?' once, since the screen cannot show it as one
// character. n = 0 means typeable.
inline int untypable(const char* s, size_t len, char* bad, size_t badCap) {
  int n = 0; size_t w = 0; bool nonAscii = false;
  if (badCap) bad[0] = 0;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = (uint8_t)s[i];
    if (c >= 0x80) { if (!nonAscii) { nonAscii = true; n++; if (w + 1 < badCap) { bad[w++] = '?'; bad[w] = 0; } } continue; }
    if (keyFor((char)c).usage) continue;
    bool seen = false; for (size_t j = 0; j < w; j++) if ((uint8_t)bad[j] == c) seen = true;
    if (seen) continue;
    n++; if (w + 1 < badCap) { bad[w++] = (char)c; bad[w] = 0; }
  }
  return n;
}

}  // namespace kbd
