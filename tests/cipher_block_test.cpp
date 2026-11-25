// 11bs (issue #39, stage 3): src/cipher_block.h, the daily block check.
// Real headers: block 125552 (the Bitcoin wiki's hashing example) and the
// genesis block. Their difficulty is far below today's floor, so the floor is
// lowered here to test the proof-of-work maths; the floor itself is tested on
// its own. A header from today's chain is checked on the bench.
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -Ihost/inc -Isrc tests/cipher_block_test.cpp -lcrypto -o /tmp/cb && /tmp/cb
#include <cstdio>
#include <cstring>
#include <string>
#include "cipher_block.h"

static int pass = 0, fail = 0;
static void check(bool c, const char* m) { (c ? pass : fail)++; if (!c) printf("FAIL %s\n", m); }

static const char* H125552 =
  "01000000"
  "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
  "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
  "c7f5d74d" "f2b9441a" "42a14695";
static const char* HGENESIS =
  "01000000"
  "0000000000000000000000000000000000000000000000000000000000000000"
  "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
  "29ab5f49" "ffff001d" "1dac2b7c";

int main() {
  CgBlock b;
  std::string ok = std::string("125568,") + H125552;
  check(cgblock::parse(ok.c_str(), 0, b, 40), "125552 header passes with a low floor");
  { char hx[65]; cgblock::hashHex(b, hx);
    check(!strcmp(hx, "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"), "block hash matches the known hash"); }
  check(b.height == 125568 && b.time == 0x4dd7f5c7, "height and time read");
  check(!cgblock::parse(ok.c_str(), 0, b), "125552 header refused at the real floor (difficulty too low)");
  check(cgblock::parse((std::string("FCD1:125568:") + H125552).c_str(), 0, b, 40), "FCD1 QR form accepted");
  check(cgblock::parse((std::string("  125568,") + H125552 + "\r\n").c_str(), 0, b, 40), "surrounding whitespace allowed");
  check(cgblock::parse((std::string("144,") + HGENESIS).c_str(), 0, b, 32), "genesis header passes (floor 32)");
  { char hx[65]; cgblock::hashHex(b, hx);
    check(!strcmp(hx, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"), "genesis hash matches"); }

  // tampering
  { std::string t = ok; t[7 + 150] = (t[7 + 150] == '0') ? '1' : '0';   // the nonce
    check(!cgblock::parse(t.c_str(), 0, b, 40), "changed nonce fails the proof of work"); }
  { std::string t = ok; t[7 + 10] = (t[7 + 10] == '0') ? '1' : '0';     // prev hash
    check(!cgblock::parse(t.c_str(), 0, b, 40), "changed prev hash fails"); }
  { std::string t = ok; t.replace(7 + 144, 8, "ffff7f20");              // easy regtest bits, same nonce
    check(!cgblock::parse(t.c_str(), 0, b, 40), "regtest bits refused by the floor"); }
  check(!cgblock::parse((std::string("125552,") + H125552).c_str(), 0, b, 40), "height not a multiple of 144 refused");
  check(!cgblock::parse((std::string("0,") + H125552).c_str(), 0, b, 40), "height 0 refused");
  check(!cgblock::parse((std::string("125568,") + std::string(H125552).substr(0, 158)).c_str(), 0, b, 40), "short header refused");
  check(!cgblock::parse((std::string("125568,") + H125552 + "00").c_str(), 0, b, 40), "extra bytes refused");
  check(!cgblock::parse((std::string("125568;") + H125552).c_str(), 0, b, 40), "bad separator refused");
  check(!cgblock::parse(nullptr, 0, b), "null refused");

  // age: block time 0x4dd7f5c7 = 2011-05-21
  const int64_t bt = 0x4dd7f5c7;
  check(cgblock::parse(ok.c_str(), bt + 3600, b, 40), "an hour old is fine");
  check(!cgblock::parse(ok.c_str(), bt + 3 * 86400, b, 40), "three days old refused (replay)");
  check(!cgblock::parse(ok.c_str(), bt - 3 * 3600, b, 40), "three hours in the future refused");
  check(cgblock::parse(ok.c_str(), 0, b, 40), "clock unknown (0): age not checked");

  // the floor maths
  { uint8_t t[32]; check(cgblock::bitsToTarget(0x1d00ffff, t) && cgblock::leadingZeros(t) == 32, "diff-1 target has 32 leading zeros"); }
  { uint8_t t[32]; check(cgblock::bitsToTarget(0x17053894, t) && cgblock::leadingZeros(t) >= 76, "a 2024-era target clears the floor"); }
  { uint8_t t[32]; check(!cgblock::bitsToTarget(0x1d80ffff, t), "negative bits refused"); }

  // the seed: stable, and different blocks give different seeds
  { CgBlock a, g; cgblock::parse(ok.c_str(), 0, a, 40); cgblock::parse((std::string("144,") + HGENESIS).c_str(), 0, g, 32);
    check(cgblock::seed(a) == cgblock::seed(a) && cgblock::seed(a) != cgblock::seed(g) && cgblock::seed(a) != 0, "seed stable and distinct"); }

  printf("cipher_block: %d checks, %d failures\n", pass + fail, fail);
  return fail ? 1 : 0;
}
