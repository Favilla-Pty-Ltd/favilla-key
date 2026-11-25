// Host tests + fuzz for login_qr.h (Vault phase 5).
// g++ -std=c++17 -O1 -fsanitize=address,undefined -I../../pbuild/src loginqr_host.cpp -o loginqr_host
#include "login_qr.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <random>

static int fails = 0, passes = 0;
static void expect(const char* name, const std::string& in, int want, const char* site = nullptr, const char* user = nullptr){
  char s[loginqr::FIELD_MAX + 1], u[loginqr::FIELD_MAX + 1];
  int r = loginqr::parse(in.data(), in.size(), s, u);
  bool ok = r == want;
  if(ok && site) ok = !strcmp(s, site);
  if(ok && user) ok = !strcmp(u, user);
  if(ok && r != loginqr::OK) ok = !s[0] && !u[0];
  if(ok) passes++; else { fails++; printf("FAIL %s: got %d site[%s] user[%s]\n", name, r, s, u); }
}

int main(){
  using namespace loginqr;
  expect("basic", "favilla:login?v=1&s=github.com&u=josh%40favillakey.io", OK, "github.com", "josh@favillakey.io");
  expect("no user", "favilla:login?v=1&s=github.com", OK, "github.com", "");
  expect("empty user", "favilla:login?v=1&s=a.io&u=", OK, "a.io", "");
  expect("order", "favilla:login?u=me&s=x.com&v=1", OK, "x.com", "me");
  expect("upper", "FAVILLA:LOGIN?V=1&S=GITHUB.COM&U=JOSH", OK, "GITHUB.COM", "JOSH");
  expect("plus literal", "favilla:login?v=1&s=x.com&u=a+b%40c.com", OK, "x.com", "a+b@c.com");
  expect("space", "favilla:login?v=1&s=My%20Bank&u=me", OK, "My Bank", "me");
  expect("hex lower/upper", "favilla:login?v=1&s=%2a%2A", OK, "**", "");
  expect("unknown key ignored", "favilla:login?v=1&s=x&note=hello&u=y", OK, "x", "y");
  expect("trailing amp", "favilla:login?v=1&s=x&", OK, "x", "");
  expect("double amp", "favilla:login?v=1&&s=x", OK, "x", "");
  expect("plain text", "github.com", NOT_LOGIN);
  expect("other scheme", "favilla:other?v=1&s=x", NOT_LOGIN);
  expect("short", "favilla:login", NOT_LOGIN);
  expect("no version", "favilla:login?s=x", E_VERSION);
  expect("version 2", "favilla:login?v=2&s=x", E_VERSION);
  expect("version 10", "favilla:login?v=10&s=x", E_VERSION);
  expect("no site", "favilla:login?v=1&u=me", E_NO_SITE);
  expect("empty site", "favilla:login?v=1&s=&u=me", E_NO_SITE);
  expect("password p", "favilla:login?v=1&s=x&p=hunter2", E_PASSWORD);
  expect("password PASSWORD", "favilla:login?v=1&s=x&PASSWORD=hunter2", E_PASSWORD);
  expect("password pass empty", "favilla:login?v=1&s=x&pass=", E_PASSWORD);
  expect("bad escape short", "favilla:login?v=1&s=x%4", E_BAD_TEXT);
  expect("bad escape end", "favilla:login?v=1&s=x%", E_BAD_TEXT);
  expect("bad escape hex", "favilla:login?v=1&s=x%zz", E_BAD_TEXT);
  expect("nul", "favilla:login?v=1&s=x%00y", E_BAD_TEXT);
  expect("newline", "favilla:login?v=1&s=x%0Ay", E_BAD_TEXT);
  expect("utf8", "favilla:login?v=1&s=caf%C3%A9", E_BAD_TEXT);
  expect("del", "favilla:login?v=1&s=x%7F", E_BAD_TEXT);
  expect("repeat s", "favilla:login?v=1&s=a&s=b", E_REPEAT);
  expect("repeat v", "favilla:login?v=1&v=1&s=a", E_REPEAT);
  expect("repeat u", "favilla:login?v=1&s=a&u=1&u=2", E_REPEAT);
  { std::string s100(100, 'a'), s101(101, 'a');
    expect("site 100", "favilla:login?v=1&s=" + s100, OK, s100.c_str(), "");
    expect("site 101", "favilla:login?v=1&s=" + s101, E_TOO_LONG);
    std::string e100; for(int i = 0; i < 100; i++) e100 += "%41";
    expect("site 100 escaped", "favilla:login?v=1&s=" + e100 + "&u=" + s100, OK, std::string(100, 'A').c_str(), s100.c_str());
    expect("user 101", "favilla:login?v=1&s=x&u=" + s101, E_TOO_LONG); }
  { char b[200]; int n = snprintf(b, sizeof b, "favilla:login?v=1&s=x");   // not NUL-terminated input: parse only n bytes
    std::string in(b, n); in += "&u=SHOULD_NOT_SEE"; expect("length bound", std::string(b, n), OK, "x", ""); }
  // fuzz: random and mutated inputs; ASan/UBSan catch any overrun; check invariants
  std::mt19937 rng(1234);
  const char* seeds[] = { "favilla:login?v=1&s=github.com&u=josh%40x.io", "favilla:login?v=1&s=%41%42&u=a+b", "FAVILLA:LOGIN?V=1&S=X" };
  const char alpha[] = "favilla:login?v=1&s=u%0Aa+F=&pP%%7E\x01\xff";
  long fz = 0;
  for(int it = 0; it < 300000; it++){
    std::string in = seeds[rng() % 3];
    int muts = rng() % 6;
    for(int m = 0; m < muts; m++){
      int op = rng() % 3; size_t pos = in.empty() ? 0 : rng() % (in.size() + 1);
      if(op == 0) in.insert(pos, 1, alpha[rng() % (sizeof(alpha) - 1)]);
      else if(op == 1 && !in.empty() && pos < in.size()) in.erase(pos, 1);
      else if(!in.empty() && pos < in.size()) in[pos] = (char)(rng() & 0xFF);
    }
    if(rng() % 50 == 0) in.append(rng() % 400, (char)('a' + rng() % 26));
    char s[FIELD_MAX + 1], u[FIELD_MAX + 1];
    int r = parse(in.data(), in.size(), s, u);
    bool okInv = true;
    if(r == OK){ size_t sl = strlen(s), ul = strlen(u); okInv = sl >= 1 && sl <= 100 && ul <= 100;
      for(size_t i = 0; i < sl; i++) if((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7E) okInv = false;
      for(size_t i = 0; i < ul; i++) if((unsigned char)u[i] < 0x20 || (unsigned char)u[i] > 0x7E) okInv = false; }
    else okInv = !s[0] && !u[0] && r >= -6 && r <= 0;
    if(!okInv){ fails++; printf("FUZZ invariant broken (r=%d) on input of %zu bytes\n", r, in.size()); break; }
    fz++;
  }
  // siteMatch (sign in by QR)
  struct M { const char* saved; const char* want; int exp; } mt[] = {
    {"github.com","github.com",3},{"GitHub.com","github.com",3},{"https://www.github.com/login","github.com",3},{"github.com:443","github.com",3},
    {"github.com","gist.github.com",2},{"accounts.google.com","google.com",2},{"google.com","accounts.google.com",2},
    {"GitHub","github.com",1},{"github.io","github.com",1},{"My Bank","mybank.com.au",1},{"bbc.co.uk","news.bbc.co.uk",2},
    {"github-login.com","github.com",0},{"github.com","github.com.evil.io",0},{"evil.io","github.com",0},{"co.uk","bbc.co.uk",0},
    {"com","github.com",0},{"gh","gh.io",0},{"","github.com",0},{"github.com","",0},{"New entry 3","github.com",0},
    {"example.co.uk","other.co.uk",0},{"x.github.com","y.github.com",1},
  };
  for(auto& m : mt){ int r = siteMatch(m.saved, m.want); if(r == m.exp) passes++; else { fails++; printf("FAIL siteMatch(%s, %s) = %d, want %d\n", m.saved, m.want, r, m.exp); } }
  // savedName: the address saved on a login after a close match
  { struct { const char* in; const char* exp; } sv[] = { {"dash.cloudflare.com","cloudflare.com"}, {"cloudflare.com","cloudflare.com"}, {"www.bbc.co.uk","bbc.co.uk"},
      {"login.bank.com.au","bank.com.au"}, {"127.0.0.1","127.0.0.1"}, {"localhost","localhost"}, {"GitHub.com","github.com"}, {"a.b.c.github.io","github.io"} };
    for(auto& v : sv){ char o[LQ_NAME_MAX]; savedName(v.in, o, sizeof o); if(!strcmp(o, v.exp)) passes++; else { fails++; printf("FAIL savedName(%s) = %s, want %s\n", v.in, o, v.exp); }
      if(strchr(v.exp, '.') && strcmp(v.exp, "127.0.0.1")){ if(siteMatch(o, v.in) >= 2) passes++; else { fails++; printf("FAIL saved %s does not strongly match %s\n", o, v.in); } } } }
  // fuzz siteMatch for crashes and symmetry of exact
  for(int it = 0; it < 200000; it++){
    char a[160], b[160]; int an = rng() % 150, bn = rng() % 150;
    for(int i = 0; i < an; i++) a[i] = "abc.:/ wGHT-0"[rng() % 13]; a[an] = 0;
    for(int i = 0; i < bn; i++) b[i] = "abc.:/ wGHT-0"[rng() % 13]; b[bn] = 0;
    int r1 = siteMatch(a, b), r2 = siteMatch(b, a);
    if((r1 == 3) != (r2 == 3)){ fails++; printf("FUZZ exact not symmetric [%s] [%s]\n", a, b); break; }
  }
  printf("loginqr: %d passed, %d failed; fuzz %ld inputs\n", passes, fails, fz);
  return fails ? 1 : 0;
}
