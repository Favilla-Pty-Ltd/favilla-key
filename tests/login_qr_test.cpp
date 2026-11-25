// login_qr_test.cpp - site matching for saved logins (src/login_qr.h).
// 3 = the same name, 2 = the same registrable domain, 1 = a close name (listed
// for the user to pick, never typed by itself), 0 = no match.
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -I src tests/login_qr_test.cpp -o /tmp/lq && /tmp/lq
#include <cstdio>
#include "login_qr.h"
int main(){ int bad = 0, n = 0;
#define T(a,b,w) do{ n++; int r = loginqr::siteMatch(a,b); if(r != w){ printf("FAIL %s vs %s: got %d want %d\n", a, b, r, w); bad++; } }while(0)
  T("github.com", "github.com", 3);  T("github.com", "www.github.com", 3);      // www is stripped
  T("github.com", "gist.github.com", 2); T("bbc.co.uk", "news.bbc.co.uk", 2);  T("proton.me", "account.proton.me", 2);
  T("GitHub", "github.com", 1);                                                  // a name for the domain
  T("protonmail.com", "account.proton.me", 1);                                   // 11av: one main name begins the other (5+)
  T("google.com", "googleusercontent.com", 1);
  T("amazon.com", "amazon.co.uk", 1);
  T("github.com", "gitlab.com", 0);  T("git.com", "github.com", 0);             // three in common is not close
  T("paypal.com", "paypa1.com", 0);  T("co.uk", "bbc.co.uk", 0);  T("", "github.com", 0);
  printf("login_qr: %d checks, %d failures\n", n, bad); return bad ? 1 : 0; }
