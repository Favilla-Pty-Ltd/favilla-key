// Host test for src/otpauth.h (9i). g++ -std=c++17 -Wall -I src tests/otpauth_test.cpp -o /tmp/otp && /tmp/otp
#include <cstdio>
#include <cstring>
#include "otpauth.h"
static int pass = 0, fail = 0;
#define CHECK(c, m) do { if (c) { pass++; printf("PASS  %s\n", m); } else { fail++; printf("FAIL  %s\n", m); } } while (0)
static int P(const char* u, otpauth::Entry* e) { return otpauth::parse(u, strlen(u), e); }
int main() {
  otpauth::Entry e;
  CHECK(P("otpauth://totp/GitHub:josh?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub", &e) == 0 &&
        !strcmp(e.site, "GitHub") && !strcmp(e.acct, "josh") && e.secretN == 20 && !memcmp(e.secret, "12345678901234567890", 20) &&
        e.digits == 6 && e.period == 30, "a GitHub-style QR: site, account, the RFC 6238 key, defaults 6 digits and 30 s");
  CHECK(P("otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=60", &e) == 0 &&
        !strcmp(e.site, "ACME Co") && !strcmp(e.acct, "john.doe@email.com") && e.digits == 8 && e.period == 60 && e.secretN == 20, "percent-decoding, 8 digits, 60 s");
  CHECK(P("otpauth://totp/alice?secret=jbswy3dpehpk3pxp", &e) == 0 && !strcmp(e.site, "alice") && e.acct[0] == 0 && e.secretN == 10, "no issuer and no colon: the label is the site; lower-case base32");
  CHECK(P("otpauth://totp/Example:alice?secret=JBSW Y3DP EHPK 3PXP====", &e) == 0 && e.secretN == 10, "spaces and padding in the secret");
  CHECK(P("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Real", &e) == 0 && !strcmp(e.site, "Real") && !strcmp(e.acct, "alice"), "the issuer parameter wins over the label's prefix");
  CHECK(P("otpauth://hotp/x?secret=JBSWY3DP&counter=1", &e) == otpauth::HOTP, "HOTP refused");
  CHECK(P("otpauth://totp/x?secret=JBSWY3DP&algorithm=SHA256", &e) == otpauth::ALGO && e.secretN == 0, "SHA256 refused, nothing kept");
  CHECK(P("otpauth://totp/x?secret=JBSWY3DP&digits=5", &e) == otpauth::DIGITS, "5 digits refused");
  CHECK(P("otpauth://totp/x?secret=JBSWY3DP&period=0", &e) == otpauth::PERIOD, "period 0 refused");
  CHECK(P("otpauth://totp/x?secret=JBSWY3D1", &e) == otpauth::BAD_SECRET, "a 1 in base32 refused");
  CHECK(P("otpauth://totp/x?issuer=y", &e) == otpauth::NO_SECRET, "no secret refused");
  CHECK(P("https://github.com", &e) == otpauth::NOT_OTP, "a web address is not a code QR");
  { char big[200]; strcpy(big, "otpauth://totp/x?secret="); for (int i = 0; i < 110; i++) strcat(big, "A");
    CHECK(P(big, &e) == otpauth::BAD_SECRET, "a secret over 64 bytes refused"); }
  CHECK(otpauth::siteMatch("GitHub", "github.com") && otpauth::siteMatch("GitHub", "www.github.com") && otpauth::siteMatch("github.com", "github.com"), "GitHub matches github.com and www.github.com");
  CHECK(otpauth::siteMatch("My Bank", "MyBank") && otpauth::siteMatch("ACME Co", "acmeco.com"), "spaces and case ignored");
  CHECK(!otpauth::siteMatch("GitHub", "gitlab.com") && !otpauth::siteMatch("Git", "github.com"), "no loose prefix matches");
  printf("\n%d passed, %d failed\n", pass, fail);
  return fail ? 1 : 0;
}
