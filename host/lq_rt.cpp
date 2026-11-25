#include "login_qr.h"
#include <cstdio>
#include <fstream>
#include <string>
int main(int c, char** v){ std::ifstream f(v[1]); std::string line; int bad = 0;
  while(std::getline(f, line)){ char s[101], u[101]; int r = loginqr::parse(line.data(), line.size(), s, u); printf("%d site[%s] user[%s]\n", r, s, u); if(r != 1) bad++; }
  return bad; }
