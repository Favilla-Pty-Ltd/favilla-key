#include "Arduino.h"
#include "rk_host.cpp"
#include <cstdio>
S Serial; std::map<std::string, std::vector<uint8_t>> g_nvs;
using namespace favilla;
static RkPass mk(const char* site, const char* user, const char* pw){ RkPass p; memset(&p,0,sizeof p); p.slot=-1; strcpy(p.site,site); strcpy(p.user,user); strcpy(p.pass,pw); return p; }
int main(){
  rk_mount(); rk_wipe_all(); rk_forget_cache();
  uint8_t K[32]={1}; rk_idx_open(K,7,rk_lock_epoch());
  for(int i=0;i<5;i++){ char s[32]; snprintf(s,32,"s%d.example",i); RkPass e=mk(s,"u","p"); rk_pw_save(&e,nullptr); }
  rk_forget_cache(); rk_idx_open(K,7,rk_lock_epoch());
  RkPass e=mk("new.example","me","pw"); int slot=-1; printf("save %d slot %d\n", rk_pw_save(&e,&slot), slot);
  int ord[200]; int n=rk_pw_order(ord,200); RkRow row;
  for(int k=0;k<n;k++){ bool ok=rk_pw_row(ord[k],&row); printf("%d: idx %d ok %d slot %d site %s\n",k,ord[k],ok,row.slot,ok?row.site:"-"); }
}
