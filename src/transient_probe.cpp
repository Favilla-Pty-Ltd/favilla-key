// =============================================================================
// transient_probe.cpp — does THIS SE051 allow TRANSIENT objects at all?
// =============================================================================
// The transient PCR failed here (create 6A80 / ops 6985). But PCR is only one
// transient type. This probes transient BINARY and transient COUNTER: create
// (INS_WRITE|INS_TRANSIENT), write/read, report SW. If either is USABLE, the
// two-door "fresh boot" gate can be built on the SE alone (transient clears on
// power loss) — no G0 witness needed. If all 6A80, transient objects are off on
// this applet config and the G0 must tell the SE about the power cycle.
//
// Also the KEY question: run it, note the value, POWER CYCLE, run again — a
// transient object must READ BACK EMPTY/ABSENT after a real power cycle. That's
// the "SE saw a fresh boot" signal.
//
// Uses favilla::se_transceive_raw (public). Throwaway ids 0x20000094/95.
// Caller holds the I2C lock. Remove after.
// =============================================================================
#include <Arduino.h>
#include <string.h>
#include "se_signer.h"

static constexpr uint8_t INS_WRITE     = 0x01;
static constexpr uint8_t INS_TRANSIENT = 0x80;
static constexpr uint8_t INS_READ      = 0x02;
static constexpr uint8_t P1_BINARY     = 0x06;
static constexpr uint8_t P1_COUNTER    = 0x08;
static constexpr uint8_t P1_DEFAULT    = 0x00;
static constexpr uint8_t P2_DEFAULT    = 0x00;
static constexpr uint8_t TAG_1         = 0x41;
static constexpr uint8_t TAG_2         = 0x42;
static constexpr uint8_t TAG_3         = 0x43;

static constexpr uint32_t PROBE_BIN = 0x20000094u;
static constexpr uint32_t PROBE_CTR = 0x20000095u;

static void id4(uint32_t o, uint8_t b[4]){ b[0]=o>>24; b[1]=o>>16; b[2]=o>>8; b[3]=o; }
static uint16_t swf(const uint8_t*r,size_t n){ return n>=2?(uint16_t)((r[n-2]<<8)|r[n-1]):0xFFFF; }
static size_t tlv(uint8_t*b,size_t p,uint8_t t,const uint8_t*v,size_t l){ b[p++]=t;b[p++]=(uint8_t)l;memcpy(b+p,v,l);return p+l; }
static size_t apdu(uint8_t*o,uint8_t cla,uint8_t ins,uint8_t p1,uint8_t p2,const uint8_t*d,size_t dl,int le){
  o[0]=cla;o[1]=ins;o[2]=p1;o[3]=p2;size_t p=4;
  if(dl){o[p++]=(uint8_t)dl;memcpy(o+p,d,dl);p+=dl;} if(le>=0)o[p++]=(uint8_t)le; return p;
}
static uint16_t tx(const uint8_t*a,size_t al,uint8_t*r,size_t rc,size_t*rl){
  *rl=0; if(!favilla::se_transceive_raw(a,al,r,rc,rl))return 0xFFFF; return swf(r,*rl);
}

// transient binary: create+write 4 bytes at offset 0
static uint16_t bin_create(uint32_t oid,const uint8_t v[4]){
  uint8_t idb[4]; id4(oid,idb); uint8_t off[2]={0,0}; 
  uint8_t pl[48]; size_t p=0;
  p=tlv(pl,p,TAG_1,idb,4); p=tlv(pl,p,TAG_2,off,2); p=tlv(pl,p,TAG_3,v,4);
  uint8_t a[64]; size_t n=apdu(a,0x80,INS_WRITE|INS_TRANSIENT,P1_BINARY,P2_DEFAULT,pl,p,-1);
  uint8_t r[32]; size_t rl; return tx(a,n,r,sizeof r,&rl);
}
static uint16_t bin_read(uint32_t oid,uint8_t out[4],bool*got){
  uint8_t idb[4]; id4(oid,idb); uint8_t off[2]={0,0}; uint8_t len[2]={0,4};
  uint8_t pl[24]; size_t p=0; p=tlv(pl,p,TAG_1,idb,4); p=tlv(pl,p,TAG_2,off,2); p=tlv(pl,p,TAG_3,len,2);
  uint8_t a[32]; size_t n=apdu(a,0x80,INS_READ,P1_DEFAULT,P2_DEFAULT,pl,p,0x00);
  uint8_t r[32]; size_t rl; uint16_t sw=tx(a,n,r,sizeof r,&rl);
  *got=false; if(rl>=2+6 && r[0]==TAG_1){ memcpy(out,r+2,4); *got=true; } return sw;
}
// transient counter: create size 4
static uint16_t ctr_create(uint32_t oid){
  uint8_t idb[4]; id4(oid,idb); uint8_t sz[2]={0,4};
  uint8_t pl[24]; size_t p=0; p=tlv(pl,p,TAG_1,idb,4); p=tlv(pl,p,TAG_2,sz,2);
  uint8_t a[32]; size_t n=apdu(a,0x80,INS_WRITE|INS_TRANSIENT,P1_COUNTER,P2_DEFAULT,pl,p,-1);
  uint8_t r[32]; size_t rl; return tx(a,n,r,sizeof r,&rl);
}
static uint16_t ctr_read(uint32_t oid,uint8_t out[8],int*len,bool*got){
  uint8_t idb[4]; id4(oid,idb);
  uint8_t pl[8]; size_t p=tlv(pl,0,TAG_1,idb,4);
  uint8_t a[24]; size_t n=apdu(a,0x80,INS_READ,P1_DEFAULT,P2_DEFAULT,pl,p,0x00);
  uint8_t r[32]; size_t rl; uint16_t sw=tx(a,n,r,sizeof r,&rl);
  *got=false; *len=0;
  if(rl>=2+2 && r[0]==TAG_1){ int l=r[1]; if(l<=8 && (size_t)(2+l+2)<=rl){ memcpy(out,r+2,l); *len=l; *got=true; } }
  return sw;
}

void transient_probe_run(){
  Serial.println("========== [TRANSPROBE] ==========");
  // ---- transient BINARY ----
  { uint8_t v[4]; bool got=false; uint16_t rsw=bin_read(PROBE_BIN,v,&got);
    if(got){ Serial.printf("[TRANSPROBE] bin AS-FOUND read SW %04X val %02X%02X%02X%02X (survived? if EMPTY after power-cycle = good)\n",rsw,v[0],v[1],v[2],v[3]); }
    else   { Serial.printf("[TRANSPROBE] bin absent (SW %04X) -> creating transient\n",rsw);
             uint8_t mk[4]={0xB7,0x0B,0x17,0x01}; uint16_t c=bin_create(PROBE_BIN,mk);
             bool g2=false; uint8_t v2[4]; uint16_t r2=bin_read(PROBE_BIN,v2,&g2);
             Serial.printf("[TRANSPROBE] bin create SW %04X, readback SW %04X got=%d %s\n",c,r2,g2,
               (c==0x9000&&g2)?"USABLE":(c==0x6A80?"REFUSED 6A80 (transient binary NOT allowed)":"?")); } }
  // ---- transient COUNTER ----
  { uint8_t v[8]; int l=0; bool got=false; uint16_t rsw=ctr_read(PROBE_CTR,v,&l,&got);
    if(got){ Serial.printf("[TRANSPROBE] ctr AS-FOUND read SW %04X len %d (EMPTY after power-cycle = good)\n",rsw,l); }
    else   { Serial.printf("[TRANSPROBE] ctr absent (SW %04X) -> creating transient\n",rsw);
             uint16_t c=ctr_create(PROBE_CTR);
             bool g2=false; uint8_t v2[8]; int l2=0; uint16_t r2=ctr_read(PROBE_CTR,v2,&l2,&g2);
             Serial.printf("[TRANSPROBE] ctr create SW %04X, readback SW %04X got=%d %s\n",c,r2,g2,
               (c==0x9000&&g2)?"USABLE":(c==0x6A80?"REFUSED 6A80 (transient counter NOT allowed)":"?")); } }
  Serial.println("[TRANSPROBE] --> POWER CYCLE + run again: an object that reads ABSENT/EMPTY = the");
  Serial.println("[TRANSPROBE]     SE saw the power loss (the 'fresh boot' signal we need).");
  Serial.println("[TRANSPROBE] --> SOFT REBOOT + run again: if it also clears, that's fine (harmless).");
  Serial.println("========== [TRANSPROBE end] ==========");
}
