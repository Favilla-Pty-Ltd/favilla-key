// sha256.h — reference SHA-256 for the HOST HARNESS ONLY.
// Not used on device; exists so firmware headers that call mbedtls can be
// compiled on the desktop under sanitizers.
//
// All shifts use explicit uint32_t operands. A uint8_t shifted left by 24
// promotes to int and overflows — undefined behaviour, which the sanitizer
// correctly flagged in the first draft of this very file.
#pragma once
#include <stdint.h>
#include <string.h>

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t bl; } sctx;

static const uint32_t _K[64] = {
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };

static inline uint32_t _rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void _sha_block(sctx* c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16)
             | ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = _rotr(w[i-15],7) ^ _rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = _rotr(w[i-2],17) ^ _rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],hh=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1  = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25);
        uint32_t ch  = (e & f) ^ ((~e) & g);
        uint32_t t1  = hh + S1 + ch + _K[i] + w[i];
        uint32_t S0  = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2  = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g;  c->h[7]+=hh;
}

static void sinit(sctx* c) {
    c->h[0]=0x6a09e667u; c->h[1]=0xbb67ae85u; c->h[2]=0x3c6ef372u; c->h[3]=0xa54ff53au;
    c->h[4]=0x510e527fu; c->h[5]=0x9b05688cu; c->h[6]=0x1f83d9abu; c->h[7]=0x5be0cd19u;
    c->len = 0; c->bl = 0;
}

static void _supd_raw(sctx* c, const uint8_t* d, size_t n) {
    while (n) {
        size_t k = 64 - c->bl; if (k > n) k = n;
        memcpy(c->buf + c->bl, d, k);
        c->bl += k; d += k; n -= k;
        if (c->bl == 64) { _sha_block(c, c->buf); c->bl = 0; }
    }
}
static void supd(sctx* c, const uint8_t* d, size_t n) { c->len += n; _supd_raw(c, d, n); }

static void sfin(sctx* c, uint8_t* out) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80; _supd_raw(c, &pad, 1);          // padding is not message length
    uint8_t z = 0; while (c->bl != 56) _supd_raw(c, &z, 1);
    uint8_t l[8];
    for (int i = 0; i < 8; i++) l[i] = (uint8_t)((bits >> (56 - 8*i)) & 0xFF);
    _supd_raw(c, l, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

static void __attribute__((unused)) SHA256(const uint8_t* d, size_t n, uint8_t* o) {
    sctx c; sinit(&c); supd(&c, d, n); sfin(&c, o);
}
