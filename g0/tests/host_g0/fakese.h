#pragma once
#include <stdint.h>
#include <stddef.h>
#define FSE_MAX 96
enum { FSE_K_AUTH = 1, FSE_K_PCR, FSE_K_AES, FSE_K_BIN, FSE_K_PIN, FSE_K_EC };
#define FSE_R_READ   0x01u
#define FSE_R_WRITE  0x02u
#define FSE_R_DELETE 0x04u
#define FSE_R_ENC    0x08u
#define FSE_R_DEC    0x10u
#define FSE_ANON     0x00000000u
typedef struct { uint32_t who, rights, gate_pcr; uint8_t gate_val[32]; } fse_pol_t;
typedef struct {
    int used; uint32_t id; int kind;
    uint8_t val[256]; size_t len;   /* AUTH: key (16); PCR: value (32); AES: key (32); BIN: data; PIN: the PIN */
    fse_pol_t pol[8]; int npol;
    int reset_base;
} fse_obj_t;
extern fse_obj_t fse[FSE_MAX];
extern int fse_log;
fse_obj_t *fse_find(uint32_t id);
fse_obj_t *fse_create(uint32_t id, int kind);
void fse_neutral(uint8_t out[32]);
void fse_ext(const uint8_t cur[32], const uint8_t e[32], uint8_t out[32]);
uint32_t fse_rights(const fse_obj_t *o, uint32_t p);
void fse_crypt(const fse_obj_t *k, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]);
int fse_cipher(uint32_t P, uint32_t key, int decrypt, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]);
