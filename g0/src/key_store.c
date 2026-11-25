/* key_store.c — see key_store.h. STM32G0B1 flash: 2 KB pages, 8-byte
 * doubleword programming (RM0444 §3.3). */
#include "key_store.h"
#include "stm32g0xx_hal.h"
#include "sha256.h"
#include <string.h>

static const uint8_t KS_MAGIC[8] = { 'F','A','V','I','L','G','0', 0x03 };   /* v2: + k_mode (S); v3 (v5.1): + SE object generation */

/* Offsets within the page. */
#define OFF_MAGIC   0u
#define OFF_KSE     8u
#define OFF_KG0     24u
#define OFF_KMODE   56u          /* S — BTC-door secret (16 Sep 2026) */
#define OFF_DIGEST  88u
#define OFF_GEN     120u         /* v5.1: SE object generation (1 byte, 7 bytes 0x00 pad) */
#define OFF_END     128u         /* first free doubleword after the record */
#define REC_DWORDS  (OFF_END / 8u)   /* 16 doublewords written */

static void wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }

static const uint8_t *page = (const uint8_t *)KS_PAGE_ADDR;

/* Recompute SHA256(magic || kse || kg0) over the page's own bytes. */
static void ks_digest_of_page(uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, page + OFF_MAGIC, 8);
    sha256_update(&c, page + OFF_KSE, KS_KSE_LEN);
    sha256_update(&c, page + OFF_KG0, KS_KG0_LEN);
    sha256_update(&c, page + OFF_KMODE, KS_KMODE_LEN);
    sha256_update(&c, page + OFF_GEN, 8);
    sha256_final(&c, out);
}

int ks_present(void) {
    if (memcmp(page + OFF_MAGIC, KS_MAGIC, 8) != 0) return 0;
    uint8_t d[32]; ks_digest_of_page(d);
    int ok = (memcmp(d, page + OFF_DIGEST, 32) == 0);
    wipe(d, 32);
    return ok;
}

int ks_load(uint8_t kse[KS_KSE_LEN], uint8_t kg0[KS_KG0_LEN], uint8_t kmode[KS_KMODE_LEN], uint8_t *gen) {
    if (!ks_present()) return 0;
    if (gen) *gen = page[OFF_GEN];
    memcpy(kse, page + OFF_KSE, KS_KSE_LEN);
    memcpy(kg0, page + OFF_KG0, KS_KG0_LEN);
    memcpy(kmode, page + OFF_KMODE, KS_KMODE_LEN);
    return 1;
}

/* Erase one 2 KB page by address. */
/* STM32G0B1 is a DUAL-BANK part (128 KB = 2 x 64 KB banks). HAL_FLASHEx_Erase
 * only auto-forces Banks to BANK_1 on SINGLE-bank products; on the G0B1 we MUST
 * set Banks ourselves, and the Page number is WITHIN the bank (0..31), not a
 * linear page across the whole flash. KS_PAGE_ADDR = 0x0801F800 lives in bank 2
 * (0x08010000..0x0801FFFF), page 31; SS_PAGE_ADDR = 0x0801F000 is bank 2 page 30.
 * Leaving Banks = 0 (the old {0} bug) made HAL_FLASHEx_Erase pass an invalid
 * bank to FLASH_PageErase, so the erase never completed correctly -> ks_store
 * returned 0 -> SETKEYS answered no ack. */
static int page_erase_locked(uint32_t addr) {
    FLASH_EraseInitTypeDef e = {0};
    uint32_t bankSize = FLASH_BANK_SIZE;              /* 0x10000 on 128 KB G0B1 */
    uint32_t off      = addr - FLASH_BASE;
    e.TypeErase = FLASH_TYPEERASE_PAGES;
    if (off >= bankSize) {
        e.Banks = FLASH_BANK_2;
        e.Page  = (off - bankSize) / KS_PAGE_SIZE;
    } else {
        e.Banks = FLASH_BANK_1;
        e.Page  = off / KS_PAGE_SIZE;
    }
    e.NbPages = 1;
    uint32_t err = 0;
    return HAL_FLASHEx_Erase(&e, &err) == HAL_OK && err == 0xFFFFFFFFu;
}
static int ks_erase_locked(void) { return page_erase_locked(KS_PAGE_ADDR); }

/* Emberwill pages (28 Oct 2026, src/ember_store.h): 0x0801D800..0x0801EFFF,
 * bank 2. Same unlock / bank arithmetic as the key and seed pages. 0 ok. */
int ks_flash_erase_page(uint32_t addr) {
    if (addr < 0x0801D800u || addr > 0x0801E800u || (addr & (KS_PAGE_SIZE - 1u))) return -1;
    if (HAL_FLASH_Unlock() != HAL_OK) return -1;
    int ok = page_erase_locked(addr);
    HAL_FLASH_Lock();
    return ok ? 0 : -1;
}
int ks_flash_program(uint32_t addr, const uint8_t *d, size_t n) {
    if (addr < 0x0801D800u || addr + n > 0x0801F000u || (addr & 7u) || (n & 7u)) return -1;
    if (HAL_FLASH_Unlock() != HAL_OK) return -1;
    int ok = 1;
    for (size_t i = 0; ok && i < n; i += 8) {
        uint64_t dw; memcpy(&dw, d + i, 8);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, addr + i, dw) != HAL_OK) ok = 0;
    }
    HAL_FLASH_Lock();
    return ok ? 0 : -1;
}

int ks_erase(void) {
    if (HAL_FLASH_Unlock() != HAL_OK) return 0;
    int ok = ks_erase_locked();
    HAL_FLASH_Lock();
    return ok;
}

int ks_store(const uint8_t kse[KS_KSE_LEN], const uint8_t kg0[KS_KG0_LEN], const uint8_t kmode[KS_KMODE_LEN], uint8_t gen) {
    /* Build the record in a RAM staging buffer, doubleword-aligned. */
    uint8_t rec[OFF_END];
    memset(rec, 0xFF, sizeof(rec));
    memcpy(rec + OFF_MAGIC, KS_MAGIC, 8);
    memcpy(rec + OFF_KSE, kse, KS_KSE_LEN);
    memcpy(rec + OFF_KG0, kg0, KS_KG0_LEN);
    memcpy(rec + OFF_KMODE, kmode, KS_KMODE_LEN);
    memset(rec + OFF_GEN, 0x00, 8); rec[OFF_GEN] = gen;
    {   /* digest over the record's own magic||kse||kg0||kmode||gen, same order as read-back */
        sha256_ctx c; sha256_init(&c);
        sha256_update(&c, rec + OFF_MAGIC, 8);
        sha256_update(&c, rec + OFF_KSE, KS_KSE_LEN);
        sha256_update(&c, rec + OFF_KG0, KS_KG0_LEN);
        sha256_update(&c, rec + OFF_KMODE, KS_KMODE_LEN);
        sha256_update(&c, rec + OFF_GEN, 8);
        sha256_final(&c, rec + OFF_DIGEST);
    }

    if (HAL_FLASH_Unlock() != HAL_OK) { wipe(rec, sizeof(rec)); return 0; }
    int ok = ks_erase_locked();
    for (uint32_t i = 0; ok && i < REC_DWORDS; i++) {
        uint64_t dw;
        memcpy(&dw, rec + i * 8u, 8);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD,
                              KS_PAGE_ADDR + i * 8u, dw) != HAL_OK) ok = 0;
    }
    HAL_FLASH_Lock();
    wipe(rec, sizeof(rec));

    /* Durability gate: only report success if the page now validates AND
     * reads back the exact keys. A torn write leaves the record invalid, so
     * the caller (which acks on 1) never trusts a key that isn't really there. */
    if (!ok) return 0;
    if (!ks_present()) return 0;
    if (memcmp(page + OFF_KSE, kse, KS_KSE_LEN) != 0) return 0;
    if (memcmp(page + OFF_KG0, kg0, KS_KG0_LEN) != 0) return 0;
    if (memcmp(page + OFF_KMODE, kmode, KS_KMODE_LEN) != 0) return 0;
    if (page[OFF_GEN] != gen) return 0;
    return 1;
}

/* =============================================================================
 * v5.1 seed store (15 Oct 2026) - see key_store.h
 * ========================================================================== */
static const uint8_t SS_MAGIC[8] = { 'F','A','V','S','E','E','D', 0x01 };
#define SS_OFF_MAGIC   0u
#define SS_OFF_KIND    8u            /* 1 byte, then 7 bytes 0x00 pad */
#define SS_OFF_OUTER   16u           /* 96 */
#define SS_OFF_IHASH   112u          /* 32 */
#define SS_OFF_DIGEST  144u          /* 32: SHA256(magic || kind8 || outer || ihash) */
#define SS_OFF_END     176u
#define SS_DWORDS      (SS_OFF_END / 8u)
static const uint8_t *spage = (const uint8_t *)SS_PAGE_ADDR;

static void ss_digest(const uint8_t *rec, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, rec + SS_OFF_MAGIC, SS_OFF_DIGEST);   /* magic, kind+pad, outer, ihash */
    sha256_final(&c, out);
}

int ss_present(void) {
    if (memcmp(spage + SS_OFF_MAGIC, SS_MAGIC, 8) != 0) return 0;
    uint8_t k = spage[SS_OFF_KIND];
    if (k != SS_KIND_SEED && k != SS_KIND_ENTROPY) return 0;
    uint8_t d[32]; ss_digest(spage, d);
    int ok = (memcmp(d, spage + SS_OFF_DIGEST, 32) == 0);
    wipe(d, 32);
    return ok;
}

int ss_load(uint8_t *kind, uint8_t outer[SS_OUTER_LEN], uint8_t ihash[32]) {
    if (!ss_present()) return 0;
    if (kind)  *kind = spage[SS_OFF_KIND];
    if (outer) memcpy(outer, spage + SS_OFF_OUTER, SS_OUTER_LEN);
    if (ihash) memcpy(ihash, spage + SS_OFF_IHASH, 32);
    return 1;
}

int ss_erase(void) {
    if (HAL_FLASH_Unlock() != HAL_OK) return 0;
    int ok = page_erase_locked(SS_PAGE_ADDR);
    HAL_FLASH_Lock();
    return ok;
}

int ss_store(uint8_t kind, const uint8_t outer[SS_OUTER_LEN], const uint8_t ihash[32]) {
    if (kind != SS_KIND_SEED && kind != SS_KIND_ENTROPY) return 0;
    if (ss_present()) return 0;                        /* write-once: only an erase (wipe) clears it */
    uint8_t rec[SS_OFF_END];
    memset(rec, 0x00, sizeof(rec));
    memcpy(rec + SS_OFF_MAGIC, SS_MAGIC, 8);
    rec[SS_OFF_KIND] = kind;
    memcpy(rec + SS_OFF_OUTER, outer, SS_OUTER_LEN);
    memcpy(rec + SS_OFF_IHASH, ihash, 32);
    ss_digest(rec, rec + SS_OFF_DIGEST);

    if (HAL_FLASH_Unlock() != HAL_OK) return 0;
    int ok = page_erase_locked(SS_PAGE_ADDR);
    for (uint32_t i = 0; ok && i < SS_DWORDS; i++) {
        uint64_t dw;
        memcpy(&dw, rec + i * 8u, 8);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, SS_PAGE_ADDR + i * 8u, dw) != HAL_OK) ok = 0;
    }
    HAL_FLASH_Lock();
    if (!ok) return 0;
    /* Durability gate, as ks_store: the page must validate and read back exactly. */
    if (!ss_present()) return 0;
    if (memcmp(spage, rec, SS_OFF_END) != 0) return 0;
    return 1;
}

/* ---- v24 (25 Nov 2026): the vault limit log (key_store.h) ------------------ */
#define OFF_LIM     256u
#define LIM_SLOTS   ((KS_PAGE_SIZE - OFF_LIM) / 8u)   /* 224 */
static int lim_entry_ok(const uint8_t *e) {
    return e[0] == 'V' && e[1] == 'L' && e[2] == 'I' && e[3] == 'M' && (uint8_t)(e[4] ^ e[5]) == 0xFF && e[6] == 0x5A && e[7] == 0x5A;
}
static int lim_erased(const uint8_t *e) { for (int i = 0; i < 8; i++) if (e[i] != 0xFF) return 0; return 1; }
int ks_lim_load(uint8_t *lim) {
    int found = 0;
    for (uint32_t i = 0; i < LIM_SLOTS; i++) {
        const uint8_t *e = page + OFF_LIM + i * 8u;
        if (lim_erased(e)) break;
        if (lim_entry_ok(e)) { *lim = e[4]; found = 1; }
    }
    return found;
}
int ks_lim_store(uint8_t lim) {
    if (!ks_present()) return 0;   /* only on an onboarded G0 (the page holds its keys) */
    uint8_t ent[8] = { 'V','L','I','M', lim, (uint8_t)~lim, 0x5A, 0x5A };
    uint32_t slot = LIM_SLOTS;
    for (uint32_t i = 0; i < LIM_SLOTS; i++) if (lim_erased(page + OFF_LIM + i * 8u)) { slot = i; break; }
    if (slot == LIM_SLOTS) return 0;   /* full (224 changes): never erase the page that holds the keys for this; onboarding starts a new log */
    uint64_t dw; memcpy(&dw, ent, 8);
    if (HAL_FLASH_Unlock() != HAL_OK) return 0;
    int ok = HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, KS_PAGE_ADDR + OFF_LIM + slot * 8u, dw) == HAL_OK;
    HAL_FLASH_Lock();
    if (!ok) return 0;
    uint8_t got = 0xFE;
    return ks_lim_load(&got) && got == lim;
}
