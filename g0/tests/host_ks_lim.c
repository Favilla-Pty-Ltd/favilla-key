/* 25 Nov 2026 (v24) host test for the vault limit log in the key page (key_store.c, ks_lim_*).
 * The real key_store.c, with the two flash pages mapped at their real addresses
 * and a fake HAL that only clears bits (as NOR flash does) and erases whole pages. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include "stm32g0xx_hal.h"
#include "key_store.h"
static int pass, fail;
#define CHECK(c, m) do { if (c) { pass++; printf("PASS  %s\n", m); } else { fail++; printf("FAIL  %s\n", m); } } while (0)
static int unlocked = 0, programs = 0, erases = 0, prog_fail_at = -1;
HAL_StatusTypeDef HAL_FLASH_Unlock(void) { unlocked = 1; return HAL_OK; }
HAL_StatusTypeDef HAL_FLASH_Lock(void) { unlocked = 0; return HAL_OK; }
HAL_StatusTypeDef HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef *e, uint32_t *err) {
    if (!unlocked) return 1;
    uint32_t a = FLASH_BASE + (e->Banks == FLASH_BANK_2 ? FLASH_BANK_SIZE : 0) + e->Page * 2048u;
    memset((void *)(uintptr_t)a, 0xFF, 2048); erases++; *err = 0xFFFFFFFFu; return HAL_OK;
}
HAL_StatusTypeDef HAL_FLASH_Program(uint32_t t, uint32_t a, uint64_t d) {
    (void)t; if (!unlocked || (a & 7u)) return 1;
    if (prog_fail_at >= 0 && programs == prog_fail_at) { programs++; return 1; }
    uint64_t *p = (uint64_t *)(uintptr_t)a; if (*p != ~0ull) return 1;   /* G0: a doubleword is written once per erase */
    *p = d; programs++; return HAL_OK;
}
int main(void) {
    void *m = mmap((void *)(uintptr_t)0x0801F000u, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 2; }
    memset(m, 0xFF, 4096);
    uint8_t kse[16], kg0[32], km[32], L = 0xAA;
    for (int i = 0; i < 16; i++) kse[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) { kg0[i] = (uint8_t)(0x40 + i); km[i] = (uint8_t)(0x80 + i); }
    CHECK(!ks_lim_load(&L) && L == 0xAA, "erased page: no limit written");
    CHECK(!ks_lim_store(16), "no key record (not onboarded): refused");
    CHECK(ks_store(kse, kg0, km, 1), "a key record stored");
    CHECK(!ks_lim_load(&L), "after onboarding: none written (no limit)");
    CHECK(ks_lim_store(16) && ks_lim_load(&L) && L == 16, "16 stored and read back");
    CHECK(ks_lim_store(0) && ks_lim_load(&L) && L == 0, "then none: the newest entry wins");
    { uint8_t a[16], b[32], c[32], g = 0; CHECK(ks_present() && ks_load(a, b, c, &g) && !memcmp(a, kse, 16) && !memcmp(b, kg0, 32) && !memcmp(c, km, 32) && g == 1, "the key record is untouched by the log"); }
    { uint8_t *e = (uint8_t *)(uintptr_t)(KS_PAGE_ADDR + 256 + 8); e[5] ^= 0x01;   /* a torn last entry (its check byte bad) */
      CHECK(ks_lim_load(&L) && L == 16, "a bad newest entry is skipped: the one before it counts"); e[5] ^= 0x01; }
    { int e0 = erases, ok = 1, n = 2; while (ks_lim_store((uint8_t)(n % 2 ? 32 : 64))) n++;
      CHECK(n == 224 && erases == e0, "224 entries fit, then refused, and the key page is never erased for it");
      CHECK(ks_lim_load(&L) && L == ((n - 1) % 2 ? 32 : 64) && ks_present(), "full: the last one written still reads, the keys still load"); (void)ok; }
    CHECK(ks_store(kse, kg0, km, 1) && !ks_lim_load(&L), "a new onboarding (ks_store) starts a fresh log: no limit");
    prog_fail_at = programs;
    CHECK(!ks_lim_store(8) && !ks_lim_load(&L), "a failed flash write: refused, nothing reads back");
    prog_fail_at = -1;
    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
