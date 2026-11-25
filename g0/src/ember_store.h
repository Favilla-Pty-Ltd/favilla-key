/* ember_store.h — Emberwill's flash: one plan page, two state pages. 28 Oct 2026.
 *
 *   0x0801E800  plan page   written once per ceremony, erased at EMBER_CLEAR or
 *                           when the Kindling transaction is 6 deep
 *   0x0801E000  state A  \  append-only log of state records, ping-pong:
 *   0x0801D800  state B  /  records go to the page holding the newest one; when
 *                           it is full the OTHER page is erased and written, so
 *                           the newest valid record survives a power cut at any
 *                           moment (during an erase or in a torn write)
 * Image cap: 0x0801D800 - 0x08000000 = 120832 (platformio.ini maximum_size).
 *
 * Every record carries a digest; a torn or foreign record reads as absent.
 * The flash itself is behind three function pointers so the host tests can
 * cut power at every doubleword.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "ember_walk.h"
#include "ember_hdr.h"
#include "ember_plan.h"

#define ES_PAGE_SIZE     2048u
#define ES_PLAN_ADDR     0x0801E800u
#define ES_STATE_A_ADDR  0x0801E000u
#define ES_STATE_B_ADDR  0x0801D800u
#define ES_IMAGE_CAP     (ES_STATE_B_ADDR - 0x08000000u)

typedef struct {
    int  (*erase)(void *ctx, uint32_t page_addr);                       /* 0 ok */
    int  (*prog)(void *ctx, uint32_t addr, const uint8_t *d, size_t n); /* n multiple of 8, 0 ok */
    const uint8_t *(*map)(void *ctx, uint32_t addr);
    void *ctx;
} es_flash_t;

typedef struct {
    uint8_t  plan_id[32];
    uint8_t  blob_key[32];       /* G0-only: AEAD key for the plan's ciphertexts */
    uint32_t tip0, x0;
    uint8_t  set_wire[EP_SET_LEN];
    uint8_t  rtxid[EP_MAX_LINKS][32];               /* R1..RN */
    uint8_t  ctxid[EP_MAX_LINKS + 1][EP_CVARS][32]; /* C0..CN, each variant */
} es_plan_t;

/* The header clock's restart point: a block at least 6 below the tip at the
 * time of writing, and the 11 timestamps ending at it. */
typedef struct {
    eh_anchor_t settled;
    ew_state_t  walk;
    uint8_t     owner[32];    /* the owner's Nostr x-only key, bound by the G0 itself at a tier-1 fetch */
    uint8_t     owner_set;
    uint32_t    seq;
} es_state_t;

int  es_plan_write(const es_flash_t *f, const es_plan_t *p);   /* erase, program, read back: 0 ok */
int  es_plan_load(const es_flash_t *f, es_plan_t *p);          /* 1 present and valid, 0 absent */
int  es_plan_erase(const es_flash_t *f);

int  es_state_load(const es_flash_t *f, const uint8_t plan_id[32], es_state_t *s);   /* newest valid for this plan */
int  es_state_append(const es_flash_t *f, const uint8_t plan_id[32], es_state_t *s); /* seq set inside; 0 ok */
int  es_state_erase(const es_flash_t *f);

/* Settled anchor from a live chain: the main block `depth` below the tip
 * (if the ring holds it and its 11 predecessors' times), else the current
 * floor anchor unchanged. */
void es_settle(const eh_chain_t *c, uint32_t depth, const eh_anchor_t *fallback, eh_anchor_t *out);
