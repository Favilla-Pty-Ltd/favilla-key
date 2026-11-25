/* =============================================================================
 * key_store.h — persistent K_SE / K_G0 for the Favilla G0 (STEP 5)
 * =============================================================================
 *
 * Before this, K_SE and K_G0 lived only in RAM, so every reboot (and every
 * flash) wiped them and forced a re-onboard. That also made the reboot-into-
 * WiFi live-signing test impossible. This module puts both keys in the LAST
 * 2 KB flash page of the 128 KB G0B1 and loads them at boot.
 *
 * LAYOUT v2 (page @ KS_PAGE_ADDR, 2 KB, only the first 128 bytes used):
 *     off 0   magic     8   "FAVILG0\x02"     (KS_MAGIC — v2 adds k_mode)
 *     off 8   k_se      16
 *     off 24  k_g0      32
 *     off 56  k_mode    32   S: the BTC-door secret (16 Sep 2026). Used ONLY to
 *                            extend MODE_PCR (G0_CMD_MODEBTC). Never output.
 *     off 88  digest    32   SHA256(magic || k_se || k_g0 || k_mode || gen8)
 *     off 120 gen       8    v3 (v5.1): SE object generation, 1 byte + 7 zero
 *  (v3 magic "FAVILG0\x03"; a v2 record reads as ABSENT -> re-onboard)
 *
 * A v1 record ("FAVILG0\x01") fails the magic check and reads as ABSENT: a
 * unit flashed with this firmware must be re-onboarded, which is required
 * anyway because the SE policies change in the same step.
 *
 * The digest is the durability check: a torn or corrupted write fails to
 * validate and the record is treated as absent (fail closed to onboarding).
 * It is NOT a confidentiality measure — anyone with the flash has the keys.
 * Confidentiality of K_G0 comes from RDP Level 2 (step 6), which makes the
 * SWD pads inert so the page cannot be read out. Until RDP is burned, a
 * bench device's flash is readable; that is understood and is why RDP is the
 * last production step.
 *
 * G0B1 flash programs in 8-byte DOUBLEWORDS and erases in 2 KB PAGES. All
 * offsets above are doubleword-aligned by construction.
 * ========================================================================== */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Last 2 KB page of 128 KB flash: 0x08000000 + 0x20000 - 0x800. v5.1: the
 * page below it (0x0801F000) is the seed store, so the build is capped at
 * 124 KB (platformio.ini board_upload.maximum_size = 126976) and the firmware
 * image can never grow into either page. If you raise the cap, move the pages
 * and the cap together. */
#define KS_PAGE_ADDR   0x0801F800u
#define KS_PAGE_SIZE   2048u
#define KS_KSE_LEN     16u
#define KS_KG0_LEN     32u
#define KS_KMODE_LEN   32u

/* Load the stored keys into the caller's buffers if a valid record exists.
 * Returns 1 and fills kse/kg0 on success; 0 if absent or corrupt (keys stay
 * whatever the caller pre-set them to — the caller must treat 0 as "no keys").
 * Pure read, no flash unlock needed. */
int  ks_load(uint8_t kse[KS_KSE_LEN], uint8_t kg0[KS_KG0_LEN], uint8_t kmode[KS_KMODE_LEN], uint8_t *gen);

/* Erase the page, write the record, read it back and verify the digest.
 * Returns 1 only if the read-back record validates — so a caller that acks
 * on 1 is acking durable storage, not just a submitted write. Returns 0 on
 * any HAL error or a verify mismatch (and leaves the page erased, i.e. no
 * keys, rather than a half-written record). */
int  ks_store(const uint8_t kse[KS_KSE_LEN], const uint8_t kg0[KS_KG0_LEN], const uint8_t kmode[KS_KMODE_LEN], uint8_t gen);

/* v24 (25 Nov 2026): the vault limit (records opened and site tags made per
 * sitting; 0 = no limit), kept as an append-only log in the key page's unused
 * tail (offset 256..2047, one doubleword per change). ks_store (onboarding)
 * erases the page, so a new owner starts with no limit.
 * ks_lim_load: 1 and *lim = the newest entry, 0 = none written.
 * ks_lim_store: 1 if the new entry reads back. 0 when the log is full (224
 * changes): the page is never erased for this, since a power cut mid-rewrite
 * would lose the keys. A new onboarding starts a fresh log. */
int  ks_lim_load(uint8_t *lim);
int  ks_lim_store(uint8_t lim);

/* Erase the page. Returns 1 on success. After this ks_load() reports absent. */
int  ks_erase(void);

/* True if a valid record is present (cheap: checks magic+digest). */
int  ks_present(void);

/* =============================================================================
 * v5.1 (15 Oct 2026): the SEED STORE. The double-wrapped seed blob used to live
 * in the ESP32's NVS, where any code on the ESP32 could replace it (a seed the
 * attacker chose, sealed through an ungated SEEDSEAL, so the user receives
 * funds to the attacker's wallet) or delete it. It now lives here, in its own
 * 2 KB page just below the key page.
 *
 * LAYOUT (page @ SS_PAGE_ADDR, first 176 bytes):
 *     off 0    magic   8   "FAVSEED\x01"
 *     off 8    kind    1   0 = BIP-39 seed, 1 = entropy container (+7 zero pad)
 *     off 16   outer  96   the SE-wrapped blob, IV_lo|CT_lo|IV_hi|CT_hi
 *     off 112  ihash  32   SHA256(inner ciphertext, 64 bytes): the G0 layer
 *     off 144  digest 32   SHA256(bytes 0..143), durability check only
 *
 * WRITE-ONCE: ss_store refuses while a valid record exists. Only ss_erase
 * (called from wipe_keys, i.e. behind the WIPEKEYS gate) clears it.
 * ihash binds the record to what SEEDSEAL/ENTSEAL produced in the same power-on
 * life, and every fetch checks the inner packet against it, so the ESP32 can
 * neither substitute a different inner ciphertext nor redirect to another blob.
 * Nothing here is secret: the outer blob opens only with the spend PIN inside
 * the SE, the inner only with K_G0.
 * ========================================================================== */
#define SS_PAGE_ADDR      0x0801F000u
#define SS_OUTER_LEN      96u
#define SS_KIND_SEED      0u
#define SS_KIND_ENTROPY   1u
int  ss_present(void);
int  ss_load(uint8_t *kind, uint8_t outer[SS_OUTER_LEN], uint8_t ihash[32]);
int  ss_store(uint8_t kind, const uint8_t outer[SS_OUTER_LEN], const uint8_t ihash[32]);
int  ss_erase(void);

/* Emberwill pages only (0x0801D800..0x0801EFFF). 0 ok. */
int ks_flash_erase_page(uint32_t addr);
int ks_flash_program(uint32_t addr, const uint8_t *d, size_t n);
