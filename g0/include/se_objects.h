/* SE051 object ids the G0 talks to. MUST match FKIO/src/se_signer.h — the ESP32
 * provisions these; the G0 only ever names them. If se_signer.h changes an id,
 * change it here in the same commit. Confirm on first build (see README). */
#pragma once
#include <stdint.h>
/* v5.1 GENERATIONS (15 Oct 2026). Every object that a policy names (PINs, auth
 * objects, PCRs) or that holds wallet secrets lives at  base + (gen << 8),
 * gen 1..SE_GEN_MAX, chosen fresh at each onboarding and stored in this chip's
 * key page. Why: no one may DELETE a PIN or auth object any more (a deleted
 * object can be recreated at the same id with a known PIN, which passes every
 * policy that names the id: a PIN reset). So a recovery wipe can no longer free
 * those ids, and the next onboarding moves to fresh ones. Old objects stay as
 * dead weight that guards nothing. gen 0 = the pre-v5.1 ids. PAIR_WRAP (device
 * identity, no-auth) and the attestation key are NOT per generation. */
#define SE_GEN_MAX             63u
extern uint32_t g_gen_off;   /* gen << 8, set from the key page / SETKEYS */
#define SE_AUTH_OBJ_G0        (0x20000030u + g_gen_off)   /* AES-128 AESKey auth object = K_SE (this chip's identity to the SE) */
#define SE_OBJ_PCR_UNLOCK     (0x20000031u + g_gen_off)   /* Door-1 PCR. v5.1: the G0 holds WRITE (extend) only, for DOOR1LOCK; no reset/delete/read */
#define SE_OBJ_DOOR1_SECRET   (0x20000036u + g_gen_off)   /* v5.1: 48 B binary, READ by the DAILY PIN only; X = SHA256(it) is the Door-1 unlock extend. Replaces PCR_UNLOCK in WIPE_ORDER (RECOVER no longer deletes the PCR) */
#define SE_OBJ_AES_WRAP_DAILY (0x20000022u + g_gen_off)   /* daily wrap key; DEC granted to G0-auth AND PCR==unlocked */
#define SE_OBJ_NOSTR_SCALAR   (0x20000002u + g_gen_off)   /* binary 48 B = IV(16) || AES(K_DAILY, AES(K_G0, scalar)) */
#define SE_OBJ_NSEC_IMPORT    (0x20000003u + g_gen_off)   /* same layout, restore-from-nsec path (step 4: which slot?) */
#define SE_OBJ_PCR_MODE       (0x20000033u + g_gen_off)   /* two-door mode latch; G0 resets it to NEUTRAL once per physical boot */
#define SE_OBJ_AES_WRAP_SEED  (0x20000020u + g_gen_off)   /* v3: seed wrap key; DEC granted to G0-auth AND MODE_PCR==BTC (nobody else can DEC) */
#define SE_AUTH_OBJ_RECOVER   (0x20000035u + g_gen_off)   /* 14 Oct 2026: moved from 0x20000034 (orphaned by N21). v4.1 (24 Sep 2026): AESKey auth object = K_RECOVER (derived from K_SE). v5.1: DELETE on the wallet secrets and MODE_PCR only; NO right on PINs or the Door-1 PCR. 20 Oct 2026 (N2): DELETE on the G0 auth object too from SE generation 9, used last-but-one in WIPEALL */
#define SE_OBJ_PK_SCRATCH     (0x20000037u + g_gen_off)   /* 30 Oct 2026, restorable passkeys: P-256 key object, private key only. Policy: SIGN|WRITE|DELETE for SE_AUTH_OBJ_G0, DELETE for RECOVER, nothing else. A site key lives in it for one PKSIGN, then junk is written over it */
#define SE_OBJ_PK_MASTER      (0x20000038u + g_gen_off)   /* 30 Oct 2026, restorable passkeys: binary 48 B, same layout and policy as NOSTR_SCALAR, holds S_pk */
/* 2 Nov 2026, Vault spec v0.25 section 1b (phase 2b); v19 (13 Nov 2026, one door one PIN):
 *   K_PK   AES: passkey PIN ENC|DEC|WRITE|DELETE @ MODE_PCR==V_3; RECOVER DELETE. NO G0 entry (v19).
 *   PK_MASTER_P binary 80 B = IV || AES(K_PK, inner32 || tag32): passkey PIN READ|WRITE|DELETE,
 *          RECOVER DELETE, no G0 entry (v19). The passkey session DECs it and hands inner || tag
 *          to the G0 on PKM_IN.
 *   K_PKN, PK_MASTER (the NOSTR copy) and K_IXN are no longer made (v19); WIPEALL still deletes
 *          them where an older generation left them. */
#define SE_OBJ_K_PK           (0x20000039u + g_gen_off)
#define SE_OBJ_K_PKN          (0x2000003Au + g_gen_off)
#define SE_OBJ_PK_MASTER_P    (0x2000003Bu + g_gen_off)
/* 2 Nov 2026 (v14, Vault spec phase 3): binary 48 B = IV || AES(K_PKN, AES(K_G0, k_pub)), the vault
 * backup publishing key. Policy: G0 READ; passkey PIN WRITE|DELETE; RECOVER DELETE; no daily entry.
 * Written by the ESP32 inside a passkey window; the NOSTR gate never deletes it. */
#define SE_OBJ_VPUB           (0x2000003Cu + g_gen_off)
#define SE_OBJ_PAIR_WRAP       0x20000021u   /* device-identity wrap key (NO-AUTH); listed for WIPEALL */
#define SE_OBJ_PIN_DAILY      (0x70000003u + g_gen_off)   /* UserID auth objects. v5.1: NOT deleted by WIPEALL (no one but the PIN itself may delete a PIN) */
#define SE_OBJ_PIN_SPEND      (0x70000005u + g_gen_off)
#define SE_BLOB_LEN            48
