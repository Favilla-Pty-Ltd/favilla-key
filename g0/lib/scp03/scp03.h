/* =============================================================================
 * scp03.h — SE05x AESKey APPLET session (SCP03) for the Favilla G0
 * =============================================================================
 *
 * A transport-agnostic port of the session path in NXP Plug & Trust
 * (fsl_sss_se05x_scp03.c, nxScp03_Com.c, se05x_tlv.c: se05x_Transform /
 * se05x_Transform_scp / nxpSCP03_Decrypt_ResponseAPDU) for the G0's use of
 * the SE051 over the ESP32 blind relay.
 *
 * What it does, byte for byte as the middleware does it:
 *   1. CreateSession(authObj)                      plain, 8-byte session id
 *   2. INITIALIZE UPDATE  (80 50 00 00 08 hc)      wrapped in ProcessSessionCmd
 *   3. derive S-ENC/S-MAC/S-RMAC, check card cryptogram, host cryptogram
 *   4. EXTERNAL AUTHENTICATE (84 82 33 00 10 hcrypto mac)   wrapped, plain
 *   5. every later command: pad 80 00.., AES-CBC(S-ENC, ICV=AES(ctr)),
 *      CMAC(S-MAC, MCV || hdr|04 || Lc || ct) -> 8 bytes appended, wrapped in
 *      ProcessSessionCmd; response: CMAC(S-RMAC, MCV || body || SW) checked,
 *      body decrypted with ICV = AES(80 || ctr[1..15]), counter++.
 *   6. CloseSession — encrypted, empty payload
 *
 * This is an APPLET session (AN12543 3.6.3.2), NOT Platform SCP. The single
 * 16-byte auth key K_SE is the static ENC, MAC and DEK, exactly as
 * ex_sss_se05x_prepare_host_AppletScp03Keys() sets them. Key version 0x00.
 *
 * The transport callback is the ONLY thing that touches the outside world.
 * On the G0 it parks the frame for the ESP32 relay; on the host tests it
 * talks to a Python SE simulator.
 * ========================================================================== */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define SCP03_APDU_MAX 512       /* largest frame either direction (= G0_RELAY_MAX) */

/* Error codes. Negative = failed; s->last_sw carries the SE status word for
 * SCP03_E_SW; s->stage says how far the open got. */
#define SCP03_OK           0
#define SCP03_E_XFER      -1     /* transport (relay) failed or SE gave no SW */
#define SCP03_E_SW        -2     /* SE answered with SW != 9000 (see last_sw) */
#define SCP03_E_FORMAT    -3     /* response not the shape the spec says */
#define SCP03_E_CRYPTOGRAM -4    /* card cryptogram did not verify: wrong K_SE */
#define SCP03_E_RMAC      -5     /* response MAC bad: tampered or desynced */
#define SCP03_E_PAD       -6     /* decrypted response padding bad */
#define SCP03_E_STATE     -7     /* called in the wrong state */
#define SCP03_E_SIZE      -8     /* would not fit a frame / caller buffer */

/* Stages, for diagnostics */
#define SCP03_ST_NONE      0
#define SCP03_ST_CREATED   1     /* CreateSession returned a session id */
#define SCP03_ST_IU_DONE   2     /* INITIALIZE UPDATE answered */
#define SCP03_ST_KEYS      3     /* session keys derived, card cryptogram OK */
#define SCP03_ST_AUTHED    4     /* EXTERNAL AUTHENTICATE accepted: channel up */
#define SCP03_ST_CLOSED    5

/* Transport: send one complete C-APDU, get the complete R-APDU including SW.
 * Return 0 on success (rsp/rlen filled, rlen >= 2), non-zero on failure. */
typedef int (*scp03_xfer_fn)(void *ctx, const uint8_t *apdu, size_t alen,
                             uint8_t *rsp, size_t rcap, size_t *rlen);

typedef struct {
    scp03_xfer_fn xfer;
    void         *xctx;
    uint8_t  sid[8];
    uint8_t  senc[16], smac[16], srmac[16];
    uint8_t  mcv[16];            /* MAC chaining value */
    uint8_t  ctr[16];            /* command counter, big-endian, starts at 1 */
    uint16_t last_sw;
    uint8_t  stage;
    uint8_t  authed;
    uint8_t  nxfer;              /* APDUs sent so far in this session (relay steps) */
} scp03_session_t;

/* Open + authenticate. host_chal is the 8-byte host challenge (caller supplies
 * it; the G0 has no TRNG so it mixes what entropy it has). On return
 * card_chal_out (may be NULL) holds the SE's 8 random bytes — feed them back
 * into the caller's entropy pool. kse is consumed; the session keys are what
 * remain in the struct. */
int scp03_open(scp03_session_t *s, scp03_xfer_fn xfer, void *xctx,
               const uint8_t kse[16], uint32_t auth_obj,
               const uint8_t host_chal[8], uint8_t card_chal_out[8]);

/* One encrypted + MACed command inside the session. hasle selects the
 * middleware's Case4_ext framing (extended Lc + Le 0000, used by ReadObject
 * and CipherOneShot) versus Case3/Case4 (short Lc, no Le). out receives the
 * decrypted body WITHOUT the SW. Returns SCP03_OK only if SW == 9000. */
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2,
              const uint8_t *data, size_t dlen, int hasle,
              uint8_t *out, size_t ocap, size_t *olen);

/* Convenience wrappers matching AN12543 + Plug & Trust TLV orders. */
int scp03_read_object(scp03_session_t *s, uint32_t obj,
                      uint8_t *out, size_t ocap, size_t *olen);
int scp03_cipher_oneshot(scp03_session_t *s, uint32_t key_obj, int decrypt,
                         const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]);

/* Restorable passkeys (30 Oct 2026): private-only EC key write over an
 * existing P-256 object, and ECDSA-SHA256 sign returning DER. */
int scp03_ec_write_priv(scp03_session_t *s, uint32_t obj, const uint8_t priv[32]);
int scp03_ec_sign(scp03_session_t *s, uint32_t obj, const uint8_t hash[32],
                  uint8_t *der, size_t dcap, size_t *dlen);

/* CloseSession (encrypted). Always wipes the struct afterwards, even on error. */
int scp03_close(scp03_session_t *s);

/* Zeroize everything. */
void scp03_wipe(scp03_session_t *s);

/* AES-128 CMAC (RFC 4493), exported for the host tests. */
void aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t mlen, uint8_t mac[16]);
