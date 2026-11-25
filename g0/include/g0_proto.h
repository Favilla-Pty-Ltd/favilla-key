/* =============================================================================
 * g0_proto.h — wire protocol shared with the ESP32
 * =============================================================================
 *
 * MUST match esp32/g0_signer.h byte for byte. If you change anything here,
 * change it there in the same commit.
 *
 * DESIGN RULE: every signing-path length in this protocol is FIXED. There is no
 * length field on the signing path for an attacker to lie about, and therefore
 * no buffer-overflow surface on the path that touches the key. The only
 * variable-length messages are the SCP03 relay frames, which are authenticated
 * by CMAC and discarded whole on failure.
 * ========================================================================== */

#ifndef G0_PROTO_H
#define G0_PROTO_H

#include <stdint.h>

#define G0_I2C_ADDR        0x42

/* Registers */
#define G0_REG_CMD         0x00   /* W, 1 byte                        */
#define G0_REG_STATUS      0x01   /* R, 1 byte, idempotent            */
#define G0_REG_HASH_IN     0x10   /* W, exactly 32 bytes: hash, scalar,
                                   *    or peer x-only pubkey (by command) */
#define G0_REG_SIG_OUT     0x11   /* R, exactly 64 bytes              */
#define G0_REG_KEYS_IN     0x12   /* W, exactly 48 bytes: K_SE(16) || K_G0(32)          */
#define G0_REG_SELFTEST    0x7F   /* R, 16 bytes: "G0ST",ver,npass,ntotal,flags,sign/verify/ecdh ms  */
#define G0_REG_RELAY_OUT   0x20   /* R, [len_hi][len_lo][payload]. EVERY read
                                   *    of this register streams from byte 0;
                                   *    the master reads 2 bytes for the
                                   *    length, then 2+len for the frame. An
                                   *    I2C target cannot know how many bytes
                                   *    the master will clock, so there is no
                                   *    "header-only" reply mode.            */
#define G0_REG_RELAY_IN    0x21   /* W, [len_hi][len_lo][payload]     */

/* Commands */
#define G0_CMD_SIGN        0x01
#define G0_CMD_RESET       0x02
#define G0_CMD_PROVISION   0x03
#define G0_CMD_ECDH        0x04   /* NIP-04/44 shared secret          */
#define G0_CMD_PUBKEY      0x05   /* x-only public key (no input)     */
#define G0_CMD_CACHEKEY    0x06   /* HKDF-derived PWA cache key       */
#define G0_CMD_SETKEYS     0x07   /* onboarding: store K_SE||K_G0 from REG 0x12, ack SHA256 on SIG_OUT */
#define G0_CMD_WIPEKEYS    0x08   /* wallet delete: erase both keys from flash, return to IDLE */

/* Status */
#define G0_ST_IDLE         0x00
#define G0_ST_NEED_RELAY   0x01
#define G0_ST_BUSY         0x02
#define G0_ST_SIG_READY    0x03
#define G0_ST_ERROR        0xE0

/* Sizes */
#define G0_HASH_LEN        32
#define G0_SIG_LEN         64
#define G0_RELAY_MAX       512
#define G0_SEALED_LEN      32    /* CT only; IV derived from K_G0 */
#define G0_ECDH_LEN        32    /* shared secret X, fixed */
#define G0_SE_BLOB_LEN     48    /* what the SE stores: IV(16)||CT(32) */

#endif /* G0_PROTO_H */
