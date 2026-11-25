/* =============================================================================
 * se_session.h — AESKey applet session, G0 -> SE051
 * =============================================================================
 *
 * REPLACES the earlier scp03.h, which specified Platform SCP. That was wrong
 * for this design; see "Why not Platform SCP" below.
 *
 * WHAT THIS IS
 * ------------
 * An applet-level session on the SE051, authenticated with an AES key that only
 * this chip holds. Per AN12543 §3.6.3.2 the handshake is the GlobalPlatform
 * SCP03 pair — SCPInitializeUpdate then SCPExternalAuthenticate — and once
 * established, every command is carried inside ProcessSessionCmd together with
 * the session ID.
 *
 * WHY THIS WORKS ACROSS A RELAY
 * -----------------------------
 * The session is addressed by TLV[TAG_SESSION_ID] carried *in the APDU
 * payload* (AN12543 §4.5.1.3). The applet identifies the session from the
 * command itself, never from the transport. The ESP32 relaying our frames is
 * therefore invisible to the SE — it is moving bytes, not participating.
 *
 * Confirmed properties (AN12543):
 *   §3.6.5     sessions are fully transient; closed by CloseSession, policy
 *              expiry, applet deselect, or power cycle
 *   §4.3.41.1  no session timeout and no APDU limit unless a policy sets one
 *   p30        multiple applet sessions may be open in parallel by default
 *
 * WHY NOT PLATFORM SCP
 * --------------------
 * Platform SCP is platform-wide, not per-session. AN12543 §4.6.3: if
 * SCP_REQUIRED is set, "any applet APDU command will be refused by the applet
 * when platform SCP is not enabled." Mandating it would lock the ESP32 out of
 * the SE entirely and break every Bitcoin operation, since the ESP32 holds no
 * SCP03 keys — and giving it keys would defeat the whole design.
 *
 *   *** DO NOT SET SCP_REQUIRED DURING PROVISIONING. ***
 *
 * An AESKey applet session gives us the same SCP03 cryptography, scoped to one
 * session, while the ESP32 keeps using plain APDUs for Bitcoin on its own
 * concurrent PIN session.
 *
 * HOW THE NOSTR OBJECT IS BOUND TO US
 * -----------------------------------
 * The scalar object carries an object policy naming our AES authentication
 * object. The access rules are only active inside a session opened with that
 * object (AN12543 §3.6.3), so the ESP32 cannot reach it from its own session
 * even with a valid PIN.
 *
 * IMPLEMENTATION NOTE
 * -------------------
 * Do not hand-roll the SCP03 handshake or the counter handling. Port NXP's
 * Plug & Trust host (Se05x_API_* / sss layer) onto se_transport() below.
 * ========================================================================== */

#ifndef SE_SESSION_H
#define SE_SESSION_H

#include <stdint.h>

#define SE_OK                    0
#define SE_ERR_HANDSHAKE        -1
#define SE_ERR_MAC              -2   /* frame tampered or corrupted        */
#define SE_ERR_TRANSPORT        -3   /* relay stalled or failed            */
#define SE_ERR_NO_SESSION       -4   /* SE refused: no PIN session / policy */
#define SE_ERR_SESSION_LOST     -5   /* applet deselected or power cycled   */

/* Spin budget before concluding the ESP32 has stopped relaying. Sized well
 * above a full handshake plus one unwrap. Exceeding it is a fault, and a fault
 * must fail rather than hang. */
#define SE_RELAY_TIMEOUT_SPINS   2000000UL

/* Our AES authentication object in the SE. Provisioned at manufacture; the key
 * itself lives only in G0 flash behind RDP-2. The Nostr scalar object's policy
 * names this identifier. */
#define SE_AUTH_OBJ_G0           0x20000030u

/* Open an AESKey applet session:
 *   CreateSession(SE_AUTH_OBJ_G0)  -> session ID
 *   SCPInitializeUpdate            (inside ProcessSessionCmd)
 *   SCPExternalAuthenticate        (inside ProcessSessionCmd)
 *
 * The session ID is retained internally and applied to every subsequent
 * command. Safe to call when a session is already open — returns SE_OK.
 *
 * NOTE ON LIFETIME: the ESP32 controls applet selection, so it can deselect and
 * destroy our session at any time. That is denial of service, not compromise.
 * Callers must treat SE_ERR_SESSION_LOST as "re-open and retry once", not as a
 * fatal error. */
int se_session_open(void);

/* Close the session and zeroize session keys. Always safe to call. */
void se_session_close(void);

/* True if we believe a session is currently established. Advisory only — the
 * SE is the authority and may have closed it underneath us. */
int se_session_is_open(void);

/* Ask the SE to release the daily-wrapped Nostr object.
 *
 * The SE verifies the Door-1 PIN session before it will unwrap; no session
 * means it refuses, and that refusal is the security boundary — enforced by the
 * SE, not by us and not by the ESP32.
 *
 * IMPORTANT: what comes back is NOT the scalar. It is AES(K_G0, scalar); the SE
 * only ever strips its own outer layer. The inner layer is opened in main.c
 * with a key that never leaves this chip. */
int se_unwrap_nostr_object(uint8_t *out, uint16_t out_cap);

/* Draw entropy from the SE's certified TRNG (AIS31 PTG.2 / AIS20 DRG.4).
 *
 * This part has no hardware RNG, which is why the signing nonce is
 * deterministic. This exists for the places that genuinely need entropy: the
 * SCP03 host challenge during the handshake. Never source it from the ESP32. */
int se_get_random(uint8_t *out, uint16_t len);

/* Provided by main.c. Parks a frame for the ESP32 to relay and blocks until the
 * reply arrives. The frame is already wrapped in ProcessSessionCmd and
 * SCP03-protected before it gets here. */
int se_transport(const uint8_t *req, uint16_t req_len,
                 uint8_t *resp, uint16_t resp_cap, uint16_t *resp_len);

/* AES-256-CBC for the inner K_G0 wrap. Constant-time implementation required:
 * the ESP32 can time our responses, and a data-dependent branch here leaks. */
int aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *pt, uint16_t len, uint8_t *ct);
int aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *ct, uint16_t len, uint8_t *pt);

/* SHA-256 over two concatenated buffers, for the inner-wrap IV derivation. */
void sha256_two(const uint8_t *a, uint16_t alen,
                const uint8_t *b, uint16_t blen, uint8_t out[32]);

/* Platform init: clocks, GPIO, I2C target at G0_I2C_ADDR. */
void hw_init(void);

#endif /* SE_SESSION_H */
