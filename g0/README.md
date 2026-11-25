# favilla-g0 — STM32G0B1KBU6 isolated Nostr signer firmware

**27 Oct 2026: anti-exfil signing.** Every signature is now INIT + FINISH with a
host-contributed nonce tweak; SIGN / BTCSIGN / MSGSIGN are retired. Self-test
v8. `src/antiexfil.{h,c}` is the core.

PlatformIO project. Replaces `favilla-g0-stub`. Build and flash exactly as the
stub: `pio run`, then `pio run -t upload` (STLINK-V3SET on the Tag-Connect) or
STM32CubeProgrammer with `.pio/build/g0/firmware.elf`.

## Build order (from the g0-signer record) — where we are

1. libsecp256k1 on the M0+, BIP-340 vectors on-chip — DONE 9 Sep (20/20 on silicon;
   sign ~205 ms, verify ~225 ms, ECDH ~150 ms at 64 MHz)
2. I2C register map + state machine, `fetch_scalar()` stubbed — DONE 9 Sep (first
   G0 signature on silicon)
3. SE05x AESKey (SCP03) session layer over the blind relay — DONE 9 Sep (session test PASS on silicon: 6 relay round trips, scalar round-trips byte-exact, 342 ms)
4. `fetch_scalar()` for real — DONE 9 Sep (offline QR sign path exercised).
5. **K_SE/K_G0 persist in flash** — THIS DROP. src/key_store.{c,h} keeps both
   keys in the last 2 KB page (0x0801F800); SETKEYS writes+verifies before it
   acks; boot loads them; WIPEKEYS erases the page. Image capped to 126 KB so
   firmware can never grow into the key page. A reboot no longer wipes keys —
   onboard once, then reboot/sign freely. RDP-2 (step 6) seals the page.
5. SETKEYS / WIPEKEYS with flash storage
6. RDP = 0xCC — last, after everything passes

## What step 3 does

`lib/scp03` is a transport-agnostic port of the Plug & Trust applet-session
path: CreateSession, INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, then every
command AES-CBC encrypted under S-ENC and CMAC-chained under S-MAC, responses
R-MAC checked and decrypted, CloseSession. The single AES-128 auth key K_SE is
the static ENC/MAC/DEK, exactly as `ex_sss_se05x_prepare_host_AppletScp03Keys`
does it. Every framing choice cites the middleware function it was copied from.
`lib/aes128` is a second, renamed copy of tiny-AES-c (AES-128, ECB+CBC) so it
can coexist with `lib/tinyaes` (AES-256 for K_G0).

`src/main.c` gains the relay (RELAY_OUT / RELAY_IN, ISR-side length checks,
STATUS=NEED_RELAY while a frame is parked, BUSY the instant a reply lands),
an entropy pool for the host challenge (K_SE, tick, SysTick, every card
challenge the SE's TRNG has sent), `fetch_scalar_se()` — the complete step-4
fetch: ReadObject(48-byte blob) + CipherOneShot(daily key, DEC) inside the
session, CloseSession, then AES-256-CBC(K_G0) locally — and CMD 0x09
SESSIONTEST, which runs that fetch and writes a 64-byte diagnostic on SIG_OUT
(see the layout comment above `g_sesdiag`). `fetch_scalar()` still returns the
RAM stub, so a session fault cannot break signing while step 3 is being proven.

Host verification (`tests/run_scp03_test.sh`): CMAC against RFC 4493, then the
whole session against `tests/se_sim.py`, an independent SCP03 card side written
with pycryptodome: open/read/cipher/read/close = 7 APDUs, all PASS; wrong K_SE
fails at the card cryptogram; PCR locked is refused 6986 at ReadObject; a relay
that flips one ciphertext byte fails the R-MAC. Cross-linked for the M0+: ~60 KB.

Expected relay budget per fetch: 6 round trips (ESP32 `G0_MAX_RELAY_STEPS` is 8).

**Object ids** live in `include/se_objects.h` and MUST match `FKIO/src/se_signer.h`
(auth 0x20000030, PCR 0x20000031, daily wrap 0x20000022, scalar 0x20000002,
nsec-import 0x20000003). Confirm those four before the first run. Which of the
two scalar slots is active on a restore-from-nsec wallet is a step-4 decision.

## What step 2 does

`src/main.c` is now the real register map and command state machine
(`g0_proto.h` in FKIO/g0 describes the same thing). SETKEYS, PROVISION,
PUBKEY, SIGN, ECDH, CACHEKEY, WIPEKEYS and RESET all work end to end from the
ESP32. Commands are latched in the I2C ISR and executed from `main()`; STATUS
reads BUSY meanwhile; a command or input is accepted whenever the machine is
IDLE, SIG_READY or ERROR (the ESP32 only sends RESET on failure paths).

**STEP-2 STUB:** `fetch_scalar()` returns the scalar PROVISION sealed in this
power cycle, from RAM. Keys from SETKEYS are RAM too. So after a power cycle
the G0 has nothing and every Nostr op fails closed until you re-onboard.
Steps 3–5 replace exactly `fetch_scalar()` (SE session) and the two key
arrays (flash); nothing else in the file changes.

I2C receive is one byte at a time with an explicit counter: the HAL clears
`XferCount` on the STOP-after-short-write path, so it cannot be used to
recover a write's length. Inputs of the wrong length are dropped
(invariant 1). Only STATUS, SIG_OUT (in SIG_READY) and SELFTEST are readable
(invariant 3). The Schnorr aux_rand is SHA256(K_G0 || msg) — no TRNG on this
chip, so the nonce is key- and message-bound rather than random (invariant 2).

K_G0 wrap: AES-256-CBC, IV = SHA256(K_G0 || "favilla-g0-wrap-iv")[0:16],
32-byte scalar -> 32-byte ciphertext, no padding. Step 4 decrypts the same
way after the SE strips its outer layer. `lib/tinyaes` (kokke/tiny-AES-c,
Unlicense) and `lib/g0crypto` (SHA-256/HMAC/HKDF, verified against Python)
provide the primitives; both are host-tested in `tests/`.

The step-1 self-test still runs at boot (SELFTEST v2) and gates everything:
if it fails, STATUS is ERROR and no command executes.

## What step 1 did

At boot it signs vectors 0–3 (with their aux_rand) and verifies all 15
fixed-length vectors (4 valid, 11 must-fail), then one ECDH round trip.
20 checks total. Result is reported over I2C — there is no UART:

    STATUS   (0x01): 0x00 if 20/20, 0xE0 otherwise
    SELFTEST (0x7F): "G0ST", ver, npass, ntotal, flags, sign_ms, verify_ms, ecdh_ms

The ESP32 build from `FKIO-g0-port-v5` reads 0x7F in `g0_init()` and prints:

    [G0] self-test v1: 20/20 passed, flags=0x00, sign N ms, verify N ms, ecdh N ms

flags: 0x01 a sign vector mismatched, 0x02 a verify result mismatched,
0x04 ECDH mismatch, 0x40 context create failed, 0x80 context buffer too small.

## lib/secp256k1

bitcoin-core/secp256k1 vendored at the commit in `VENDORED_COMMIT.txt`, with
only the three compilation units the library needs. Configured for flash:
`ECMULT_WINDOW_SIZE=2` (128-byte verify table) and `COMB_BLOCKS=2,
COMB_TEETH=5` (2 KB gen table). Total footprint of this firmware: ~51 KB
flash, ~9 KB RAM including an 8 KB stack reserve. The same macros appear in
`platformio.ini` and `library.json` — keep them identical.

`USE_EXTERNAL_DEFAULT_CALLBACKS`: the library's illegal-argument / internal
error callbacks are ours (`main.c`) and trap with `BKPT` — there is nothing
sensible to print to on this chip.

The context is preallocated in a static 512-byte buffer (208 needed). No
malloc anywhere in this firmware, ever. `secp256k1_context_randomize` is not
called yet; in step 3+ it will be seeded from the SE's TRNG over the session.

## Timing expectation

At 64 MHz on an M0+ with the small tables, expect on the order of a few
hundred ms per Schnorr sign and similar per verify. The numbers the ESP32
prints are the sum over 4 signs / 15 verifies.
