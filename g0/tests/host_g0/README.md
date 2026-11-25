# Whole-G0 host harness (audit 21 Nov 2026)

Builds all of `src/main.c` for Linux and drives it the way the ESP32 does.
Nothing is extracted by hand: `transform.py` turns `main()` into
`g0_boot()` (the init) and the command loop body into `g0_step()` (one
command), then includes the harness at the end of the file so it can see
every static.

## Pieces

- `stm32g0xx_hal.h`: a fake HAL. Flash is a fixed `mmap` at 0x08000000, so
  `key_store.c` and the Emberwill store read and write real pages.
  `RCC->CSR` chooses a power reset (PWRRSTF) or a non-power reset.
- `fakese.c` / `fakese.h`: a fake SE051 behind the `scp03_*` API. It holds
  objects with the policies the ESP32 gives them (se_signer.cpp,
  mode_pcr.inc): the first entry per auth object counts, PCR gates, a reset at
  the initial value is refused 6985, a delete of an absent object is 6985.
  The cipher is a stand-in (XOR with a hash of key and IV), not AES.
- `harness.inc`: the bus (`host_write` into the real `commit_write`),
  honest onboarding, honest NOSTR and BTC lives.
- `scenarios.inc`, `extra.inc`, `hostmain.inc`: the tests.

## Scenarios

- S1: the door model as designed.
- S2: issue #53, the seed swap from a NOSTR life. Refused since G0 v21.
- S3 / S4: a random attacker in a NOSTR life that knows the daily PIN (S4:
  and the inner packet from an earlier BTC life). Invariants are checked
  after every step.
- S5: ARM by the daily PIN plus a replayed inner packet (needs code in a
  BTC-door boot; documents the limit of the spend-PIN rule).
- S6: issue #60, the same swap in the UNSET window of a boot whose door
  commit failed. Refused since G0 v22.
- S7: a random attacker in a VAULT (Bluetooth) life that knows the passkey PIN.
- S8 (`S8ONLY=1`): a raw attacker. Every command byte 0x00..0x3F (bar the two
  Stop-mode sleeps) and every input register, mostly at the exact length with
  random content, from a NOSTR life and a VAULT life. Built with ASan and UBSan,
  so a memory error in any handler aborts the run; the door invariants are
  checked after every step.

`g0_power_on()` clears the RAM statics a real boot starts at zero (the door,
the wipe flag, the label count ...). A static added to `main.c` that
`life_restore()` refills must be added there too, or the harness carries it
across a simulated power cycle.

## Run (from `g0/`)

```
bash tests/run_host_g0.sh
```

```
ITERS=2000 SEED=7 bash tests/run_host_g0.sh
```

```
S8ONLY=1 ITERS8=2000 bash tests/run_host_g0.sh
```

The fake SE models only what the G0's own commands touch, plus the ESP32's
PIN-session and anonymous operations used by the scenarios. A pass here is
evidence about the G0's logic, not about the SE051.

## Rule: statics that `life_restore()` refills

When you add a RAM static to `g0/src/main.c` that `life_restore()` refills from the backup registers, also clear it in `g0_power_on()` in `harness.inc`. A host keeps RAM across a simulated boot, and a real boot does not. A static that is missed there carries the last life's value across a power-on, so a test passes against state the device never has.

