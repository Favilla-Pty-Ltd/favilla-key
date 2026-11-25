# Favilla KEY firmware

Firmware for the Favilla KEY: a hardware Nostr signer, Bitcoin wallet and
password and passkey vault. An ESP32-S3 runs the screen, radios and the KEY's
web page; an STM32G0 holds and uses the keys in isolation, behind an NXP SE051
secure element.

- `src/`: the ESP32-S3 firmware and the KEY's web page (`pwa.html`)
- `g0/`: the isolated signer (STM32G0)
- `extension/`: the browser extension for signing in with the KEY
- `docs/`: protocols, including `BLE_PASSKEY_PROTOCOL.md`
- `tools/verify_release.py`: check a signed release against your own build

Builds are reproducible: `REPRODUCE.md` says how to rebuild a release and get
the same file, `PINNING.md` lists the pinned toolchain.

## About

The Favilla KEY is made by Favilla Pty Ltd, Western Australia.

- Website: https://favillakey.io
- General contact: info@favillakey.io
- Security reports: security@favillakey.io, or privately through this
  repository (see `SECURITY.md`)

## Licence

Copyright (C) 2026 Favilla Pty Ltd.

Licensed under the GNU General Public License v3.0 (`LICENSE`). Third-party
code keeps its own licence (`THIRD_PARTY_NOTICES.md`). Security reports:
`SECURITY.md`.
