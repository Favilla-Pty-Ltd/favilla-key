# Building the Favilla KEY firmware

Layout:
- `src/`, `lib/`, `platformio.ini`: the ESP32-S3 firmware (main MCU).
- `g0/`: the STM32G0B1 isolated signer (its own PlatformIO project, env `g0`;
  `g0_fuse` is a short-fuse bench image, never ship it). Flash with the
  STLINK-V3SET on the Tag-Connect: `pio run -d g0 -e g0 -t upload`.
- `extension/favilla-login/`: the Chrome extension (load unpacked).

## On GitHub (every push to `main`)
Actions > **firmware** builds the G0 signer, both passkey envs, and packs the
extension. Per ESP32 env it attaches:
`firmware.bin` (UNSIGNED app image), its SHA-256, and `firmware.elf`
(for decoding backtraces). Download from the run's **Artifacts**.

## On the Dev PC (PowerShell, never the VS Code build button)
The passkey envs need the stock Arduino core in their own PlatformIO folder:

    $env:PLATFORMIO_CORE_DIR="C:\pio-fido"
    C:\pio-fido\penv\Scripts\pio.exe run -e favilla_key_fido

Channel build (browser extension, no serial log): `-e favilla_key_fido_vchan`.

Everyday bench build with the channel (11u, 11 Nov 2026): `-e favilla_key_fido_pmv`,
the light-sleep build with the USB serial port off and the browser channel on
(the S3's four IN endpoints: serial took two). The log and console are in the
extension's options page (Bench panel), and the KEY is put on its flashing port
from Settings > Device > Flash mode (or the Bench panel's Flash mode button)
before `-t upload`, since esptool has no serial port to toggle. Start from a
copy of the pm core folder:

    robocopy C:\pio-fido-pm C:\pio-fido-pmv /E /NFL /NDL
    $env:PLATFORMIO_CORE_DIR="C:\pio-fido-pmv"
    C:\pio-fido\penv\Scripts\pio.exe run -e favilla_key_fido_pmv -t upload

## Flashing (Secure Boot boards)
- Sign and flash the **app only**, on the Forge. The signing key never leaves it.
- Never flash an unsigned `bootloader.bin`, and never use `-t upload` on a
  Secure Boot board (it writes the unsigned bootloader).

## Drops
Each bench drop is a commit; the drop name is `FAVILLA_BENCH_DROP` in
`src/main.cpp` and appears in the boot log and in the artifact name.
