# components/arduino_tinyusb (vendored, 9n, 8 Nov 2026)

Why this folder exists: the pioarduino hybrid compile (`custom_sdkconfig`, the
light-sleep core) rebuilds the Arduino libraries without the lib builder's own
`arduino_tinyusb` component, so `CONFIG_TINYUSB_*` does not exist in the rebuilt
core and the OTG USB stack (FIDO, keyboard, CDC serial) is missing ("USBSerial
was not declared", 30 Oct 2026). ESP-IDF picks up every folder under the
project's `components/` in that compile, which puts the component back.

Ordinary (stock-core) builds never read this folder.

Pinned to exactly what built the stock Arduino 3.3.3 libs (their versions.txt):

| Part | Source | Commit |
|---|---|---|
| CMakeLists.txt, Kconfig.projbuild, include/tusb_config.h | github.com/espressif/esp32-arduino-lib-builder `components/arduino_tinyusb` | 64767cc7a88f3f39829e448a7a91ea4d4165fb7c |
| tinyusb/src, tinyusb/LICENSE, tinyusb/hw/bsp/*.h | github.com/hathach/tinyusb | a6c16d147593732028ed89292805e0e6a972e4b5 |

Changes from those sources:
- lib builder `patches/dwc2_esp32_h.diff` applied to `tinyusb/src/portable/synopsys/dwc2/dwc2_esp32.h` (as the lib builder does).
- CMakeLists.txt: `priv_requires arduino main` replaced by `esp_hw_support esp_mm` (comment in the file says why).
- Only the top-level headers of `tinyusb/hw/bsp` are kept (the folder is an include path; the board folders are not used).

The public headers were checked byte-for-byte against the stock 3.3.3 package's
`esp32s3/include/arduino_tinyusb` copy: identical.

Licences: TinyUSB is MIT (tinyusb/LICENSE). tusb_config.h carries its MIT header.
