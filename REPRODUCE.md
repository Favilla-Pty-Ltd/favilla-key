# Reproducing a Favilla KEY release

Anyone can rebuild the Favilla KEY's main firmware from this source and get the
exact file Favilla signs and ships. You do not have to trust our build machine:
build the same commit yourself, then check that the signed release is your
build plus a signature.

## What this covers

- **Covered:** the ESP32-S3 application, `firmware.bin` from the
  `favilla_key_fido_release` environment: the KEY's main firmware, which runs
  the screen, buttons, camera, Wi-Fi and Bluetooth, and serves the phone page.
- **Not covered yet:** the STM32G0 isolated signer (`g0/`) and the ESP32-S3
  bootloader. Their reproducibility has not been checked.

## Checked so far

The method was first checked on 25 Nov 2026 on a pre-release build: two
Windows builds in separate folders and one Linux build in Docker gave the same
SHA-256.

Commits are those of the public repository (github.com/Favilla-Pty-Ltd/favilla-key).

| Release | Commit | SHA-256 of firmware.bin | Checked on |
|---|---|---|---|
| Drop 11et (first public release) | `651f053` | `80c2ba83c35dc957e1f56b96508fe0cc94cbc26c7dd564900222d1e44a310f4e` | Windows 11 (PlatformIO 6.1.18, own PlatformIO home), Docker on Windows (`docker/Dockerfile`), GitHub Actions (Linux), 25 Nov 2026 |

## Route 1: Docker (any computer)

You need git and Docker.

1. Get the source at the release's commit:

   ```
   git clone https://github.com/Favilla-Pty-Ltd/favilla-key
   cd favilla-key
   git checkout <release commit>
   ```

2. Build the build image (once):

   ```
   docker build -t favilla-build docker
   ```

3. Build the release. The first run downloads the toolchain and rebuilds the
   core, which takes 10 to 40 minutes. It ends by printing the SHA-256 of
   `firmware.bin`:

   ```
   docker run --rm -v "<full path of your clone>:/favilla" favilla-build
   ```

## Route 2: PlatformIO directly (checked on Windows)

You need git, Python 3 and PlatformIO 6.1.18 (`pip install platformio==6.1.18`). This route has been checked on Windows; Linux and macOS use the same steps but have not been checked yet.

1. Get the source at the release's commit, as in Route 1.
2. Build:

   ```
   pio run -e favilla_key_fido_release
   ```

3. Hash the result:
   - Linux or macOS: `sha256sum .pio/build/favilla_key_fido_release/firmware.bin`
   - Windows PowerShell: `Get-FileHash .pio\build\favilla_key_fido_release\firmware.bin -Algorithm SHA256`

## The G0 signer

The STM32G0 signer (`g0/`) is reproducible on Linux: Docker on any computer,
a Linux PC, or GitHub Actions. Its toolchain, platform and STM32 framework are
pinned in `g0/platformio.ini`, and nothing in it stamps a date or a path.

| Release | Commit | SHA-256 of g0 firmware.bin | Checked on |
|---|---|---|---|
| Drop 11et (G0 v24) | `651f053` | `352f617822493e220c72df0f1272846202e89e051ad3f29166617b4c0234cb23` | Docker on Windows, GitHub Actions (two runs), 25 Nov 2026 |

The G0 source did not change in the commits after `651f053` that only touched
tests, documents and the build check, so they give the same file.

With Docker (the image from Route 1), from the top of your clone. Delete
`g0/.pio` first if you built the G0 outside Docker in the same folder, so no
object from another compiler is reused:

```
docker run --rm -v "<your clone>:/favilla" favilla-build sh -c "pio run -d g0 -e g0 && sha256sum g0/.pio/build/g0/firmware.bin"
```

A G0 build made directly on Windows differs from the Linux one in one function
(`run_selftest`, the power-on BIP-340 check): 59 bytes, the same instructions
in a different but equivalent order. The Windows build of the same GCC 7.2.1
makes some different internal choices. Every symbol sits at the same address
and every section has the same size; the code does the same thing. Use Docker
or Linux to compare a G0 build with a release.

## Check a signed release against your build

A signed release is your build, padded to a whole 4096-byte sector, plus one
signature sector. A signature is different every time it is made, so the
signed file itself never matches a rebuild byte for byte. This checks
everything the signature covers:

```
python tools/verify_release.py <signed release .bin> .pio/build/favilla_key_fido_release/firmware.bin
```

`MATCH` means the signed release is exactly your build plus a signature. To
check the signature itself, use `espsecure verify_signature` with the Secure
Boot public key published with the release.

## Rules that matter

- **Build the release's exact commit.** The build stamps in the commit's
  time instead of the clock, so a different commit gives a different file,
  even if no code changed.
- **Start from the committed files.** The core rebuild deletes
  `dependencies.lock` and `CMakeLists.txt` and edits `sdkconfig.defaults` in
  the project folder. Before building again in the same folder, run
  `git restore .`
- **One build at a time per computer.** Builds share a component download
  cache, and two at once can fail with "cannot lock ref".
- **Do not flash what you build.** A Favilla KEY with Secure Boot only runs
  firmware signed by Favilla. Your build is for comparing.

## What makes it reproducible

- **Pinned tools:** `platformio.ini` names one fixed platform release
  (pioarduino 55.03.33), which fixes the ESP-IDF, Arduino core and GCC
  toolchain versions. The Docker image pins Python 3.12 and
  PlatformIO 6.1.18.
- **Pinned components:** `dependencies.lock` pins the ESP-IDF components, and
  `scripts/pin_hybrid.py` pins the one component the core rebuild would
  otherwise fetch from a moving branch.
- **No clock:** `scripts/build_epoch.py` sets `SOURCE_DATE_EPOCH` to the
  commit time, and the firmware has no `__DATE__` or `__TIME__`.
- **No folder names:** source paths are mapped to fixed names for C, C++ and
  assembly (`scripts/build_epoch.py`), and `CONFIG_APP_REPRODUCIBLE_BUILD`
  does the same inside the core rebuild.
- **Same bytes on every OS:** `.gitattributes` checks text files out with LF
  line endings everywhere, and `scripts/strip_for_hash.py` removes the
  ELF's debug information before the image is made. Each OS writes paths
  into debug information in its own way, and the image carries a hash of the
  ELF. The full ELF is kept as `firmware.debug.elf` for decoding crashes.
