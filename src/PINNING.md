# PINNING — what the binary depends on

Audited 5 August 2026. The point of this file is that a future bump should be
**visibly deliberate**. If a build stops reproducing, diff against this.

Short version: the build was already in far better shape than a normal Arduino
project. `platform` is an exact archive, the IDF components are content-hash
locked, and the one loose library is vendored. Two real gaps remain and both
are recorded below.

---

## What pins what

| Layer | How it is pinned | Strength |
|---|---|---|
| ESP-IDF, Arduino core, GCC toolchain | `platform` = exact release zip URL | Strong — but see *the URL gap* |
| IDF managed components | `dependencies.lock`, committed | **Strongest** — content hashes |
| WebSockets_Generic 2.16.1 | vendored in `lib/`, committed | **Strongest** — it is your source now |
| TFT_eSPI 2.5.43, ArduinoJson 7.0.0 | vendored in `lib/`, committed | **Strongest** — closed 5 Aug 2026 |
| TFT_eSPI configuration | `build_flags` + `USER_SETUP_LOADED=1` | Strong — no edited file in `.pio` |
| IDF config | `sdkconfig.defaults`, committed | Strong |
| Partitions, fonts | committed (`.csv`, `data/*.vlw`) | Strong |

---

## Resolved versions, 5 Aug 2026

**Platform** — pioarduino `platform-espressif32` **55.03.33**

```
sha256  465767188e58eb39156357ac6c9b7a01d21c3b18042214773f8b5ea8e8b7ae41
size    1,632,095 bytes
url     https://github.com/pioarduino/platform-espressif32/releases/download/55.03.33/platform-espressif32.zip
```

**ESP-IDF** 5.3.2 · **target** esp32s3 · **lock format** 2.0.0 · **manifest_hash** `9e34198f7f2d4443`

**PlatformIO Core** 6.1.18 — record this on every reproducibility test; a
different core can resolve differently even with identical pins.

**Packages actually resolved** (`pio pkg list`, 5 Aug 2026). Note the two
columns: some are pinned by URL in the platform manifest, some resolve to
whatever is already installed locally.

| Package | Version | Pinned by |
|---|---|---|
| platform espressif32 | 55.3.33 | **URL** (the release zip) |
| framework-arduinoespressif32 | 3.3.3 | **URL** (arduino-esp32 release) |
| framework-arduinoespressif32-libs | 5.5.0+sha.f1a1df9b2e | **URL**, with a git SHA |
| tool-dfuutil-arduino | 1.11.0 | **URL** |
| tool-mkfatfs | 2.0.1 | **URL** |
| tool-mklittlefs4 | 4.0.2 | **URL** |
| tool-mkspiffs | 2.230.0 | **URL** |
| **toolchain-xtensa-esp-elf** | **14.2.0+20250730** | local install |
| tool-esptoolpy | 5.1.0 | local install |
| tool-mklittlefs | 3.2.0 | local install |
| contrib-piohome | 3.4.4 | local install |

### The compiler is not pinned by this repo

The four "local install" rows resolve to whatever is in
`~/.platformio/packages`, not to a URL this repo controls. The most important
of them is **the toolchain**: GCC `14.2.0+20250730`. Different compiler, different
code generation, different binary — from identical source and identical
libraries.

In practice the platform manifest constrains which version the package manager
fetches, so a fresh machine converges on the same one. But that constraint lives
in the platform archive, not here, and it is a *range* rather than a hash.

Two consequences worth being clear about:

- **Your own rebuilds are fine.** The local copy does not change unless you
  update it.
- **A third party reproducing a release is not guaranteed the same compiler.**
  If a published-hash claim ever matters, record the toolchain version with the
  release (it is in the table above) and state it as a build requirement, or
  archive `~/.platformio/packages/toolchain-xtensa-esp-elf` alongside the
  platform zip.

**Managed components** — all content-hash pinned in `dependencies.lock`:

| Component | Version | Hash (first 8) |
|---|---|---|
| chmorgan/esp-libhelix-mp3 | 1.0.3 | `cbb76089` |
| espressif/cbor | 0.6.0~1 | `440f4ee4` |
| espressif/cmake_utilities | 0.5.3 | `35135061` |
| espressif/esp_modem | 1.4.2 | `40af7f39` |
| espressif/fb_gfx | git `43a8f6dfb71719621c530faf5401d920905c808d` | `b5f6592c` |
| espressif/libsodium | 1.0.22 | `39c9dc77` |
| espressif/mdns | 1.11.1 | `8bcf12e3` |
| espressif/qrcode | 0.1.0~2 | `3b493771` |
| joltwallet/littlefs | 1.22.1 | `01faa388` |

**Vendored libraries** — all three in `lib/`, committed:

| Library | Version | Source | Tarball sha256 | Tree sha256 |
|---|---|---|---|---|
| WebSockets_Generic | 2.16.1 | pre-existing | — | — |
| TFT_eSPI | 2.5.43 | `github.com/Bodmer/TFT_eSPI` tag `V2.5.43` | `a303b432cbdb6476...` | `213178c2d8b9a584...` |
| ArduinoJson | 7.0.0 | `github.com/bblanchon/ArduinoJson` tag `v7.0.0` | `d2ed24acc5431279...` | `b4c702a36e7e7e3d...` |

Tarball hash = the GitHub release archive as downloaded. Tree hash = sha256 of
the sorted per-file sha256 list, which is what you can re-verify from the repo
after trimming:

```
find lib/TFT_eSPI -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
```

Trimmed on vendoring: `examples/`, `docs/`, `Tools/`, `extras/`, CI config.
Verified by walking every `#include` in both trees. One unresolved include
remains in TFT_eSPI — `Extensions/AA_graphics.cpp` — which does not exist in
the upstream 2.5.43 release either and is guarded by `#ifdef AA_GRAPHICS`,
undefined in this build. Nothing the firmware compiles was removed.

---

## The two real gaps

### 1. The URL gap

`platform` points at a GitHub release asset. If that asset is deleted or
replaced, the build does not merely drift — it becomes **impossible**. The hash
above detects substitution; it does not survive deletion.

**Closed 5 Aug 2026 by committing the archive.** `vendor/platform-espressif32-55.03.33.zip`,
sha256 `465767188e58eb39156357ac6c9b7a01d21c3b18042214773f8b5ea8e8b7ae41`,
1,632,095 bytes, downloaded from the release URL and verified.

It lives in the repo rather than in object storage for one reason: it is then
impossible to lose without losing the repo. The 1.6 MB clone cost is nothing
next to the 8.1 MB of vendored WebSockets_Generic this repo already carries, and
the alternative — an R2 bucket — just moves the single point of failure from
GitHub to Cloudflare.

**TRAP: `.gitignore` line 27 is `*.zip`.** Dropping the file in and running
`git add` silently does nothing, and you would believe it was archived when it
was not. A negation is required and must come AFTER the `*.zip` line:

```
!vendor/platform-espressif32-55.03.33.zip
```

Verify with `git check-ignore -v vendor/platform-espressif32-55.03.33.zip` —
it should print nothing.

`platform =` still points at the GitHub URL, which is correct: that is the fast
path and the hash detects substitution. The committed copy is the fallback. If
the URL ever 404s, unzip and re-point:

```
platform = file://vendor/platform-espressif32-55.03.33
```

(a DIRECTORY, not the zip — PlatformIO's local-platform form takes an unpacked
folder).

### The layer underneath, which this does NOT close

Pinning the platform archive pins **which toolchain versions** get used. It does
not pin the toolchains themselves — those are fetched from PlatformIO's package
registry on first build and cached in `~/.platformio/packages`. So a build on a
fresh machine still reaches the network for the compiler.

For most purposes that is fine: the platform manifest names exact package
versions and the package manager checksums what it downloads. It stops being
fine the day you need to rebuild a two-year-old release and a package has been
pulled. If that matters, archive `~/.platformio/packages` for the toolchain
entries alongside this zip, and record their versions here.

### 2. The registry gap — CLOSED 5 Aug 2026

Was: `@ 2.5.43` meant *whatever the registry serves for that version*, and the
PlatformIO registry is not content-addressed. Nothing suggested bodmer or
bblanchon would republish a tag — the point was not having to trust that they
won't.

**Closed by vendoring.** Both libraries are now source in this repo, `lib_deps`
is empty, and the only way either changes is a commit visible in the log. Bump
procedure: replace the tree from the upstream tag, verify the tarball hash,
update the table above, all in the same commit.

---

## Two smaller notes

**`.dummy/idf_component.yml` carries loose ranges** — `cmake_utilities: "0.*"`
and `fb_gfx: "master"`. Those are *currently harmless* because
`dependencies.lock` overrides them while `manifest_hash` matches. But that makes
the lock **load-bearing**: delete it, or edit the manifest, and `master` moves.
Never regenerate the lock casually, and never gitignore it. `managed_components/`
is correctly ignored; the lock is correctly tracked.

**Absolute paths are still in the binary.** `__FILE__` embeds the build
directory, so two machines building the same commit produce different bytes.
Irrelevant for your own builds, decisive for a third party verifying a published
hash. `-ffile-prefix-map` fixes it; the flag is drafted and commented in
`platformio.ini` because the interpolation form is untested here.

---

## The test that decides it

Pinning is a claim. This is the check:

```
pio pkg list                                   # record what resolved
pio --version                                  # record the core version too
rmdir /s /q .pio
del sdkconfig.favilla_key
pio run -e favilla_key
certutil -hashfile .pio\build\favilla_key\firmware.bin SHA256
```

Then delete `.pio` again, rebuild, hash again.

**Same hash or it is not pinned.** It usually fails the first attempt, for a
reason nobody predicted — that is the value of running it rather than reasoning
about it. Record the result here with the date and the PlatformIO core version,
since a different core can resolve differently even with identical pins.

| Date | PIO core | firmware.bin sha256 | Same across clean builds? |
|---|---|---|---|
| 5 Aug 2026 | 6.1.18 | `645c500b8e0c20d0...` then `f662a78f4db06828...` | **NO** — see below |
| | | | |

### Attempt 1 failed, and the reason was expected

Two clean builds, minutes apart, same source, same libraries, same machine —
different binaries. That rules out everything the pinning work addressed and
points at something the build itself injects.

`fc.exe /b b1.bin b2.bin` — note `fc.exe`, since PowerShell aliases bare `fc`
to `Format-Custom`. The entire difference is **four real bytes** plus two
downstream hashes:

| Offset | Change | What it is |
|---|---|---|
| `0xB4DE`, `0xB4E1` | `'7'→'8'`, `'6'→'1'` | **ASCII digits** — minute and second of `__TIME__` |
| `0x11245`, `0x11248` | `'7'→'8'`, `'9'→'4'` | the same string again, second copy |
| `0xB0`–`0xCF` | 32 bytes | `app_elf_sha256` in `esp_app_desc_t` — a hash OF the change |
| `0x3078FF`–`0x30791F` | 33 bytes | esptool's appended image hash + checksum — likewise |

**What did NOT differ is the interesting part.** The app descriptor's own `time`
and `date` fields sit at image offsets `0x70` and `0x80`, and they were
identical. So the ESP-IDF was not stamping anything — the first hypothesis was
wrong, and only the byte comparison caught it. **Always run `fc /b` before
applying a fix**; the diagnosis was one line of source, not an IDF setting.

**Root cause:** `main.cpp:20373`, the boot banner —

```c
LOG_BOOT("[BUILD] v22.2 quiesce+prewarm+gate (" __DATE__ " " __TIME__ ")\n");
```

The only use of `__DATE__` or `__TIME__` in the entire source tree.

**Fixed** by dropping both macros. The build no longer says when it was
compiled, and does not need to: **with the build reproducible, the firmware hash
IS the build id** — and unlike a timestamp, it can be checked by someone who did
not build it. If a readable stamp is wanted back, inject the git commit at build
time (`-DFW_GIT=...` via a pre-build script), which is deterministic per commit.

### Still worth adding later, for a different reason

`CONFIG_APP_REPRODUCIBLE_BUILD=y` (drafted in `sdkconfig-addition.txt`) makes
`__FILE__` relative across the IDF's own sources. That is the cross-MACHINE
case — absolute build paths baked into assert and log strings — not the
same-machine one fixed above. Apply it separately, and remember
`sdkconfig.defaults` is only read when the generated `sdkconfig.favilla_key`
does not exist.
