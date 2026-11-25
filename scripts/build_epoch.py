# 11bw (issue #40 B6): reproducible builds. The Arduino core's chip report
# (cores/esp32/chip-debug-report.cpp) prints __DATE__ and __TIME__, so two
# builds of the same commit differed in those bytes (and in the hashes over
# them). GCC takes SOURCE_DATE_EPOCH in place of the clock for both macros, so
# every build of one commit now carries that commit's time and the same bytes.
# Uncommitted changes build with the last commit's time; no git: 1 Jan 2026.
Import("env")
import os, subprocess

t = ""
try:
    t = subprocess.check_output(["git", "log", "-1", "--format=%ct"],
                                cwd=env.subst("$PROJECT_DIR"), stderr=subprocess.DEVNULL).decode().strip()
except Exception:
    pass
if not t.isdigit():
    t = "1767225600"
env["ENV"]["SOURCE_DATE_EPOCH"] = t
os.environ["SOURCE_DATE_EPOCH"] = t

# The same bytes from any folder: assert messages and __FILE__ carry source
# paths, which differ between machines (C:\dev\... on the bench PC, the CI
# runner's home). Map the project and the PlatformIO packages to fixed names.
_proj = env.subst("$PROJECT_DIR")
_pkgs = env.subst("$PROJECT_PACKAGES_DIR")
env.Append(CCFLAGS=["-ffile-prefix-map=%s=." % _proj, "-ffile-prefix-map=%s=/pio" % _pkgs])
# 24 Nov 2026: assembly too. Two release builds of one commit in different
# folders differed ONLY in the debug info of ten ESP-IDF .S files (GNU as
# wrote the full source and working-folder paths); the ELF's SHA-256 is
# stamped into the app descriptor, so firmware.bin differed by those 32 bytes
# and the image hash. gas takes the map as --debug-prefix-map.
# .S goes through gcc (ASPPFLAGS; SCons does not pass CCFLAGS there), .s
# straight to as (ASFLAGS).
_aspp, _as = [], []
for _from, _to in ((_proj, "."), (_pkgs, "/pio")):
    _aspp += ["-ffile-prefix-map=%s=%s" % (_from, _to), "-Wa,--debug-prefix-map=%s=%s" % (_from, _to)]
    _as += ["--debug-prefix-map=%s=%s" % (_from, _to)]
env.Append(ASPPFLAGS=_aspp, ASFLAGS=_as)
