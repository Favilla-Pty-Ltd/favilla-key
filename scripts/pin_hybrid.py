# 24 Nov 2026: reproducible core rebuild. The light-sleep core rebuild
# (custom_sdkconfig, "hybrid compile") builds the Arduino libraries from the
# platform's builder/build_lib/idf_component.yml, which pulls espressif/fb_gfx
# from esp32-arduino-lib-builder at "master": whatever that branch holds on
# the day of the build. fb_gfx changed there on 23 Nov 2026, so two builds of
# one commit could differ by date. This pins it to a fixed commit, in the
# platform's copy and in the project's working copy (.dummy) that the rebuild
# actually reads.
#
# 26d96aa (28 Oct 2026) is the commit dependencies.lock records, and its
# fb_gfx is the same as the branch held from April 2022 until 23 Nov 2026,
# i.e. what every core rebuild before that date used.
Import("env")
from pathlib import Path

PIN = "26d96aa61a3b71261ca6de083cc2f6135bbafbd1"
REPO = "https://github.com/espressif/esp32-arduino-lib-builder.git"


def _pin(path):
    p = Path(path)
    if not p.is_file():
        return
    lines = p.read_text().splitlines()
    out, changed = [], False
    # within a dependency block that fetches from the lib builder, any
    # version line becomes the pinned commit
    blocks, cur = [], []
    for ln in lines:
        if ln.startswith("  ") and not ln.startswith("    ") and cur:
            blocks.append(cur); cur = []
        cur.append(ln)
    if cur:
        blocks.append(cur)
    for b in blocks:
        if any(REPO in x for x in b):
            for i, x in enumerate(b):
                s = x.strip()
                if s.startswith("version:") and PIN not in s:
                    b[i] = x[: len(x) - len(x.lstrip())] + 'version: "%s"' % PIN
                    changed = True
        out.extend(b)
    if changed:
        p.write_text("\n".join(out) + "\n")
        print("pin_hybrid: fb_gfx pinned to %s in %s" % (PIN[:8], p))


_pin(Path(env.PioPlatform().get_dir()) / "builder" / "build_lib" / "idf_component.yml")
_pin(Path(env.subst("$PROJECT_DIR")) / ".dummy" / "idf_component.yml")
