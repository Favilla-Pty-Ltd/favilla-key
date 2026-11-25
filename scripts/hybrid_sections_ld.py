# Favilla KEY — hybrid-compile fix-up for pioarduino 55.03.33 (7 Oct 2026)
#
# WHY: with `custom_sdkconfig`, pioarduino rebuilds the Arduino core and its
# idf_lib_copy() moves the rebuilt archives (libfreertos.a, libesp_system.a,
# ...) and memory.ld into the framework-arduinoespressif32-libs package — but
# NOT the generated sections.ld. The nested compile it starts links against
# $BUILD_DIR/sections.ld (still present from the IDF build); every later build
# cleans $BUILD_DIR and links the PM-built archives against the STOCK
# esp32s3/<memory_type>/sections.ld. Symptom: "orphan section .text.vApplicationSleep"
# warnings and "dangerous relocation: l32r: literal placed after use" in
# libesp_pm.a(pm_impl.c.o). Upstream: pioarduino/platform-espressif32 #532/#534.
#
# WHAT: after the link ("checkprogsize" post-action, which runs AFTER
# idf_lib_copy and its nested compile), copy $BUILD_DIR/sections.ld into the
# package dir the linker searches. No-op on ordinary builds (no generated
# sections.ld in $BUILD_DIR) and when the package copy is already newer.
#
# HOW: platformio.ini  [env:favilla_key_pm]  extra_scripts = post:scripts/hybrid_sections_ld.py
Import("env")
import shutil
from pathlib import Path


def _copy_sections_ld(source, target, env):
    src = Path(env.subst("$BUILD_DIR")) / "sections.ld"
    if not src.is_file():
        return
    try:
        libs = Path(env.PioPlatform().get_package_dir("framework-arduinoespressif32-libs"))
    except Exception as e:
        print("*** [favilla] hybrid fix-up: core libs package not found (%s) ***" % e)
        return
    board = env.BoardConfig()
    mcu = board.get("build.mcu", "esp32")
    if mcu == "esp32s3":
        # On the S3 sections.ld is per memory type (qio_opi, dio_qspi, ...).
        mem = board.get("build.arduino.memory_type", board.get("build.flash_mode", "dio") + "_qspi")
        dst = libs / mcu / mem / "sections.ld"
    else:
        dst = libs / mcu / "ld" / "sections.ld"
    if dst.is_file() and dst.stat().st_mtime >= src.stat().st_mtime:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(src), str(dst))
    print("*** [favilla] hybrid fix-up: copied generated sections.ld -> %s ***" % dst)


env.AddPostAction("checkprogsize", _copy_sections_ld)
