# Favilla KEY: refuse to flash the core rebuild's placeholder (9x, 9 Nov 2026).
#
# WHY: on a run where pioarduino rebuilds the core (custom_sdkconfig changed),
# the app it links is its own placeholder sketch (builder/build_lib/sketch.cpp,
# which prints "Hello World!" forever), and `-t upload` flashed THAT to the
# bench KEY: a black screen and "Hello World!" on the serial port (9w, 8 Nov).
#
# WHAT: before any upload, look for the KEY's own boot line in firmware.bin.
# Not there: stop, and say to run the same command again (the second run builds
# the real app on the rebuilt core).
Import("env")
import os

def _guard(source, target, env):
    fw = os.path.join(env.subst("$BUILD_DIR"), "firmware.bin")
    try:
        data = open(fw, "rb").read()
    except OSError:
        return
    # 22 Nov 2026: the release image compiles LOG_BOOT out, so the [BUILD]
    # line is not in it; a restart-screen text that every KEY image draws is.
    if b"[BUILD] drop " not in data and b"Restart the key." not in data:
        print("")
        print("*** NOT FLASHING: firmware.bin is the core rebuild's placeholder (\"Hello World!\"), not the KEY.")
        print("*** The core was just rebuilt. Run the same command again: that run builds and flashes the real app.")
        print("")
        env.Exit(1)

env.AddPreAction("upload", _guard)
