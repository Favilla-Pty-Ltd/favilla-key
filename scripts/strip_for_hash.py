# 25 Nov 2026: one release hash on every OS.
#
# A release built on Windows and one built on Linux (docker/) had the same
# code and data byte for byte; only the ELF's debug info differed (each OS's
# compiler writes its own path forms into DWARF). esptool stamps the ELF's
# SHA-256 into the app descriptor at image offset 0xB0, so the two
# firmware.bin files still differed there and in the image hash.
#
# This strips debug info from firmware.elf right after linking, before
# esptool makes the .bin, so the hash stamped into the image is that of the
# stripped ELF, which is the same on every OS. Tested on the 25 Nov builds:
# both stripped ELFs hash 06e598f8..., and the images made from them are
# identical (and identical to the unstripped image apart from those 32 bytes,
# the checksum and the appended hash). The full ELF is kept next to it as
# firmware.debug.elf for addr2line and crash decoding (same addresses).
Import("env")
import os
import shutil


def _strip_debug(target, source, env):
    elf = str(target[0])
    dbg = elf[:-4] + ".debug.elf"
    tmp = elf + ".tmp"
    shutil.copyfile(elf, dbg)
    # $OBJCOPY is esptool on this platform; the toolchain's objcopy sits next
    # to its gcc (xtensa-esp32s3-elf-gcc -> xtensa-esp32s3-elf-objcopy)
    objcopy = env.subst("$CC")[: -len("gcc")] + "objcopy"
    rc = env.Execute(env.VerboseAction(
        '"%s" --strip-debug "%s" "%s"' % (objcopy, dbg, tmp),
        "Stripping debug info from the release ELF (one hash on every OS)"))
    if rc:
        return rc
    os.replace(tmp, elf)


env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", _strip_debug)
