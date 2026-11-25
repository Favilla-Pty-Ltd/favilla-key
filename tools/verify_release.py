#!/usr/bin/env python3
"""verify_release.py - check a signed Favilla KEY release against a build from source.

A release is signed on the manufacturing station with the Secure Boot v2 key,
and a signature differs every time it is made, so the signed file can never
match a rebuild byte for byte. What can match is everything the signature
covers. espsecure (sign_data, Secure Boot v2) lays a signed image out as:

    the unsigned image, padded with 0xFF to a multiple of 4096 bytes
    + one 4096-byte signature sector

So: build the same commit yourself (see REPRODUCE.md), then run

    python tools/verify_release.py <signed release .bin> <your firmware.bin>

It pads your build the same way and compares it with the signed file minus its
last 4096 bytes. "MATCH" means the signed release is exactly your build plus a
signature. It does not check the signature itself (espsecure verify_signature
with the published public key does that).
"""
import hashlib
import sys

SECTOR = 4096


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    signed = open(sys.argv[1], "rb").read()
    built = open(sys.argv[2], "rb").read()
    print("signed release  %s  %d bytes" % (hashlib.sha256(signed).hexdigest(), len(signed)))
    print("your build      %s  %d bytes" % (hashlib.sha256(built).hexdigest(), len(built)))
    if len(signed) < SECTOR or len(signed) % SECTOR:
        print("NOT A SIGNED IMAGE: its length is not a whole number of 4096-byte sectors")
        return 1
    body = signed[:-SECTOR]
    padded = built + b"\xff" * ((-len(built)) % SECTOR)
    if body == padded:
        print("MATCH: the signed release is your build plus one signature sector")
        return 0
    n = min(len(body), len(padded))
    first = next((i for i in range(n) if body[i] != padded[i]), n)
    print("DIFFERENT: the signed body is %d bytes, your padded build %d; first difference at offset 0x%x"
          % (len(body), len(padded), first))
    return 1


if __name__ == "__main__":
    sys.exit(main())
