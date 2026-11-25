#!/bin/bash
# 28 Oct 2026: looped libsecp256k1 SHA-256 compression == upstream unrolled one. Run from the project root.
set -e
python3 - <<'PY'
s=open("lib/secp256k1/src/hash_impl.h").read()
i=s.index("#else\n/** Perform one SHA-256 transformation"); j=s.index("#endif /* FAVILLA_UNROLLED_SHA256 */")
body=s[i+6:j].replace("secp256k1_sha256_transform_impl","unrolled_impl")
k=s.index("#define Ch(x,y,z)"); e=s.index("} while(0)", k) + len("} while(0)\n")
body=s[k:e]+body
open("/tmp/unrolled_impl.inc","w").write(body)
PY
gcc -O1 -Wall -Wno-unused-function -Ilib/secp256k1/src -Ilib/secp256k1/include -Ilib/secp256k1 tests/host_secp_sha256.c -o /tmp/g0_secp_sha256
/tmp/g0_secp_sha256
