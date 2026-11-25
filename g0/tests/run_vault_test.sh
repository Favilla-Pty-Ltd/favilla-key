#!/bin/bash
# 2 Nov 2026 host test for vault records (VAULT, vault_glue.inc). Run from the project root.
set -e
MBT=${MBT:-../mbt/src}
python3 - <<'PY'
import re
src=open("src/main.c").read()
def grab(a, b):
    i=src.index(a); return src[i:src.index(b, i)]
cw=grab("static void commit_write(size_t n) {", "case G0_REG_HASH_IN:")
assert "G0_CMD_VAULT:" in cw, "commit_write must accept VAULT"
cwall=grab("static void commit_write(size_t n) {", "\n}\n")
i=cwall.index("case G0_REG_VAULT_IN:"); seg=cwall[i:cwall.index("break;", i)]
assert "plen == VLT_IN_LEN && accepting()" in seg, "VAULT_IN: exactly 514 bytes, only when accepting"
tx=grab("static void tx_next(I2C_HandleTypeDef *h) {", "\n}\n")
i=tx.index("case G0_REG_VAULT_OUT:"); seg=tx[i:tx.index("break;", i)]
assert "g_status == G0_ST_SIG_READY" in seg and "VLT_OUT_LEN" in seg, "VAULT_OUT readable only in SIG_READY, bounded"
fin=grab("static void finish(int rc) {", "\n}\n")
assert "secure_wipe(g_vlt_in" in fin and "g_vlt_in_valid = 0" in fin, "finish() must make VAULT_IN single-use"
wt=grab("static void wipe_transient(void) {", "\n}\n")
assert "secure_wipe(g_vlt_in" in wt and "secure_wipe(g_vlt_out" in wt, "wipe_transient() must clear VAULT_IN and VAULT_OUT"
dp=grab("static int door_permits(uint8_t cmd) {", "\n}\n")
i=dp.index("case G0_CMD_VAULT:"); seg=dp[i:dp.index("return", i)+80]
assert "return g_door == DOOR_PASSKEY;" in seg, "v19: VAULT in a PASSKEY life only"
ac=grab("static void door_autocommit(uint8_t cmd) {", "\n}\n")
assert "G0_CMD_VAULT" not in ac, "v19: VAULT never commits the NOSTR door"
disp=grab("        switch (cmd) {\n        case G0_CMD_SIGN_INIT:", "default:               rc = -1;")
assert "rc = do_vault();" in disp
allsrc=src+open("src/ember_glue.inc").read()+open("src/pk_glue.inc").read()+open("src/vault_glue.inc").read()
for kind in ("REG","CMD"):
    ids={}
    for n,v in re.findall(r"#define (G0_%s_\w+)\s+(0x[0-9A-Fa-f]+)" % kind, allsrc): ids.setdefault(int(v,16),set()).add(n)
    dup={hex(k):v for k,v in ids.items() if len(v)>1 and not (kind=="CMD" and k==0x1B)}
    assert not dup, "%s id used twice: %s" % (kind, dup)
m=re.search(r"#define RX_MAX \(1 \+ 2 \+ (\d+)\)", src); assert 1+2+int(m.group(1)) >= 1+514, "RX_MAX must hold a VAULT_IN write"
open("/tmp/extracted_pk.inc","w").write(grab("static void kg0_iv(uint8_t iv[16]) {", "/* Every scalar op goes through"))
ik=grab("static int is_key_op(uint8_t cmd) {", "\n}\n")
assert "case 0x28:" in ik, "VAULT gets the key-op jitter (review)"
assert "case G0_CMD_VSIGN_INIT:" in ik, "VSIGN_INIT gets the key-op jitter and counts toward re-blinding (v14 review)"
lw=grab("static void latch_write(void) {", "\n}\n")
assert "s_rx_n <= RX_MAX" in lw, "an overlong write must not be cut down to a valid one"
ml=src[src.index("door_autocommit(cmd);   /* 19 Oct")-200:src.index("door_autocommit(cmd);   /* 19 Oct")]
assert "if (cmd != G0_CMD_VAULT) secure_wipe(g_vlt_out" in ml, "VAULT_OUT wiped before any other command"
print("PASS  wiring: commit_write (exact 514), VAULT_OUT only in SIG_READY, single-use input, wipe on RESET, NOSTR-only door + autocommit, dispatch, no id clash, RX_MAX fits")
PY
gcc -O1 -Wall -Wno-unused-function -Iinclude -Ilib/g0crypto -Ilib/scp03 -Ilib/tinyaes -Isrc -Itests -I/tmp -I$MBT/include \
  tests/host_vault.c src/totp.c lib/g0crypto/sha256.c lib/tinyaes/aes.c $MBT/library/libmbedcrypto.a -o /tmp/g0_vault
# v14: the same suite with the real vpub_glue.inc (libsecp256k1 + antiexfil.c): PUBSEAL and VSIGN_INIT
gcc -O1 -Wall -Wno-unused-function -Wno-unused-parameter -DHOST_VPUB -Iinclude -Ilib/g0crypto -Ilib/scp03 -Ilib/tinyaes -Isrc -Itests -I/tmp -I$MBT/include \
  -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 \
  tests/host_vault.c src/totp.c src/antiexfil.c lib/g0crypto/sha256.c lib/tinyaes/aes.c \
  lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  $MBT/library/libmbedcrypto.a -o /tmp/g0_vault_vpub
/tmp/g0_vault_vpub
/tmp/g0_vault
# v14: the same suite with the real vpub_glue.inc (libsecp256k1 + antiexfil.c): PUBSEAL and VSIGN_INIT
gcc -O1 -Wall -Wno-unused-function -Wno-unused-parameter -DHOST_VPUB -Iinclude -Ilib/g0crypto -Ilib/scp03 -Ilib/tinyaes -Isrc -Itests -I/tmp -I$MBT/include \
  -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 \
  tests/host_vault.c src/totp.c src/antiexfil.c lib/g0crypto/sha256.c lib/tinyaes/aes.c \
  lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  $MBT/library/libmbedcrypto.a -o /tmp/g0_vault_vpub
/tmp/g0_vault_vpub
