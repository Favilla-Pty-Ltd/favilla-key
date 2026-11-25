#!/bin/bash
# 30 Oct 2026 host test for restorable passkeys (PKSIGN / PKSCRUB, pk_glue.inc).
# Needs a host mbedtls 3.6 build: MBT=path/to/mbedtls (default ../mbt/src).
# Run from the project root.
set -e
MBT=${MBT:-../mbt/src}
python3 - <<'PY'
src=open("src/main.c").read()
def grab(a, b):
    i=src.index(a); return src[i:src.index(b, i)]
cw=grab("static void commit_write(size_t n) {", "case G0_REG_HASH_IN:")
assert "G0_CMD_PKSIGN:" in cw and "G0_CMD_PKSCRUB:" in cw, "commit_write must accept PKSIGN and PKSCRUB"
fin=grab("static void finish(int rc) {", "\n}\n")
assert "secure_wipe(g_pk_in" in fin and "g_pk_in_valid = 0" in fin, "finish() must make PK_IN single-use"
wt=grab("static void wipe_transient(void) {", "\n}\n")
assert "secure_wipe(g_pk_in" in wt, "wipe_transient() must clear PK_IN"
dp=grab("static int door_permits(uint8_t cmd) {", "\n}\n")
i=dp.index("case G0_CMD_PKSIGN:"); seg=dp[i:dp.index("return", i)+80]
assert "return g_door == DOOR_PASSKEY;" in seg, "v19: PKSIGN in a PASSKEY life only"
ac=grab("static void door_autocommit(uint8_t cmd) {", "\n}\n")
assert "case G0_CMD_PKSIGN:" not in ac and "G0_CMD_VAULT" not in ac, "v19: PKSIGN and VAULT never commit the NOSTR door"
assert "case G0_REG_PKM_IN:" in src and "plen == PKM_IN_LEN && accepting()" in src, "v19: PKM_IN is exactly 64 or dropped"
assert "secure_wipe(g_pkm_in" in wt, "v19: wipe_transient clears PKM_IN"
assert "secure_wipe(g_pkm_in" in grab("static void wipe_keys(void) {", "\n}\n"), "v19: wipe_keys clears PKM_IN"
wo=grab("static uint32_t wipe_order(int i) {", "\n}\n")
order=["return SE_OBJ_K_PK;","return SE_OBJ_K_PKN;","return SE_OBJ_PK_MASTER_P;","return SE_OBJ_PCR_MODE;","return SE_OBJ_PK_SCRATCH;","return SE_OBJ_PK_MASTER;","return SE_OBJ_VPUB;","return SE_AUTH_OBJ_G0;","return SE_AUTH_OBJ_RECOVER;"]
pos=[wo.index(o) for o in order]
assert pos==sorted(pos), "wipe order (2b): K_PK, K_PKN, PK_MASTER_P before the latch; PK objects, then our auth object, then RECOVER last"
assert "(1u << 9) | (1u << 10) | (1u << 11)" in src, "WIPE_G0AUTH_DEPS covers every object that names the G0 (2b)"
assert "WIPE_IDX_KPK" in wo or "WIPE_IDX_KPK" in src, "the latch waits for both passkey keys"
assert "(1u << 7) | (1u << 8)" in src, "WIPE_G0AUTH_DEPS must include both PK objects"
assert "(1u << 11) | (1u << 12))" in src and "#define WIPE_N 15" in src and "#define WIPE_IDX_G0AUTH  13" in src, "v14: VPUB (index 12, names the G0) is gone before the G0 auth object (13)"
disp=grab("        switch (cmd) {\n        case G0_CMD_SIGN_INIT:", "default:               rc = -1;")
assert "rc = do_pksign();" in disp and "rc = do_pkscrub();" in disp
assert "rc = do_pkmaster();" in disp
assert "rc = do_uvset();" in disp and "rc = do_uvcheck();" in disp and "rc = do_uvclear();" in disp
assert "G0_CMD_UVSET:" in cw and "G0_CMD_UVCHECK:" in cw and "G0_CMD_UVCLEAR:" in cw, "commit_write must accept the UV commands"
wk=grab("static void wipe_keys(void) {", "\n}\n")
assert "uv_clear();" in wk, "wipe_keys must forget the UV reference"
assert "G0_CMD_PKMASTER:" in cw, "commit_write must accept PKMASTER"
import re
regs=re.findall(r"#define (G0_REG_\w+)\s+(0x[0-9A-Fa-f]+)", src+open("src/ember_glue.inc").read()+open("src/pk_glue.inc").read())
ids={}
for n,v in regs: ids.setdefault(int(v,16),set()).add(n)
dup={hex(k):v for k,v in ids.items() if len(v)>1}
assert not dup, "register id used twice: %s" % dup
sk=grab("static int do_setkeys(void) {", "\n}\n")
assert "g_pk_scratch_own = 0" in sk and "g_pk_master_done = 0" in sk and "uv_clear();" in sk, "SETKEYS must reset the passkey and UV state"
wa=grab("static int do_wipeall(void) {", "\n}\n")
assert "g_pk_scratch_own = 0" in wa, "WIPEALL must drop scratch ownership"
open("/tmp/extracted_pk.inc","w").write(grab("static void kg0_iv(uint8_t iv[16]) {", "/* Every scalar op goes through"))
print("PASS  wiring: commit_write, PK_IN single-use, NOSTR-only door + autocommit, wipe order, dispatch, no register id clash, state reset on SETKEYS/WIPEALL")
PY
gcc -O1 -Wall -Wno-unused-function -Iinclude -Ilib/g0crypto -Ilib/scp03 -Ilib/tinyaes -Ilib/p256m -Isrc -Itests -I/tmp -I$MBT/include \
  tests/host_pk.c src/p256_det.c lib/p256m/p256-m.c lib/g0crypto/sha256.c lib/tinyaes/aes.c $MBT/library/libmbedcrypto.a -o /tmp/g0_pk
/tmp/g0_pk
