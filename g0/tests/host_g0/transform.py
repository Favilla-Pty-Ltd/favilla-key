# Turn g0/src/main.c into a host-runnable unit: main() becomes g0_boot()
# (init only) and the command loop body becomes g0_step() (one command).
import re, sys
src = open(sys.argv[1]).read()
# RAM scrub walks real RAM: neutralise
src = re.sub(r'static void ram_scrub_at_boot\(void\) \{.*?\n\}\n', 'static void ram_scrub_at_boot(void) {}\n', src, flags=re.S)
src = src.replace('extern uint32_t _ebss;', '')
# main -> g0_boot + g0_step
i = src.index('int main(void) {')
j = src.index('    for (;;) {\n        if (g_reset_pending) {', i)
head, loop = src[:j], src[j:]
loop = loop.replace('    for (;;) {\n', '    return selftest_ok;\n}\nstatic int g_selftest_ok_host = 0;\nvoid g0_step(void) {\n    int selftest_ok = g_selftest_ok_host;\n    do {\n', 1)
# the loop ends with "    }\n}\n" at the end of file
k = loop.rindex('    }\n}')
loop = loop[:k] + '    } while (0);\n}\n' + loop[k+len('    }\n}'):]
src = head.replace('int main(void) {', 'int g0_boot(void) {') + loop
if '-DFIX53' in sys.argv:
    src = src.replace('    if (g_keys_valid) return -1;\n    /* v5.1: no keys = no wallet.', '    if (g_keys_valid) return -1;\n    if (g_door != DOOR_UNSET) return -1;   /* HOST FIX53 */\n    /* v5.1: no keys = no wallet.', 1)
    assert 'HOST FIX53' in src
# expose a few statics to the harness through accessors appended at the end
src += r'''
/* ---- host accessors (audit harness) ---- */
void host_set_selftest(int v) { g_selftest_ok_host = v; }
uint8_t host_door(void) { return g_door; }
int host_keys_valid(void) { return g_keys_valid; }
int host_seal_window(void) { return g_seal_window; }
uint8_t host_arm_reset(void) { return g_mode_reset_arm; }
uint8_t host_arm_btc(void) { return g_mode_btc_arm; }
uint8_t host_arm_pk(void) { return g_mode_pk_arm; }
uint8_t host_status(void) { return g_status; }
void host_cmd(uint8_t c) { g_cmd_pending = c; }
uint8_t *host_sig_out(void) { return g_sig_out; }
uint8_t *host_btc_out(void) { return g_btc_out; }
void host_write(const uint8_t *b, size_t n) { if (n > sizeof(s_rx)) n = sizeof(s_rx); memcpy(s_rx, b, n); commit_write(n); }
void host_reset_pending(void) { }
'''
src = src.replace('for (;;) __BKPT(0);', 'abort();')
src += '\n#include <stdlib.h>\n#include "harness.inc"\n#include "scenarios.inc"\n#include "extra.inc"\n#include "hostmain.inc"\n'
open(sys.argv[2], 'w').write(src)
