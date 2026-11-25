/* 23 Nov 2026 (#57): host test for PSBT_IN_NON_WITNESS_UTXO checking in
 * src/psbt.h. Build and run: sh run.sh */
#include <stdio.h>
#include "psbt.h"
#include "vectors.h"
static psbt_t P; static int fails = 0;
static void t(const char *name, const unsigned char *b, size_t n, int want_parse, int want_err, int want_proven) {
    memset(&P, 0, sizeof P);
    int ok = psbt_parse(b, n, &P);
    int pr = ok ? psbt_amounts_proven(&P) : -1;
    int pass = (ok == want_parse) && (ok || psbt_last_err == want_err) && (!ok || pr == want_proven);
    printf("%s  %-12s parse=%d err=%d (%s) proven=%d\n", pass ? "PASS" : "FAIL", name, ok, psbt_last_err,
           ok ? "-" : psbt_err_str(psbt_last_err), pr);
    if (!pass) fails++;
}
int main(void) {
    t("ok_both",     v_ok_both,     sizeof v_ok_both,     1, 0, 1);
    t("ok_nwu_only", v_ok_nwu_only, sizeof v_ok_nwu_only, 1, 0, 1);
    if (P.inputs[1].witness_utxo_value != 123456 || !P.inputs[0].nwu_verified) { printf("FAIL  nwu_only did not fill witness_utxo\n"); fails++; }
    t("wu_only_2in", v_wu_only_2in, sizeof v_wu_only_2in, 1, 0, 0);
    t("wu_only_1in", v_wu_only_1in, sizeof v_wu_only_1in, 1, 0, 1);
    t("lie_amount",  v_lie_amount,  sizeof v_lie_amount,  0, 20, 0);
    t("wrong_prev",  v_wrong_prev,  sizeof v_wrong_prev,  0, 19, 0);
    t("vout_range",  v_vout_range,  sizeof v_vout_range,  0, 19, 0);
    printf(fails ? "RESULT: FAIL\n" : "RESULT: input amounts are proven by the previous transactions\n");
    return fails != 0;
}
