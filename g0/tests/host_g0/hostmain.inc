#include "s8.inc"
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getenv("S8ONLY")) { h_flash_init(); s8_raw(); return 0; }   /* raw attacker only (s8.inc) */
    s1_doors();
    s2_seed_swap(1);   /* G0 v21 (#53): SETKEYS only while the door is UNSET */
    s5_arm_by_daily();
    s6_unset_window();
    extra_scenarios();
    printf(fails ? "\n%d FAILED\n" : "\nall passed\n", fails);
    return fails != 0;
}
