/* libsecp256k1 is built with USE_EXTERNAL_DEFAULT_CALLBACKS (as on the G0). */
#include <stdio.h>
#include <stdlib.h>
void secp256k1_default_illegal_callback_fn(const char *m, void *d) { (void)d; printf("ILLEGAL: %s\n", m); abort(); }
void secp256k1_default_error_callback_fn(const char *m, void *d) { (void)d; printf("ERROR: %s\n", m); abort(); }
