#include "uistub.h"
#include "psbt.h"
#include "psbt_sign.h"
#include "multisig.h"
#include "ur_psbt.h"
// globals multisig_ui.inc expects from bitcoin_menu.inc
static ms_store_t *g_ms = nullptr;
static bip32_xpub  g_ms_our_xpub;
static bool        g_ms_our_valid = false;
static uint8_t    *g_ms_scratch = nullptr;
static uint8_t     g_btc_master_fp[4];
static bip32_xpub  g_btc_account_xpub;
static bool        g_btc_xpub_valid = false;
static ur_decoder_t* urAirgapDec = nullptr;
static bool urAirgapEnsure(){ if(!urAirgapDec){ urAirgapDec=(ur_decoder_t*)malloc(sizeof(ur_decoder_t)); if(urAirgapDec) ur_decoder_reset(urAirgapDec);} return urAirgapDec!=nullptr; }
static bool msEnsureMem(){ return true; }
static bool ms_store_save(){ return true; }
#include "multisig_ui.inc"
int main(){ runMultisigMenu(); return 0; }
