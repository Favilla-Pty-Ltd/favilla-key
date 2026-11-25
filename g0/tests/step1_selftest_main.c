/* =============================================================================
 * Favilla KEY — STM32G0B1KBU6 isolated Nostr signer
 * STEP 1 of the build order: libsecp256k1 on the M0+, BIP-340 vectors on-chip.
 * =============================================================================
 *
 * What this firmware does, in order, at boot:
 *   1. Runs every fixed-length BIP-340 test vector: sign (where a secret key
 *      is given, with the vector's aux_rand) and compare byte-for-byte; verify
 *      (all vectors) and compare the expected TRUE/FALSE.
 *   2. Runs one ECDH (x-only) round trip against a known pair.
 *   3. Brings up I2C1 as a target at 0x42 and sits in WFI.
 *
 * How the result gets out — there is no UART on the board, so the ESP32 reads
 * it over I2C and prints it in its boot log:
 *   STATUS (0x01)  : 0x00 IDLE if every test passed, 0xE0 ERROR otherwise
 *   SELFTEST (0x7F): 16 bytes  'G','0','S','T', ver, npass, ntotal, flags,
 *                    sign_ms(u16 LE), verify_ms(u16 LE), ecdh_ms(u16 LE), 0, 0
 * Every other register behaves as the bring-up stub did (reads return 0x00,
 * writes are swallowed). NO signing, ECDH or relay is exposed yet.
 *
 * Clock: HSI16 -> PLL -> 64 MHz so the timings are representative.
 * ========================================================================== */

#include "stm32g0xx_hal.h"
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_preallocated.h"
#include "bip340_vectors.h"

#define G0_I2C_ADDR       0x42
#define G0_REG_STATUS     0x01
#define G0_REG_SELFTEST   0x7F
#define G0_ST_IDLE        0x00
#define G0_ST_ERROR       0xE0
#define SELFTEST_VER      1

/* ---------------------------------------------------------------------------
 * libsecp256k1 hooks. USE_EXTERNAL_DEFAULT_CALLBACKS means WE provide these;
 * on a chip with no stderr the only sane reaction is to trap.
 * ------------------------------------------------------------------------- */
void secp256k1_default_illegal_callback_fn(const char *msg, void *data) {
    (void)msg; (void)data;
    __disable_irq();
    for (;;) __BKPT(0);
}
void secp256k1_default_error_callback_fn(const char *msg, void *data) {
    (void)msg; (void)data;
    __disable_irq();
    for (;;) __BKPT(0);
}

/* Context lives in a static buffer — no malloc on this chip, ever. */
static uint8_t g_ctx_buf[512] __attribute__((aligned(16)));
static secp256k1_context *g_ctx;

/* ---------------------------------------------------------------------------
 * Results, laid out exactly as the ESP32 reads them from REG 0x7F.
 * ------------------------------------------------------------------------- */
static uint8_t g_selftest[16];
static uint8_t g_status = G0_ST_ERROR;    /* pessimistic until proven */

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static void run_selftest(void) {
    uint8_t npass = 0, ntotal = 0, flags = 0;
    uint32_t t_sign = 0, t_verify = 0, t_ecdh = 0;

    size_t need = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE);
    if (need > sizeof(g_ctx_buf)) { flags |= 0x80; goto done; }   /* buffer too small */
    g_ctx = secp256k1_context_preallocated_create(g_ctx_buf, SECP256K1_CONTEXT_NONE);
    if (!g_ctx) { flags |= 0x40; goto done; }

    for (size_t i = 0; i < BIP340_NVECS; i++) {
        const bip340_vec_t *v = &BIP340_VECS[i];

        /* --- sign ------------------------------------------------------- */
        if (v->has_sk) {
            ntotal++;
            secp256k1_keypair kp;
            uint8_t sig[64];
            uint32_t t0 = HAL_GetTick();
            int ok = secp256k1_keypair_create(g_ctx, &kp, v->sk) &&
                     secp256k1_schnorrsig_sign32(g_ctx, sig, v->msg, &kp, v->aux);
            t_sign += HAL_GetTick() - t0;
            if (ok && memcmp(sig, v->sig, 64) == 0) npass++; else flags |= 0x01;
            memset(&kp, 0, sizeof(kp));
        }

        /* --- verify ----------------------------------------------------- */
        ntotal++;
        {
            secp256k1_xonly_pubkey pk;
            int parsed = secp256k1_xonly_pubkey_parse(g_ctx, &pk, v->pk);
            uint32_t t0 = HAL_GetTick();
            int ok = parsed && secp256k1_schnorrsig_verify(g_ctx, v->sig, v->msg, 32, &pk);
            t_verify += HAL_GetTick() - t0;
            if ((ok ? 1 : 0) == v->expect_ok) npass++; else flags |= 0x02;
        }
    }

    /* --- ECDH round trip: X(a*B) == X(b*A) ------------------------------- */
    {
        ntotal++;
        static const uint8_t a[32] = { [31] = 0x03 };
        static const uint8_t b[32] = { 0xB7,0xE1,0x51,0x62,0x8A,0xED,0x2A,0x6A,0xBF,0x71,0x58,0x80,0x9C,0xF4,0xF3,0xC7,
                                       0x62,0xE7,0x16,0x0F,0x38,0xB4,0xDA,0x56,0xA7,0x84,0xD9,0x04,0x51,0x90,0xCF,0xEF };
        secp256k1_pubkey A, B; uint8_t s1[32], s2[32];
        uint32_t t0 = HAL_GetTick();
        int ok = secp256k1_ec_pubkey_create(g_ctx, &A, a) &&
                 secp256k1_ec_pubkey_create(g_ctx, &B, b) &&
                 secp256k1_ecdh(g_ctx, s1, &B, a, NULL, NULL) &&   /* default hashed ECDH */
                 secp256k1_ecdh(g_ctx, s2, &A, b, NULL, NULL);
        t_ecdh += HAL_GetTick() - t0;
        if (ok && memcmp(s1, s2, 32) == 0) npass++; else flags |= 0x04;
    }

done:
    memset(g_selftest, 0, sizeof(g_selftest));
    g_selftest[0] = 'G'; g_selftest[1] = '0'; g_selftest[2] = 'S'; g_selftest[3] = 'T';
    g_selftest[4] = SELFTEST_VER;
    g_selftest[5] = npass;
    g_selftest[6] = ntotal;
    g_selftest[7] = flags;
    put16(g_selftest + 8,  t_sign);
    put16(g_selftest + 10, t_verify);
    put16(g_selftest + 12, t_ecdh);
    g_status = (ntotal > 0 && npass == ntotal && flags == 0) ? G0_ST_IDLE : G0_ST_ERROR;
}

/* ---------------------------------------------------------------------------
 * Clocks: HSI16 -> PLL(M=1,N=8,R=2) = 64 MHz. FLASH latency 2 at 64 MHz.
 * ------------------------------------------------------------------------- */
static void SystemClock_Config(void) {
    RCC_OscInitTypeDef osc = {0};
    RCC_ClkInitTypeDef clk = {0};
    osc.OscillatorType      = RCC_OSCILLATORTYPE_HSI;
    osc.HSIState            = RCC_HSI_ON;
    osc.HSIDiv              = RCC_HSI_DIV1;
    osc.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    osc.PLL.PLLState        = RCC_PLL_ON;
    osc.PLL.PLLSource       = RCC_PLLSOURCE_HSI;
    osc.PLL.PLLM            = RCC_PLLM_DIV1;
    osc.PLL.PLLN            = 8;
    osc.PLL.PLLP            = RCC_PLLP_DIV2;
    osc.PLL.PLLQ            = RCC_PLLQ_DIV2;
    osc.PLL.PLLR            = RCC_PLLR_DIV2;
    HAL_RCC_OscConfig(&osc);
    clk.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1;
    clk.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
    clk.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_2);
}

/* ---------------------------------------------------------------------------
 * I2C1 target on PB6 (SCL) / PB7 (SDA), AF6. Register-select semantics:
 * the first byte of a write is the register; a read streams that register.
 * ------------------------------------------------------------------------- */
static I2C_HandleTypeDef hi2c1;
static uint8_t s_reg = 0;                 /* last selected register */
static volatile uint8_t s_writing = 0;    /* a master write is/was in progress */
static uint8_t s_rx[64];
static uint8_t s_tx_zero = 0;
static uint8_t s_tx_idx = 0;

void HAL_I2C_MspInit(I2C_HandleTypeDef *h) {
    if (h->Instance != I2C1) return;
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_I2C1_CLK_ENABLE();
    GPIO_InitTypeDef g = {0};
    g.Pin = GPIO_PIN_6 | GPIO_PIN_7;
    g.Mode = GPIO_MODE_AF_OD; g.Pull = GPIO_NOPULL; g.Speed = GPIO_SPEED_FREQ_HIGH;
    g.Alternate = GPIO_AF6_I2C1;
    HAL_GPIO_Init(GPIOB, &g);
    HAL_NVIC_SetPriority(I2C1_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(I2C1_IRQn);
}

static void MX_I2C1_Init(void) {
    hi2c1.Instance              = I2C1;
    hi2c1.Init.Timing           = 0x10B17DB5;   /* CubeMX: PCLK 64 MHz, 100 kHz Sm */
    hi2c1.Init.OwnAddress1      = (G0_I2C_ADDR << 1);
    hi2c1.Init.AddressingMode   = I2C_ADDRESSINGMODE_7BIT;
    hi2c1.Init.DualAddressMode  = I2C_DUALADDRESS_DISABLE;
    hi2c1.Init.OwnAddress2      = 0;
    hi2c1.Init.OwnAddress2Masks = I2C_OA2_NOMASK;
    hi2c1.Init.GeneralCallMode  = I2C_GENERALCALL_DISABLE;
    hi2c1.Init.NoStretchMode    = I2C_NOSTRETCH_DISABLE;
    HAL_I2C_Init(&hi2c1);
    HAL_I2CEx_ConfigAnalogFilter(&hi2c1, I2C_ANALOGFILTER_ENABLE);
    HAL_I2CEx_ConfigDigitalFilter(&hi2c1, 0);
}

/* One byte at a time keeps the ISR trivial and lets a read of any length
 * work: the master NACKs when it has had enough. */
static void tx_next(I2C_HandleTypeDef *h) {
    const uint8_t *src = &s_tx_zero;
    if (s_reg == G0_REG_STATUS) {
        src = &g_status;
    } else if (s_reg == G0_REG_SELFTEST && s_tx_idx < sizeof(g_selftest)) {
        src = &g_selftest[s_tx_idx];
    }
    s_tx_idx++;
    HAL_I2C_Slave_Seq_Transmit_IT(h, (uint8_t *)src, 1, I2C_NEXT_FRAME);
}

/* The ESP32 does write(reg) + REPEATED START + read. So the register byte
 * has landed in s_rx[0] by the time the read's address match arrives, but
 * neither RxCplt (64-byte buffer not full) nor ListenCplt (no STOP yet) has
 * fired. Latch it in the read's AddrCallback instead, and also at STOP for
 * the write-only case. */
static void latch_reg(void) {
    if (s_writing) { s_reg = s_rx[0]; s_writing = 0; }
}
void HAL_I2C_AddrCallback(I2C_HandleTypeDef *h, uint8_t dir, uint16_t addr) {
    (void)addr;
    if (dir == I2C_DIRECTION_TRANSMIT) {           /* master writes: [reg][data...] */
        s_writing = 1;
        HAL_I2C_Slave_Seq_Receive_IT(h, s_rx, sizeof(s_rx), I2C_FIRST_AND_LAST_FRAME);
    } else {                                       /* master reads the selected reg */
        latch_reg();
        s_tx_idx = 0;
        tx_next(h);
    }
}
void HAL_I2C_SlaveTxCpltCallback(I2C_HandleTypeDef *h) { tx_next(h); }
void HAL_I2C_SlaveRxCpltCallback(I2C_HandleTypeDef *h) { (void)h; latch_reg(); }
void HAL_I2C_ListenCpltCallback(I2C_HandleTypeDef *h) {
    latch_reg();
    HAL_I2C_EnableListen_IT(h);
}
void HAL_I2C_ErrorCallback(I2C_HandleTypeDef *h) {
    /* AF on the last byte of a read is the normal end of transfer. */
    HAL_I2C_EnableListen_IT(h);
}

void SysTick_Handler(void) { HAL_IncTick(); }
void I2C1_IRQHandler(void) {
    HAL_I2C_EV_IRQHandler(&hi2c1);
    HAL_I2C_ER_IRQHandler(&hi2c1);
}

int main(void) {
    HAL_Init();
    SystemClock_Config();

    /* Tests first, I2C second: the ESP32's g0_init() would otherwise read an
     * ERROR status mid-run. The ESP32 retries at its next boot anyway. */
    run_selftest();

    MX_I2C1_Init();
    HAL_I2C_EnableListen_IT(&hi2c1);
    for (;;) __WFI();
}
