/* Host fake of the STM32G0 HAL, enough for g0/src/main.c to compile and run
 * on Linux (audit 21 Nov 2026). Flash is a fixed mmap at 0x08000000 (see
 * g0host.c); everything else is a plain struct or a no-op. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef enum { HAL_OK = 0, HAL_ERROR = 1 } HAL_StatusTypeDef;
typedef enum { GPIO_PIN_RESET = 0, GPIO_PIN_SET = 1 } GPIO_PinState;
typedef enum { I2C1_IRQn = 23, SysTick_IRQn = -1 } IRQn_Type;

typedef struct { volatile uint32_t CR1, CR2, OAR1, OAR2, TIMINGR, ISR, ICR; } I2C_TypeDef;
typedef struct { uint32_t Timing, OwnAddress1, AddressingMode, DualAddressMode, OwnAddress2, OwnAddress2Masks, GeneralCallMode, NoStretchMode; } I2C_InitTypeDef;
typedef struct { I2C_TypeDef *Instance; I2C_InitTypeDef Init; } I2C_HandleTypeDef;
typedef struct { volatile uint32_t MODER, OTYPER, OSPEEDR, PUPDR, IDR, ODR, BSRR; } GPIO_TypeDef;
typedef struct { uint32_t Pin, Mode, Pull, Speed, Alternate; } GPIO_InitTypeDef;
typedef struct { volatile uint32_t BKP0R, BKP1R, BKP2R, BKP3R, BKP4R; } TAMP_TypeDef;
typedef struct { volatile uint32_t CSR, CR, CFGR, IOPENR, APBENR1, APBENR2; } RCC_TypeDef;
typedef struct { volatile uint32_t ECCR, OPTR, SR, CR; } FLASH_TypeDef;
typedef struct { volatile uint32_t CTRL, LOAD, VAL, CALIB; } SysTick_Type;
typedef struct { volatile uint32_t SCR, AIRCR, SHCSR, CCR, VTOR; } SCB_Type;
typedef struct { volatile uint32_t CR; } RNG_TypeDef;
typedef struct { volatile uint32_t CTRL, RNR, RBAR, RASR; } MPU_Type;
typedef struct { uint8_t Enable, Number; uint32_t BaseAddress; uint8_t Size, SubRegionDisable, TypeExtField, AccessPermission, DisableExec, IsShareable, IsCacheable, IsBufferable; } MPU_Region_InitTypeDef;
typedef struct { uint32_t TypeErase, Banks, Page, NbPages; } FLASH_EraseInitTypeDef;
typedef struct { uint32_t PLLState, PLLSource, PLLM, PLLN, PLLP, PLLQ, PLLR; } RCC_PLLInitTypeDef;
typedef struct { uint32_t OscillatorType, HSIState, HSIDiv, HSICalibrationValue, LSIState, HSEState, LSEState; RCC_PLLInitTypeDef PLL; } RCC_OscInitTypeDef;
typedef struct { uint32_t ClockType, SYSCLKSource, AHBCLKDivider, APB1CLKDivider; } RCC_ClkInitTypeDef;
typedef struct { uint32_t PeriphClockSelection, I2c1ClockSelection; } RCC_PeriphCLKInitTypeDef;

extern I2C_TypeDef fake_i2c1; extern GPIO_TypeDef fake_gpioa, fake_gpiob; extern TAMP_TypeDef fake_tamp;
extern RCC_TypeDef fake_rcc; extern FLASH_TypeDef fake_flash_regs; extern SysTick_Type fake_systick;
extern SCB_Type fake_scb; extern RNG_TypeDef fake_rng; extern MPU_Type fake_mpu;
#define I2C1 (&fake_i2c1)
#define GPIOA (&fake_gpioa)
#define GPIOB (&fake_gpiob)
#define TAMP (&fake_tamp)
#define RCC (&fake_rcc)
#define FLASH (&fake_flash_regs)
#define SysTick (&fake_systick)
#define SCB (&fake_scb)
#define RNG (&fake_rng)
#define MPU (&fake_mpu)

#define FLASH_BASE 0x08000000UL
#define FLASH_BANK_SIZE 0x10000UL
#define FLASH_PAGE_SIZE 0x800UL
#define FLASH_BANK_1 1u
#define FLASH_BANK_2 2u
#define FLASH_TYPEERASE_PAGES 0u
#define FLASH_TYPEPROGRAM_DOUBLEWORD 1u
#define FLASH_ECCR_ECCD (1u << 31)
#define FLASH_ECCR_ECCC (1u << 30)
#define FLASH_OPTR_RDP_Msk 0xFFu

#define RCC_CSR_PWRRSTF (1u << 27)
#define RCC_CSR_PINRSTF (1u << 26)
#define RCC_CSR_SFTRSTF (1u << 28)
#define RCC_CSR_IWDGRSTF (1u << 29)
#define RCC_CSR_OBLRSTF (1u << 25)
#define RCC_CSR_WWDGRSTF (1u << 30)
#define RCC_CSR_LPWRRSTF (1u << 31)
#define RCC_OSCILLATORTYPE_HSI 2u
#define RCC_HSI_ON 1u
#define RCC_HSI_DIV1 0u
#define RCC_HSICALIBRATION_DEFAULT 64u
#define RCC_PLL_ON 2u
#define RCC_PLLSOURCE_HSI 2u
#define RCC_PLLM_DIV1 0u
#define RCC_PLLP_DIV2 0u
#define RCC_PLLQ_DIV2 0u
#define RCC_PLLR_DIV2 0u
#define RCC_CLOCKTYPE_SYSCLK 1u
#define RCC_CLOCKTYPE_HCLK 2u
#define RCC_CLOCKTYPE_PCLK1 4u
#define RCC_SYSCLKSOURCE_PLLCLK 2u
#define RCC_SYSCLK_DIV1 0u
#define RCC_HCLK_DIV1 0u
#define RCC_PERIPHCLK_I2C1 1u
#define RCC_I2C1CLKSOURCE_PCLK1 0u
#define RCC_I2C1CLKSOURCE_HSI 1u
#define FLASH_LATENCY_2 2u

#define GPIO_PIN_0 0x0001u
#define GPIO_PIN_1 0x0002u
#define GPIO_PIN_2 0x0004u
#define GPIO_PIN_6 0x0040u
#define GPIO_PIN_7 0x0080u
#define GPIO_PIN_8 0x0100u
#define GPIO_PIN_9 0x0200u
#define GPIO_MODE_OUTPUT_PP 1u
#define GPIO_MODE_AF_OD 0x12u
#define GPIO_MODE_INPUT 0u
#define GPIO_MODE_ANALOG 3u
#define GPIO_NOPULL 0u
#define GPIO_PULLUP 1u
#define GPIO_SPEED_FREQ_LOW 0u
#define GPIO_SPEED_FREQ_HIGH 2u
#define GPIO_AF6_I2C1 6u

#define I2C_ADDRESSINGMODE_7BIT 1u
#define I2C_DUALADDRESS_DISABLE 0u
#define I2C_OA2_NOMASK 0u
#define I2C_GENERALCALL_DISABLE 0u
#define I2C_NOSTRETCH_DISABLE 0u
#define I2C_ANALOGFILTER_ENABLE 0u
#define I2C_NEXT_FRAME 0u
#define I2C_FIRST_FRAME 1u
#define I2C_LAST_FRAME 2u
#define I2C_DIRECTION_TRANSMIT 0u
#define I2C_DIRECTION_RECEIVE 1u
#define I2C_CR1_WUPEN (1u << 18)
#define I2C_FLAG_STOPF (1u << 5)
#define __HAL_I2C_CLEAR_FLAG(h, f) ((void)(h), (void)(f))

#define PWR_LOWPOWERREGULATOR_ON 1u
#define PWR_STOPENTRY_WFI 1u
#define MPU_REGION_ENABLE 1u
#define MPU_REGION_DISABLE 0u
#define MPU_REGION_FULL_ACCESS 3u
#define MPU_REGION_PRIV_RO 5u
#define MPU_REGION_NO_ACCESS 0u
#define MPU_INSTRUCTION_ACCESS_ENABLE 0u
#define MPU_INSTRUCTION_ACCESS_DISABLE 1u
#define MPU_ACCESS_SHAREABLE 1u
#define MPU_ACCESS_NOT_SHAREABLE 0u
#define MPU_ACCESS_CACHEABLE 1u
#define MPU_ACCESS_NOT_CACHEABLE 0u
#define MPU_ACCESS_BUFFERABLE 1u
#define MPU_ACCESS_NOT_BUFFERABLE 0u
#define MPU_PRIVILEGED_DEFAULT 4u
#define MPU_REGION_NUMBER0 0u
#define MPU_REGION_NUMBER1 1u
#define MPU_REGION_NUMBER2 2u
#define MPU_REGION_NUMBER3 3u
#define MPU_REGION_SIZE_2KB 10u
#define MPU_REGION_SIZE_4KB 11u
#define MPU_REGION_SIZE_8KB 12u
#define MPU_REGION_SIZE_16KB 13u
#define MPU_REGION_SIZE_32KB 14u
#define MPU_REGION_SIZE_64KB 15u
#define MPU_REGION_SIZE_256KB 17u
#define MPU_REGION_SIZE_1KB 9u
#define MPU_REGION_SIZE_256B 7u
#define MPU_REGION_SIZE_32B 4u
#define MPU_REGION_SIZE_128KB 16u
#define MPU_REGION_SIZE_512MB 28u
#define MPU_TEX_LEVEL0 0u

uint32_t HAL_GetTick(void);
void HAL_IncTick(void);
static inline HAL_StatusTypeDef HAL_Init(void) { return HAL_OK; }
static inline void HAL_SuspendTick(void) {}
static inline void HAL_ResumeTick(void) {}
HAL_StatusTypeDef HAL_FLASH_Unlock(void);
HAL_StatusTypeDef HAL_FLASH_Lock(void);
HAL_StatusTypeDef HAL_FLASH_Program(uint32_t type, uint32_t addr, uint64_t data);
HAL_StatusTypeDef HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef *e, uint32_t *err);
static inline HAL_StatusTypeDef HAL_RCC_OscConfig(RCC_OscInitTypeDef *o) { (void)o; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_RCC_ClockConfig(RCC_ClkInitTypeDef *c, uint32_t l) { (void)c; (void)l; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_RCCEx_PeriphCLKConfig(RCC_PeriphCLKInitTypeDef *p) { (void)p; return HAL_OK; }
static inline void HAL_GPIO_Init(GPIO_TypeDef *g, GPIO_InitTypeDef *i) { (void)g; (void)i; }
static inline void HAL_GPIO_WritePin(GPIO_TypeDef *g, uint16_t p, GPIO_PinState s) { if (s) g->ODR |= p; else g->ODR &= ~(uint32_t)p; }
static inline GPIO_PinState HAL_GPIO_ReadPin(GPIO_TypeDef *g, uint16_t p) { return (g->ODR & p) ? GPIO_PIN_SET : GPIO_PIN_RESET; }
static inline void HAL_NVIC_SetPriority(IRQn_Type i, uint32_t a, uint32_t b) { (void)i; (void)a; (void)b; }
static inline void HAL_NVIC_EnableIRQ(IRQn_Type i) { (void)i; }
static inline void HAL_NVIC_DisableIRQ(IRQn_Type i) { (void)i; }
static inline void HAL_PWR_EnterSTOPMode(uint32_t r, uint32_t e) { (void)r; (void)e; }
static inline void HAL_PWR_EnableBkUpAccess(void) {}
static inline void HAL_MPU_Enable(uint32_t c) { (void)c; }
static inline void HAL_MPU_Disable(void) {}
static inline void HAL_MPU_ConfigRegion(MPU_Region_InitTypeDef *r) { (void)r; }
static inline HAL_StatusTypeDef HAL_I2C_Init(I2C_HandleTypeDef *h) { (void)h; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_I2CEx_ConfigAnalogFilter(I2C_HandleTypeDef *h, uint32_t f) { (void)h; (void)f; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_I2CEx_ConfigDigitalFilter(I2C_HandleTypeDef *h, uint32_t f) { (void)h; (void)f; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_I2C_EnableListen_IT(I2C_HandleTypeDef *h) { (void)h; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_I2C_Slave_Seq_Receive_IT(I2C_HandleTypeDef *h, uint8_t *p, uint16_t n, uint32_t f) { (void)h; (void)p; (void)n; (void)f; return HAL_OK; }
static inline HAL_StatusTypeDef HAL_I2C_Slave_Seq_Transmit_IT(I2C_HandleTypeDef *h, uint8_t *p, uint16_t n, uint32_t f) { (void)h; (void)p; (void)n; (void)f; return HAL_OK; }
static inline void HAL_I2C_EV_IRQHandler(I2C_HandleTypeDef *h) { (void)h; }
static inline void HAL_I2C_ER_IRQHandler(I2C_HandleTypeDef *h) { (void)h; }
#define __HAL_RCC_GPIOA_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_GPIOB_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_I2C1_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_PWR_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_RTCAPB_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_RNG_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_SYSCFG_CLK_ENABLE() do {} while (0)
#define __HAL_RCC_CLEAR_RESET_FLAGS() do {} while (0)
#define __HAL_FLASH_SET_LATENCY(x) do {} while (0)
#define __WFI() do {} while (0)
#define __NOP() do {} while (0)
#define __DSB() do {} while (0)
#define __ISB() do {} while (0)
#define __BKPT(x) do {} while (0)
#define __disable_irq() do {} while (0)
#define __enable_irq() do {} while (0)
static inline uint32_t __get_PRIMASK(void) { return 0; }
static inline void __set_PRIMASK(uint32_t x) { (void)x; }
