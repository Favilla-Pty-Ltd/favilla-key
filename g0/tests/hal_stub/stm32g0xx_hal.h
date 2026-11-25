/* host stub: only what key_store.c uses (tests/run_ks_lim.sh) */
#include <stdint.h>
typedef enum {HAL_OK=0} HAL_StatusTypeDef;
typedef struct {uint32_t TypeErase,Banks,Page,NbPages;} FLASH_EraseInitTypeDef;
#define FLASH_BANK_SIZE 0x10000u
#define FLASH_BASE 0x08000000u
#define FLASH_TYPEERASE_PAGES 0
#define FLASH_BANK_1 1
#define FLASH_BANK_2 2
#define FLASH_TYPEPROGRAM_DOUBLEWORD 1
HAL_StatusTypeDef HAL_FLASH_Unlock(void);HAL_StatusTypeDef HAL_FLASH_Lock(void);
HAL_StatusTypeDef HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef*,uint32_t*);
HAL_StatusTypeDef HAL_FLASH_Program(uint32_t,uint32_t,uint64_t);
