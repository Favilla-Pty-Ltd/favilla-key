// pk_restorable.h — restorable passkeys, ESP32 side (30 Oct 2026). See pk_restorable.cpp.
#pragma once
#ifdef FAVILLA_PK_RESTORABLE
#include <stdint.h>
#include <stddef.h>

namespace favilla {

constexpr size_t  PKR_ID_LEN  = 34;     // ver || kind || nonce16 || tag16
constexpr uint8_t PKR_ID_VER  = 0x01;
constexpr uint8_t PKR_ID_KIND = 0x01;   // restorable
// Results: 0 ok; 0xE1..0xE9 are the G0's PK_E_* codes; these are ESP32-side.
constexpr int PKR_E_NOG0    = 0xF1;
constexpr int PKR_E_DER     = 0xF2;
constexpr int PKR_E_RECOVER = 0xF3;
constexpr int PKR_E_ID      = 0xF4;

struct pkr_timing_t { uint32_t g0Ms; uint32_t recoverMs; };

const char* pkr_res_name(uint8_t r);
int  pkr_der_to_raw(const uint8_t* der, size_t n, uint8_t raw[64]);
bool pkr_scrub(uint8_t* res, uint16_t* sw);
// Daily PIN unlocked, NOSTR life. Callers must NOT hold the I2C lock: the G0
// calls take the bus themselves, and recovery runs with the bus free.
int  pkr_register(const uint8_t rpIdHash[32], uint8_t credId[PKR_ID_LEN], uint8_t pub65[65], pkr_timing_t* t = nullptr);
int  pkr_sign(const uint8_t rpIdHash[32], const uint8_t credId[PKR_ID_LEN], const uint8_t hash[32],
              uint8_t* der, size_t* derN, pkr_timing_t* t = nullptr);

}  // namespace favilla
#endif
