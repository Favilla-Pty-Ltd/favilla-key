#pragma once
// host stub (3 Nov 2026, P4-1): one data partition backed by g_part (a test
// image). size 0 = no partition (find returns nullptr), as the older tests expect.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
typedef int esp_err_t;
#ifndef ESP_OK
#define ESP_OK 0
#endif
#define ESP_FAIL -1
typedef enum { ESP_PARTITION_TYPE_DATA = 1 } esp_partition_type_t;
typedef enum { ESP_PARTITION_SUBTYPE_DATA_NVS = 2 } esp_partition_subtype_t;
typedef struct { uint32_t address, size; char label[17]; } esp_partition_t;
extern std::vector<uint8_t> g_part;
extern int g_partErases;
inline const esp_partition_t* esp_partition_find_first(esp_partition_type_t, esp_partition_subtype_t, const char*) {
  static esp_partition_t p; if (g_part.empty()) return nullptr; p.address = 0xFB0000; p.size = (uint32_t)g_part.size(); strcpy(p.label, "nvs_vault"); return &p;
}
inline esp_err_t esp_partition_read(const esp_partition_t*, size_t off, void* d, size_t n) { if (off + n > g_part.size()) return ESP_FAIL; memcpy(d, g_part.data() + off, n); return ESP_OK; }
inline esp_err_t esp_partition_erase_range(const esp_partition_t*, size_t off, size_t n) { if (off % 4096 || n % 4096 || off + n > g_part.size()) return ESP_FAIL; memset(g_part.data() + off, 0xFF, n); g_partErases++; return ESP_OK; }
