#pragma once
#include <map>
#include <string>
#include <vector>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NVS_NO_FREE_PAGES 0x110d
#define ESP_ERR_NVS_NEW_VERSION_FOUND 0x1110
extern int g_nvsMountErr;
extern std::map<std::string,std::vector<uint8_t>> g_nvs;
inline esp_err_t nvs_flash_init_partition(const char*){ int e = g_nvsMountErr; if (e == ESP_ERR_NVS_NO_FREE_PAGES) g_nvsMountErr = 0; return e; }
inline esp_err_t nvs_flash_deinit_partition(const char*){ return ESP_OK; }
inline esp_err_t nvs_flash_erase_partition(const char* p){ std::string pre = std::string(p) + "/"; for (auto it = g_nvs.begin(); it != g_nvs.end();) { if (it->first.rfind(pre, 0) == 0) it = g_nvs.erase(it); else ++it; } return ESP_OK; }
// 3 Nov 2026 (P4-10 re-review): free entries of a named partition; tests set g_nvsFree (the usable
// entries, as the firmware sees them after it takes off the 126-entry spare page).
extern int g_nvsFree;
typedef struct { size_t used_entries, free_entries, available_entries, total_entries, namespace_count; } nvs_stats_t;
inline esp_err_t nvs_get_stats(const char*, nvs_stats_t* s){ s->free_entries = (size_t)g_nvsFree + 126; s->used_entries = 0; s->available_entries = s->free_entries; s->total_entries = 4032; s->namespace_count = 1; return ESP_OK; }
