// Definitions the firmware headers reference but main.cpp normally provides.
#include <stdint.h>
#include <stdbool.h>
typedef bool (*nostr_ecdh_hook_t)(const uint8_t peer_xonly32[32], uint8_t shared[32]);
nostr_ecdh_hook_t g_nostr_ecdh_hook = nullptr;
