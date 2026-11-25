#pragma once
#include <cstring>
inline void mbedtls_platform_zeroize(void* p, size_t n){ volatile unsigned char* v=(volatile unsigned char*)p; while(n--) *v++=0; }
