// Host stub. 2 Nov 2026: every call differs (record ids must be unique for
// the phase 3 merge tests); still deterministic from run to run.
inline void esp_fill_random(void* b, unsigned n){ static unsigned c = 0; c++; for(unsigned i=0;i<n;i++) ((unsigned char*)b)[i]=(unsigned char)((0xA0+i) ^ (c*37) ^ (c>>3)); if(n>=8){ ((unsigned char*)b)[0]=(unsigned char)(c>>8); ((unsigned char*)b)[1]=(unsigned char)c; } }   // 3 Nov: ids unique past 256 calls (200-record tests)
