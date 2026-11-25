#pragma once
#include <map>
#include <string>
#include <vector>
#include <cstring>
extern std::map<std::string,std::vector<uint8_t>> g_nvs;
extern int g_nvsPutFail;   // test hook: the next N putBytes fail
extern int g_nvsFree;      // test hook: what freeEntries() reports
struct Preferences{ std::string ns;
 bool begin(const char* n,bool=false,const char* part=nullptr){ ns = std::string(part?part:"nvs") + "/" + n + "/"; return true;} void end(){}
 std::string k(const char* key){ return ns + key; }
 size_t getBytes(const char*key,void*b,size_t n){ auto it=g_nvs.find(k(key)); if(it==g_nvs.end()||it->second.size()!=n) return 0; memcpy(b,it->second.data(),n); return n;}
 size_t getBytesLength(const char* key){ auto it=g_nvs.find(k(key)); return it==g_nvs.end()?0:it->second.size(); }
 bool isKey(const char* key){ return g_nvs.count(k(key)) > 0; }
 size_t putBytes(const char*key,const void*b,size_t n){ if(g_nvsPutFail>0){ g_nvsPutFail--; return 0; } g_nvs[k(key)]=std::vector<uint8_t>((const uint8_t*)b,(const uint8_t*)b+n); return n;}
 size_t freeEntries(){ return (size_t)g_nvsFree; }
 bool remove(const char* key){ return g_nvs.erase(k(key)) > 0; }
 uint8_t getUChar(const char* key, uint8_t d){ auto it=g_nvs.find(k(key)); return it==g_nvs.end()||it->second.size()!=1 ? d : it->second[0]; }
 size_t putUChar(const char* key, uint8_t v){ g_nvs[k(key)]=std::vector<uint8_t>(1,v); return 1; }
 uint32_t getUInt(const char* key, uint32_t d){ auto it=g_nvs.find(k(key)); if(it==g_nvs.end()||it->second.size()!=4) return d; uint32_t v; memcpy(&v,it->second.data(),4); return v; }
 size_t putUInt(const char* key, uint32_t v){ g_nvs[k(key)]=std::vector<uint8_t>((uint8_t*)&v,(uint8_t*)&v+4); return 4; }
 bool clear(){ for(auto it=g_nvs.begin(); it!=g_nvs.end();){ if(it->first.rfind(ns,0)==0) it=g_nvs.erase(it); else ++it; } return true;} };
