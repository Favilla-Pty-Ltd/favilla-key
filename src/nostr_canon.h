// nostr_canon.h - the NIP-01 event id preimage, written the way every Nostr
// client writes it (11an, 12 Nov 2026, audit finding 1).
//
// The id is sha256 of JSON.stringify([0, pubkey, created_at, kind, tags,
// content]). Until 11an the KEY trusted the phone's pre-computed id ("pre_id")
// because ArduinoJson's serializer differs from JSON.stringify (it writes
// control characters other than \b \f \n \r \t raw). A client that lied about
// pre_id would have had any event signed while the screen showed another.
// This file writes the preimage exactly as JSON.stringify does, so the KEY
// computes the id itself from the event it displays and refuses a pre_id that
// does not match.
//
// JSON.stringify rules reproduced here (ECMA-262 QuoteJSONString):
//   "  -> \"      \  -> \\      \b \f \n \r \t -> two-character escapes
//   other code points below 0x20 -> \u00xx, lowercase hex
//   everything else raw: DEL, U+2028, U+2029, "/" and all non-ASCII
//   integers as decimal, true/false/null as words, arrays with no spaces
// What it cannot reproduce, and therefore refuses (returns 0, caller fails
// closed): floating point numbers (JS has one formatting for 1e21 and the KEY
// does not need it), objects (key order is ambiguous), nesting deeper than 8.
// A NUL inside a string (\u0000) and a lone UTF-16 surrogate cannot survive
// ArduinoJson's parse, so those events produce a different id and are refused
// too. No real client produces either.
//
// Host-tested against Node's JSON.stringify: tests/event_id_test.cpp with
// tests/event_id_vectors.mjs (thousands of random events with hostile
// strings).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ArduinoJson.h>

namespace nostrcanon {

struct Out {
  char* p; size_t cap; size_t n;
  void put(char c){ if(n < cap) p[n] = c; n++; }
  void puts(const char* s){ while(*s) put(*s++); }
};

inline void writeString(Out& o, const char* s){
  o.put('"');
  for(; *s; s++){
    unsigned char c = (unsigned char)*s;
    switch(c){
      case '"':  o.puts("\\\""); break;
      case '\\': o.puts("\\\\"); break;
      case '\b': o.puts("\\b"); break;
      case '\f': o.puts("\\f"); break;
      case '\n': o.puts("\\n"); break;
      case '\r': o.puts("\\r"); break;
      case '\t': o.puts("\\t"); break;
      default:
        if(c < 0x20){ char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o.puts(b); }
        else o.put((char)c);
    }
  }
  o.put('"');
}

inline void writeInt(Out& o, long long v){ char b[24]; snprintf(b, sizeof(b), "%lld", v); o.puts(b); }
inline void writeUInt(Out& o, unsigned long long v){ char b[24]; snprintf(b, sizeof(b), "%llu", v); o.puts(b); }

// Any value a tags array may hold. Order of the checks matters: in ArduinoJson
// is<float>() is also true for integers, so integers are tested first.
inline bool writeValue(Out& o, JsonVariantConst v, int depth){
  if(depth > 8) return false;
  if(v.isNull()){ o.puts("null"); return true; }
  if(v.is<bool>()){ o.puts(v.as<bool>() ? "true" : "false"); return true; }
  if(v.is<const char*>()){ const char* s = v.as<const char*>(); writeString(o, s ? s : ""); return true; }
  if(v.is<long long>()){ writeInt(o, v.as<long long>()); return true; }
  if(v.is<unsigned long long>()){ writeUInt(o, v.as<unsigned long long>()); return true; }
  if(v.is<JsonArrayConst>()){
    o.put('[');
    bool first = true;
    for(JsonVariantConst e : v.as<JsonArrayConst>()){
      if(!first) o.put(',');
      first = false;
      if(!writeValue(o, e, depth + 1)) return false;
    }
    o.put(']');
    return true;
  }
  return false;  // float, object, or something ArduinoJson could not type
}

// Writes [0,pubkey,created_at,kind,tags,content] into out. Returns the length
// written (without a terminator) or 0 when the event cannot be written
// faithfully or does not fit (cap must leave room for the terminator; the
// caller gets a NUL-terminated string when the result is non-zero).
// pubkeyHex is the pubkey to use (the event's own, or the KEY's when the client
// left it out); tags may be an unbound variant (treated as []).
inline size_t eventPreimage(const char* pubkeyHex, JsonVariantConst createdAt, JsonVariantConst kind,
                            JsonVariantConst tags, const char* content, char* out, size_t cap){
  if(!out || cap < 2) return 0;
  Out o{out, cap - 1, 0};
  o.puts("[0,");
  writeString(o, pubkeyHex ? pubkeyHex : "");
  o.put(',');
  // created_at and kind: integers only. A missing created_at or kind is the
  // caller's problem to fill in before calling; here a missing value is 0,
  // as the KEY's older code treated it.
  if(createdAt.isNull()) o.puts("0");
  else if(createdAt.is<long long>()) writeInt(o, createdAt.as<long long>());
  else if(createdAt.is<unsigned long long>()) writeUInt(o, createdAt.as<unsigned long long>());
  else return 0;
  o.put(',');
  if(kind.isNull()) o.puts("0");
  else if(kind.is<long long>()) writeInt(o, kind.as<long long>());
  else return 0;
  o.put(',');
  if(tags.isNull()) o.puts("[]");
  else if(tags.is<JsonArrayConst>()){ if(!writeValue(o, tags, 1)) return 0; }
  else return 0;
  o.put(',');
  writeString(o, content ? content : "");
  o.put(']');
  if(o.n > o.cap) return 0;   // did not fit
  out[o.n] = 0;
  return o.n;
}

// Any JSON value, objects included (keys in the order the document holds
// them), with the same string escaping. For the signed event the KEY hands
// back: ArduinoJson's serializer writes control characters raw, which is not
// JSON, and the phone's parse of the reply then fails (seen on the bench,
// 12 Nov 2026, content with \u0001). Floats are refused here too.
inline bool writeJson(Out& o, JsonVariantConst v, int depth){
  if(depth > 16) return false;
  if(v.is<JsonObjectConst>()){
    o.put('{');
    bool first = true;
    for(JsonPairConst kv : v.as<JsonObjectConst>()){
      if(!first) o.put(',');
      first = false;
      writeString(o, kv.key().c_str());
      o.put(':');
      if(!writeJson(o, kv.value(), depth + 1)) return false;
    }
    o.put('}');
    return true;
  }
  if(v.is<JsonArrayConst>()){
    o.put('[');
    bool first = true;
    for(JsonVariantConst e : v.as<JsonArrayConst>()){
      if(!first) o.put(',');
      first = false;
      if(!writeJson(o, e, depth + 1)) return false;
    }
    o.put(']');
    return true;
  }
  return writeValue(o, v, depth);
}
// Serialises v into out; returns the length or 0 (unwritable, or did not fit).
inline size_t serialize(JsonVariantConst v, char* out, size_t cap){
  if(!out || cap < 2) return 0;
  Out o{out, cap - 1, 0};
  if(!writeJson(o, v, 0) || o.n > o.cap) return 0;
  out[o.n] = 0;
  return o.n;
}

}  // namespace nostrcanon
