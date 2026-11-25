// event_id_vectors.mjs - reference vectors for the KEY's NIP-01 event id
// (src/nostr_canon.h, 11an, audit finding 1). Node is the reference: every
// Nostr client computes the id as sha256(JSON.stringify([0, pubkey,
// created_at, kind, tags, content])), nostr-tools included, so this file
// needs no library. One JSON line per vector: {"event": <the event as the
// phone would POST it>, "id": <hex>}. Negative vectors (the KEY must refuse)
// carry "refuse": true instead of an id.
//
//   node tests/event_id_vectors.mjs [count] > /tmp/ev.jsonl
import { createHash } from 'node:crypto';

const N = parseInt(process.argv[2] || '3000', 10);
let seed = 0x9e3779b9;
function rnd(){ seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed / 4294967296; }
function ri(n){ return Math.floor(rnd() * n); }
function pick(a){ return a[ri(a.length)]; }

// Hostile pieces: every escape JSON.stringify knows, every one it does not,
// raw control characters, quotes, backslashes, solidus, DEL, U+2028/9, BOM,
// combining marks, emoji (surrogate pairs), CJK, RTL, long runs.
const pieces = ['"', '\\', '\b', '\f', '\n', '\r', '\t', '/', '\u0001', '\u001f', '\u007f', ' ', ' ', '﻿',
  'plain text', 'nostr:npub1abc', 'é', '🔥', '👩‍👩‍👧‍👧', '漢字', 'مرحبا', 'é', ' ', '  ', '\\n', '\\u0041', '{', '}', '[', ']', ',', ':',
  '<script>', '&amp;', 'ä'.repeat(40), 'x'.repeat(300)];
function str(maxPieces){ let s = ''; const n = ri(maxPieces + 1); for(let i = 0; i < n; i++) s += pick(pieces); return s; }
function hex(n){ let s = ''; for(let i = 0; i < n; i++) s += '0123456789abcdef'[ri(16)]; return s; }

function tags(){
  const t = []; const n = ri(6);
  for(let i = 0; i < n; i++){
    const r = rnd();
    if(r < 0.5) t.push([pick(['e', 'p', 't', 'r', 'd', 'a']), hex(64)]);
    else if(r < 0.8) t.push([pick(['e', 'p', 'alt', 'client']), hex(64), str(2), pick(['root', 'reply', 'mention', ''])]);
    else if(r < 0.9) t.push([]);
    else if(r < 0.95) t.push([str(1), [str(1), 7, true, null]]);   // nested array with non-strings: JSON.stringify handles them, so must the KEY
    else t.push([str(3)]);
  }
  return t;
}

function event(){
  const e = { pubkey: hex(64), created_at: pick([0, 1, 1700000000 + ri(100000000), 2147483647, 4294967295, 9007199254740991]),
              kind: pick([0, 1, 3, 4, 6, 7, 1059, 13, 14, 9734, 10002, 30023, 65535, 2147483647]), tags: tags(), content: str(8) };
  if(rnd() < 0.1) delete e.tags;          // the KEY fills in [] before hashing
  if(rnd() < 0.05) e.content = '';
  return e;
}

function idOf(e){
  const pre = JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags ?? [], e.content]);
  return createHash('sha256').update(pre, 'utf8').digest('hex');
}

const out = [];
// fixed vectors first: the NIP-01 shape everyone knows, then each hostile piece on its own
out.push({ event: { pubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', created_at: 1700000000, kind: 1, tags: [], content: 'hello' } });
for(const p of pieces) out.push({ event: { pubkey: hex(64), created_at: 1700000000, kind: 1, tags: [['t', p]], content: p } });
for(let i = 0; i < N; i++) out.push({ event: event() });
for(const v of out){ v.id = idOf(v.event); v.event_json = JSON.stringify({ ...v.event, tags: v.event.tags ?? [] }); }  // what the KEY's reply writer must produce for the event as staged

// the KEY must refuse these: JSON.stringify's output for them is either
// ambiguous or not something ArduinoJson can carry faithfully
const refuse = [
  { pubkey: hex(64), created_at: 1700000000.5, kind: 1, tags: [], content: 'float created_at' },
  { pubkey: hex(64), created_at: 1700000000, kind: 1.5, tags: [], content: 'float kind' },
  { pubkey: hex(64), created_at: 1700000000, kind: 1, tags: [['t', 1.25]], content: 'float in tags' },
  { pubkey: hex(64), created_at: 1700000000, kind: 1, tags: [{ a: 1 }], content: 'object in tags' },
  { pubkey: hex(64), created_at: 1700000000, kind: 1, tags: [[[[[[[[[['deep']]]]]]]]]], content: 'too deep' },
];
for(const e of refuse) out.push({ event: e, refuse: true });

for(const v of out) process.stdout.write(JSON.stringify(v) + '\n');
