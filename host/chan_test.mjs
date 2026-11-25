// chan_test.mjs - the extension's chan.js against the KEY's chan_key.h (chan_sim).
// node chan_test.mjs
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const F = require('../../ext/favilla-login/chan.js');

let pass = 0, fail = 0;
const ok = (c, name) => { if (c) pass++; else { fail++; console.log('FAIL', name); } };

const sim = spawn('./chan_sim', [], { stdio: ['pipe', 'pipe', 'inherit'] });
let buf = '', waiters = [], lines = [];
sim.stdout.on('data', d => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); lines.push(l); flush(); } });
function flush() { while (waiters.length && lines.length) waiters.shift()(lines.shift()); }
const next = (ms = 3000) => new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('timeout')), ms); waiters.push(l => { clearTimeout(t); res(l); }); flush(); });
const cmd = s => sim.stdin.write(s + '\n');
const sendMsg = m => { for (const r of F.frag(m)) cmd('R ' + F.hex(r)); };
async function recvMsg() { const ra = new F.Reasm(); for (;;) { const l = await next(); if (!l.startsWith('R ')) throw new Error('expected report, got ' + l); const m = ra.feed(F.unhex(l.slice(2))); if (m) return m; } }

async function pair(accept = true, opts = {}) {
  const kp = await F.genKeyPair(); const nonce = crypto.getRandomValues(new Uint8Array(16));
  sendMsg(F.cat(new Uint8Array([F.C.PAIR_COMMIT]), await F.commitment(kp.pub, nonce)));
  const m = await recvMsg();
  if (m[0] !== F.C.R_PAIR_KEY) return { err: m };
  const keyPub = m.subarray(1, 66), id = m.slice(66, 74);
  if (opts.badReveal) { const n2 = new Uint8Array(16); sendMsg(F.cat(new Uint8Array([F.C.PAIR_REVEAL]), kp.pub, n2)); return { revealErr: await recvMsg() }; }
  sendMsg(F.cat(new Uint8Array([F.C.PAIR_REVEAL]), kp.pub, nonce));
  const d = await F.derive(kp.priv, kp.pub, keyPub);
  const show = await next();
  ok(show === 'SHOW ' + d.code, 'code matches on both ends (' + show + ' vs ' + d.code + ')');
  if (opts.intruder) {   // a second commit in the same window, while the code is on screen
    const kp2 = await F.genKeyPair(); sendMsg(F.cat(new Uint8Array([F.C.PAIR_COMMIT]), await F.commitment(kp2.pub, nonce)));
    const e = await recvMsg(); ok(e[0] === 0xBF && e[2] === 6, 'a second pairing in the same window is refused');
    cmd('X');   // a decision for some other attempt: ignored
  }
  cmd('D ' + (accept ? 1 : 0));
  const done = await recvMsg(); const o = await F.openRsp(done, d.k);
  ok(o && o.type === F.C.R_PAIR_DONE, 'pair done mac checks');
  return { id, k: d.k, status: o ? o.body[0] : -1 };
}
async function req(c, cmdb, ctr, body) { sendMsg(await F.buildReq(cmdb, c.id, ctr, body, c.k)); return recvMsg(); }

(async () => {
  // 1 window closed
  cmd('W 0');
  { sendMsg(F.cat(new Uint8Array([0x20]), new Uint8Array(32))); const m = await recvMsg(); ok(m[0] === 0xBF && m[2] === 10, 'pairing refused while the window is closed'); }
  cmd('W 1');
  // 2 pair
  const c = await pair(true, { intruder: true }); ok(c.status === 0, 'paired (the intruder did not replace it)');
  // 3 hello
  { const m = await req(c, 0x30, 1); const o = await F.openRsp(m, c.k); ok(o && o.type === 0xB0 && o.body[0] === 0 && o.body[1] === 2, 'hello: ok, PASSKEY ready');
    ok(o && new TextDecoder().decode(o.body.subarray(2)).replace(/\0.*/, '') === 'sim', 'hello carries the drop'); }
  // 4 sign in
  { sendMsg(await F.buildReq(0x31, c.id, 2, F.loginBody('github.com', 'josh@favillakey.io'), c.k));
    const r = await next(); ok(r === 'REQ 31 github.com|josh@favillakey.io', 'sign-in reaches the KEY with site and user');
    const ack = await F.openRsp(await recvMsg(), c.k); ok(ack && ack.type === 0xB1 && ack.body[0] === 0, 'ack: shown');
    cmd('F 1'); const ev = await F.openRsp(await recvMsg(), c.k); ok(ev && ev.type === 0xB2 && ev.body[0] === 1 && ev.ctr === 2, 'event: typed, for that request'); }
  // 5 replay
  { const m = await req(c, 0x30, 2); const o = await F.openRsp(m, c.k); ok(o && o.type === 0xBF && o.body[0] === 9 && o.body.length === 5, 'replayed counter refused, with the floor'); }
  // 6 bad mac
  { const m = await F.buildReq(0x30, c.id, 3, null, c.k); m[m.length - 1] ^= 1; sendMsg(m); const r = await recvMsg(); ok(r[0] === 0xBF && r[2] === 8, 'bad mac refused'); }
  { const other = new Uint8Array(32).fill(7); const m = await F.buildReq(0x30, c.id, 4, null, other); sendMsg(m); const r = await recvMsg(); ok(r[0] === 0xBF && r[2] === 8, 'wrong key refused'); }
  // 7 life
  cmd('L 1'); { const o = await F.openRsp(await req(c, 0x31, 5, F.loginBody('a.io', '')), c.k); ok(o && o.body[0] === 5, 'locked'); }
  cmd('L 3'); { const o = await F.openRsp(await req(c, 0x31, 6, F.loginBody('a.io', '')), c.k); ok(o && o.body[0] === 4, 'not here in NOSTR'); }
  cmd('L 2');
  // 8 busy
  { sendMsg(await F.buildReq(0x32, c.id, 7, F.loginBody('x.com', 'me'), c.k)); const r = await next(); ok(r === 'REQ 32 x.com|me', 'new login reaches the KEY');
    const a1 = await F.openRsp(await recvMsg(), c.k); ok(a1 && a1.body[0] === 0, 'new login shown');
    const a2 = await F.openRsp(await req(c, 0x31, 8, F.loginBody('y.com', '')), c.k); ok(a2 && a2.body[0] === 6, 'second request while busy: busy');
    cmd('F 13'); const ev = await F.openRsp(await recvMsg(), c.k); ok(ev && ev.body[0] === 13 && ev.ctr === 7, 'new login event: saved'); }
  // 8b automatic ask: reaches the KEY like a sign-in, the event says what happened
  { sendMsg(await F.buildReq(0x33, c.id, 8000, F.loginBody('github.com', ''), c.k)); const r = await next(); ok(r === 'REQ 33 github.com|', 'automatic ask reaches the KEY');
    const a = await F.openRsp(await recvMsg(), c.k); ok(a && a.type === 0xB1 && a.body[0] === 0, 'automatic ask taken');
    cmd('F 3'); const ev = await F.openRsp(await recvMsg(), c.k); ok(ev && ev.body[0] === 3 && ev.ctr === 8000, 'automatic ask: no saved login, as an event'); }
  // 8c 7g: a sign-in replaces a sign-in still on the KEY; the old one is told "nothing typed"
  { sendMsg(await F.buildReq(0x31, c.id, 8001, F.loginBody('github.com', ''), c.k)); await next(); const a1 = await F.openRsp(await recvMsg(), c.k); ok(a1 && a1.body[0] === 0, 'sign-in on screen');
    sendMsg(await F.buildReq(0x33, c.id, 8002, F.loginBody('cloudflare.com', ''), c.k));
    const old = await F.openRsp(await recvMsg(), c.k); ok(old && old.type === 0xB2 && old.ctr === 8001 && old.body[0] === 2, 'the replaced sign-in: nothing typed, as an event');
    const r = await next(); ok(r === 'REQ 33 cloudflare.com|', 'the newer ask reaches the KEY');
    const a2 = await F.openRsp(await recvMsg(), c.k); ok(a2 && a2.ctr === 8002 && a2.body[0] === 0, 'the newer ask taken');
    sendMsg(await F.buildReq(0x32, c.id, 8003, F.loginBody('z.com', ''), c.k));
    const old2 = await F.openRsp(await recvMsg(), c.k); ok(old2 && old2.ctr === 8002 && old2.body[0] === 2, 'a new login from the popup replaces the sign-in');
    ok(await next() === 'REQ 32 z.com|', 'new login reaches the KEY'); const a3 = await F.openRsp(await recvMsg(), c.k); ok(a3 && a3.ctr === 8003 && a3.body[0] === 0, 'new login taken');
    const a4 = await F.openRsp(await req(c, 0x31, 8004, F.loginBody('github.com', '')), c.k); ok(a4 && a4.body[0] === 6, 'a sign-in never replaces a new login: busy');
    cmd('F 13'); const ev = await F.openRsp(await recvMsg(), c.k); ok(ev && ev.ctr === 8003 && ev.body[0] === 13, 'the new login finishes as usual');
  }
  // 9 bodies
  { const bad = F.cat(new Uint8Array([3]), new TextEncoder().encode('a\nb'), new Uint8Array([0]));
    const o = await F.openRsp(await req(c, 0x31, 8009, bad), c.k); ok(o && o.body[0] === 7, 'control character refused');
    const sp = F.cat(new Uint8Array([2]), new TextEncoder().encode('  '), new Uint8Array([0]));
    const o2 = await F.openRsp(await req(c, 0x31, 8010, sp), c.k); ok(o2 && o2.body[0] === 7, 'spaces-only site refused');
    const tr = F.cat(F.loginBody('a.io', 'u'), new Uint8Array([1]));
    const o3 = await F.openRsp(await req(c, 0x31, 8011, tr), c.k); ok(o3 && o3.body[0] === 7, 'trailing byte refused');
    const big = F.cat(new Uint8Array([101]), new Uint8Array(101).fill(97), new Uint8Array([0]));
    const o4 = await F.openRsp(await req(c, 0x31, 8012, big), c.k); ok(o4 && o4.body[0] === 7, 'site over 100 refused');
    sendMsg(await F.buildReq(0x31, c.id, 8013, F.loginBody('s'.repeat(100), 'u'.repeat(100)), c.k)); const r = await next();
    ok(r === 'REQ 31 ' + 's'.repeat(100) + '|' + 'u'.repeat(100), '100 + 100 over several reports');
    await recvMsg(); cmd('F 2'); const ev = await F.openRsp(await recvMsg(), c.k); ok(ev && ev.body[0] === 2, 'cancelled event'); }
  // 10 refused pairing
  cmd('W 1'); { const r = await pair(false); ok(r.status === 11, 'refused on the KEY');
    const m = await req(r, 0x30, 1); ok(m[0] === 0xBF && m[2] === 8, 'a refused browser is not paired'); }
  // 12 bad reveal (nonce does not match the commitment), and a point off the curve
  cmd('W 1'); { const r = await pair(true, { badReveal: true }); ok(r.revealErr && r.revealErr[0] === 0xBF && r.revealErr[2] === 7, 'a reveal that does not match the commitment is refused'); }
  cmd('W 1'); { const nonce = new Uint8Array(16), p = new Uint8Array(65); p[0] = 4;
    const kp = await F.genKeyPair(); sendMsg(F.cat(new Uint8Array([0x20]), await F.commitment(p, nonce))); await recvMsg();
    sendMsg(F.cat(new Uint8Array([0x22]), p, nonce)); const m = await recvMsg(); ok(m[0] === 0xBF && m[2] === 7, 'point not on the curve refused'); }
  // 13 a restart: the stored ceiling becomes the floor; the browser learns it from the replay answer
  cmd('B'); { const m = await req(c, 0x30, 8014); const o = await F.openRsp(m, c.k);
    const floor = o && o.body.length === 5 ? (o.body[1] | (o.body[2] << 8) | (o.body[3] << 16) | (o.body[4] << 24)) >>> 0 : -1;
    ok(o && o.body[0] === 9 && floor >= 8013, 'after a restart old counters are refused (floor ' + floor + ')');
    const o2 = await F.openRsp(await req(c, 0x30, floor + 1), c.k); ok(o2 && o2.type === 0xB0, 'resynced above the floor'); }
  // 11 full
  { for (let i = 0; i < 3; i++) { cmd('W 1'); await pair(true); }
    cmd('W 1'); sendMsg(F.cat(new Uint8Array([0x20]), new Uint8Array(32))); const m = await recvMsg(); ok(m[0] === 0xBF && m[2] === 12, 'fifth browser: full'); }
  cmd('Q'); console.log((await next()));
  console.log(`chan: ${pass} passed, ${fail} failed`);
  sim.stdin.end(); process.exit(fail ? 1 : 0);
})().catch(e => { console.log('ERROR', e.message); process.exit(1); });
