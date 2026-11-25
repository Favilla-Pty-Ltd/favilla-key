// ════════════════════════════════════════════════════════════════════════
// PASSWORDS — 3 Nov 2026 (Vault spec 7f, phase 4: the PWA in NOSTR mode)
//   The KEY holds password entries sealed by its G0. This page lists their
//   site and username (the KEY's LABEL op: never a password), adds, edits and
//   deletes them (each confirmed on the KEY with a held ENTER), finishes the
//   KEY's "New entry N" generator entries, and imports exports from other
//   password managers through the KEY's import window (a PIN on the KEY).
//   KEY endpoints: /api/vault/pw, /pw/save, /pw/delete, /pw/result,
//   /import/begin, /import/end (vault_api.inc).
// ════════════════════════════════════════════════════════════════════════
(function () {
  'use strict';
  const enc = new TextEncoder();
  const B = s => enc.encode(String(s || '')).length;          // the KEY counts bytes (UTF-8)
  const LIM = { site: 199, field: 128, all: 415 };              // all = 431 sealed bytes less the 16 of lengths and dates
  const GATE_TEXT = 'Passkeys and the vault are not allowed in NOSTR mode on this KEY. Add this entry on the KEY in PASSKEY mode.';
  const ERR = {
    gate: GATE_TEXT,
    locked: 'Unlock your KEY first.',
    'Device locked': 'Unlock your KEY first.',
    unsupported: 'This KEY cannot hold passwords yet: it needs the passkey firmware with the v15 signer.',
    busy: 'The KEY is already asking about another entry. Answer it on the KEY first.',
    declined: 'Cancelled on the KEY. Nothing was changed.',
    timeout: 'No answer on the KEY in time. Nothing was changed.',
    gone: 'That entry changed on the KEY meanwhile. The list has been read again.',
    size: 'Too long for the KEY: a site up to 199 bytes; username, password and note up to 128 each, 415 in all.',
    nopass: 'A new entry needs a password.',
    full: 'The KEY is full: 200 records, passkeys and passwords together.',
    budget: 'The KEY has used the record opens for this sitting. Lock and unlock the KEY, then try again.',
    uv: 'Lock the KEY, then unlock it with its PIN on the KEY itself, and try again. An unlock from the phone does not count.',
    used: 'The import window was already used since the KEY was switched on. Switch the KEY off and on to import again.',
    pin: 'Too many wrong PINs. Lock and unlock the KEY, then try again.',
    refused: 'The KEY’s signer refused the import window. Try again; if it happens again, switch the KEY off and on.',
    window: 'The import window is closed on the KEY.',
    Unauthorized: 'The KEY did not accept this phone’s session. Pair again.',
  };
  const errText = e => ERR[e] || ('The KEY could not do it (' + (e || 'no reply') + ').');

  // ── import parsers (pure: also run by the host test, tools/pw_import_test) ──
  function parseCsv(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    // RFC 4180, as the managers write it; a quote opens a quoted field only as
    // its first character (a bare quote inside a field is a character).
    const rows = []; let row = [], f = '', q = false, fresh = true, i = 0;
    for (; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; }
        else f += c;
      } else if (c === '"' && fresh) { q = true; fresh = false; }
      else if (c === ',') { row.push(f); f = ''; fresh = true; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(f); f = ''; fresh = true;
        if (row.length > 1 || row[0] !== '') rows.push(row);
        row = [];
      } else { f += c; fresh = false; }
    }
    if (f !== '' || row.length) { row.push(f); if (row.length > 1 || row[0] !== '') rows.push(row); }
    return rows;
  }
  // Header names as the managers write them, lower case. First match wins.
  const COLS = {
    url:  ['url', 'login_uri', 'web site', 'website', 'login url', 'uri', 'urls'],
    name: ['name', 'title', 'account', 'item name'],
    user: ['username', 'login_username', 'login name', 'user name', 'email', 'login'],
    pass: ['password', 'login_password'],
    note: ['note', 'notes', 'comments', 'extra'],
  };
  function normSite(url, name) {
    const u = String(url || '').trim().split(/[\s,]+/)[0] || '';
    if (u) {
      try {
        const x = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : 'https://' + u);
        if ((x.protocol === 'http:' || x.protocol === 'https:') && x.hostname) return x.hostname.replace(/^www\./i, '').toLowerCase();
      } catch (e) {}
    }
    const n = String(name || '').trim();
    return n || u;
  }
  // Fit one entry to the KEY. Returns {site,user,pass,note,why} — why is set when it cannot go in.
  function fitEntry(site, user, pass, note) {
    const e = { site: String(site || '').trim(), user: String(user || ''), pass: String(pass || ''), note: String(note || '').replace(/\r\n?/g, '\n'), why: '' };
    if (!e.pass) e.why = 'no password';
    else if (!e.site) e.why = 'no site';
    else if (B(e.site) > LIM.site) e.why = 'site too long';
    else if (B(e.user) > LIM.field) e.why = 'username too long';
    else if (B(e.pass) > LIM.field) e.why = 'password too long';
    if (e.why) return e;
    // A long note is cut (on a character), the rest never is.
    const room = Math.min(LIM.field, LIM.all - B(e.site) - B(e.user) - B(e.pass));
    if (B(e.note) > room) { let n = e.note; while (n && B(n) > Math.max(room - 3, 0)) n = Array.from(n).slice(0, -1).join(''); e.note = room >= 3 ? n + '...' : ''; e.cut = true; }
    return e;
  }
  function fromRows(rows) {
    if (!rows.length) return { kind: 'empty', items: [] };
    const h = rows[0].map(x => String(x).trim().toLowerCase());
    const col = k => { for (const n of COLS[k]) { const i = h.indexOf(n); if (i >= 0) return i; } return -1; };
    const ci = { url: col('url'), name: col('name'), user: col('user'), pass: col('pass'), note: col('note') };
    const em = h.indexOf('email');   // a file with both: the username signs in, the email goes in the note
    if (ci.pass < 0) return { kind: 'unknown', items: [] };
    const kind = h.includes('login_uri') ? 'Bitwarden CSV' : h.includes('httprealm') ? 'Firefox' : h.includes('otpauth') && h.includes('title') ? (h.includes('archived') ? '1Password' : 'Safari')
               : h.includes('group') && h.includes('title') ? 'KeePassXC' : h.includes('login name') ? 'KeePass' : h.includes('name') && h.includes('url') ? 'Chrome or Edge' : 'CSV';
    const typeCol = h.indexOf('type');
    const items = [];
    for (let r = 1; r < rows.length; r++) {
      const row = rows[r], g = i => (i >= 0 && i < row.length ? row[i] : '');
      if (typeCol >= 0 && kind === 'Bitwarden CSV' && g(typeCol) && g(typeCol) !== 'login') continue;   // cards, notes, identities
      let note = g(ci.note), user = g(ci.user);
      if (em >= 0 && em !== ci.user && g(em) && g(em) !== user) {
        if (!user) user = g(em);                                   // no username on this row: the email is what signs in
        else note = 'Email: ' + g(em) + (note ? '\n' + note : '');
      }
      items.push(fitEntry(normSite(g(ci.url), g(ci.name)), user, g(ci.pass), note));
    }
    return { kind, items };
  }
  function fromBitwardenJson(j) {
    if (j && j.encrypted) return { kind: 'Bitwarden (encrypted)', items: [], err: 'This Bitwarden export is encrypted. Export again as JSON (not encrypted), or as CSV.' };
    const items = [];
    for (const it of (j && j.items) || []) {
      if (it.type !== 1 || !it.login) continue;   // 1 = login
      const uri = ((it.login.uris || [])[0] || {}).uri || '';
      items.push(fitEntry(normSite(uri, it.name), it.login.username, it.login.password, it.notes));
    }
    return { kind: 'Bitwarden', items };
  }
  function parseExport(text) {
    const t = String(text || '').replace(/^﻿/, '');
    if (/^\s*[{[]/.test(t)) { try { return fromBitwardenJson(JSON.parse(t)); } catch (e) { return { kind: 'unknown', items: [], err: 'This JSON file could not be read.' }; } }
    return fromRows(parseCsv(t));
  }
  const untypable = s => Array.from(new Set(Array.from(String(s || '')).filter(c => { const k = c.charCodeAt(0); return c.length > 1 || k > 0x7E || (k < 0x20 && c !== '\t' && c !== '\n'); })));
  window.PWIMPORT = { parseCsv, parseExport, normSite, fitEntry, untypable, B };
  if (typeof document === 'undefined' || !document.getElementById) return;   // host test stops here

  // ── page ──────────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const esc = s => (typeof escHtml === 'function' ? escHtml(s) : String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]));
  let open = false, entries = [], listTimer = null, editing = null, busy = false, picks = null, pickKind = '';
  let selMode = false; const selected = new Set();   // 4 Nov 2026: "slot:id" of the ticked entries
  const st = (msg, bad) => { const el = $('pw-status'); if (el) { el.textContent = msg || ''; el.style.color = bad ? 'var(--danger)' : 'var(--muted)'; } };
  // The outcome of the last change: its own line, so a list refresh does not overwrite it.
  const say = (msg, bad) => { const el = $('pw-note'); if (!el) return; el.hidden = !msg; el.textContent = msg || ''; el.style.color = bad ? 'var(--danger)' : 'var(--text)'; };
  const waitBox = msg => { const el = $('pw-wait'); if (!el) return; el.hidden = !msg; el.textContent = msg || ''; };
  const show = (id, on) => { const el = $(id); if (el) el.hidden = !on; };
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function showGate(on) {
    const g = $('pw-gate'); if (g) { g.hidden = !on; g.textContent = on ? GATE_TEXT : ''; }
    ['pw-pending-blk', 'pw-list-blk', 'pw-add-blk', 'pw-import-blk'].forEach(id => { if (on) show(id, false); });
  }

  async function load(quiet) {
    if (!open) return;
    if (!quiet) st('Reading from the KEY…');
    // 3 Nov 2026 (bench, 194 entries): the list comes in pages of 40 (one reply of
    // the whole list was ~19 KB and timed out on a busy KEY). Each page is shown as
    // it lands; a change on the KEY between pages (the total moves) starts over once.
    const page = from => deviceApi('/vault/pw/page', { method: 'POST', body: JSON.stringify({ from }) }).catch(() => null);
    let r = await page(0), got = [], restarts = 0;
    while (true) {
      if (!open) return;
      if (!r || r.error) break;
      got = got.concat(r.entries || []);
      if (r.next === null || r.next === undefined) break;
      if (!quiet) st('Reading from the KEY… ' + got.length + ' of ' + (r.total || 0));
      const total = r.total, nx = await page(r.next);
      if (nx && !nx.error && nx.total !== total && restarts++ < 1) { got = []; r = await page(0); continue; }
      r = nx;
    }
    if (!open) return;
    clearTimeout(listTimer); listTimer = null;
    if (!r) { st('Could not reach the KEY. Pair it and unlock it first.', true); return; }
    if (r.error) { showGate(r.error === 'gate'); if (r.error !== 'gate') st(errText(r.error), true); else st(''); return; }
    showGate(false);
    // Keep usernames already read on demand: the list never sends them (they come per entry, on Edit).
    const known = {}; for (const e of entries) if (e.user !== null && e.user !== undefined && e.site !== null) known[e.slot + ':' + e.id] = e;
    entries = got.map(e => { const k = known[e.slot + ':' + e.id]; return (e.user === null && k) ? Object.assign(e, { user: k.user, site: k.site, cut: false }) : e; });
    ['pw-list-blk', 'pw-add-blk', 'pw-import-blk'].forEach(id => show(id, true));
    // P4-10: names come from the KEY's sealed index at once (site is null for one it is
    // still reading); a username is read from the KEY when it is needed (Edit, a new entry).
    const more = (r.total || 0) - (r.listed || 0);
    st((r.total === 1 ? '1 password' : (r.total || 0) + ' passwords') + ' on the KEY · ' + (r.records || 0) + ' of ' + (r.max || 200) + ' records used'
       + (more > 0 ? ' · reading ' + more + ' more…' : ''));
    render();
    if (more > 0) listTimer = setTimeout(() => load(true), 1500);
    fetchPendingUsers();
  }
  // One entry's username (and full name) from the KEY: one read on the KEY, about half a second.
  async function fetchUser(e) {
    let r; try { r = await deviceApi('/vault/pw/user', { method: 'POST', body: JSON.stringify({ slot: e.slot, id: e.id }) }); } catch (x) { r = null; }
    if (!r || r.error || typeof r.user !== 'string') return false;
    e.user = r.user; e.site = r.site; e.cut = false; return true;
  }
  let fetchingPending = false;
  async function fetchPendingUsers() {   // a New entry card needs its username to be saved; there are only ever a few
    if (fetchingPending || busy) return;
    fetchingPending = true;
    try { for (const e of entries.filter(x => x.pending && x.user === null)) { if (!open) break; if (await fetchUser(e)) render(); } }
    finally { fetchingPending = false; }
  }

  function render() {
    const pend = entries.filter(e => e.pending), rest = entries.filter(e => !e.pending);
    show('pw-pending-blk', pend.length > 0);
    const pe = $('pw-pending');
    if (pe) pe.innerHTML = pend.map(e => `
      <div data-pw-row="${e.slot}" style="padding:12px;border:1px solid var(--border2);border-radius:12px;display:flex;flex-direction:column;gap:8px;">
        <div><div class="pw-name">${esc(e.site)}</div><div class="pw-sub">${e.user === null ? 'Reading the username from the KEY…' : 'Made on the KEY' + (e.user ? ' for ' + esc(e.user) : '')}</div></div>
        <input data-pw-psite="${e.slot}" placeholder="Site, e.g. github.com" style="font-family:var(--mono);font-size:11px;" autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false">
        <input data-pw-puser="${e.slot}" placeholder="Username or email" value="${esc(e.user || '')}" ${e.user === null ? 'disabled' : ''} style="font-family:var(--mono);font-size:11px;" autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false">
        <div style="display:flex;gap:8px;">${e.user === null ? '' : `<button class="btn-sm-accent" data-pw="pend-save" data-arg="${e.slot}">Save on KEY</button>`}<button class="btn-sm" data-pw="del" data-arg="${e.slot}">Delete</button></div>
      </div>`).join('');
    const f = (($('pw-filter') || {}).value || '').trim().toLowerCase();
    const shown = f ? rest.filter(e => ((e.site || '') + ' ' + (e.user || '')).toLowerCase().includes(f)) : rest;
    const le = $('pw-list');
    if (!le) return;
    for (const k of Array.from(selected)) if (!rest.some(e => e.slot + ':' + e.id === k)) selected.delete(k);   // gone from the KEY: untick
    renderSelBar(shown);
    if (!rest.length) { le.innerHTML = '<div class="pw-meta" style="padding:4px 0;">No saved passwords yet.</div>'; return; }
    le.innerHTML = shown.map(e => `
      <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid var(--border2);border-radius:12px;">
        ${selMode ? `<input type="checkbox" data-pw-sel="${e.slot}:${e.id}" ${selected.has(e.slot + ':' + e.id) ? 'checked' : ''} style="width:16px;height:16px;flex-shrink:0;">` : ''}
        <div style="flex:1;min-width:0;">
          <div class="pw-name">${e.site === null ? 'Reading the name…' : esc(e.site) + (e.cut ? '…' : '')}</div>
          <div class="pw-sub">${e.user === null ? (e.site === null ? 'One moment' : 'Edit to see the username') : e.user ? esc(e.user) : 'no username'}</div>
        </div>
        ${selMode ? '' : (e.site === null ? '' : `<button class="btn-sm" data-pw="edit" data-arg="${e.slot}">Edit</button>`) + `<button class="btn-sm" data-pw="del" data-arg="${e.slot}">Delete</button>`}
      </div>`).join('') || '<div class="pw-meta" style="padding:4px 0;">Nothing matches.</div>';
  }
  function renderSelBar(shown) {
    show('pw-sel-bar', selMode);
    const b = $('pw-sel-btn'); if (b) b.textContent = selMode ? 'Done' : 'Select';
    if (!selMode) return;
    const n = selected.size;
    const c = $('pw-sel-count'); if (c) c.textContent = n ? (n === 1 ? '1 ticked' : n + ' ticked') : 'Tick the entries to delete. All ticks every entry the search shows.';
    const d = $('pw-sel-del'); if (d) { d.textContent = n ? 'Delete ' + n : 'Delete'; d.disabled = !n; }
  }
  // 4 Nov 2026: every ticked entry in one question on the KEY (a 2 s hold there).
  async function delMany() {
    if (busy || !selected.size) return;
    const items = Array.from(selected).slice(0, 200);
    const n = items.length;
    busy = true;
    let r;
    try { r = await job('/vault/pw/delete-many', { items }, 'Check your KEY: hold ENTER there for 2 seconds to delete ' + (n === 1 ? '1 entry' : n + ' entries') + ', or BACK to keep them.'); } catch (x) { r = { ok: false, error: 'no reply' }; } finally { busy = false; }
    if (r.ok) {
      const d = typeof r.deleted === 'number' ? r.deleted : n;
      say('Deleted from the KEY: ' + (d === 1 ? '1 entry' : d + ' entries') + (d < n ? ' (' + (n - d) + ' had changed on the KEY and were kept)' : '') + '.');
      selected.clear(); selMode = false;
    } else say(errText(r.error), true);
    if (editing && items.some(k => k.startsWith(editing.slot + ':'))) formReset();
    load(true);
  }

  // POST a job, then follow it on the KEY until it is answered.
  async function job(path, body, waitMsg) {
    let r;
    try { r = await deviceApi(path, { method: 'POST', body: JSON.stringify(body) }); } catch (e) { r = null; }
    if (!r) return { ok: false, error: 'no reply' };
    if (r.error) return { ok: false, error: r.error };
    const seq = r.seq;
    if (r.state === 'done' && r.seq === seq) return r;
    if (waitMsg) waitBox(waitMsg);
    const t0 = Date.now();
    try {
      while (Date.now() - t0 < 120000) {
        await sleep(r.state === 'working' ? 300 : 700);
        try { r = await deviceApi('/vault/pw/result', { method: 'GET' }); } catch (e) { r = null; }
        if (r && r.seq === seq && r.state === 'done') return r;
        if (r && r.seq !== seq) return { ok: false, error: 'busy' };
      }
      return { ok: false, error: 'timeout' };
    } finally { if (waitMsg) waitBox(''); }
  }

  function formReset() {
    editing = null;
    ['pw-f-site', 'pw-f-user', 'pw-f-pass', 'pw-f-note'].forEach(id => { const el = $(id); if (el) el.value = ''; });
    const p = $('pw-f-pass'); if (p) { p.type = 'password'; p.placeholder = 'Password'; }
    const s = $('pw-f-show'); if (s) s.textContent = 'Show';
    const n = $('pw-f-note'); if (n) n.placeholder = 'Note, e.g. the email if the site also has one';
    const t = $('pw-form-title'); if (t) t.textContent = 'Add an entry';
    const h = $('pw-form-help'); if (h) h.textContent = 'Username or email: whichever the site asks for when you sign in. The KEY types it, then Tab, then the password. If the site has both, put the other one in the note.';
    show('pw-f-cancel', false); warn('');
  }
  const warn = m => { const el = $('pw-f-warn'); if (el) el.textContent = m || ''; };
  function formCheck(site, user, pass, note, isEdit) {
    if (!site.trim()) return 'Add the site.';
    if (!isEdit && !pass) return 'Add the password.';
    if (B(site) > LIM.site) return 'The site is too long for the KEY (199 bytes at most).';
    if (B(user) > LIM.field || B(pass) > LIM.field || B(note) > LIM.field) return 'Username, password and note: 128 bytes each at most.';
    if (B(site) + B(user) + B(pass) + B(note) > LIM.all) return 'Too long in all for one entry on the KEY. Shorten the note.';
    return '';
  }

  async function save() {
    if (busy) return;
    const site = ($('pw-f-site').value || '').trim(), user = $('pw-f-user').value || '', pass = $('pw-f-pass').value || '', note = $('pw-f-note').value || '';
    const bad = formCheck(site, user, pass, note, !!editing);
    if (bad) { warn(bad); return; }
    say('');
    const odd = untypable(pass);
    warn(odd.length ? 'Saved as typed, but the KEY can only type US keyboard characters. It will refuse to type: ' + odd.join(' ') : '');
    const body = { site, user };
    if (pass) body.pass = pass;
    if (note || !editing) body.note = note;
    if (editing) { body.slot = editing.slot; body.id = editing.id; }
    busy = true;
    let r;
    try { r = await job('/vault/pw/save', body, 'Check your KEY: it shows ' + site + (user ? ' as ' + user : '') + '. Hold ENTER there to save it, or BACK to cancel.'); } catch (x) { r = { ok: false, error: 'no reply' }; } finally { busy = false; }
    $('pw-f-pass').value = ''; body.pass = '';
    if (r.ok) { formReset(); say('Saved on the KEY: ' + site + (user ? ' as ' + user : '') + '.'); if (odd.length) warn('Saved. The KEY will refuse to type: ' + odd.join(' ')); }
    else { say(errText(r.error), true); }
    load(true);
  }

  async function startEdit(slot) {
    const e = entries.find(x => x.slot === slot); if (!e || e.site === null) return;
    if (e.user === null || e.cut) {   // read the username and the full name first: an edit must never blank one or save a cut name
      say('Reading the username from the KEY…');
      const ok = await fetchUser(e);
      if (!ok) { say('Could not read this entry from the KEY. Try again.', true); return; }
      say(''); render();
    }
    editing = { slot: e.slot, id: e.id };
    $('pw-f-site').value = e.site; $('pw-f-user').value = e.user; $('pw-f-pass').value = ''; $('pw-f-note').value = '';
    $('pw-f-pass').placeholder = 'New password (blank keeps the one on the KEY)';
    $('pw-f-note').placeholder = 'New note (blank keeps the note on the KEY)';
    $('pw-form-title').textContent = 'Edit ' + e.site;
    $('pw-form-help').textContent = 'Change what you need. A blank password or note keeps what the KEY holds.';
    show('pw-f-cancel', true); warn('');
    $('pw-add-blk').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  async function savePending(slot) {
    if (busy) return;
    const e = entries.find(x => x.slot === slot); if (!e || e.user === null) return;
    const site = (document.querySelector('[data-pw-psite="' + slot + '"]').value || '').trim();
    const user = document.querySelector('[data-pw-puser="' + slot + '"]').value || '';
    const bad = formCheck(site, user, '', '', true);
    if (bad) { say(bad, true); return; }
    busy = true;
    let r;
    try { r = await job('/vault/pw/save', { slot: e.slot, id: e.id, site, user }, 'Check your KEY: it shows ' + site + (user ? ' as ' + user : '') + '. Hold ENTER there to save it.'); } catch (x) { r = { ok: false, error: 'no reply' }; } finally { busy = false; }
    say(r.ok ? 'Saved on the KEY: ' + site + (user ? ' as ' + user : '') + ', with the password the KEY made.' : errText(r.error), !r.ok);
    load(true);
  }

  async function del(slot) {
    if (busy) return;
    const e = entries.find(x => x.slot === slot); if (!e) return;
    busy = true;
    let r;
    try { r = await job('/vault/pw/delete', { slot: e.slot, id: e.id }, 'Check your KEY: hold ENTER there to delete ' + e.site + (e.user ? ' as ' + e.user : '') + ', or BACK to keep it.'); } catch (x) { r = { ok: false, error: 'no reply' }; } finally { busy = false; }
    say(r.ok ? 'Deleted from the KEY: ' + e.site + (e.user ? ' as ' + e.user : '') + '.' : errText(r.error), !r.ok);
    if (editing && editing.slot === slot) formReset();
    load(true);
  }

  // ── import ────────────────────────────────────────────────────────────────
  function wipePicks() {
    if (picks) for (const p of picks) { p.pass = ''; p.note = ''; p.user = ''; p.site = ''; }
    picks = null; pickKind = '';
    const f = $('pw-file'); if (f) f.value = '';
    const pk = $('pw-pick'); if (pk) pk.innerHTML = '';
    show('pw-pick-head', false); show('pw-import-go', false); show('pw-import-clear', false);
  }
  function renderPicks() {
    const pk = $('pw-pick'); if (!pk || !picks) return;
    const n = picks.filter(p => p.on).length;
    $('pw-pick-count').textContent = pickKind + ': ' + picks.length + ' entries, ' + n + ' picked';
    $('pw-import-go').textContent = n === 1 ? 'Import 1 on KEY' : 'Import ' + n + ' on KEY';
    pk.innerHTML = picks.map((p, i) => `
      <label style="display:flex;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--border);border-radius:10px;${p.why ? 'opacity:.55;' : ''}">
        <input type="checkbox" data-pw-pick="${i}" ${p.on ? 'checked' : ''} ${p.why ? 'disabled' : ''} style="width:16px;height:16px;flex-shrink:0;">
        <span style="flex:1;min-width:0;">
          <span class="pw-name" style="display:block;">${esc(p.site || '(no site)')}</span>
          <span class="pw-sub" style="display:block;">${p.user ? esc(p.user) : 'no username'}${p.why ? ' · ' + esc(p.why) : p.dup ? ' · already on the KEY: importing replaces it' : p.cut ? ' · note shortened' : p.odd ? ' · the KEY cannot type some characters' : ''}</span>
        </span>
      </label>`).join('');
  }
  async function onFile(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    $('pw-import-remind').hidden = true;
    if (file.size > 8 * 1024 * 1024) { $('pw-import-status').textContent = 'That file is too large for an export.'; return; }
    let text = await file.text();
    const res = parseExport(text); text = '';
    if (res.err || !res.items.length) { $('pw-import-status').textContent = res.err || (res.kind === 'unknown' ? 'This file does not look like a password export (no password column).' : 'No logins in this file.'); wipePicks(); return; }
    const have = new Set(entries.filter(e => e.user !== null && !e.cut).map(e => e.site + '\u0000' + e.user));
    const seen = new Set();
    picks = res.items.map(p => {
      const k = p.site + '\u0000' + p.user;
      p.dup = have.has(k); p.odd = untypable(p.pass).length > 0;
      if (!p.why && seen.has(k)) p.why = 'twice in this file';
      seen.add(k);
      p.on = !p.why && !p.dup;
      return p;
    });
    pickKind = res.kind;
    $('pw-import-status').textContent = 'Read on this phone only. Untick anything you do not want on the KEY. Entries already on the KEY start unticked.';
    show('pw-pick-head', true); show('pw-import-go', true); show('pw-import-clear', true);
    renderPicks();
  }
  async function runImport() {
    if (busy || !picks) return;
    const list = picks.filter(p => p.on && !p.why);
    if (!list.length) { $('pw-import-status').textContent = 'Pick at least one entry.'; return; }
    const out = $('pw-import-status');
    let done = 0, failed = 0, firstErr = '';
    busy = true;
    try {
    const w = await job('/vault/import/begin', {}, 'Enter your PIN on the KEY to open its import window. BACK on the first digit cancels.');
    if (!w.importOpen) { out.textContent = errText(w.error || 'refused'); return; }   // open already (a second tap) counts as open
    for (const p of list) {
      out.textContent = 'Sealing on the KEY: ' + (done + failed + 1) + ' of ' + list.length + ' (' + p.site + ')';
      const r = await job('/vault/pw/save', { site: p.site, user: p.user, pass: p.pass, note: p.note, import: true }, '');
      if (r.ok) { done++; p.on = false; p.done = true; }
      else {
        failed++; if (!firstErr) firstErr = r.error;
        if (r.error === 'window' || r.error === 'locked' || r.error === 'full' || r.error === 'Device locked' || r.error === 'gate') break;
      }
    }
    try { await deviceApi('/vault/import/end', { method: 'POST', body: '{}' }); } catch (e) {}
    } finally { busy = false; }
    const left = list.length - done - failed;
    out.textContent = done + ' imported' + (failed ? ', ' + failed + ' not: ' + errText(firstErr) : '') + (left > 0 ? ' ' + left + ' not tried.' : '');
    wipePicks();
    $('pw-import-remind').hidden = false;
    load(true);
  }

  document.addEventListener('click', ev => {
    const t = ev.target && ev.target.closest && ev.target.closest('[data-pw]');
    if (!t) return;
    const a = t.getAttribute('data-pw'), arg = parseInt(t.getAttribute('data-arg'), 10);
    ev.preventDefault();
    switch (a) {
      case 'reload': load(); return;
      case 'save': save(); return;
      case 'cancel-edit': formReset(); return;
      case 'showpass': { const p = $('pw-f-pass'); p.type = p.type === 'password' ? 'text' : 'password'; t.textContent = p.type === 'password' ? 'Show' : 'Hide'; return; }
      case 'edit': startEdit(arg); return;
      case 'del': del(arg); return;
      case 'pend-save': savePending(arg); return;
      case 'sel-mode': selMode = !selMode; if (!selMode) selected.clear(); render(); return;
      case 'sel-all': { const f = (($('pw-filter') || {}).value || '').trim().toLowerCase();
        for (const e of entries) if (!e.pending && (!f || ((e.site || '') + ' ' + (e.user || '')).toLowerCase().includes(f))) selected.add(e.slot + ':' + e.id);
        render(); return; }
      case 'sel-none': selected.clear(); render(); return;
      case 'sel-delete': delMany(); return;
      case 'pick-all': if (picks) { picks.forEach(p => { if (!p.why) p.on = true; }); renderPicks(); } return;
      case 'pick-none': if (picks) { picks.forEach(p => p.on = false); renderPicks(); } return;
      case 'import': runImport(); return;
      case 'import-clear': wipePicks(); $('pw-import-status').textContent = ''; return;
    }
  });
  document.addEventListener('change', ev => {
    const t = ev.target; if (!t) return;
    if (t.id === 'pw-file') { onFile(ev); return; }
    if (t.hasAttribute && t.hasAttribute('data-pw-sel')) { const k = t.getAttribute('data-pw-sel'); if (t.checked) selected.add(k); else selected.delete(k); renderSelBar(); return; }
    if (t.hasAttribute && t.hasAttribute('data-pw-pick') && picks) { const p = picks[parseInt(t.getAttribute('data-pw-pick'), 10)]; if (p) { p.on = t.checked; renderPicks(); } }
  });
  document.addEventListener('input', ev => { if (ev.target && ev.target.id === 'pw-filter') render(); });

  window.pwPageOpen = function () { open = true; formReset(); say(''); load(); };
  window.pwPageClose = function () { open = false; clearTimeout(listTimer); listTimer = null; wipePicks(); entries = []; selected.clear(); selMode = false; const p = $('pw-f-pass'); if (p) p.value = ''; };
})();
