// Smoke test: the real pwa.html in Chromium, with deviceApi replaced by a mock KEY.
const { chromium } = require('playwright');
const path = require('path'); const fs = require('fs');
const D = __dirname, html = path.resolve(D, '../pbuild/src/pwa.html');
(async () => {
  const b = await chromium.launch(); const pg = await b.newPage({ viewport: { width: 390, height: 844 } });
  const errs = []; pg.on('pageerror', e => errs.push(String(e))); pg.on('console', m => { if (m.type() === 'error' && /Content Security Policy|pw-|PWIMPORT|vault/i.test(m.text())) errs.push(m.text()); });
  await pg.goto('file://' + html); await pg.waitForTimeout(1500);
  const res = {};
  res.loaded = await pg.evaluate(() => typeof window.pwPageOpen === 'function' && !!window.PWIMPORT);
  // mock KEY
  await pg.evaluate(() => {
    const K = { entries: [ { slot: 3, id: '00112233aabbccdd', updated: 9, site: 'New entry 3', user: 'josh@test.io', pending: true },
                           { slot: 1, id: '1111111111111111', updated: 8, site: 'github.com', user: 'josh', pending: false },
                           { slot: 2, id: '2222222222222222', updated: 7, site: 'mail.example', user: '', pending: false },
                           { slot: 4, id: '4444444444444444', site: 'slow.example', user: null, pending: false },
                           { slot: 5, id: '5555555555555555', site: null, user: null, pending: false } ],
                total: 6, seq: 0, job: null, gate: false, imp: false, saves: [], calls: [] };
    window.__K = K;
    window.deviceApi = async (p, o = {}) => {
      const body = o.body ? JSON.parse(o.body) : null; K.calls.push([p, body && Object.assign({}, body, body.pass ? { pass: '***' } : {})]);
      if (K.gate) return { error: 'gate' };
      if (p === '/vault/pw') { const r = { entries: K.entries.slice(0, K.total > K.entries.length ? K.entries.length : K.total), total: K.total, listed: K.entries.length, max: 200, records: K.entries.length + 2, importOpen: K.imp }; if (K.total > K.entries.length) K.total--; return r; }
      if (p === '/vault/pw/page') {   // pages of 2, so the 6-row list takes 3 replies
        if (!body.from) { K.snap = { entries: K.entries.slice(0, K.total > K.entries.length ? K.entries.length : K.total), total: K.total, listed: K.entries.length, max: 200, records: K.entries.length + 2, importOpen: K.imp }; if (K.total > K.entries.length) K.total--; K.pages = 0; }
        K.pages++; const f = body.from || 0, all = K.snap.entries, nx = f + 2 < all.length ? f + 2 : null;
        return Object.assign({}, K.snap, { entries: all.slice(f, f + 2), from: f, next: nx });
      }
      if (p === '/vault/pw/delete-many') { K.seq++; K.many = body.items; K.job = { seq: K.seq, state: 'waiting', ok: true, error: '', deleted: body.items.length }; setTimeout(() => { K.job.state = 'done'; }, 200); return K.job; }
      if (p === '/vault/pw/save') { K.seq++; K.saves.push(body); if (body.import && !K.imp) return { error: 'window' }; K.job = { seq: K.seq, state: body.import ? 'done' : 'waiting', ok: true, error: '', importOpen: K.imp }; setTimeout(() => { K.job.state = 'done'; }, 200); return K.job; }
      if (p === '/vault/pw/delete') { K.seq++; K.job = { seq: K.seq, state: 'waiting', ok: false, error: 'declined' }; setTimeout(() => { K.job.state = 'done'; }, 200); return K.job; }
      if (p === '/vault/import/begin') { K.seq++; K.job = { seq: K.seq, state: 'waiting', ok: true, error: '', importOpen: false }; setTimeout(() => { K.imp = true; K.job.state = 'done'; K.job.importOpen = true; }, 300); return K.job; }
      if (p === '/vault/import/end') { K.imp = false; return { seq: K.seq, state: 'done', ok: true }; }
      if (p === '/vault/pw/result') return K.job;
      if (p === '/vault/pw/user') { const e = K.entries.find(x => x.slot === body.slot); return e ? { slot: e.slot, site: e.site || 'x', user: 'fetched-user' } : { error: 'gone' }; }
      return { error: 'nope' };
    };
  });
  await pg.evaluate(() => { showSection('settings'); });
  await pg.waitForTimeout(300);
  await pg.click('[data-set-go="passwords"]');
  await pg.waitForTimeout(2200);
  res.title = await pg.textContent('#set-title');
  res.status = await pg.textContent('#pw-status');
  res.rows = await pg.$$eval('#pw-list > div', d => d.length);
  res.pagesPerLoad = await pg.evaluate(() => window.__K.pages);
  res.unnamedRowListed = await pg.evaluate(() => /Reading the name/.test(document.getElementById('pw-list').textContent) && !document.querySelector('[data-pw="edit"][data-arg="5"]'));
  await pg.click('[data-pw="edit"][data-arg="4"]'); await pg.waitForTimeout(400);
  res.editFetchesUser = await pg.inputValue('#pw-f-user');
  await pg.click('[data-pw="cancel-edit"]');
  res.pending = await pg.$$eval('#pw-pending > div', d => d.length);
  await pg.screenshot({ path: path.join(D, 'shots/pw_list.png'), fullPage: false });
  res.pickHeadHiddenBeforeFile = await pg.evaluate(() => getComputedStyle(document.getElementById('pw-pick-head')).display === 'none');
  // select mode: All ticks every listed entry, one delete-many with "slot:id" items
  await pg.click('[data-pw="sel-mode"]'); await pg.waitForTimeout(150);
  res.selBoxes = await pg.$$eval('#pw-list input[data-pw-sel]', x => x.length);
  res.selEditHidden = await pg.evaluate(() => !document.querySelector('#pw-list [data-pw="edit"]'));
  await pg.click('[data-pw="sel-all"]'); await pg.waitForTimeout(100);
  res.selCount = await pg.textContent('#pw-sel-count');
  await pg.click('#pw-list input[data-pw-sel]'); await pg.waitForTimeout(100);   // untick one
  res.selBtn = await pg.textContent('#pw-sel-del');
  await pg.screenshot({ path: path.join(D, 'shots/pw_select.png'), fullPage: false });
  await pg.click('[data-pw="sel-delete"]'); await pg.waitForTimeout(1600);
  res.manyItems = await pg.evaluate(() => JSON.stringify(window.__K.many));
  res.manyNote = await pg.textContent('#pw-note');
  res.selModeOff = await pg.evaluate(() => !document.querySelector('#pw-list input[data-pw-sel]'));
  // pending save
  await pg.fill('[data-pw-psite="3"]', 'example.org');
  await pg.click('[data-pw="pend-save"][data-arg="3"]');
  await pg.waitForTimeout(150);
  res.waitShown = await pg.evaluate(() => !document.getElementById('pw-wait').hidden && document.getElementById('pw-wait').textContent);
  await pg.waitForTimeout(1500);
  res.pendSave = await pg.evaluate(() => JSON.stringify(window.__K.saves[0]));
  res.afterPend = await pg.textContent('#pw-note');
  // add with a non-ASCII password
  await pg.fill('#pw-f-site', 'shop.example'); await pg.fill('#pw-f-user', 'me'); await pg.fill('#pw-f-pass', 'pässword1'); await pg.click('#pw-f-save');
  await pg.waitForTimeout(1500);
  res.addSave = await pg.evaluate(() => { const s = window.__K.saves[1]; return s && s.site + '|' + s.user + '|' + (s.pass ? 'pass' : '') + '|' + s.slot; });
  res.addWarn = await pg.textContent('#pw-f-warn');
  res.passCleared = await pg.inputValue('#pw-f-pass');
  // edit: no password sent when blank
  await pg.click('[data-pw="edit"][data-arg="1"]'); await pg.waitForTimeout(200);
  res.editTitle = await pg.textContent('#pw-form-title');
  await pg.fill('#pw-f-user', 'josh2'); await pg.click('#pw-f-save'); await pg.waitForTimeout(1500);
  res.editSave = await pg.evaluate(() => JSON.stringify(window.__K.saves[2]));
  // delete declined
  await pg.click('[data-pw="del"][data-arg="2"]'); await pg.waitForTimeout(1500);
  res.delStatus = await pg.textContent('#pw-note');
  // import: a Chrome CSV with 50 entries + a duplicate of github.com/josh
  let csv = 'name,url,username,password,note\n'; for (let i = 0; i < 50; i++) csv += `S${i},https://s${i}.example,u${i},p${i}x!,\n`; csv += 'GH,https://github.com,josh,dup,\n,https://nopass.example,u,,\n';
  fs.writeFileSync(path.join(D, 'shots/export.csv'), csv);
  await pg.setInputFiles('#pw-file', path.join(D, 'shots/export.csv')); await pg.waitForTimeout(500);
  res.pickCount = await pg.textContent('#pw-pick-count');
  res.pickHeadShownWithFile = await pg.evaluate(() => getComputedStyle(document.getElementById('pw-pick-head')).display === 'flex');
  res.pickDisabled = await pg.$$eval('#pw-pick input[disabled]', x => x.length);
  await pg.screenshot({ path: path.join(D, 'shots/pw_import.png'), fullPage: false });
  const before = await pg.evaluate(() => window.__K.saves.length);
  await pg.click('#pw-import-go'); await pg.waitForTimeout(6000);
  res.imported = await pg.evaluate(n => window.__K.saves.length - n, before);
  res.importAllFlagged = await pg.evaluate(n => window.__K.saves.slice(n).every(s => s.import === true && s.pass), before);
  res.importStatus = await pg.textContent('#pw-import-status');
  res.remind = await pg.evaluate(() => !document.getElementById('pw-import-remind').hidden);
  res.picksWiped = await pg.$$eval('#pw-pick > *', x => x.length);
  res.fileCleared = await pg.evaluate(() => document.getElementById('pw-file').value === '');
  res.endCalled = await pg.evaluate(() => window.__K.calls.some(c => c[0] === '/vault/import/end'));
  await pg.screenshot({ path: path.join(D, 'shots/pw_imported.png'), fullPage: false });
  // gate closed
  await pg.evaluate(() => { window.__K.gate = true; }); await pg.click('[data-pw="reload"]'); await pg.waitForTimeout(500);
  res.gate = await pg.textContent('#pw-gate'); res.gateShown = await pg.evaluate(() => !document.getElementById('pw-gate').hidden && document.getElementById('pw-list-blk').hidden);
  await pg.screenshot({ path: path.join(D, 'shots/pw_gate.png'), fullPage: false });
  // back to hub wipes
  await pg.click('#set-back'); await pg.waitForTimeout(200);
  res.hub = await pg.evaluate(() => !document.getElementById('set-hub').hidden);
  res.errors = errs;
  console.log(JSON.stringify(res, null, 1));
  await b.close();
})();
