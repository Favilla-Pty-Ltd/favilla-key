// Host test of the PWA's import parsers (pw_page.js, pure part).
global.window = {}; require('./pw_page.js'); const P = window.PWIMPORT;
let pass = 0, fail = 0; const ok = (c, m) => { (c ? pass++ : fail++); console.log((c ? 'PASS ' : 'FAIL ') + m); };
const one = (txt) => P.parseExport(txt);
// Chrome / Edge
let r = one('name,url,username,password,note\r\nGitHub,https://www.github.com/login,josh,pa"ss,\r\n"Bank, The",https://bank.example/,"j@x.io","p,1","line1\nline2"\r\n');
ok(r.kind === 'Chrome or Edge' && r.items.length === 2, 'Chrome: two rows');
ok(r.items[0].site === 'github.com' && r.items[0].user === 'josh' && r.items[0].pass === 'pa"ss', 'Chrome: host without www, a quote inside an unquoted field');
ok(r.items[1].site === 'bank.example' && r.items[1].pass === 'p,1' && r.items[1].note === 'line1\nline2', 'Chrome: quoted comma and a two-line note');
// BOM + Edge (no note column)
r = one('﻿name,url,username,password\nx,https://x.example,u,p\n'); ok(r.items.length === 1 && r.items[0].site === 'x.example', 'Edge: BOM, no note column');
// Firefox
r = one('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n"https://accounts.firefox.com","a@b.c","pw1",,"https://accounts.firefox.com","{1}","1","2","3"\n');
ok(r.kind === 'Firefox' && r.items[0].site === 'accounts.firefox.com' && r.items[0].pass === 'pw1', 'Firefox');
// Safari
r = one('Title,URL,Username,Password,Notes,OTPAuth\nApple (appleid.apple.com),https://appleid.apple.com/,me@icloud.com,pw2,hi,\n');
ok(r.kind === 'Safari' && r.items[0].site === 'appleid.apple.com' && r.items[0].note === 'hi', 'Safari');
// 1Password 8
r = one('Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nNotion,notion.so,me,pw3,,false,false,,n\n');
ok(r.kind === '1Password' && r.items[0].site === 'notion.so' && r.items[0].pass === 'pw3', '1Password: URL without a scheme');
// KeePassXC
r = one('"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n"Root","Server","root","pw4","","ssh box","","0","",""\n');
ok(r.kind === 'KeePassXC' && r.items[0].site === 'Server' && r.items[0].user === 'root', 'KeePassXC: no URL falls back to the title');
// KeePass 2
r = one('"Account","Login Name","Password","Web Site","Comments"\n"Mail","me","pw5","http://mail.example.org/x","c"\n');
ok(r.kind === 'KeePass' && r.items[0].site === 'mail.example.org' && r.items[0].note === 'c', 'KeePass 2');
// Bitwarden CSV
r = one('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,GH,,,,https://github.com,me,pw6,\n,,note,Secret,text,,,,,,\n');
ok(r.kind === 'Bitwarden CSV' && r.items.length === 1 && r.items[0].pass === 'pw6', 'Bitwarden CSV: notes skipped');
// Bitwarden JSON
r = one(JSON.stringify({ encrypted: false, items: [ { type: 1, name: 'GL', notes: null, login: { username: 'u', password: 'pw7', uris: [{ uri: 'https://gitlab.com/users/sign_in' }] } }, { type: 3, name: 'card' }, { type: 1, name: 'NoUri', login: { username: 'v', password: 'pw8' } } ] }));
ok(r.kind === 'Bitwarden' && r.items.length === 2 && r.items[0].site === 'gitlab.com' && r.items[1].site === 'NoUri' && r.items[0].note === '', 'Bitwarden JSON: logins only, null note, name when no URI');
r = one(JSON.stringify({ encrypted: true, items: [] })); ok(!!r.err && r.items.length === 0, 'Bitwarden encrypted export refused with a reason');
r = one('a,b,c\n1,2,3\n'); ok(r.kind === 'unknown' && !r.items.length, 'a CSV with no password column is not an export');
r = one('{bad json'); ok(!!r.err, 'bad JSON has a reason');
// limits
const long = n => 'x'.repeat(n);
ok(P.fitEntry('s', 'u', '', '').why === 'no password', 'no password: cannot go in');
ok(P.fitEntry(long(200), 'u', 'p', '').why === 'site too long' && !P.fitEntry(long(199), 'u', 'p', '').why, 'site 199 bytes fits, 200 does not');
ok(P.fitEntry('s', long(129), 'p', '').why === 'username too long', 'username 129 bytes refused');
ok(P.fitEntry('s', 'u', long(129), '').why === 'password too long' && !P.fitEntry('s', 'u', long(128), '').why, 'password 128 fits, 129 does not');
ok(P.fitEntry('s', 'u', 'é'.repeat(65), '').why === 'password too long', 'bytes, not characters: 65 x 2-byte = 130');
let e = P.fitEntry(long(199), long(100), long(100), long(128));
ok(!e.why && e.cut && P.B(e.site) + P.B(e.user) + P.B(e.pass) + P.B(e.note) <= 415, 'a long note is cut so the entry fits 431 sealed bytes');
e = P.fitEntry('s', 'u', 'p', '\u{1F600}'.repeat(40)); ok(!e.why && e.cut && P.B(e.note) <= 128 && !/�/.test(e.note), 'a note of emoji is cut on a character');
ok(P.fitEntry('s', 'u', 'p', 'a\r\nb').note === 'a\nb', 'CRLF in a note becomes LF');
// typability (US table: printable ASCII, tab, newline)
ok(P.untypable('Abc!@#~`|\\').length === 0, 'printable ASCII types');
ok(P.untypable('pässwörd').join('') === 'äö', 'non-ASCII named, each once');
ok(P.untypable('a\u{1F511}b').length === 1, 'an emoji counts once');
// site normalisation
ok(P.normSite('HTTPS://WWW.Example.COM:8443/a?b', '') === 'example.com', 'host only, lower case, no www');
ok(P.normSite('android://abc@com.example.app/', 'App') === 'App', 'an app URL falls back to the name');
ok(P.normSite('https://a.example https://b.example', '') === 'a.example', 'several URLs: the first');
// username and email both in the file: the email goes in the note
r = one('name,url,username,email,password,note\nX,https://x.example,josh,j@x.io,pw,hi\nY,https://y.example,,y@x.io,pw,\nZ,https://z.example,same@x.io,same@x.io,pw,\n');
ok(r.items[0].user === 'josh' && r.items[0].note === 'Email: j@x.io\nhi', 'username and email: the email goes in the note, before the old note');
ok(r.items[1].user === 'y@x.io' && r.items[1].note === '', 'no username on the row: the email becomes the login');
ok(r.items[2].note === '', 'the same value in both: no note added');
// a 50-entry file
let big = 'name,url,username,password,note\n'; for (let i = 0; i < 50; i++) big += `S${i},https://s${i}.example,u${i},p${i}x!,\n`;
r = one(big); ok(r.items.length === 50 && r.items.every((x, i) => x.site === 's' + i + '.example' && !x.why), '50 rows read');
console.log(`\n${fail ? 'SOME FAILED' : 'ALL PASS'} (${pass} passed, ${fail} failed)`); process.exit(fail ? 1 : 0);
