# csp.py <pwa.html> [--fix]: every inline <script> block's SHA-256 must be in the CSP script-src.
import sys, re, hashlib, base64
p = sys.argv[1]; fix = '--fix' in sys.argv
s = open(p, encoding='utf-8').read()
csp_m = re.search(r'<meta http-equiv="Content-Security-Policy" content="(.*?)">', s, re.S)
csp = csp_m.group(1)
have = re.findall(r"'sha256-([A-Za-z0-9+/=]+)'", csp)
blocks = []
for m in re.finditer(r'<script(\s[^>]*)?>(.*?)</script>', s, re.S):
    attrs = m.group(1) or ''
    if 'src=' in attrs: continue
    body = m.group(2)
    if m.start() > csp_m.start() and m.start() < csp_m.end(): continue
    h = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode()
    blocks.append((s[:m.start()].count('\n') + 1, h))
# script-src occurrences of "<script" inside JS strings are not real blocks: only count blocks at line starts
ok = [b for b in blocks if b[1] in have]
print(f"{len(ok)}/{len(blocks)} inline blocks hashed; CSP lists {len(have)}")
for ln, h in blocks:
    if h not in have: print(f"  MISSING line {ln}: sha256-{h}")
if fix:
    sm = re.search(r"(script-src\s+'self'\s+'wasm-unsafe-eval')((?:\s*'sha256-[A-Za-z0-9+/=]+')+)", csp)
    new = sm.group(1) + ''.join(f" 'sha256-{h}'" for _, h in blocks)
    csp2 = csp[:sm.start()] + new + csp[sm.end():]
    s = s[:csp_m.start(1)] + csp2 + s[csp_m.end(1):]
    open(p, 'w', encoding='utf-8').write(s)
    print("fixed")
sys.exit(0 if len(ok) == len(blocks) else 1)
