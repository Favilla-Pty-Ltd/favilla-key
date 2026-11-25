# Security

The Favilla KEY holds Nostr keys, Bitcoin keys and a password vault, so security
reports matter more to us than anything else in this repository.

## Reporting a vulnerability

- Report it privately: the **Security** tab of this repository, then **Report a
  vulnerability**, or email security@favillakey.io. Please do not open a
  public issue.
- Include the firmware drop (the `[BUILD] drop ...` line from the boot log), what
  you did, what happened, and what an attacker gains.
- We answer within a week, and we credit reporters who want credit once a fix
  has shipped.

## Scope

- In scope: the ESP32-S3 firmware (`src/`), the isolated signer (`g0/`), the
  KEY's web page (`src/pwa.html`), the browser extension (`extension/`), and the
  build and verification tools (`tools/`).
- Third-party code (`components/`, `lib/`, `g0/lib/`) is in scope where our use
  of it is the problem; bugs in the projects themselves are best reported to them
  as well.

## Known limitations

Gaps that are already known, and how each is bounded, are listed in
`docs/KNOWN_ISSUES.md`, so you do not need to report those again.
