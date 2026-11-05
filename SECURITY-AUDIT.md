# Local Security Audit

Verification date: November 6, 2026, Asia/Shanghai.

Scope: `shougt-v0-backend`, `shougt-v4-frontend`, and the independently
implemented `shougt-sa`. This continues the original implementation and local
audit. It is an offline code review and bounded adversarial regression, not a
production penetration test or an online dependency-advisory scan.

## Result

The local release gate passed after the reproduced findings were fixed.
No unresolved reproduced finding remains in this reviewed scope. This is not
a claim that the application has no vulnerabilities or is ready for production.

| Verification | Result |
| --- | --- |
| Django backend suite, including 24 account/media adversarial tests | 126 passed |
| Independent certificate, local-policy and HTTP-boundary suite | 16 passed |
| Standard Edge browser suite, including three adversarial cases | 15 passed; certified-key case intentionally skipped |
| Certified-key browser case, using separate isolated trust metadata | 1 passed |
| Vue TypeScript check and production build | Passed |
| Django checks and migration drift | No issues; no pending model changes |
| Python dependency consistency in both environments | Passed |
| npm 11.12.1 clean offline install in an isolated directory | 748 packages installed; lifecycle scripts disabled |
| Source syntax, credential-pattern and private/runtime-file checks | Passed; no matching findings |

The two browser configurations together exercise all 16 cases. Ordinary
hardware and certified hardware intentionally use different test fixtures.
Automated certification metadata is not evidence about a physical key.

## Findings Fixed

Severity is a local risk assessment, not an externally assigned CVSS score.

| ID | Risk | Finding and remediation |
| --- | --- | --- |
| A1 | High | A user administrator could reset an exempt administrator's password. Management-account password resets now require `super_admin`, with protected-account checks retained. |
| A2 | High | Stored article HTML could execute in a visitor's browser. Article display, editor preview and Mermaid output now use explicit DOMPurify sanitizers; external links isolate the opener. |
| A3 | High | Guessed account IDs could force shared-role membership or disclose private identity through trust lists. Invitation consent is checked separately from directory visibility, trust is directional, and existing references redact hidden identity. |
| A4 | High | Global image-hash deduplication and guessed attachment IDs could reveal another uploader's data. Deduplication is scoped to the uploader, storage keys are random, and new attachments require ownership. Shared authors may retain the same post's existing images. |
| A5 | Medium | Rotating a supplied forwarding header could reset authentication throttling. Limits now use connection-derived `REMOTE_ADDR`; the client cannot nominate its own trusted address. |
| A6 | Medium | Invalid upload sizes and metadata could bypass quota validation. Sizes must be positive, image types and hashes are validated, and batches are bounded before upload signing. |
| A7 | Medium | Transfer/report references exposed hidden names, and a stale balance could spend coins twice. References follow privacy policy, ledger details omit real names, and balance changes lock fresh rows atomically. |
| A8 | Medium | Deep JSON below normal request-size limits raised uncaught exceptions. A roughly 10 KB test input reproduced failures in bearer-token parsing, login and media endpoints. Tokens now return 401; JSON decoder depth failures return 400. Ordinary objects, media arrays and forms remain supported. |
| A9 | Medium | Ambiguous HTTP framing and stalled TLS handshakes weakened the independent service boundary. Duplicate Host/Content-Length headers are rejected; failures close connections; handshake and business connections share 64 bounded slots. |

The added depth tests first failed with three uncaught exceptions, then passed
after the parser/token fix. Browser HTTP regressions verify the same inputs
through the actual frontend proxy.

## Other Boundaries Verified

- WebAuthn signature, RP ID, Origin, user-verification and challenge-replay
  checks; synced credentials and arbitrary model names do not grant hardware
  trust or FIPS exemptions.
- Session revocation, account-version checks, selected-role ownership,
  expiring administrator exemptions and TOTP replay rejection.
- Whole-site mTLS: missing certificates cannot obtain frontend assets.
  CA/subCA, certificate usage, expiration and revocation are checked.
- Independent operations require the original login key, bind the approved
  payload digest, expire and execute once. CSRF and certificate/session
  bindings remain enforced.
- Privileged assignment boundaries, protected accounts, primary-role
  management badges, real-name visibility and private-post membership.
- Impersonation remains short-lived and cannot access security or management
  functions; the original administrator's browser state is retained.
- Post pinning preserves visibility and review state and writes an audit
  record. Text, spatial and frequency watermark regressions remain covered.

## Data and Execution Safety

Tests used disposable SQLite databases, generated test certificates and
virtual authenticators. They did not reset the persistent preview accounts,
passwords, real FIDO registrations or existing TOTP enrollment.

The previous `gt_file.0003_image_ownership` migration was backed up and rehearsed
on a database copy before application to the local preview. Its recorded
comparison preserved every business-table row. This continuation adds no
database migration and does not rerun that migration rehearsal against real
accounts.

Only loopback ports above 10000 were used. No production database, real
SMTP/mail ingestion, external storage, remote Git endpoint or online advisory
service was contacted. Protocol probes used at most three connections, not
traffic flooding.

Private keys, databases, `.local-preview`, actual configuration files and
runtime tokens are excluded from Git. Audit output records paths, counts and
digests, not credential values.

## Reproduction

From the backend, with its existing virtual environment:

```powershell
$env:SHOUGT_MODE = 'dev'
.\.venv\Scripts\python.exe manage.py check --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py test --settings=gt.test_settings
```

From `shougt-sa`:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

From the frontend, after `npm ci`, with all three test ports available:

```powershell
$env:SHOUGT_UI_WORK = Join-Path (Get-Location) '.test-work/audit'
node --require ./tests/local-dns.cjs tests/run-ui.mjs
$env:SHOUGT_UI_WORK = Join-Path (Get-Location) '.test-work/audit-gold'
$env:SHOUGT_UI_CERTIFIED_KEY = '1'
node --require ./tests/local-dns.cjs tests/run-ui.mjs --grep 'certified key shows gold'
Remove-Item Env:SHOUGT_UI_CERTIFIED_KEY
```

## Remaining Acceptance

- Review current third-party advisories before deployment. No online CVE scan
  was performed. Installation reports deprecated legacy/transitive packages.
- Validate production PostgreSQL, cache/task services, real authenticated mail
  reception, storage/CDN privacy and deployment TLS configuration.
- Verify production CA/subCA/CRL issuance, PIV middleware and physical hardware
  attestation. Local CA and FIPS appearance exceptions are not production trust.
- Test watermark recovery under the intended image processing and send audit
  records to an appropriately protected external logging system when needed.
- Preserve the existing licenses and evaluate the intended release arrangement;
  implementation provenance and boundaries remain documented in
  `shougt-sa/PROVENANCE.md`.

Build warnings about legacy Sass APIs and large chunks remain non-blocking.
Local Git commits do not mean remote push or production deployment occurred.
