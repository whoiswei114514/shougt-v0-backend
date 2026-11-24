# Local Security Audit

## November 12, 2026 continuation

This review covered account privacy, content ownership, shared-role history,
anonymous follow relationships, reports, and the independent console's optional
operation notes. Existing uncommitted watermark changes were preserved.

The new adversarial tests reproduced these issues before the fixes:

| Finding | Fix |
| --- | --- |
| An authenticated request without a selected role could read orphaned private posts and comments because both author and selected role were null. | Author queries now require a selected role; moderator queries retain their explicit permission check. |
| Shared-role edit/history and comment-management responses disclosed another member's username, real name and student ID; comment review history also exposed moderator IDs. | Account references obey current privacy permissions, serializers receive the request context, and reviewer IDs are limited to forum moderators. |
| A previously authored comment exposed a parent post's summary after that post became inaccessible. | Non-moderator comment management also checks current parent-post visibility and uses uniform not-found responses. |
| Guessed private role IDs could reveal their public follow relationships. | Both follow filters authorize the referenced role before querying the relationship. |
| Reporting hidden or nonexistent objects was accepted and could reveal private post-type metadata. | Reports now resolve targets through the same visibility boundaries before duplicate checks or writes. |

Authenticated and account/security responses additionally use `Cache-Control:
no-store, private`. This is cache hardening, not a claim that a cache leak was
observed in production.

The console no longer asks for operation reasons or written review notes.
Missing notes are accepted without inventing an audit justification. Original
FIDO approval, certificate/session binding, action permissions, replay rejection,
and automatic audit records remain enforced. The bootstrap CLI still validates
its required reason. Identity review still requires explicit confirmation.

Validation: 157 backend tests, 39 independent-console tests, and a subsequent
38-test console/bootstrap run with reasonless actions passed. The new 18-test
privacy/authorization subset passed after reproducing the failures. Real HTTP
privacy and mTLS rejection regressions passed. No model migration is required.
Full frontend rebuild and interactive browser checks encountered host memory
exhaustion; see the current task's verification report for their final status.

All fixtures were isolated from `.local-preview`. No account reset, credential
reset, production deployment, remote push, or low-port listener was performed.

The remainder of this file records the earlier November 6 audit.

Verification date: November 6, 2026, Asia/Shanghai.

Scope: `shougt-v0-backend`, `shougt-v4-frontend`, and the independently
implemented privileged management console. This continues the original implementation and local
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

From the independent privileged console:

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
  implementation provenance and boundaries remain documented with the
  independent privileged console.

Build warnings about legacy Sass APIs and large chunks remain non-blocking.
Local Git commits do not mean remote push or production deployment occurred.

## 2026-11-16 Reader, Dual-Key and PIV Follow-up

- Added an exclusive global-reader role across main APIs, Django Admin and the
  independent console. Read-only policy is re-evaluated at operation preparation,
  FIDO approval and execution, and also applies to the two pinned issuer test CAs.
- Added up to three active security keys, with an atomic registration-finish limit.
  Administrators may use a second trusted credential with a different public key;
  factor tickets, account versions, revocation and key ownership are checked.
- New privileged roles, including the first administrator, require the onsite
  issuance state machine. CSR, account, roles, fresh public key, CA chain and
  post-installation proof are bound to the job before transactional activation.
- Hardened offline PIV installation to reject an unknown PC/SC protocol, wrong
  stage, invalid/oversized/untrusted certificate chain and occupied slots before
  writes. Bounded empty GET RESPONSE continuations and malformed TLV handling.
- Fixed the browser registration finish request to include its required password
  proof. Fixed the dual-key test to remove the first virtual authenticator before
  inserting the second, matching a physical key swap.

Validation on 2026-11-16: 185 Django tests and 61 independent-console tests passed.
The ordinary browser suite passed 23 cases, including automatic PIV and onboarding;
the one high-assurance-only case was run separately and passed. Reader/dual-key browser cases also passed after the
test fixture correction. Migration drift and Django system checks passed.
Screenshots were inspected at desktop and 390px mobile widths. These counts do
not include live production red-team probing or physical card validation.

The offline tool proves key possession and verifies declared readback, but generic
PIV does not let the server independently prove non-exportable hardware generation
or physical installation. WebAuthn likewise cannot generally prove distinct device
serials for two credentials. Onsite operator/device trust remains explicit in
the independent console's PIV issuance documentation. The only enumerated local reader was a UICC reader;
USB/NFC PIV hardware, browser middleware and production PostgreSQL remain to be
accepted. OneDrive was assessed against current official docs, without connecting
to a tenant or migrating files; see `ONEDRIVE-STORAGE-ASSESSMENT.md`.

The final UI starts PIV provisioning inside role assignment, without a separate
page or manual JSON exchange. The attended helper binds only 127.0.0.1 on a port
at least 10000 and validates an exact HTTPS Origin, Host, one-time pairing code,
short-lived token, body limits and operation identity. Only public jobs/results
cross the loopback bridge; PINs and management secrets use local terminal prompts.
Repeated operation IDs do not repeat hardware mutation. The production bridge
has no simulation switch; browser tests use a separate, isolated fixture server.

New manager grants set admin_onboarding_required and invalidate old sessions.
Initial login is limited to enrollment until a fresh, session-bound WebAuthn
proof verifies the trusted key, current identity/version and independent login
factor. Ordinary-role grants can precede FIDO setup, but do not grant effective
management access until setup and identity review complete. Special roles still
require onsite CA issuance before activation.
