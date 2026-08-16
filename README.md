# IFT542 Practical Assignment -- Student Registration Web Application -- 2021/1/84174CF

A PHP/MySQL student registration app built to demonstrate identifying,
exploiting-in-principle, and remediating common web vulnerabilities
(SQL injection, XSS, CSRF, SSRF, broken access control, weak auth) as
required by the assignment brief.

## Folder structure

```
config/                 App configuration (reads .env, no hardcoded secrets)
database/
  schema.sql            Full MySQL schema
  seed.sql              Fictitious seed data
public/                 Web root -- point your server here
  bootstrap.php          Shared init (session, headers, autoload)
  login.php, register.php, dashboard.php, courses.php, upload.php,
  url_preview.php, password_reset_request.php, password_reset_confirm.php
  admin/                 Admin-only pages (role-checked server-side)
src/                    Core classes: Auth, Database, Csrf, Session,
                        Validator, Logger, UrlGuard, SecurityHeaders
legacy/                 VULNERABLE baseline snippets, NOT routed --
                        kept only for before/after comparison in the
                        report. Do not deploy these files.
scripts/generate_hash.php   CLI helper to generate a real Argon2id hash
tests/
  run_tests.php          Plain-PHP unit tests (no Composer needed)
  README.md              Manual/DB-backed test plan for evidence screenshots
docs/
  dfd_diagram.png/.svg    Data-flow diagram (also see dfd.dot source)
  stride_worksheet.md     Full STRIDE analysis per data flow
  risk_register.md        Likelihood/impact scoring, pre/post mitigation
  incident_response_runbook.md
  sample_logs/            Redacted fictitious log sample
SECURITY_NOTES.md        Before/after code excerpts, one per finding
```

## Local setup (XAMPP/MAMP/native PHP + MySQL)

1. Install PHP 8.1+ with the `pdo_mysql`, `curl`, and `fileinfo`
   extensions enabled (all bundled with XAMPP/MAMP by default).
2. Create the database and load fixtures:
   ```
   mysql -u root -p < database/schema.sql
   mysql -u root -p student_registration < database/seed.sql
   ```
3. Copy `.env.example` to `.env` and fill in your local DB credentials.
4. Generate a real password hash for the seed accounts and update
   `database/seed.sql` with it, then re-import:
   ```
   php scripts/generate_hash.php "Tr0ub4dor&3"
   ```
5. Serve the app with PHP's built-in server (fine for local grading):
   ```
   php -S localhost:8000 -t public
   ```
   Then visit `http://localhost:8000/`.
6. Run the unit tests:
   ```
   php tests/run_tests.php
   ```
7. Work through `tests/README.md` section 2 for the manual/DB-backed
   scenarios and capture screenshots for your evidence folder.

## Security controls implemented (see SECURITY_NOTES.md for detail)

- Parameterised queries everywhere (`src/Database.php`) -- SQL injection
- Argon2id password hashing, rate limiting, temporary lockout, session
  regeneration on login, secure single-use password reset tokens (`src/Auth.php`)
- Output encoding via `e()` + restrictive CSP -- stored XSS
- Per-session CSRF tokens on every state-changing form (`src/Csrf.php`)
- Host allowlist + resolved-IP checks + no redirect-following for the
  link-preview feature -- SSRF (`src/UrlGuard.php`)
- Server-side role re-check on every admin page -- broken access control
- Content-sniffed MIME validation, random filenames, storage outside
  the web root -- malicious file upload
- Global security response headers, fail-closed error display -- security misconfiguration
- Structured, redacted security-event logging to file + DB (`src/Logger.php`)

## Notes on scope / honesty about what this is

- This app is for local coursework use only; it has not been
  penetration-tested against a live deployment.
- The `legacy/` files intentionally contain vulnerable patterns for
  educational before/after comparison. They are never included or
  routed by any file in `public/`.
- MFA, a WAF, and automated dependency scanning are documented as
  recommended future work in `docs/risk_register.md` rather than
  implemented, to keep the submission focused on the assignment's
  required control set.
