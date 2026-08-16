# Test Plan

## 1. Automated (no DB needed)

```
php tests/run_tests.php
```

Covers `Validator`, `Auth` password hashing, `Csrf`, and `UrlGuard`
allowlist logic in isolation. Run this first and screenshot the
`Total / Passed / Failed` summary line for your evidence folder.

## 2. Manual, DB-backed checks (run against your local MySQL instance)

For each of these, take a screenshot of the request/response (browser
devtools Network tab, or Burp/curl output) and of the corresponding
line appended to `storage/logs/security.log`.

| # | Scenario | Steps | Expected result |
|---|----------|-------|------------------|
| 1 | SQLi on login | Submit identifier `admin@example.test' -- ` with any password on `/login.php` | Rejected by `Validator::isLoginIdentifier()` before it ever reaches a query; generic error shown; `validation_rejected` logged |
| 2 | SQLi on admin search | As admin, search `%' OR '1'='1` on `/admin/students.php` | Treated as a literal search string (matches nothing), not an always-true condition; no extra rows returned |
| 3 | Brute force / lockout | Submit 6 wrong passwords for the same account within 15 minutes | 6th+ attempt returns the generic error immediately; `account_locked` logged; DB row appears in `account_lockouts` |
| 4 | Session fixation | Note the session cookie value before login, confirm it changes immediately after a successful login | Cookie value differs pre/post login (`session_regenerate_id` fired) |
| 5 | Stored XSS on bio | Set bio to `<script>alert(1)</script>` and view the profile page | Tag is rendered as visible text, not executed; view source shows `&lt;script&gt;` |
| 6 | CSRF on enrolment | Build a standalone HTML page with a form auto-posting to `/courses.php` (no token) and open it while logged in | Request rejected with the "session expired" message; `csrf_rejected` logged; no enrolment created |
| 7 | SSRF on link preview | Submit `http://169.254.169.254/` and `http://127.0.0.1/` to `/url_preview.php` | Both rejected with "not on the approved allowlist" / "disallowed internal address"; `ssrf_blocked` logged |
| 8 | Broken access control | Log in as a student, navigate directly to `/admin/index.php` | HTTP 403 "Forbidden"; `authorization_denied` logged |
| 9 | File upload type spoofing | Rename a `.php` file to `evil.png` and upload it | Rejected -- `finfo` detects the real content type, not the extension |
| 10 | Security headers | Load any page, inspect response headers (browser devtools) | `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` all present |

## 3. Regenerating seed password hashes

The placeholder hash in `database/seed.sql` is illustrative. Before
testing, generate real hashes:

```
php scripts/generate_hash.php "Tr0ub4dor&3"
```

Paste the output over the `password_hash` values in `seed.sql`, then
re-import the seed file.
