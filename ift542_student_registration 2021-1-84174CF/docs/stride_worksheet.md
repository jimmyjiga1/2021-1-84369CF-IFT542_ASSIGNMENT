# STRIDE Threat Model -- Student Registration Web Application

Reference the data-flow diagram (`dfd_diagram.png`). Numbered flows
below correspond to the numbered arrows in that diagram.

## Assets
- User credentials (password hashes, session tokens)
- Student PII (names, matric numbers, emails, uploaded documents)
- Course/enrolment records (integrity of academic records)
- Application availability
- Server-side network position (can it be abused to reach other hosts?)

## Trust boundaries
- Browser &harr; Application server (flows 1, 5, 7, 9, 12, 14)
- Application server &harr; MySQL (flows 2, 6, 8, 11, 15, 16)
- Application server &harr; External verification site (flow 13) -- the
  only flow that crosses out to a third party, and therefore the
  focus of the SSRF analysis.

## STRIDE per data flow

| Flow | Threat category | Threat | Mitigation implemented |
|---|---|---|---|
| 1. Credentials submitted | Spoofing | Credential stuffing / brute force against login | Rate limiting + temporary account lockout (`Auth::isRateLimited`, `account_lockouts` table); generic error message prevents user enumeration |
| 1. Credentials submitted | Tampering | Interception/modification in transit | TLS required in production (HSTS header); session cookie `Secure` flag in production |
| 2. Auth DB lookup | Tampering | SQL injection to bypass authentication | 100% parameterised queries via `Database::run()`; `PDO::ATTR_EMULATE_PREPARES = false` |
| 2. Auth DB lookup | Information Disclosure | Timing side-channel reveals valid accounts | `password_verify()` always runs (against a dummy hash if user not found) so response timing doesn't distinguish "no such user" from "wrong password" |
| 3. Failure logging | Repudiation | User denies attempting an attack; no audit trail | `security_events` table + `security.log` JSON lines record every login failure, lockout, denied authorization and rejected input with timestamp/IP/subject |
| 4. Session cookie issuance | Spoofing / Elevation of Privilege | Session fixation -- attacker pre-sets a session ID, victim logs in, attacker reuses it | `Session::regenerate()` (`session_regenerate_id(true)`) called on every successful login |
| 4. Session cookie issuance | Information Disclosure | Cookie theft via XSS or network sniffing | `HttpOnly`, `Secure` (prod), `SameSite=Lax` cookie flags |
| 5/7/9/12. Form submissions | Tampering | Cross-Site Request Forgery -- a third-party site submits state-changing requests using the victim's session | Per-session CSRF token (`Csrf` class), verified with `hash_equals()`, required on every POST; token rotates after use |
| 5. Profile update | Tampering / Info Disclosure | Stored XSS via the `bio` field, executed for every later viewer (including admins) | All dynamic output passed through `e()` (`htmlspecialchars`, `ENT_QUOTES`); CSP `script-src 'self'` blocks any inline script that slips through |
| 6/8/11/15. DB writes/reads | Tampering | SQL injection via search, enrolment, or profile fields | Parameterised queries throughout; input format validation (`Validator`) as defence in depth |
| 8. Enrolment | Tampering | Race condition over-subscribes a capacity-limited course | `SELECT ... FOR UPDATE` inside a transaction serialises concurrent enrolment attempts |
| 9/10. Document upload | Tampering / Elevation of Privilege | Malicious file (e.g. a `.php` script renamed `.png`) uploaded and later executed | `finfo` content-sniffed MIME check (not extension/Content-Type), random on-disk filename, storage directory outside the web root |
| 12/13. Link preview | Tampering / Elevation of Privilege | SSRF -- server made to fetch internal/cloud-metadata addresses on the attacker's behalf | Host allowlist, HTTPS-only, resolved-IP re-check against private/loopback/link-local/metadata ranges, redirects not followed, small timeout/size cap (`UrlGuard`) |
| 14. Admin search | Elevation of Privilege | Broken access control -- a student reaches admin-only pages directly by URL | `Auth::requireAdmin()` re-checks role server-side on every admin request, independent of UI nav visibility |
| Any authenticated flow | Denial of Service | Resource exhaustion via large uploads or rapid requests | Upload size cap (5 MB), login rate limiting; full DDoS protection is out of scope (see report limitations) |
| All flows | Security Misconfiguration | Debug info, verbose errors, or missing headers leak internals | `display_errors` fails closed to off, security headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `HSTS`) applied globally in `bootstrap.php` |

## Residual risks (not fully mitigated by this assignment scope)
- No Web Application Firewall / network-layer DDoS protection.
- No multi-factor authentication (documented as a recommended future control in the risk register).
- No automated dependency/vulnerability scanning pipeline (manual review only).
- No IP-reputation or CAPTCHA layer on login (rate limiting only).
