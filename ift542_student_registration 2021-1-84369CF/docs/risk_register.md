# Risk Register

Scoring: Likelihood and Impact each rated 1 (Low) - 3 (High).
Risk Score = Likelihood x Impact. Status reflects state **after**
the mitigations in this codebase are applied.

| ID | Risk | Likelihood (pre) | Impact | Score (pre) | Mitigation | Likelihood (post) | Score (post) | Status |
|---|---|---|---|---|---|---|---|---|
| R1 | SQL injection allows authentication bypass / full data dump | 3 | 3 | 9 | Parameterised queries everywhere; input format validation | 1 | 3 | Mitigated |
| R2 | Stored XSS in bio field executes for other users, including admins | 3 | 3 | 9 | Output encoding (`e()`), CSP `script-src 'self'` | 1 | 3 | Mitigated |
| R3 | CSRF forces enrolment/profile changes without user consent | 2 | 2 | 4 | Per-session CSRF token on all state-changing POSTs | 1 | 2 | Mitigated |
| R4 | SSRF reaches internal services / cloud metadata via link preview | 2 | 3 | 6 | Host allowlist, HTTPS-only, resolved-IP re-check, no redirect follow | 1 | 3 | Mitigated |
| R5 | Broken access control -- student reaches admin pages directly | 2 | 3 | 6 | Server-side `Auth::requireAdmin()` role check on every admin request | 1 | 3 | Mitigated |
| R6 | Credential stuffing / brute force against login | 3 | 2 | 6 | Rate limiting + temporary lockout, generic error messages | 1 | 2 | Mitigated |
| R7 | Session fixation / hijacking | 2 | 3 | 6 | `session_regenerate_id()` on login; HttpOnly/Secure/SameSite cookies | 1 | 3 | Mitigated |
| R8 | Malicious file upload (disguised executable) | 2 | 3 | 6 | Content-sniffed MIME validation, random filenames, storage outside web root | 1 | 3 | Mitigated |
| R9 | Verbose errors / debug output leak internals | 2 | 2 | 4 | `display_errors` fails closed; generic user-facing error messages | 1 | 2 | Mitigated |
| R10 | Password database compromise leads to fast offline cracking | 2 | 3 | 6 | Argon2id hashing (memory-hard, tunable cost) replacing MD5 | 1 | 3 | Mitigated |
| R11 | Race condition over-subscribes a capacity-limited course | 2 | 1 | 2 | `SELECT ... FOR UPDATE` inside a transaction | 1 | 1 | Mitigated |
| R12 | No MFA -- a leaked password alone is sufficient for full account takeover | 3 | 2 | 6 | *(not implemented in this scope)* | 3 | 6 | **Accepted / Recommended for future work** |
| R13 | No WAF/DDoS protection at the network edge | 2 | 2 | 4 | *(out of scope -- infrastructure-level control)* | 2 | 4 | **Accepted / Recommended for future work** |
| R14 | No automated dependency/vulnerability scanning in CI | 2 | 2 | 4 | *(out of scope -- manual review only in this assignment)* | 2 | 4 | **Accepted / Recommended for future work** |

## Recommendations for future iterations
1. Add TOTP-based multi-factor authentication for admin accounts (R12).
2. Place the application behind a WAF/CDN with basic DDoS mitigation (R13).
3. Integrate a dependency scanner (e.g. `composer audit` equivalent, or a
   SAST tool) into a CI pipeline (R14).
4. Add a CAPTCHA or proof-of-work challenge after repeated failed logins,
   as a layer in addition to rate limiting.
