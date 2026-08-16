# Incident Response Runbook -- Student Registration Web Application

## Scope
Covers the four scenarios most likely to be triggered by the threats
identified in the STRIDE model: credential-stuffing/brute-force,
attempted SQL injection, attempted SSRF, and a suspected account
compromise.

## Detection sources
- `storage/logs/security.log` (JSON lines, append-only)
- `security_events` table (same events, queryable with SQL)
- Web server access log (request rate, status codes, unusual paths)
- Database slow-query log (unusually expensive or malformed queries)

Key event types to alert on: `login_rate_limited`, `login_denied_locked`,
`account_locked`, `csrf_rejected`, `ssrf_blocked`, `authorization_denied`,
`validation_rejected`.

## 1. Suspected brute-force / credential-stuffing attack

**Trigger:** spike in `login_failed` / `login_rate_limited` events from
one IP or against one account within a short window.

1. **Identify** -- query recent events:
   ```sql
   SELECT * FROM security_events
   WHERE event_type IN ('login_failed','login_rate_limited','account_locked')
     AND created_at > NOW() - INTERVAL 1 HOUR
   ORDER BY created_at DESC;
   ```
2. **Contain** -- the application already rate-limits and locks the
   targeted account automatically. If the source IP is hitting many
   different accounts (stuffing), block the IP at the firewall/WAF.
3. **Eradicate** -- no code change needed if the built-in control held;
   if an account shows a *successful* login immediately after a burst
   of failures, treat as a suspected compromise (see Section 4).
4. **Recover** -- lift IP block once the source is confirmed stopped for
   a full observation window (e.g. 24 hours).
5. **Report** -- record start/end time, source IP(s), accounts targeted,
   whether any login ultimately succeeded, actions taken.

## 2. Suspected SQL injection attempt

**Trigger:** `validation_rejected` events with `field` indicating a
malformed identifier/search term containing SQL metacharacters
(quotes, `--`, `UNION`, etc.), or a spike of malformed requests to
`/admin/students.php` or `/login.php`.

1. **Identify** -- pull the raw request logs for the source IP/session
   around the event timestamp; confirm the payload shape.
2. **Contain** -- confirm the request was rejected by validation (it
   should have been, since parameterised queries mean even a
   successfully-submitted payload cannot alter query structure). If
   requests are succeeding in ways that look like data exfiltration
   (e.g. abnormal response sizes), take the affected endpoint offline
   immediately pending review.
3. **Eradicate** -- review `src/Database.php` usage across the codebase
   (`grep -rn "Database::run" public/ src/`) to confirm every call site
   still uses bound parameters; no raw string interpolation into SQL.
4. **Recover** -- redeploy the confirmed-clean codebase; rotate the DB
   credentials if there is any indication a query actually executed
   with attacker-controlled structure.
5. **Report** -- payload used, endpoint, whether it was blocked at the
   validation layer or reached the database layer, remediation applied.

## 3. Suspected SSRF attempt

**Trigger:** `ssrf_blocked` events, or outbound connections observed
from the application server to unexpected internal/link-local/metadata
addresses.

1. **Identify** -- query:
   ```sql
   SELECT * FROM security_events WHERE event_type = 'ssrf_blocked'
   ORDER BY created_at DESC LIMIT 50;
   ```
   and check `storage/logs/security.log` for the `url` and `reason`
   fields on those entries.
2. **Contain** -- confirm `UrlGuard::isAllowed()` rejected the request
   (expected outcome). If any outbound connection from the app server
   to a private/link-local/metadata address is observed in network
   logs despite this, disable the link-preview feature immediately
   (`public/url_preview.php`) pending investigation.
3. **Eradicate** -- review `config/config.php`'s
   `URL_PREVIEW_ALLOWLIST` for unintended entries; confirm
   `CURLOPT_FOLLOWLOCATION` remains `false`.
4. **Recover** -- re-enable the feature once the allowlist and guard
   logic are confirmed intact.
5. **Report** -- URL(s) attempted, whether any request actually left
   the server, remediation applied.

## 4. Suspected account compromise

**Trigger:** login from an unusual IP/geography immediately following a
failed-login burst, a user reporting unrecognised activity, or a
profile/enrolment change the account owner denies making.

1. **Identify** -- pull all `security_events` for the account (by
   `subject`) across the last 30 days; correlate login IPs, enrolment
   changes, and profile updates.
2. **Contain** -- force-expire the account's session (delete server-side
   session data / rotate the session-cookie secret if shared), then
   lock the account (insert a far-future `account_lockouts` row) pending
   user contact.
3. **Eradicate** -- require a password reset via the existing
   `password_reset_request.php` flow (single-use, hashed, 30-minute
   token) before unlocking; review whether any admin-privileged action
   occurred while compromised.
4. **Recover** -- unlock the account only after the password reset is
   confirmed complete and the user has re-verified their identity
   through an out-of-band channel (e.g. institutional email/ID check).
5. **Report** -- timeline of events, data potentially exposed
   (bio/profile/enrolment/documents), notification obligations under
   the institution's data-protection policy.

## General notification checklist (all scenarios)
- Note incident start/detection time and who detected it.
- Preserve `security.log` and the `security_events` table rows for the
  affected window (do not delete/rotate logs mid-investigation).
- Assess whether any student PII was exposed; if so, follow the
  institution's breach-notification procedure.
- After resolution, add a line to a post-incident log summarising
  root cause and any control gap the risk register should be updated
  to reflect.
