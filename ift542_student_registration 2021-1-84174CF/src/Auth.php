<?php
declare(strict_types=1);

/**
 * Authentication logic.
 *
 * Remediates Task 2 activities 13-14:
 *  - Argon2id password hashing (activity 13).
 *  - Rate limiting + temporary lockout, and session-ID regeneration
 *    on login (activity 14, "at least two additional controls").
 *
 * All account lookups happen by identifier first, then password
 * verification happens against the retrieved hash (never the other
 * way around), and every failure path returns the SAME generic
 * message so the login form does not reveal which part was wrong
 * (activity 12: generic errors, no user enumeration).
 */
final class Auth
{
    private const MAX_ATTEMPTS_PER_WINDOW = 5;
    private const WINDOW_MINUTES          = 15;
    private const LOCKOUT_MINUTES         = 15;

    public const GENERIC_ERROR = 'Invalid credentials, or this account is temporarily locked. Please try again later.';

    /**
     * @return array{ok:bool, user?:array, error?:string}
     */
    public static function attemptLogin(string $identifier, string $password, string $ip): array
    {
        $identifier = mb_strtolower(trim($identifier));

        if (self::isRateLimited($identifier, $ip)) {
            Logger::log('login_rate_limited', $identifier, $ip);
            return ['ok' => false, 'error' => self::GENERIC_ERROR];
        }

        if (self::isLockedOut($identifier)) {
            Logger::log('login_denied_locked', $identifier, $ip);
            return ['ok' => false, 'error' => self::GENERIC_ERROR];
        }

        $stmt = Database::run(
            'SELECT id, matric_no, email, password_hash, full_name, role, is_active
             FROM users WHERE email = ? OR matric_no = ? LIMIT 1',
            [$identifier, $identifier]
        );
        $user = $stmt->fetch();

        // Always run password_verify, even against a dummy hash when
        // no user was found, so the response time doesn't leak
        // whether the identifier exists (timing side-channel).
        $hashToCheck = $user['password_hash'] ?? self::dummyHash();
        $passwordOk  = password_verify($password, $hashToCheck);

        self::recordAttempt($identifier, $ip, $user && $passwordOk);

        if (!$user || !$passwordOk || !$user['is_active']) {
            Logger::log('login_failed', $identifier, $ip);
            self::registerFailureAndMaybeLock($identifier, $ip);
            return ['ok' => false, 'error' => self::GENERIC_ERROR];
        }

        self::clearFailures($identifier);

        // Session fixation defence: rotate the session ID on every
        // successful authentication before storing identity in it.
        Session::regenerate();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role']    = $user['role'];

        unset($user['password_hash']);
        return ['ok' => true, 'user' => $user];
    }

    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost'   => 4,
            'threads'     => 1,
        ]);
    }

    private static function dummyHash(): string
    {
        // A fixed, valid-format Argon2id hash of an unrelated random
        // string, purely so password_verify() has constant-ish work
        // to do even when the account doesn't exist.
        return '$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0c2E$OcXjM3l0m5m0YyG3s8w2N6u5s2wq0k9Xh3m2f9pQmC0';
    }

    private static function isRateLimited(string $identifier, string $ip): bool
    {
        $stmt = Database::run(
            'SELECT COUNT(*) AS n FROM login_attempts
             WHERE (identifier = ? OR ip_address = ?)
               AND success = 0
               AND attempted_at > (NOW() - INTERVAL ? MINUTE)',
            [$identifier, $ip, self::WINDOW_MINUTES]
        );
        return (int) $stmt->fetch()['n'] >= self::MAX_ATTEMPTS_PER_WINDOW;
    }

    private static function recordAttempt(string $identifier, string $ip, bool $success): void
    {
        Database::run(
            'INSERT INTO login_attempts (identifier, ip_address, success) VALUES (?, ?, ?)',
            [$identifier, $ip, $success ? 1 : 0]
        );
    }

    private static function registerFailureAndMaybeLock(string $identifier, string $ip): void
    {
        $stmt = Database::run('SELECT id FROM users WHERE email = ? OR matric_no = ? LIMIT 1', [$identifier, $identifier]);
        $user = $stmt->fetch();
        if (!$user) {
            return;
        }

        $countStmt = Database::run(
            'SELECT COUNT(*) AS n FROM login_attempts
             WHERE identifier = ? AND success = 0
               AND attempted_at > (NOW() - INTERVAL ? MINUTE)',
            [$identifier, self::WINDOW_MINUTES]
        );
        $failures = (int) $countStmt->fetch()['n'];

        if ($failures >= self::MAX_ATTEMPTS_PER_WINDOW) {
            Database::run(
                'INSERT INTO account_lockouts (user_id, locked_until, reason)
                 VALUES (?, NOW() + INTERVAL ? MINUTE, "too_many_failed_attempts")
                 ON DUPLICATE KEY UPDATE locked_until = NOW() + INTERVAL ? MINUTE',
                [$user['id'], self::LOCKOUT_MINUTES, self::LOCKOUT_MINUTES]
            );
            Logger::log('account_locked', $identifier, $ip, ['minutes' => self::LOCKOUT_MINUTES]);
        }
    }

    private static function isLockedOut(string $identifier): bool
    {
        $stmt = Database::run(
            'SELECT al.locked_until FROM account_lockouts al
             JOIN users u ON u.id = al.user_id
             WHERE (u.email = ? OR u.matric_no = ?) AND al.locked_until > NOW()
             LIMIT 1',
            [$identifier, $identifier]
        );
        return (bool) $stmt->fetch();
    }

    private static function clearFailures(string $identifier): void
    {
        Database::run(
            'DELETE al FROM account_lockouts al
             JOIN users u ON u.id = al.user_id
             WHERE u.email = ? OR u.matric_no = ?',
            [$identifier, $identifier]
        );
    }

    public static function currentUser(): ?array
    {
        if (empty($_SESSION['user_id'])) {
            return null;
        }
        $stmt = Database::run(
            'SELECT id, matric_no, email, full_name, bio, role FROM users WHERE id = ?',
            [$_SESSION['user_id']]
        );
        $user = $stmt->fetch();
        return $user ?: null;
    }

    public static function requireLogin(): array
    {
        $user = self::currentUser();
        if (!$user) {
            header('Location: /login.php');
            exit;
        }
        return $user;
    }

    public static function requireAdmin(): array
    {
        $user = self::requireLogin();
        if ($user['role'] !== 'admin') {
            Logger::log('authorization_denied', $user['email'], Logger::clientIp(), ['required_role' => 'admin']);
            http_response_code(403);
            echo 'Forbidden';
            exit;
        }
        return $user;
    }

    public static function logout(): void
    {
        Logger::log('logout', $_SESSION['user_id'] ?? null, Logger::clientIp());
        Session::destroy();
    }
}
