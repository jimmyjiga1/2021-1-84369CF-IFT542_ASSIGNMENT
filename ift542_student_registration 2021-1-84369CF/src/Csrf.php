<?php
declare(strict_types=1);

/**
 * CSRF protection.
 *
 * Remediates Task 3 activity 21 (CSRF on course registration /
 * profile update).
 *
 * Approach: per-session token, verified with hash_equals to avoid
 * timing side-channels. Paired with SameSite=Lax/Strict on the
 * session cookie (see Session::start()) as defence in depth.
 */
final class Csrf
{
    public static function token(): string
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function field(): string
    {
        $token = htmlspecialchars(self::token(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="csrf_token" value="' . $token . '">';
    }

    public static function verify(?string $submitted): bool
    {
        if (empty($_SESSION['csrf_token']) || $submitted === null) {
            return false;
        }
        return hash_equals($_SESSION['csrf_token'], $submitted);
    }

    /** Call after verify() succeeds on a state-changing request to rotate the token. */
    public static function rotate(): void
    {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}
