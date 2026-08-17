<?php
declare(strict_types=1);

/**
 * Session bootstrap.
 *
 * - Cookie flags: HttpOnly, Secure (in production), SameSite=Lax
 *   (defence in depth alongside the CSRF token).
 * - regenerate() is called on every privilege change (login,
 *   logout, role elevation) to prevent session fixation.
 */
final class Session
{
    public static function start(array $config): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        session_name($config['session']['name']);
        session_set_cookie_params([
            'lifetime' => $config['session']['lifetime'],
            'path'     => '/',
            'domain'   => '',
            'secure'   => $config['app_env'] === 'production',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();

        // Idle timeout enforcement.
        $lifetime = $config['session']['lifetime'];
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $lifetime) {
            self::destroy();
            session_start();
        }
        $_SESSION['last_activity'] = time();
    }

    public static function regenerate(): void
    {
        session_regenerate_id(true);
    }

    public static function destroy(): void
    {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
    }
}
