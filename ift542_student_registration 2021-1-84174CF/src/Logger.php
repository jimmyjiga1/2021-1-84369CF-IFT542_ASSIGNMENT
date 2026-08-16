<?php
declare(strict_types=1);

/**
 * Structured security-event logging.
 *
 * Remediates Task 3 activity 24: failed-login, denied-authorization
 * and rejected-validation logs with who/what/when, no secrets or
 * unnecessary personal data.
 *
 * Design rules enforced here:
 *  - Never accepts a "password" field; log() strips known-sensitive
 *    keys defensively even if a caller passes one by mistake.
 *  - Writes JSON Lines to storage/logs/security.log (append-only).
 *  - Mirrors the same event into the security_events DB table so
 *    the evidence can be queried with SQL as well as grepped.
 */
final class Logger
{
    private const REDACT_KEYS = ['password', 'password_confirm', 'token', 'raw_token', 'secret'];

    public static function log(string $eventType, ?string $subject, string $ip, array $detail = []): void
    {
        foreach (self::REDACT_KEYS as $key) {
            unset($detail[$key]);
        }

        $entry = [
            'ts'      => gmdate('c'),
            'event'   => $eventType,
            'subject' => $subject,
            'ip'      => $ip,
            'detail'  => $detail,
        ];

        $line = json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL;
        $logDir = __DIR__ . '/../storage/logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0750, true);
        }
        file_put_contents($logDir . '/security.log', $line, FILE_APPEND | LOCK_EX);

        try {
            Database::run(
                'INSERT INTO security_events (event_type, subject, ip_address, detail) VALUES (?, ?, ?, ?)',
                [$eventType, $subject, $ip, json_encode($detail, JSON_UNESCAPED_SLASHES)]
            );
        } catch (\Throwable $e) {
            // Logging must never crash the request. If the DB write
            // fails, the file-based log line above still exists.
        }
    }

    public static function clientIp(): string
    {
        // Deliberately simple and honest: trusts REMOTE_ADDR only.
        // Trusting X-Forwarded-For without a configured, trusted
        // reverse proxy list is itself a spoofing risk, so we don't.
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
}
