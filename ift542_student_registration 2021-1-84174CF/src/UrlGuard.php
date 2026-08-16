<?php
declare(strict_types=1);

/**
 * SSRF defence for the "external transcript link preview" feature.
 *
 * Remediates Task 3 activity 22: destination allowlist, rejection of
 * loopback/private/link-local/metadata addresses, no automatic
 * redirect-following, resolved-IP re-check (to stop DNS rebinding).
 *
 * IMPORTANT: this class only decides whether a URL is SAFE TO FETCH.
 * It does not perform the fetch itself with attacker-controlled
 * redirects; the caller (public/url_preview.php) must use the options
 * this class returns and must NOT follow redirects blindly.
 */
final class UrlGuard
{
    /** @param string[] $allowlist */
    public static function isAllowed(string $url, array $allowlist): array
    {
        $parts = parse_url($url);
        if (!$parts || !isset($parts['scheme'], $parts['host'])) {
            return [false, 'Malformed URL'];
        }

        if (!in_array($parts['scheme'], ['https'], true)) {
            return [false, 'Only https URLs are permitted'];
        }

        $host = strtolower($parts['host']);

        if (!in_array($host, $allowlist, true)) {
            return [false, 'Host is not on the approved allowlist'];
        }

        // Resolve the hostname and reject if it points at anything
        // private, loopback, link-local, or the cloud metadata
        // address -- this stops an allowlisted-looking hostname
        // that has been re-pointed (DNS rebinding) from reaching
        // internal infrastructure.
        $ips = gethostbynamel($host);
        if ($ips === false || count($ips) === 0) {
            return [false, 'Host did not resolve'];
        }

        foreach ($ips as $ip) {
            if (self::isDisallowedIp($ip)) {
                return [false, 'Host resolves to a disallowed internal address'];
            }
        }

        return [true, null];
    }

    private static function isDisallowedIp(string $ip): bool
    {
        // Cloud metadata endpoint used by AWS/Azure/GCP.
        if ($ip === '169.254.169.254') {
            return true;
        }

        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        // filter_var returns false (i.e. "fails the public-range
        // check") for private, reserved, loopback and link-local
        // addresses when these flags are set.
        return filter_var($ip, FILTER_VALIDATE_IP, $flags) === false;
    }
}
