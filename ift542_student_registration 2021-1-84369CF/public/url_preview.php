<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

/**
 * Feature: a student can ask the server to fetch and display the
 * page <title> of an external "transcript verification" link
 * before submitting it, so they can confirm they pasted the right
 * URL. This is the classic SSRF-prone pattern (Task 3 activity 22):
 * a server-side fetch of a user-supplied URL.
 *
 * Baseline vulnerable version (see legacy/url_preview_vulnerable.php):
 * called file_get_contents($_POST['url']) directly, so an attacker
 * could submit http://169.254.169.254/... or http://localhost:3306
 * and have the SERVER make that request on their behalf, exfiltrating
 * internal responses back into the page.
 *
 * Hardened version below:
 *   1. Only https URLs on an explicit allowlist are ever fetched.
 *   2. The resolved IP is re-checked against private/loopback/
 *      link-local/metadata ranges (blocks DNS rebinding).
 *   3. curl is configured to NOT follow redirects, so an allowlisted
 *      URL can't 302 the request somewhere disallowed.
 *   4. A short timeout and small max-body-size bound the request.
 */

$user = Auth::requireLogin();
$preview = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', $user['email'], Logger::clientIp(), ['form' => 'url_preview']);
        $error = 'Your session expired. Please reload the page and try again.';
    } else {
        $url = trim((string) ($_POST['url'] ?? ''));
        [$allowed, $reason] = UrlGuard::isAllowed($url, $config['url_preview_allowlist']);

        if (!$allowed) {
            $error = 'That URL cannot be previewed: ' . $reason;
            Logger::log('ssrf_blocked', $user['email'], Logger::clientIp(), ['url' => $url, 'reason' => $reason]);
        } else {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false, // never auto-follow redirects
                CURLOPT_TIMEOUT        => 3,
                CURLOPT_MAXFILESIZE    => 65536,
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            ]);
            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($body === false || $status >= 300) {
                $error = 'Could not fetch a preview for that URL.';
            } else {
                if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) {
                    $preview = trim($m[1]);
                } else {
                    $preview = '(no title found)';
                }
            }
        }
        Csrf::rotate();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Link Preview - Student Registration</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <?php $activeNav = 'preview'; require __DIR__ . '/partials/nav.php'; ?>

    <main class="sheet">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Verification Utility</span>
        <h1>Preview a Transcript Verification Link</h1>
        <p>Allowed hosts: <span class="mono"><?= e(implode(', ', $config['url_preview_allowlist'])) ?></span></p>

        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>
        <?php if ($preview !== null): ?><div class="stamp stamp-notice">Page title: <?= e($preview) ?></div><?php endif; ?>

        <form method="post" action="/url_preview.php">
            <?= Csrf::field() ?>
            <label for="url">URL</label>
            <input type="url" id="url" name="url" required maxlength="2048" placeholder="https://verifieddocs.test/...">
            <button type="submit">Preview</button>
        </form>
    </main>
</body>
</html>
