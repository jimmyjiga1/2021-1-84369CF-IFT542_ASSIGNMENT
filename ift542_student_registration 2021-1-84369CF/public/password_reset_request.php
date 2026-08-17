<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$notice = null;
$error = null;
$devLink = null; // only populated when app_debug is true, for local testing without an email server

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', null, Logger::clientIp(), ['form' => 'password_reset_request']);
        $error = 'Your session expired. Please reload the page and try again.';
    } else {
        $email = trim((string) ($_POST['email'] ?? ''));

        // Always show the same message whether or not the email
        // exists, so this form cannot be used to enumerate accounts.
        $notice = 'If that email is registered, a reset link has been generated.';

        if (Validator::isEmail($email)) {
            $user = Database::run('SELECT id FROM users WHERE email = ?', [$email])->fetch();
            if ($user) {
                $rawToken = bin2hex(random_bytes(32));
                $tokenHash = hash('sha256', $rawToken);

                Database::run(
                    'INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, NOW() + INTERVAL 30 MINUTE)',
                    [$user['id'], $tokenHash]
                );
                Logger::log('password_reset_requested', $email, Logger::clientIp());

                if ($config['app_debug']) {
                    $devLink = '/password_reset_confirm.php?token=' . urlencode($rawToken);
                }
                // In production this raw link is emailed to the user
                // and never displayed or logged -- only the hash is
                // persisted, so a database compromise alone cannot be
                // used to reset a password.
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
    <title>Forgot Password - Student Registration</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <header class="letterhead">
        <div class="letterhead-inner">
            <a href="/login.php" class="brand"><span class="brand-mark">&#9670;</span> Student Registry</a>
        </div>
    </header>

    <main class="sheet narrow">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Account Recovery</span>
        <h1>Forgot Password</h1>

        <?php if ($notice): ?><div class="stamp stamp-notice"><?= e($notice) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>
        <?php if ($devLink): ?>
            <div class="stamp stamp-notice">[Dev only] Reset link: <a href="<?= e($devLink) ?>"><?= e($devLink) ?></a></div>
        <?php endif; ?>

        <form method="post" action="/password_reset_request.php">
            <?= Csrf::field() ?>
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required maxlength="190">
            <button type="submit">Send reset link</button>
        </form>

        <p><a href="/login.php">Back to login</a></p>
    </main>
</body>
</html>
