<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$error = null;
$notice = null;
$token = trim((string) ($_GET['token'] ?? $_POST['token'] ?? ''));

function findValidReset(string $rawToken): ?array
{
    if ($rawToken === '') {
        return null;
    }
    $hash = hash('sha256', $rawToken);
    $row = Database::run(
        'SELECT id, user_id FROM password_resets
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()
         LIMIT 1',
        [$hash]
    )->fetch();
    return $row ?: null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', null, Logger::clientIp(), ['form' => 'password_reset_confirm']);
        $error = 'Your session expired. Please reload the page and try again.';
    } else {
        $reset = findValidReset($token);
        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['password_confirm'] ?? '');

        if (!$reset) {
            $error = 'This reset link is invalid or has expired.';
        } elseif (!Validator::isStrongPassword($password)) {
            $error = 'Password must be between 10 and 128 characters.';
        } elseif ($password !== $confirm) {
            $error = 'Password confirmation does not match.';
        } else {
            $pdo = Database::connection();
            $pdo->beginTransaction();
            Database::run('UPDATE users SET password_hash = ? WHERE id = ?', [Auth::hashPassword($password), $reset['user_id']]);
            Database::run('UPDATE password_resets SET used_at = NOW() WHERE id = ?', [$reset['id']]);
            // Invalidate any other outstanding reset tokens for this user.
            Database::run('UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL', [$reset['user_id']]);
            $pdo->commit();

            Logger::log('password_reset_completed', (string) $reset['user_id'], Logger::clientIp());
            header('Location: /login.php?reset=1');
            exit;
        }
    }
} else {
    if (!findValidReset($token)) {
        $error = 'This reset link is invalid or has expired.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password - Student Registration</title>
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
        <h1>Reset Password</h1>
        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>

        <?php if (!$error): ?>
        <form method="post" action="/password_reset_confirm.php">
            <?= Csrf::field() ?>
            <input type="hidden" name="token" value="<?= e($token) ?>">
            <label for="password">New Password (min 10 characters)</label>
            <input type="password" id="password" name="password" required minlength="10" maxlength="128">
            <label for="password_confirm">Confirm New Password</label>
            <input type="password" id="password_confirm" name="password_confirm" required minlength="10" maxlength="128">
            <button type="submit">Reset Password</button>
        </form>
        <?php endif; ?>
    </main>
</body>
</html>
