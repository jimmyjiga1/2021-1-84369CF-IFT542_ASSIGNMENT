<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$user = Auth::requireLogin();
$notice = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', $user['email'], Logger::clientIp(), ['form' => 'profile_update']);
        $error = 'Your session expired. Please reload the page and try again.';
    } else {
        $fullName = trim((string) ($_POST['full_name'] ?? ''));
        $bio      = trim((string) ($_POST['bio'] ?? ''));

        if ($fullName === '' || mb_strlen($fullName) > 120) {
            $error = 'Full name is required (max 120 characters).';
        } elseif (!Validator::isBio($bio)) {
            $error = 'Bio must be 500 characters or fewer.';
        } else {
            // Parameterised update -- the bio value is stored exactly
            // as typed. Safety comes from ENCODING IT ON OUTPUT (see
            // e() calls below), not from stripping input.
            Database::run(
                'UPDATE users SET full_name = ?, bio = ? WHERE id = ?',
                [$fullName, $bio, $user['id']]
            );
            Csrf::rotate();
            $notice = 'Profile updated.';
            $user['full_name'] = $fullName;
            $user['bio'] = $bio;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Student Registration</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <?php $activeNav = 'profile'; require __DIR__ . '/partials/nav.php'; ?>

    <main class="sheet">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Student File &mdash; <?= e($user['matric_no']) ?></span>
        <h1>Welcome, <?= e($user['full_name']) ?></h1>

        <?php if ($notice): ?><div class="stamp stamp-notice"><?= e($notice) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>

        <h2>Edit Profile</h2>
        <!--
            Stored-XSS remediation note (see docs/stride_worksheet.md):
            The vulnerable baseline echoed `bio` directly into HTML
            ("echo $user['bio'];"), so a bio containing a <script> tag
            executed for every viewer of this page. Every dynamic value
            below is passed through e() (htmlspecialchars with ENT_QUOTES),
            which turns markup into inert text instead of executing it.
            This is paired with the response CSP header (script-src 'self')
            in src/SecurityHeaders.php as defence in depth.
        -->
        <form method="post" action="/dashboard.php">
            <?= Csrf::field() ?>
            <label for="full_name">Full Name</label>
            <input type="text" id="full_name" name="full_name" value="<?= e($user['full_name']) ?>" required maxlength="120">

            <label for="bio">Bio</label>
            <textarea id="bio" name="bio" rows="4" maxlength="500"><?= e($user['bio'] ?? '') ?></textarea>

            <button type="submit">Save</button>
        </form>
    </main>
</body>
</html>
