<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$errors = [];
$old = ['matric_no' => '', 'email' => '', 'full_name' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', null, Logger::clientIp(), ['form' => 'register']);
        $errors[] = 'Your session expired. Please reload the form and try again.';
    } else {
        $matric   = trim((string) ($_POST['matric_no'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $fullName = trim((string) ($_POST['full_name'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['password_confirm'] ?? '');

        $old = ['matric_no' => $matric, 'email' => $email, 'full_name' => $fullName];

        if (!Validator::isMatricNo($matric)) {
            $errors[] = 'Matric number format is invalid.';
        }
        if (!Validator::isEmail($email)) {
            $errors[] = 'Email address is invalid.';
        }
        if ($fullName === '' || mb_strlen($fullName) > 120) {
            $errors[] = 'Full name is required (max 120 characters).';
        }
        if (!Validator::isStrongPassword($password)) {
            $errors[] = 'Password must be between 10 and 128 characters.';
        }
        if ($password !== $confirm) {
            $errors[] = 'Password confirmation does not match.';
        }

        if (!$errors) {
            // Uniqueness relies on the UNIQUE constraints in the DB
            // schema as the authoritative check (race-safe); this
            // pre-check only improves the error message.
            $exists = Database::run(
                'SELECT id FROM users WHERE email = ? OR matric_no = ? LIMIT 1',
                [$email, $matric]
            )->fetch();

            if ($exists) {
                // Deliberately generic: do not say which of the two fields collided.
                $errors[] = 'An account with these details already exists.';
                Logger::log('validation_rejected', $email, Logger::clientIp(), ['field' => 'duplicate_account']);
            } else {
                Database::run(
                    'INSERT INTO users (matric_no, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, "student")',
                    [$matric, $email, Auth::hashPassword($password), $fullName]
                );
                Logger::log('account_created', $email, Logger::clientIp());
                header('Location: /login.php?registered=1');
                exit;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - Student Registration</title>
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
        <span class="eyebrow">New Account</span>
        <h1>Create an Account</h1>

        <?php if ($errors): ?>
            <div class="stamp stamp-error">
                Registration rejected
                <ul>
                    <?php foreach ($errors as $err): ?>
                        <li><?= e($err) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="/register.php" autocomplete="off">
            <?= Csrf::field() ?>
            <label for="matric_no">Matric Number</label>
            <input type="text" id="matric_no" name="matric_no" value="<?= e($old['matric_no']) ?>" required maxlength="20">

            <label for="email">Email</label>
            <input type="email" id="email" name="email" value="<?= e($old['email']) ?>" required maxlength="190">

            <label for="full_name">Full Name</label>
            <input type="text" id="full_name" name="full_name" value="<?= e($old['full_name']) ?>" required maxlength="120">

            <label for="password">Password (min 10 characters)</label>
            <input type="password" id="password" name="password" required minlength="10" maxlength="128">

            <label for="password_confirm">Confirm Password</label>
            <input type="password" id="password_confirm" name="password_confirm" required minlength="10" maxlength="128">

            <button type="submit">Register</button>
        </form>

        <p><a href="/login.php">Already have an account? Log in</a></p>
    </main>
</body>
</html>
