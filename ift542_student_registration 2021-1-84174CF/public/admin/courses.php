<?php
declare(strict_types=1);
require __DIR__ . '/../bootstrap.php';

$admin = Auth::requireAdmin();
$notice = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', $admin['email'], Logger::clientIp(), ['form' => 'admin_course_create']);
        $error = 'Your session expired. Please reload the page and try again.';
    } else {
        $code = strtoupper(trim((string) ($_POST['code'] ?? '')));
        $title = trim((string) ($_POST['title'] ?? ''));
        $units = (int) ($_POST['credit_units'] ?? 0);
        $capacity = (int) ($_POST['capacity'] ?? 0);

        if (!Validator::isCourseCode($code)) {
            $error = 'Course code must look like ABC123.';
        } elseif ($title === '' || mb_strlen($title) > 150) {
            $error = 'Title is required (max 150 characters).';
        } elseif ($units < 1 || $units > 6 || $capacity < 1 || $capacity > 500) {
            $error = 'Credit units (1-6) or capacity (1-500) out of range.';
        } else {
            try {
                Database::run(
                    'INSERT INTO courses (code, title, credit_units, capacity) VALUES (?, ?, ?, ?)',
                    [$code, $title, $units, $capacity]
                );
                $notice = 'Course added.';
            } catch (\PDOException $e) {
                $error = 'A course with that code already exists.';
            }
        }
        Csrf::rotate();
    }
}

$courses = Database::run('SELECT id, code, title, credit_units, capacity FROM courses ORDER BY code')->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Manage Courses - Admin</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <?php $activeNav = 'courses'; require __DIR__ . '/../partials/admin_nav.php'; ?>

    <main class="sheet">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Course Catalog Management</span>
        <h1>Manage Courses</h1>
        <?php if ($notice): ?><div class="stamp stamp-notice"><?= e($notice) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>

        <form method="post" action="/admin/courses.php">
            <?= Csrf::field() ?>
            <label for="code">Course Code (e.g. IFT530)</label>
            <input type="text" id="code" name="code" required maxlength="6">
            <label for="title">Title</label>
            <input type="text" id="title" name="title" required maxlength="150">
            <label for="credit_units">Credit Units</label>
            <input type="number" id="credit_units" name="credit_units" min="1" max="6" required>
            <label for="capacity">Capacity</label>
            <input type="number" id="capacity" name="capacity" min="1" max="500" required>
            <button type="submit">Add Course</button>
        </form>

        <table>
            <tr><th>Code</th><th>Title</th><th>Units</th><th>Capacity</th></tr>
            <?php foreach ($courses as $c): ?>
            <tr>
                <td class="mono"><?= e($c['code']) ?></td>
                <td><?= e($c['title']) ?></td>
                <td><?= (int) $c['credit_units'] ?></td>
                <td><?= (int) $c['capacity'] ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </main>
</body>
</html>
