<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$user = Auth::requireLogin();
$notice = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', $user['email'], Logger::clientIp(), ['form' => 'course_enrol']);
        $error = 'Your session expired. Please reload the page and try again.';
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $courseId = (int) ($_POST['course_id'] ?? 0);

        if ($action === 'enrol') {
            // Capacity check + insert wrapped so a full course cannot
            // be over-subscribed by concurrent requests.
            $pdo = Database::connection();
            $pdo->beginTransaction();
            try {
                $course = Database::run(
                    'SELECT id, capacity FROM courses WHERE id = ? FOR UPDATE',
                    [$courseId]
                )->fetch();

                $count = Database::run(
                    'SELECT COUNT(*) AS n FROM enrolments WHERE course_id = ? AND status = "active"',
                    [$courseId]
                )->fetch();

                if (!$course) {
                    $error = 'Course not found.';
                } elseif ((int) $count['n'] >= (int) $course['capacity']) {
                    $error = 'This course is full.';
                } else {
                    Database::run(
                        'INSERT INTO enrolments (student_id, course_id, status) VALUES (?, ?, "active")
                         ON DUPLICATE KEY UPDATE status = "active"',
                        [$user['id'], $courseId]
                    );
                    $notice = 'Enrolled successfully.';
                }
                $pdo->commit();
            } catch (\Throwable $e) {
                $pdo->rollBack();
                $error = 'Could not process enrolment. Please try again.';
            }
        } elseif ($action === 'drop') {
            Database::run(
                'UPDATE enrolments SET status = "dropped" WHERE student_id = ? AND course_id = ?',
                [$user['id'], $courseId]
            );
            $notice = 'Dropped course.';
        }
        Csrf::rotate();
    }
}

$courses = Database::run(
    'SELECT c.id, c.code, c.title, c.credit_units, c.capacity,
            (SELECT COUNT(*) FROM enrolments e WHERE e.course_id = c.id AND e.status = "active") AS taken,
            EXISTS(SELECT 1 FROM enrolments e2 WHERE e2.course_id = c.id AND e2.student_id = ? AND e2.status = "active") AS enrolled
     FROM courses c ORDER BY c.code',
    [$user['id']]
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Courses - Student Registration</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <?php $activeNav = 'courses'; require __DIR__ . '/partials/nav.php'; ?>

    <main class="sheet">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Course Catalog</span>
        <h1>Available Courses</h1>
        <?php if ($notice): ?><div class="stamp stamp-notice"><?= e($notice) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>

        <table>
            <tr><th>Code</th><th>Title</th><th>Units</th><th>Seats</th><th>Action</th></tr>
            <?php foreach ($courses as $c): ?>
            <tr>
                <td class="mono"><?= e($c['code']) ?></td>
                <td><?= e($c['title']) ?></td>
                <td><?= (int) $c['credit_units'] ?></td>
                <td><?= (int) $c['taken'] ?> / <?= (int) $c['capacity'] ?></td>
                <td>
                    <!--
                        CSRF remediation note: the vulnerable baseline used
                        a bare GET link like enrol.php?course_id=7, which a
                        forged <img>/<form> on another site could trigger
                        automatically using the victim's session cookie.
                        Enrolment/drop is now a POST form carrying the
                        per-session CSRF token, verified server-side above.
                    -->
                    <form method="post" action="/courses.php" style="margin:0;">
                        <?= Csrf::field() ?>
                        <input type="hidden" name="course_id" value="<?= (int) $c['id'] ?>">
                        <?php if ($c['enrolled']): ?>
                            <input type="hidden" name="action" value="drop">
                            <button type="submit">Drop</button>
                        <?php else: ?>
                            <input type="hidden" name="action" value="enrol">
                            <button type="submit" <?= ((int) $c['taken'] >= (int) $c['capacity']) ? 'disabled' : '' ?>>Enrol</button>
                        <?php endif; ?>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </main>
</body>
</html>
