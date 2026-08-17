<?php
declare(strict_types=1);
require __DIR__ . '/../bootstrap.php';

$admin = Auth::requireAdmin();

$search = trim((string) ($_GET['q'] ?? ''));

/*
 * SQL Injection remediation note (Task 2, primary finding):
 *
 * Vulnerable baseline (see legacy/admin_search_vulnerable.php):
 *   $sql = "SELECT * FROM users WHERE full_name LIKE '%$search%' OR matric_no LIKE '%$search%'";
 *   $result = $conn->query($sql);
 * A search value like  %' OR '1'='1  closed the quote early and
 * turned the WHERE clause into an always-true condition, dumping
 * every user (including password hashes) to an authenticated but
 * non-privileged view, and a stacked query could do far worse.
 *
 * Hardened version: PDO prepared statement, bound parameters. The
 * search string is data, never SQL text, no matter what characters
 * it contains.
 */
if ($search !== '' && strlen($search) <= 190) {
    $like = '%' . $search . '%';
    $students = Database::run(
        'SELECT id, matric_no, email, full_name, is_active FROM users
         WHERE role = "student" AND (full_name LIKE ? OR matric_no LIKE ? OR email LIKE ?)
         ORDER BY full_name',
        [$like, $like, $like]
    )->fetchAll();
} else {
    $students = Database::run(
        'SELECT id, matric_no, email, full_name, is_active FROM users WHERE role = "student" ORDER BY full_name'
    )->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Students - Admin</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <?php $activeNav = 'students'; require __DIR__ . '/../partials/admin_nav.php'; ?>

    <main class="sheet">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Student Records</span>
        <h1>Students</h1>
        <form method="get" action="/admin/students.php">
            <label for="q">Search by name, matric no. or email</label>
            <input type="text" id="q" name="q" value="<?= e($search) ?>" maxlength="190">
            <button type="submit">Search</button>
        </form>

        <table>
            <tr><th>Matric No.</th><th>Name</th><th>Email</th><th>Active</th></tr>
            <?php foreach ($students as $s): ?>
            <tr>
                <td class="mono"><?= e($s['matric_no']) ?></td>
                <td><?= e($s['full_name']) ?></td>
                <td><?= e($s['email']) ?></td>
                <td><?= $s['is_active'] ? 'Yes' : 'No' ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </main>
</body>
</html>
