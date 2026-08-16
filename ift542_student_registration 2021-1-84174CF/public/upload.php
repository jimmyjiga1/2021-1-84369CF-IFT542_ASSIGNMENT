<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$user = Auth::requireLogin();
$notice = null;
$error = null;

const ALLOWED_MIME = [
    'application/pdf' => 'pdf',
    'image/png'        => 'png',
    'image/jpeg'       => 'jpg',
];
const MAX_BYTES = 5 * 1024 * 1024; // 5 MB

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::verify($_POST['csrf_token'] ?? null)) {
        Logger::log('csrf_rejected', $user['email'], Logger::clientIp(), ['form' => 'upload']);
        $error = 'Your session expired. Please reload the page and try again.';
    } elseif (empty($_FILES['document']) || $_FILES['document']['error'] !== UPLOAD_ERR_OK) {
        $error = 'Upload failed. Please choose a file and try again.';
    } else {
        $file = $_FILES['document'];

        if ($file['size'] > MAX_BYTES) {
            $error = 'File is too large (max 5 MB).';
            Logger::log('validation_rejected', $user['email'], Logger::clientIp(), ['field' => 'upload_size']);
        } else {
            // Detect the real MIME type from file content, never trust
            // the client-supplied Content-Type or the filename extension.
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $detectedMime = $finfo->file($file['tmp_name']);

            if (!isset(ALLOWED_MIME[$detectedMime])) {
                $error = 'Only PDF, PNG or JPEG files are accepted.';
                Logger::log('validation_rejected', $user['email'], Logger::clientIp(), ['field' => 'upload_type', 'detected' => $detectedMime]);
            } else {
                $ext = ALLOWED_MIME[$detectedMime];
                // Random stored name -- never derive the on-disk path
                // from user input, which prevents path traversal and
                // overwrite/collision attacks via crafted filenames.
                $storedName = bin2hex(random_bytes(16)) . '.' . $ext;
                $destDir = __DIR__ . '/../storage/uploads';
                $dest = $destDir . '/' . $storedName;

                if (move_uploaded_file($file['tmp_name'], $dest)) {
                    Database::run(
                        'INSERT INTO documents (student_id, original_name, stored_name, mime_type, size_bytes)
                         VALUES (?, ?, ?, ?, ?)',
                        [$user['id'], mb_substr(basename($file['name']), 0, 255), $storedName, $detectedMime, $file['size']]
                    );
                    $notice = 'Document uploaded.';
                } else {
                    $error = 'Could not save the uploaded file.';
                }
            }
        }
        Csrf::rotate();
    }
}

$documents = Database::run(
    'SELECT original_name, mime_type, size_bytes, uploaded_at FROM documents WHERE student_id = ? ORDER BY uploaded_at DESC',
    [$user['id']]
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Documents - Student Registration</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <?php $activeNav = 'documents'; require __DIR__ . '/partials/nav.php'; ?>

    <main class="sheet">
        <span class="corner-bl"></span><span class="corner-br"></span>
        <span class="eyebrow">Supporting Documents</span>
        <h1>My Documents</h1>
        <?php if ($notice): ?><div class="stamp stamp-notice"><?= e($notice) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="stamp stamp-error"><?= e($error) ?></div><?php endif; ?>

        <form method="post" action="/upload.php" enctype="multipart/form-data">
            <?= Csrf::field() ?>
            <label for="document">Upload document (PDF, PNG or JPEG, max 5 MB)</label>
            <input type="file" id="document" name="document" required>
            <button type="submit">Upload</button>
        </form>

        <table>
            <tr><th>File</th><th>Type</th><th>Size</th><th>Uploaded</th></tr>
            <?php foreach ($documents as $d): ?>
            <tr>
                <td><?= e($d['original_name']) ?></td>
                <td class="mono"><?= e($d['mime_type']) ?></td>
                <td><?= number_format($d['size_bytes'] / 1024, 1) ?> KB</td>
                <td><?= e($d['uploaded_at']) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </main>
</body>
</html>
