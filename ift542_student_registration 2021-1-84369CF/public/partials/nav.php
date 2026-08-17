<?php
/**
 * Shared letterhead/nav for authenticated pages.
 * Expects $user in scope; optional $activeNav string to highlight a tab.
 */
$activeNav = $activeNav ?? '';
?>
<header class="letterhead">
    <div class="letterhead-inner">
        <a href="/dashboard.php" class="brand"><span class="brand-mark">&#9670;</span> Student Registry</a>
        <nav>
            <a href="/dashboard.php" <?= $activeNav === 'profile' ? 'aria-current="page"' : '' ?>>Profile</a>
            <a href="/courses.php" <?= $activeNav === 'courses' ? 'aria-current="page"' : '' ?>>Courses</a>
            <a href="/upload.php" <?= $activeNav === 'documents' ? 'aria-current="page"' : '' ?>>Documents</a>
            <a href="/url_preview.php" <?= $activeNav === 'preview' ? 'aria-current="page"' : '' ?>>Link Preview</a>
            <?php if ($user['role'] === 'admin'): ?>
                <a href="/admin/index.php" <?= $activeNav === 'admin' ? 'aria-current="page"' : '' ?>>Admin</a>
            <?php endif; ?>
            <a href="/logout.php">Log out</a>
        </nav>
    </div>
</header>
