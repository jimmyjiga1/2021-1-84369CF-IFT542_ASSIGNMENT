<?php
/**
 * Shared letterhead/nav for admin pages.
 * Expects $admin in scope; optional $activeNav string to highlight a tab.
 */
$activeNav = $activeNav ?? '';
?>
<header class="letterhead">
    <div class="letterhead-inner">
        <a href="/admin/index.php" class="brand"><span class="brand-mark">&#9670;</span> Student Registry <span style="opacity:.55; font-weight:500;">&mdash; Admin</span></a>
        <nav>
            <a href="/dashboard.php">My Profile</a>
            <a href="/admin/index.php" <?= $activeNav === 'admin' ? 'aria-current="page"' : '' ?>>Overview</a>
            <a href="/admin/students.php" <?= $activeNav === 'students' ? 'aria-current="page"' : '' ?>>Students</a>
            <a href="/admin/courses.php" <?= $activeNav === 'courses' ? 'aria-current="page"' : '' ?>>Manage Courses</a>
            <a href="/logout.php">Log out</a>
        </nav>
    </div>
</header>
