<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

if (Auth::currentUser()) {
    header('Location: /dashboard.php');
} else {
    header('Location: /login.php');
}
exit;
