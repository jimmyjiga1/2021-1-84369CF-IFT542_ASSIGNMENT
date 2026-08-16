<?php
declare(strict_types=1);
/**
 * Usage: php scripts/generate_hash.php "YourChosenPassword"
 * Prints a real Argon2id hash you can paste into database/seed.sql.
 */
require __DIR__ . '/../src/Auth.php';

if ($argc < 2) {
    fwrite(STDERR, "Usage: php generate_hash.php <password>\n");
    exit(1);
}

echo Auth::hashPassword($argv[1]) . PHP_EOL;
