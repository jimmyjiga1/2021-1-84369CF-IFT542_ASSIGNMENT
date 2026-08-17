<?php
declare(strict_types=1);

// Simple PSR-4-ish autoloader for src/ classes -- no Composer needed.
spl_autoload_register(function (string $class): void {
    $path = __DIR__ . '/../src/' . $class . '.php';
    if (is_file($path)) {
        require $path;
    }
});

$config = require __DIR__ . '/../config/config.php';

// Fail closed on unexpected errors: never leak stack traces/paths
// to the client, regardless of php.ini defaults on the server.
ini_set('display_errors', $config['app_debug'] ? '1' : '0');
error_reporting($config['app_debug'] ? E_ALL : 0);

Session::start($config);
SecurityHeaders::apply($config['app_debug']);
