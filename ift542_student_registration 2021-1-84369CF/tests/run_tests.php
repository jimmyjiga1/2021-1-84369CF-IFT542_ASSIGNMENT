<?php
declare(strict_types=1);

/**
 * Lightweight test runner (no PHPUnit/Composer needed).
 * Run with:  php tests/run_tests.php
 *
 * Covers unit-level checks that don't need a live database
 * (Validator, Auth password hashing, Csrf, UrlGuard allowlist
 * logic). See tests/README.md for the manual DB-backed test plan
 * (login lockout, SQLi payloads, CSRF rejection, SSRF rejection)
 * that the evidence folder screenshots correspond to.
 */

require __DIR__ . '/../src/Validator.php';
require __DIR__ . '/../src/Auth.php';
require __DIR__ . '/../src/Csrf.php';
require __DIR__ . '/../src/UrlGuard.php';

$pass = 0;
$fail = 0;

function check(string $label, bool $condition): void
{
    global $pass, $fail;
    if ($condition) {
        $pass++;
        echo "  [PASS] $label\n";
    } else {
        $fail++;
        echo "  [FAIL] $label\n";
    }
}

echo "Validator\n";
check('valid email accepted', Validator::isEmail('student1@example.test'));
check('malformed email rejected', !Validator::isEmail('not-an-email'));
check('valid matric no accepted', Validator::isMatricNo('2020/1/00001CS'));
check('malformed matric no rejected', !Validator::isMatricNo("2020/1/00001CS' OR '1'='1"));
check('SQLi-shaped login identifier rejected by format check',
    !Validator::isLoginIdentifier("admin@example.test' -- "));
check('short password rejected', !Validator::isStrongPassword('short1'));
check('acceptable password accepted', Validator::isStrongPassword('correct-horse-battery'));
check('oversized bio rejected', !Validator::isBio(str_repeat('a', 501)));
check('course code format enforced', Validator::isCourseCode('IFT542') && !Validator::isCourseCode('bad code'));

echo "\nAuth password hashing\n";
$hash = Auth::hashPassword('Tr0ub4dor&3');
check('hash uses Argon2id', str_starts_with($hash, '$argon2id$'));
check('correct password verifies', password_verify('Tr0ub4dor&3', $hash));
check('incorrect password fails verification', !password_verify('wrong-password', $hash));

echo "\nCSRF tokens\n";
session_id('test-session-' . bin2hex(random_bytes(4)));
@session_start();
$token = Csrf::token();
check('token is non-empty and 64 hex chars', (bool) preg_match('/^[0-9a-f]{64}$/', $token));
check('correct token verifies', Csrf::verify($token));
check('tampered token is rejected', !Csrf::verify($token . 'x'));
check('missing token is rejected', !Csrf::verify(null));

echo "\nSSRF allowlist (UrlGuard)\n";
$allowlist = ['verifieddocs.test'];
[$ok1, $why1] = UrlGuard::isAllowed('https://evil.test/steal', $allowlist);
check('non-allowlisted host rejected', !$ok1 && $why1 !== null);
[$ok2, $why2] = UrlGuard::isAllowed('http://verifieddocs.test/x', $allowlist);
check('non-https scheme rejected even if host matches', !$ok2);
[$ok3, $why3] = UrlGuard::isAllowed('not a url', $allowlist);
check('malformed URL rejected', !$ok3);

echo "\n----------------------------------------\n";
echo "Total: " . ($pass + $fail) . "  Passed: $pass  Failed: $fail\n";
exit($fail > 0 ? 1 : 0);
