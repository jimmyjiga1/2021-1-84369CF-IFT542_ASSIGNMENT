<?php
declare(strict_types=1);

/**
 * Input validation.
 *
 * Remediates Task 2 activity 12: validate email/auth inputs for
 * type, length and format before they ever reach a query or a view.
 */
final class Validator
{
    public static function isEmail(string $value): bool
    {
        return strlen($value) <= 190
            && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function isMatricNo(string $value): bool
    {
        // Example format: 2020/1/00001CS -- adjust to your institution's real pattern.
        return (bool) preg_match('/^[0-9]{4}\/[0-9]\/[0-9]{5}[A-Z]{2}$/', $value)
            && strlen($value) <= 20;
    }

    public static function isLoginIdentifier(string $value): bool
    {
        return self::isEmail($value) || self::isMatricNo($value);
    }

    public static function isStrongPassword(string $value): bool
    {
        // Length-based policy (NIST 800-63B style) rather than
        // forced character-class rules, which push users toward
        // predictable substitutions.
        return strlen($value) >= 10 && strlen($value) <= 128;
    }

    public static function isBio(string $value): bool
    {
        return strlen($value) <= 500;
    }

    public static function isCourseCode(string $value): bool
    {
        return (bool) preg_match('/^[A-Z]{3}[0-9]{3}$/', $value);
    }

    /** Generic "reject and log" helper used by controllers. */
    public static function requireOrFail(bool $condition, string $field, callable $onFail): void
    {
        if (!$condition) {
            $onFail($field);
        }
    }
}
