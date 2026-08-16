<?php
/**
 * ================================================================
 *  VULNERABLE BASELINE -- FOR REPORT COMPARISON ONLY.
 *  This file is NOT included/routed anywhere in public/. It exists
 *  purely so the technical report can quote real before/after code
 *  side by side. Do not deploy or execute this file.
 * ================================================================
 *
 * Findings demonstrated here:
 *  1. SQL Injection -- string concatenation builds the query.
 *  2. Plaintext-equivalent password check -- md5() is fast and
 *     unsalted, making offline cracking trivial if the DB leaks.
 *  3. No rate limiting -- unlimited guesses per second.
 *  4. Verbose errors -- raw DB error text returned to the client,
 *     which leaks schema/column names to an attacker.
 */

$identifier = $_POST['identifier']; // no validation
$password   = $_POST['password'];

$conn = new mysqli('127.0.0.1', 'root', 'root', 'student_registration');

// VULNERABLE: user input concatenated directly into SQL.
// Payload identifier = admin@example.test' -- 
// comments out the password check entirely.
$sql = "SELECT * FROM users WHERE email = '$identifier' AND password = '" . md5($password) . "'";
$result = $conn->query($sql);

if ($result === false) {
    // VULNERABLE: leaks internal error detail to the client.
    die('Query failed: ' . $conn->error . ' SQL was: ' . $sql);
}

if ($result->num_rows === 1) {
    session_start();
    $row = $result->fetch_assoc();
    $_SESSION['user_id'] = $row['id']; // no session_regenerate_id() -> fixation risk
    header('Location: dashboard.php');
} else {
    // VULNERABLE: distinct messages let an attacker enumerate valid emails.
    echo 'No account found with that email.';
}
