<?php
/**
 * VULNERABLE BASELINE -- FOR REPORT COMPARISON ONLY. Not routed.
 * Finding: SQL Injection via unparameterized LIKE search.
 */
$search = $_GET['q'];
$conn = new mysqli('127.0.0.1', 'root', 'root', 'student_registration');

// VULNERABLE: search term concatenated straight into the query.
// A value of  %' OR '1'='1  turns the WHERE clause into an
// always-true condition, dumping the entire users table
// (including password hashes) to any authenticated user who can
// reach this page.
$sql = "SELECT * FROM users WHERE full_name LIKE '%$search%' OR matric_no LIKE '%$search%'";
$result = $conn->query($sql);
