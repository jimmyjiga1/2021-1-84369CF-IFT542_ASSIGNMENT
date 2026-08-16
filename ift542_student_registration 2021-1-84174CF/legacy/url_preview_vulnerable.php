<?php
/**
 * VULNERABLE BASELINE -- FOR REPORT COMPARISON ONLY. Not routed.
 * Finding: Server-Side Request Forgery (SSRF).
 *
 * The server fetches whatever URL the client supplies, with no
 * scheme restriction, no host allowlist, and no check on the
 * resolved IP address. An attacker can submit:
 *   http://169.254.169.254/latest/meta-data/iam/security-credentials/
 * (cloud metadata service) or http://127.0.0.1:3306/ to probe or
 * reach internal-only services through the trusted server, and the
 * response is reflected straight back into the page.
 */
$url = $_POST['url'];
$content = file_get_contents($url); // no scheme/host/IP checks, follows redirects by default
echo '<pre>' . $content . '</pre>'; // also unencoded output -> secondary XSS risk
