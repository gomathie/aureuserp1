<?php

/*
 * Localhost-only gatekeeper for Adminer. The real Adminer source lives
 * outside public/ (storage/app/adminer/adminer-source.php) specifically so
 * requesting it directly can't bypass this check.
 *
 * Adminer authenticates against the database directly, not through the
 * app, so this file is never safe to expose beyond the machine running it.
 */

$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';

$allowedIps = ['127.0.0.1', '::1'];

// Docker Desktop (Mac/Windows) shows host-originated requests as its
// internal gateway IP, not 127.0.0.1. Resolve it dynamically rather than
// hardcoding it, since it can change across Docker Desktop versions/restarts.
// On a real server with no Docker involved, this resolution just fails and
// falls back to strict loopback-only, which is the correct behavior there.
$dockerHostIp = @gethostbyname('host.docker.internal');
if ($dockerHostIp !== 'host.docker.internal') {
    $allowedIps[] = $dockerHostIp;
}

if (! in_array($clientIp, $allowedIps, true)) {
    http_response_code(404);
    exit;
}

require __DIR__.'/../storage/app/adminer/adminer-source.php';
