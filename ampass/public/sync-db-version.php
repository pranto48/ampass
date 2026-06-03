<?php
// Set headers to prevent caching
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Content-Type: text/plain');

$configPath = __DIR__ . '/../config/config.php';
if (!file_exists($configPath)) {
    die("ERROR: config.php not found at: " . realpath($configPath));
}

require_once $configPath;
require_once __DIR__ . '/../app/core/Database.php';
require_once __DIR__ . '/../app/core/Security.php';
require_once __DIR__ . '/../app/version.php';
require_once __DIR__ . '/../app/services/UpdateService.php';

try {
    // Synchronize both installed and latest version settings in the DB
    UpdateService::saveSetting('installed_commit_count', (string)AMPASS_COMMIT_COUNT);
    UpdateService::saveSetting('installed_commit_sha', AMPASS_COMMIT_SHA);
    UpdateService::saveSetting('installed_version', AMPASS_VERSION_SEMVER);
    UpdateService::saveSetting('installed_version_display', AMPASS_VERSION_DISPLAY);
    UpdateService::saveSetting('installed_version_semver', AMPASS_VERSION_SEMVER);

    UpdateService::saveSetting('latest_commit_count', (string)AMPASS_COMMIT_COUNT);
    UpdateService::saveSetting('latest_commit_sha', AMPASS_COMMIT_SHA);
    UpdateService::saveSetting('latest_version', AMPASS_VERSION_SEMVER);
    UpdateService::saveSetting('latest_version_display', AMPASS_VERSION_DISPLAY);
    UpdateService::saveSetting('latest_version_semver', AMPASS_VERSION_SEMVER);
    
    UpdateService::saveSetting('update_available', '0');

    echo "SUCCESS: Database version synchronized to " . AMPASS_VERSION_DISPLAY . " (" . AMPASS_VERSION_SEMVER . ")\n";
} catch (\Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
}

// Self-destruct for security
@unlink(__FILE__);
