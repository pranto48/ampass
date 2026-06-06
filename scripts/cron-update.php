<?php
/**
 * AMPass — Automatic Update Cron Script (CLI only)
 * 
 * Checks for updates and applies them if available.
 * Run this script via cPanel Cron Jobs every hour:
 *   php /path/to/ampass/scripts/cron-update.php
 * 
 * SECURITY: This script is CLI-only.
 */

if (php_sapi_name() !== 'cli') {
    die("CLI only\n");
}

$rootDir = realpath(__DIR__ . '/..');
if (!$rootDir) {
    fwrite(STDERR, "ERROR: Cannot determine project root\n");
    exit(1);
}

// Bootstrap AMPass
require_once $rootDir . '/ampass/config/config.php';
require_once $rootDir . '/ampass/app/core/Database.php';
require_once $rootDir . '/ampass/app/services/UpdateService.php';
require_once $rootDir . '/ampass/app/services/BackupService.php';

try {
    $enabled = UpdateService::getSetting('auto_update_enabled', '0') === '1';
    if (!$enabled) {
        echo "Auto-update is disabled in settings.\n";
        exit(0);
    }

    echo "Running AMPass Auto-Update Check...\n";

    // 1. Check preflight blockers
    if (UpdateService::hasPreflightBlockers()) {
        fwrite(STDERR, "ERROR: Auto-update blocked: preflight checks failed.\n");
        exit(1);
    }

    // 2. Check for updates
    $check = UpdateService::checkForUpdates();
    if (!empty($check['error'])) {
        fwrite(STDERR, "ERROR: Update check failed: " . $check['error'] . "\n");
        exit(1);
    }

    if (!$check['update_available']) {
        echo "AMPass is already up to date. Version: " . UpdateService::getInstalledVersionDisplay() . "\n";
        exit(0);
    }

    echo "Update available! Upgrading from " . UpdateService::getInstalledVersionDisplay() . " to " . ($check['latest_version_display'] ?: $check['latest_version']) . "...\n";

    // 3. Apply update
    $backupPassword = 'auto-' . bin2hex(random_bytes(8));
    $result = UpdateService::applyUpdate($backupPassword, 1);

    if ($result['success']) {
        $sync = UpdateService::syncVersionFromGitHub();
        echo "SUCCESS: AMPass updated to " . ($sync['display'] ?? 'latest') . ". Files updated: " . ($result['files_updated'] ?? 0) . "\n";
        exit(0);
    } else {
        fwrite(STDERR, "ERROR: Update failed: " . ($result['error'] ?? 'Unknown error') . "\n");
        exit(1);
    }

} catch (\Exception $e) {
    fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
    exit(1);
}
