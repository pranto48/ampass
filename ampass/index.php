<?php
/**
 * AMPass - Secure Password Vault
 * Main entry point / Front controller
 * 
 * SECURITY: This file routes all requests through the application.
 * Ensure .htaccess is properly configured to route all traffic here.
 */

// Check if installed — redirect to installer if config doesn't exist
if (!file_exists(__DIR__ . '/config/config.php')) {
    // Use relative redirect so it works in any subdirectory (XAMPP, cPanel, etc.)
    $scriptDir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
    header('Location: ' . $scriptDir . '/install/index.php');
    exit;
}

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/app/version.php';
require_once __DIR__ . '/app/core/App.php';
require_once __DIR__ . '/app/core/Database.php';
require_once __DIR__ . '/app/core/Session.php';
require_once __DIR__ . '/app/core/CSRF.php';
require_once __DIR__ . '/app/core/RateLimit.php';
require_once __DIR__ . '/app/core/Security.php';
require_once __DIR__ . '/app/core/GoogleAuthenticator.php';

// Initialize security headers
Security::setHeaders();

// Start secure session
Session::start();

// Check maintenance mode (allow admin access to critical admin pages)
$route = trim($_GET['route'] ?? '', '/');
$isAdminRoute = str_starts_with($route, 'admin/updates') || str_starts_with($route, 'admin/backups') || str_starts_with($route, 'admin/backupDestinations') || str_starts_with($route, 'admin/backup-destinations') || str_starts_with($route, 'admin/email');
$isApiRoute = str_starts_with($route, 'api/');
$isStaticAsset = str_starts_with($route, 'public/') || str_ends_with($route, '.css') || str_ends_with($route, '.js');

try {
    $maintenance = Database::fetchOne("SELECT setting_value FROM app_settings WHERE setting_key = 'maintenance_mode'");
    if ($maintenance && $maintenance['setting_value'] === '1' && !$isAdminRoute && !$isStaticAsset) {
        if ($isApiRoute) {
            header('Content-Type: application/json');
            http_response_code(503);
            echo json_encode(['error' => 'AMPass server is updating. Try again later.', 'code' => 'MAINTENANCE']);
            exit;
        }
        if (!Session::isAdmin()) {
            http_response_code(503);
            require __DIR__ . '/app/views/errors/maintenance.php';
            exit;
        }
    }
} catch (\Exception $e) { /* DB may not be ready */ }

// Route the request
$app = new App();
$app->run();
