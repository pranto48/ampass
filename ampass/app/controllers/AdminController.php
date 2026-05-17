<?php
/**
 * AMPass - Admin Controller
 * SECURITY: All admin routes require admin role verification.
 */

require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../models/AuditLog.php';
require_once __DIR__ . '/../models/ExtensionDevice.php';
require_once __DIR__ . '/../models/ExtensionAudit.php';
require_once __DIR__ . '/../models/ExtensionToken.php';

class AdminController {

    public function __construct() {
        if (!Session::isAdmin()) {
            http_response_code(403);
            die('Access denied');
        }
    }

    public function index(): void {
        $totalUsers = User::count();
        $users = User::getAll(20, 0);
        $recentLogs = AuditLog::getAll(20);

        $data = [
            'totalUsers' => $totalUsers,
            'users' => $users,
            'recentLogs' => $recentLogs,
            'csrfToken' => CSRF::generateToken()
        ];

        require __DIR__ . '/../views/admin/index.php';
    }

    public function users(): void {
        $page = max(1, (int)($_GET['page'] ?? 1));
        $limit = 20;
        $offset = ($page - 1) * $limit;

        $users = User::getAll($limit, $offset);
        $totalUsers = User::count();

        $data = [
            'users' => $users,
            'totalUsers' => $totalUsers,
            'currentPage' => $page,
            'totalPages' => ceil($totalUsers / $limit),
            'csrfToken' => CSRF::generateToken()
        ];

        require __DIR__ . '/../views/admin/users.php';
    }

    public function suspendUser(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/users');
            exit;
        }
        CSRF::validateOrFail();

        $userId = (int)($_POST['user_id'] ?? 0);
        if ($userId && $userId !== Session::getUserId()) {
            User::suspend($userId);
            AuditLog::log('user_suspended', Session::getUserId(), 'user', $userId);
        }

        header('Location: ' . APP_URL . '/admin/users');
        exit;
    }

    public function activateUser(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/users');
            exit;
        }
        CSRF::validateOrFail();

        $userId = (int)($_POST['user_id'] ?? 0);
        if ($userId) {
            User::activate($userId);
            AuditLog::log('user_activated', Session::getUserId(), 'user', $userId);
        }

        header('Location: ' . APP_URL . '/admin/users');
        exit;
    }

    public function settings(): void {
        $csrfToken = CSRF::generateToken();
        
        // Get current settings
        $settings = Database::fetchAll("SELECT setting_key, setting_value FROM app_settings");
        $settingsMap = [];
        foreach ($settings as $s) {
            $settingsMap[$s['setting_key']] = $s['setting_value'];
        }

        $data = [
            'settings' => $settingsMap,
            'csrfToken' => $csrfToken
        ];

        require __DIR__ . '/../views/admin/settings.php';
    }

    public function saveSettings(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/settings');
            exit;
        }
        CSRF::validateOrFail();

        $allowedSettings = ['site_name', 'registration_enabled', 'vault_lock_timeout', 'max_login_attempts', 'lockout_duration'];

        foreach ($allowedSettings as $key) {
            if (isset($_POST[$key])) {
                $value = Security::sanitize($_POST[$key]);
                Database::execute(
                    "INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) 
                     ON DUPLICATE KEY UPDATE setting_value = ?",
                    [$key, $value, $value]
                );
            }
        }

        AuditLog::log('settings_updated', Session::getUserId());
        Session::flash('success', 'Settings saved successfully.');
        header('Location: ' . APP_URL . '/admin/settings');
        exit;
    }

    public function logs(): void {
        $page = max(1, (int)($_GET['page'] ?? 1));
        $limit = 50;
        $offset = ($page - 1) * $limit;
        $action = $_GET['action_filter'] ?? null;

        $logs = AuditLog::getAll($limit, $offset, $action);

        $data = [
            'logs' => $logs,
            'currentPage' => $page,
            'actionFilter' => $action
        ];

        require __DIR__ . '/../views/admin/logs.php';
    }

    // ================================================================
    // EXTENSION MANAGEMENT
    // ================================================================

    public function extensions(): void {
        $devices = ExtensionDevice::listAll(50, 0);
        $logs = ExtensionAudit::getAll(25, 0);

        // Get extension settings
        $settingsRows = Database::fetchAll(
            "SELECT setting_key, setting_value FROM app_settings WHERE setting_key LIKE 'extension_%'"
        );
        $settings = [];
        foreach ($settingsRows as $s) {
            $settings[$s['setting_key']] = $s['setting_value'];
        }

        $data = [
            'devices' => $devices,
            'logs' => $logs,
            'settings' => $settings,
            'csrfToken' => CSRF::generateToken()
        ];

        require __DIR__ . '/../views/admin/extensions.php';
    }

    public function saveExtensionSettings(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/extensions');
            exit;
        }
        CSRF::validateOrFail();

        $extensionSettings = [
            'extension_api_enabled' => isset($_POST['extension_api_enabled']) ? '1' : '0',
            'extension_allowed_origins' => trim($_POST['extension_allowed_origins'] ?? ''),
            'extension_token_lifetime_days' => max(1, min(365, (int)($_POST['extension_token_lifetime_days'] ?? 30))),
            'extension_max_devices_per_user' => max(1, min(50, (int)($_POST['extension_max_devices_per_user'] ?? 10)))
        ];

        foreach ($extensionSettings as $key => $value) {
            Database::execute(
                "INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE setting_value = ?",
                [$key, (string)$value, (string)$value]
            );
        }

        AuditLog::log('extension_settings_updated', Session::getUserId(), null, null, $extensionSettings);
        Session::flash('success', 'Extension settings saved.');
        header('Location: ' . APP_URL . '/admin/extensions');
        exit;
    }

    public function revokeExtensionDevice(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/extensions');
            exit;
        }
        CSRF::validateOrFail();

        $deviceId = (int)($_POST['device_id'] ?? 0);
        if ($deviceId) {
            ExtensionDevice::adminRevoke($deviceId);
            AuditLog::log('extension_device_revoked_admin', Session::getUserId(), 'device', $deviceId);
            Session::flash('success', 'Device revoked successfully.');
        }

        header('Location: ' . APP_URL . '/admin/extensions');
        exit;
    }
}
