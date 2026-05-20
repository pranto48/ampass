<?php
/**
 * AMPass - Admin Controller
 * SECURITY: All admin routes require admin role verification.
 */

require_once __DIR__ . '/../services/BackupService.php';
require_once __DIR__ . '/../services/EmailService.php';
require_once __DIR__ . '/../services/UpdateService.php';
require_once __DIR__ . '/../services/RemoteBackupService.php';

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

        // Fetch status info for dashboard cards
        $updateAvailable = UpdateService::getSetting('update_available', '0') === '1';
        $latestVersion = UpdateService::getSetting('latest_version', '');
        $lastBackup = Database::fetchOne("SELECT created_at FROM backup_files ORDER BY created_at DESC LIMIT 1");
        $lastRemoteBackup = Database::fetchOne("SELECT status, uploaded_at FROM remote_backup_uploads ORDER BY created_at DESC LIMIT 1");
        $emailConfigured = !empty(Database::fetchOne("SELECT setting_value FROM app_settings WHERE setting_key = 'resend_api_key_encrypted' AND setting_value != ''"));

        $data = [
            'totalUsers' => $totalUsers,
            'users' => $users,
            'recentLogs' => $recentLogs,
            'csrfToken' => CSRF::generateToken(),
            'updateAvailable' => $updateAvailable,
            'latestVersion' => $latestVersion,
            'lastBackupDate' => $lastBackup['created_at'] ?? null,
            'lastRemoteBackupStatus' => $lastRemoteBackup['status'] ?? null,
            'lastRemoteBackupDate' => $lastRemoteBackup['uploaded_at'] ?? null,
            'emailConfigured' => $emailConfigured
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

    // ================================================================
    // RELEASE DOWNLOADS MANAGEMENT
    // Routes: /admin/releases, /admin/releases/upload, /admin/releases/toggle, /admin/releases/delete
    // ================================================================

    public function releases(?string $subAction = null): void {
        // Sub-route dispatch for /admin/releases/{action}
        switch ($subAction) {
            case 'upload': $this->releasesUpload(); return;
            case 'toggle': $this->releasesToggle(); return;
            case 'delete': $this->releasesDelete(); return;
        }

        // Default: list releases
        $releases = Database::fetchAll(
            "SELECT * FROM release_downloads ORDER BY created_at DESC"
        );

        $settingsRows = Database::fetchAll(
            "SELECT setting_key, setting_value FROM app_settings WHERE setting_key = 'downloads_enabled'"
        );
        $settings = [];
        foreach ($settingsRows as $s) $settings[$s['setting_key']] = $s['setting_value'];

        $data = [
            'releases' => $releases,
            'settings' => $settings,
            'csrfToken' => CSRF::generateToken()
        ];

        require __DIR__ . '/../views/admin/releases.php';
    }

    public function releasesUpload(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }
        CSRF::validateOrFail();

        // Validate product type
        $allowedTypes = ['windows_exe', 'windows_msi', 'chrome_extension', 'edge_extension', 'firefox_extension', 'pwa'];
        $productType = $_POST['product_type'] ?? '';
        if (!in_array($productType, $allowedTypes, true)) {
            Session::flash('error', 'Invalid product type.');
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        $version = trim($_POST['version'] ?? '');
        if (empty($version) || !preg_match('/^[0-9a-zA-Z.\-]+$/', $version)) {
            Session::flash('error', 'Invalid version format.');
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        // Validate file upload
        if (!isset($_FILES['release_file']) || $_FILES['release_file']['error'] !== UPLOAD_ERR_OK) {
            Session::flash('error', 'File upload failed. Error code: ' . ($_FILES['release_file']['error'] ?? 'none'));
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        $file = $_FILES['release_file'];
        $originalName = basename($file['name']);
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        // SECURITY: Strict extension allowlist
        $allowedExtensions = ['exe', 'msi', 'zip', 'xpi'];
        if (!in_array($extension, $allowedExtensions, true)) {
            Session::flash('error', 'File type not allowed. Only .exe, .msi, .zip, .xpi are accepted.');
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        // SECURITY: Enforce product type to file extension mapping
        $typeExtensionMap = [
            'windows_exe' => ['exe'],
            'windows_msi' => ['msi'],
            'chrome_extension' => ['zip'],
            'edge_extension' => ['zip'],
            'firefox_extension' => ['xpi', 'zip'],
            'pwa' => ['zip']
        ];
        $allowedForType = $typeExtensionMap[$productType] ?? [];
        if (!in_array($extension, $allowedForType, true)) {
            Session::flash('error', 'Selected product type does not match uploaded file extension. Expected: .' . implode(' or .', $allowedForType));
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        // SECURITY: Block dangerous extensions even if disguised
        $dangerousPatterns = ['php', 'phtml', 'phar', 'js', 'html', 'htm', 'svg', 'sh', 'bat', 'cmd', 'ps1', 'htaccess'];
        foreach ($dangerousPatterns as $pattern) {
            if (stripos($originalName, '.' . $pattern) !== false) {
                Session::flash('error', 'Dangerous file type rejected.');
                header('Location: ' . APP_URL . '/admin/releases');
                exit;
            }
        }

        // Generate random stored filename
        $storedFilename = bin2hex(random_bytes(16)) . '.' . $extension;
        $storageDir = __DIR__ . '/../../app_storage/releases';

        // Ensure storage directory exists
        if (!is_dir($storageDir)) {
            mkdir($storageDir, 0755, true);
        }

        $destPath = $storageDir . '/' . $storedFilename;

        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $destPath)) {
            Session::flash('error', 'Failed to store file. Check directory permissions.');
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        // SECURITY: Verify stored path is inside app_storage/releases
        $realDest = realpath($destPath);
        $realBase = realpath($storageDir);
        if (!$realDest || !$realBase || strpos($realDest, $realBase) !== 0) {
            @unlink($destPath);
            Session::flash('error', 'File path validation failed.');
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        // Calculate checksum and size
        $sha256 = hash_file('sha256', $destPath);
        $fileSize = filesize($destPath);
        $mimeType = mime_content_type($destPath) ?: 'application/octet-stream';
        $releaseNotes = trim($_POST['release_notes'] ?? '');

        // Insert into database
        Database::insert(
            "INSERT INTO release_downloads (product_type, version, filename_original, filename_stored, file_path, file_size, sha256_checksum, mime_type, release_notes, is_active, created_by_user_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NOW())",
            [
                $productType,
                $version,
                $originalName,
                $storedFilename,
                'app_storage/releases/' . $storedFilename,
                $fileSize,
                $sha256,
                $mimeType,
                $releaseNotes,
                Session::getUserId()
            ]
        );

        AuditLog::log('release_uploaded', Session::getUserId(), 'release', null, [
            'product' => $productType, 'version' => $version, 'file' => $originalName
        ]);

        Session::flash('success', "Release uploaded: {$originalName} (v{$version}, SHA-256: " . substr($sha256, 0, 12) . "…)");
        header('Location: ' . APP_URL . '/admin/releases');
        exit;
    }

    public function releasesToggle(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }
        CSRF::validateOrFail();

        // Toggle downloads_enabled setting
        if (isset($_POST['setting']) && $_POST['setting'] === 'downloads_enabled') {
            $value = $_POST['value'] === '1' ? '1' : '0';
            Database::execute(
                "INSERT INTO app_settings (setting_key, setting_value) VALUES ('downloads_enabled', ?) ON DUPLICATE KEY UPDATE setting_value = ?",
                [$value, $value]
            );
            AuditLog::log($value === '1' ? 'downloads_enabled' : 'downloads_disabled', Session::getUserId());
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        // Toggle individual release active status
        $id = (int)($_POST['id'] ?? 0);
        $active = (int)($_POST['active'] ?? 0);
        if ($id) {
            Database::execute("UPDATE release_downloads SET is_active = ?, updated_at = NOW() WHERE id = ?", [$active, $id]);
            AuditLog::log($active ? 'release_enabled' : 'release_disabled', Session::getUserId(), 'release', $id);
            Session::flash('success', 'Release ' . ($active ? 'enabled' : 'disabled') . '.');
        }

        header('Location: ' . APP_URL . '/admin/releases');
        exit;
    }

    public function releasesDelete(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }
        CSRF::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if (!$id) {
            header('Location: ' . APP_URL . '/admin/releases');
            exit;
        }

        $release = Database::fetchOne("SELECT * FROM release_downloads WHERE id = ?", [$id]);
        if ($release) {
            // SECURITY: Validate file path stays inside app_storage/releases before unlinking
            $baseDir = realpath(__DIR__ . '/../../app_storage/releases');
            $filePath = realpath(__DIR__ . '/../../' . $release['file_path']);

            if ($baseDir && $filePath && strpos($filePath, $baseDir) === 0) {
                @unlink($filePath);
            } else {
                // Path invalid or outside allowed directory — log warning, skip file delete
                error_log("AMPass: Release delete skipped file unlink — path outside app_storage/releases (id={$id})");
            }

            // Delete DB record regardless
            Database::execute("DELETE FROM release_downloads WHERE id = ?", [$id]);

            AuditLog::log('release_deleted', Session::getUserId(), 'release', $id, [
                'product' => $release['product_type'], 'version' => $release['version']
            ]);
            Session::flash('success', 'Release deleted.');
        }

        header('Location: ' . APP_URL . '/admin/releases');
        exit;
    }

    // ================================================================
    // BACKUP MANAGEMENT
    // Routes: /admin/backups, /admin/backups/create, /admin/backups/download, /admin/backups/delete
    // ================================================================

    public function backups(?string $subAction = null): void {
        switch ($subAction) {
            case 'create': $this->backupsCreate(); return;
            case 'delete': $this->backupsDelete(); return;
            case 'download-latest': $this->backupsDownloadLatest(); return;
        }

        // Handle download with ID in query
        if (isset($_GET['download'])) {
            $this->backupsDownload((int)$_GET['download']);
            return;
        }

        $backups = Database::fetchAll("SELECT * FROM backup_files ORDER BY created_at DESC");
        $data = ['backups' => $backups, 'csrfToken' => CSRF::generateToken()];
        require __DIR__ . '/../views/admin/backups.php';
    }

    private function backupsDownloadLatest(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backups'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/backups');

        $latest = Database::fetchOne("SELECT id FROM backup_files ORDER BY created_at DESC LIMIT 1");
        if (!$latest) {
            Session::flash('error', 'No backups available to download.');
            header('Location: ' . APP_URL . '/admin/backups');
            exit;
        }
        $this->backupsDownload((int)$latest['id']);
    }

    private function backupsCreate(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backups'); exit; }
        CSRF::validateOrFail();

        $password = $_POST['backup_password'] ?? '';
        $confirmPassword = $_POST['backup_password_confirm'] ?? '';

        if (strlen($password) < 8) { Session::flash('error', 'Backup password must be at least 8 characters.'); header('Location: ' . APP_URL . '/admin/backups'); exit; }
        if ($password !== $confirmPassword) { Session::flash('error', 'Passwords do not match.'); header('Location: ' . APP_URL . '/admin/backups'); exit; }

        $options = [
            'include_database' => true,
            'include_files' => isset($_POST['include_files']),
            'include_audit' => isset($_POST['include_audit'])
        ];

        try {
            $result = BackupService::create($password, $options);

            Database::insert(
                "INSERT INTO backup_files (filename, file_path, file_size, sha256_checksum, backup_type, includes_database, includes_files, includes_audit_logs, created_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, NOW())",
                [$result['filename'], $result['file_path'], $result['file_size'], $result['sha256_checksum'],
                 $result['includes_files'] ? 'database_files' : 'database_only',
                 $result['includes_files'] ? 1 : 0, $result['includes_audit_logs'] ? 1 : 0, Session::getUserId()]
            );

            AuditLog::log('backup_created', Session::getUserId(), null, null, ['file' => $result['filename'], 'size' => $result['file_size']]);
            Session::flash('success', 'Backup created: ' . $result['filename'] . ' (' . number_format($result['file_size']/1048576, 1) . ' MB)');
        } catch (\Exception $e) {
            Session::flash('error', 'Backup failed: ' . $e->getMessage());
        }

        header('Location: ' . APP_URL . '/admin/backups');
        exit;
    }

    private function backupsDownload(int $id): void {
        $backup = Database::fetchOne("SELECT * FROM backup_files WHERE id = ?", [$id]);
        if (!$backup) { http_response_code(404); echo 'Backup not found'; return; }

        $basePath = realpath(__DIR__ . '/../../app_storage/backups');
        $filePath = realpath(__DIR__ . '/../../' . $backup['file_path']);

        if (!$basePath || !$filePath || strpos($filePath, $basePath) !== 0 || !file_exists($filePath)) {
            http_response_code(404); echo 'Backup file not found'; return;
        }

        Database::execute("UPDATE backup_files SET downloaded_at = NOW() WHERE id = ?", [$id]);
        AuditLog::log('backup_downloaded', Session::getUserId(), 'backup', $id);

        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . preg_replace('/[^a-zA-Z0-9._\-]/', '_', $backup['filename']) . '"');
        header('Content-Length: ' . filesize($filePath));
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: private, no-cache');

        $handle = fopen($filePath, 'rb');
        while (!feof($handle)) { echo fread($handle, 8192); flush(); }
        fclose($handle);
        exit;
    }

    private function backupsDelete(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backups'); exit; }
        CSRF::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $backup = Database::fetchOne("SELECT * FROM backup_files WHERE id = ?", [$id]);
        if ($backup) {
            $basePath = realpath(__DIR__ . '/../../app_storage/backups');
            $filePath = realpath(__DIR__ . '/../../' . $backup['file_path']);
            if ($basePath && $filePath && strpos($filePath, $basePath) === 0) { @unlink($filePath); }
            Database::execute("DELETE FROM backup_files WHERE id = ?", [$id]);
            AuditLog::log('backup_deleted', Session::getUserId(), 'backup', $id);
            Session::flash('success', 'Backup deleted.');
        }
        header('Location: ' . APP_URL . '/admin/backups');
        exit;
    }

    // ================================================================
    // EMAIL SETTINGS
    // Routes: /admin/email, /admin/email/save, /admin/email/test
    // ================================================================

    public function email(?string $subAction = null): void {
        switch ($subAction) {
            case 'save': $this->emailSave(); return;
            case 'test': $this->emailTest(); return;
        }

        $settings = [];
        $rows = Database::fetchAll("SELECT setting_key, setting_value FROM app_settings WHERE setting_key LIKE 'resend_%' OR setting_key LIKE '%email%'");
        foreach ($rows as $r) $settings[$r['setting_key']] = $r['setting_value'];

        $data = ['settings' => $settings, 'csrfToken' => CSRF::generateToken()];
        require __DIR__ . '/../views/admin/email.php';
    }

    private function emailSave(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/email'); exit; }
        CSRF::validateOrFail();

        $apiKey = trim($_POST['resend_api_key'] ?? '');
        $fromEmail = Security::sanitizeEmail($_POST['resend_from_email'] ?? '');
        $fromName = Security::sanitize($_POST['resend_from_name'] ?? 'AMPass');

        // Only update API key if a new one is provided (not masked)
        if (!empty($apiKey) && !str_contains($apiKey, '****')) {
            $encrypted = EmailService::encryptApiKey($apiKey);
            Database::execute("INSERT INTO app_settings (setting_key, setting_value) VALUES ('resend_api_key_encrypted', ?) ON DUPLICATE KEY UPDATE setting_value = ?", [$encrypted, $encrypted]);
        }

        $emailSettings = [
            'resend_from_email' => $fromEmail,
            'resend_from_name' => $fromName,
            'resend_reply_to' => Security::sanitizeEmail($_POST['resend_reply_to'] ?? ''),
            'security_email_enabled' => isset($_POST['security_email_enabled']) ? '1' : '0',
            'password_reset_email_enabled' => isset($_POST['password_reset_email_enabled']) ? '1' : '0',
            'new_device_email_enabled' => isset($_POST['new_device_email_enabled']) ? '1' : '0',
            'two_factor_email_enabled' => isset($_POST['two_factor_email_enabled']) ? '1' : '0',
            'backup_restore_email_enabled' => isset($_POST['backup_restore_email_enabled']) ? '1' : '0'
        ];

        foreach ($emailSettings as $key => $value) {
            Database::execute("INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?", [$key, $value, $value]);
        }

        AuditLog::log('email_settings_updated', Session::getUserId());
        Session::flash('success', 'Email settings saved.');
        header('Location: ' . APP_URL . '/admin/email');
        exit;
    }

    private function emailTest(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/email'); exit; }
        CSRF::validateOrFail();

        $user = User::findById(Session::getUserId());
        $result = EmailService::send($user['email'], 'AMPass Test Email', '<h2>AMPass Email Test</h2><p>If you received this, your Resend email integration is working correctly.</p><p>Sent at: ' . date('c') . '</p>');

        if ($result['success']) {
            Session::flash('success', 'Test email sent to ' . $user['email']);
        } else {
            Session::flash('error', 'Test email failed: ' . ($result['error'] ?? 'Unknown error'));
        }

        header('Location: ' . APP_URL . '/admin/email');
        exit;
    }

    // ================================================================
    // UPDATES
    // Routes: /admin/updates, /admin/updates/check, /admin/updates/apply
    // ================================================================

    public function updates(?string $subAction = null): void {
        switch ($subAction) {
            case 'check': $this->updatesCheck(); return;
            case 'apply': $this->updatesApply(); return;
            case 'migrations': $this->updatesRunMigrations(); return;
            case 'settings': $this->updatesSaveSettings(); return;
            case 'mark-installed': $this->updatesMarkInstalled(); return;
        }

        $data = [
            'current_version' => UpdateService::getInstalledVersion(),
            'installed_sha' => UpdateService::getSetting('installed_commit_sha', ''),
            'latest_version' => UpdateService::getSetting('latest_version', ''),
            'latest_sha' => UpdateService::getSetting('latest_commit_sha', ''),
            'update_available' => UpdateService::getSetting('update_available', '0') === '1',
            'last_checked' => UpdateService::getSetting('last_update_check_at', 'Never'),
            'commit_message' => UpdateService::getSetting('latest_commit_message', ''),
            'download_url' => UpdateService::getSetting('latest_download_url', ''),
            'check_error' => UpdateService::getSetting('last_check_error', ''),
            'source_type' => UpdateService::getSetting('update_source_type', 'github_release'),
            'github_repo_owner' => UpdateService::getSetting('github_repo_owner', 'pranto48'),
            'github_repo_name' => UpdateService::getSetting('github_repo_name', 'ampass-secure-vault'),
            'github_branch' => UpdateService::getSetting('github_branch', 'main'),
            'github_token_set' => !empty(UpdateService::getSetting('github_token_encrypted', '')),
            'history' => UpdateService::getUpdateHistory(10),
            'pending_migrations' => UpdateService::getPendingMigrations(),
            'csrfToken' => CSRF::generateToken()
        ];
        require __DIR__ . '/../views/admin/updates.php';
    }

    private function updatesCheck(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/updates'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/updates');
        $result = UpdateService::checkForUpdates();
        AuditLog::log('update_check', Session::getUserId(), null, null, ['available' => $result['update_available'] ?? false]);

        if (!empty($result['error'])) {
            Session::flash('error', $result['error']);
        } elseif ($result['update_available']) {
            $msg = 'Update available: ';
            if (!empty($result['latest_version']) && $result['latest_version'] !== $result['current_version']) {
                $msg .= 'v' . $result['latest_version'];
            } elseif (!empty($result['latest_commit_sha'])) {
                $msg .= 'new commit ' . substr($result['latest_commit_sha'], 0, 8);
            } else {
                $msg .= 'new version';
            }
            Session::flash('success', $msg);
        } elseif (!empty($result['warning'])) {
            Session::flash('error', $result['warning']);
        } else {
            Session::flash('success', 'AMPass is up to date.');
        }
        header('Location: ' . APP_URL . '/admin/updates');
        exit;
    }

    private function updatesApply(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/updates'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/updates');

        $confirmation = trim($_POST['confirmation'] ?? '');
        $backupPassword = $_POST['backup_password'] ?? '';

        if ($confirmation !== 'UPDATE AMPASS') { Session::flash('error', 'Type "UPDATE AMPASS" to confirm.'); header('Location: ' . APP_URL . '/admin/updates'); exit; }
        if (strlen($backupPassword) < 8) { Session::flash('error', 'Backup password must be at least 8 characters.'); header('Location: ' . APP_URL . '/admin/updates'); exit; }

        AuditLog::log('update_started', Session::getUserId());
        $result = UpdateService::applyUpdate($backupPassword, Session::getUserId());

        if ($result['success']) {
            AuditLog::log('update_completed', Session::getUserId(), null, null, ['version' => $result['version'] ?? '']);
            Session::flash('success', 'Update completed! v' . ($result['version'] ?? '') . ' — ' . ($result['files_updated'] ?? 0) . ' files updated.');
        } else {
            AuditLog::log('update_failed', Session::getUserId(), null, null, ['error' => substr($result['error'] ?? '', 0, 200)]);
            Session::flash('error', 'Update failed: ' . ($result['error'] ?? 'Unknown error'));
        }
        header('Location: ' . APP_URL . '/admin/updates');
        exit;
    }

    private function updatesRunMigrations(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/updates'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/updates');
        $result = UpdateService::runPendingMigrations();
        if ($result['failed']) { Session::flash('error', 'Migration failed: ' . $result['failed']); }
        elseif (count($result['applied']) > 0) { Session::flash('success', 'Applied ' . count($result['applied']) . ' migration(s).'); }
        else { Session::flash('success', 'No pending migrations.'); }
        header('Location: ' . APP_URL . '/admin/updates');
        exit;
    }

    private function updatesSaveSettings(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/updates'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/updates');

        $allowedSourceTypes = ['github_release', 'github_branch_zip'];
        $sourceType = $_POST['update_source_type'] ?? 'github_release';
        if (!in_array($sourceType, $allowedSourceTypes, true)) $sourceType = 'github_release';

        $owner = preg_replace('/[^a-zA-Z0-9\-_]/', '', trim($_POST['github_repo_owner'] ?? 'pranto48'));
        $repo = preg_replace('/[^a-zA-Z0-9\-_.]/', '', trim($_POST['github_repo_name'] ?? 'ampass-secure-vault'));
        $branch = preg_replace('/[^a-zA-Z0-9\-_./]/', '', trim($_POST['github_branch'] ?? 'main'));

        if (empty($owner)) $owner = 'pranto48';
        if (empty($repo)) $repo = 'ampass-secure-vault';
        if (empty($branch)) $branch = 'main';

        UpdateService::saveSetting('update_source_type', $sourceType);
        UpdateService::saveSetting('github_repo_owner', $owner);
        UpdateService::saveSetting('github_repo_name', $repo);
        UpdateService::saveSetting('github_branch', $branch);

        // Handle GitHub token (only update if new value provided, not masked)
        $token = trim($_POST['github_token'] ?? '');
        if (!empty($token) && !str_contains($token, '****')) {
            // Encrypt token before storing
            if (defined('APP_SECRET')) {
                $key = hash('sha256', APP_SECRET, true);
                $iv = random_bytes(12);
                $encrypted = openssl_encrypt($token, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
                UpdateService::saveSetting('github_token_encrypted', base64_encode($iv . $tag . $encrypted));
            }
        } elseif (isset($_POST['github_token_clear']) && $_POST['github_token_clear'] === '1') {
            UpdateService::saveSetting('github_token_encrypted', '');
        }

        // Reset update check state when settings change
        UpdateService::saveSetting('update_available', '0');
        UpdateService::saveSetting('last_check_error', '');

        AuditLog::log('update_settings_changed', Session::getUserId(), null, null, ['source_type' => $sourceType, 'branch' => $branch]);
        Session::flash('success', 'Update settings saved. Click "Check for Updates" to verify.');
        header('Location: ' . APP_URL . '/admin/updates');
        exit;
    }

    private function updatesMarkInstalled(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/updates'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/updates');

        $latestSha = UpdateService::getSetting('latest_commit_sha', '');
        if (!empty($latestSha)) {
            UpdateService::saveSetting('installed_commit_sha', $latestSha);
            UpdateService::saveSetting('update_available', '0');
            AuditLog::log('update_marked_installed', Session::getUserId(), null, null, ['sha' => substr($latestSha, 0, 8)]);
            Session::flash('success', 'Current code marked as installed (commit ' . substr($latestSha, 0, 8) . ').');
        } else {
            Session::flash('error', 'No latest commit SHA available. Run "Check for Updates" first.');
        }
        header('Location: ' . APP_URL . '/admin/updates');
        exit;
    }

    // ================================================================
    // BACKUP DESTINATIONS
    // Routes: /admin/backupDestinations, /admin/backupDestinations/save, etc.
    // ================================================================

    public function backupDestinations(?string $subAction = null): void {
        switch ($subAction) {
            case 'save': $this->backupDestinationsSave(); return;
            case 'edit': $this->backupDestinationsEdit(); return;
            case 'update': $this->backupDestinationsUpdate(); return;
            case 'test': $this->backupDestinationsTest(); return;
            case 'delete': $this->backupDestinationsDelete(); return;
            case 'upload': $this->backupDestinationsUpload(); return;
            case 'onedrive-connect': $this->onedriveConnect(); return;
            case 'onedrive-callback': $this->onedriveCallback(); return;
        }

        $destinations = Database::fetchAll("SELECT * FROM remote_backup_destinations ORDER BY created_at DESC");
        $backups = Database::fetchAll("SELECT id, filename, created_at FROM backup_files ORDER BY created_at DESC LIMIT 10");

        // Decode destination status for OneDrive
        foreach ($destinations as &$dest) {
            $dest['_status'] = 'enabled';
            if ($dest['provider'] === 'onedrive') {
                $config = RemoteBackupService::decryptConfigPublic($dest['encrypted_config']);
                if (!$config || empty($config['client_id'])) {
                    $dest['_status'] = 'not_configured';
                } elseif (empty($config['refresh_token'])) {
                    $dest['_status'] = 'ready_to_connect';
                } else {
                    $dest['_status'] = 'connected';
                }
            }
            if (!empty($dest['last_error'])) {
                $dest['_has_error'] = true;
            }
        }
        unset($dest);

        $preselectedBackup = isset($_GET['backup_id']) ? (int)$_GET['backup_id'] : null;
        $data = ['destinations' => $destinations, 'backups' => $backups, 'csrfToken' => CSRF::generateToken(), 'preselected_backup' => $preselectedBackup];
        require __DIR__ . '/../views/admin/backup-destinations.php';
    }

    private function backupDestinationsEdit(): void {
        $id = (int)($_GET['id'] ?? 0);
        if (!$id) { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $dest = Database::fetchOne("SELECT * FROM remote_backup_destinations WHERE id = ?", [$id]);
        if (!$dest) { Session::flash('error', 'Destination not found.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $config = RemoteBackupService::decryptConfigPublic($dest['encrypted_config']) ?: [];
        // Never expose secrets to view — mask them
        $maskedConfig = $config;
        if (!empty($maskedConfig['password'])) $maskedConfig['password'] = '';
        if (!empty($maskedConfig['client_secret'])) $maskedConfig['client_secret'] = '';
        $maskedConfig['_has_password'] = !empty($config['password']);
        $maskedConfig['_has_client_secret'] = !empty($config['client_secret']);
        $maskedConfig['_has_refresh_token'] = !empty($config['refresh_token']);

        $data = ['dest' => $dest, 'config' => $maskedConfig, 'csrfToken' => CSRF::generateToken()];
        require __DIR__ . '/../views/admin/backup-destination-edit.php';
    }

    private function backupDestinationsUpdate(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }
        CSRF::validateOrRedirect(APP_URL . '/admin/backup-destinations');

        $id = (int)($_POST['id'] ?? 0);
        if (!$id) { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $dest = Database::fetchOne("SELECT * FROM remote_backup_destinations WHERE id = ?", [$id]);
        if (!$dest) { Session::flash('error', 'Destination not found.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        // Load existing config to preserve secrets not re-entered
        $existingConfig = RemoteBackupService::decryptConfigPublic($dest['encrypted_config']) ?: [];

        $name = Security::sanitize($_POST['name'] ?? $dest['name']);
        $enabled = isset($_POST['enabled']) ? 1 : 0;

        $config = $existingConfig; // Start with existing
        $config['host'] = trim($_POST['host'] ?? $config['host'] ?? '');
        $config['port'] = (int)($_POST['port'] ?? $config['port'] ?? 21);
        $config['username'] = trim($_POST['username'] ?? $config['username'] ?? '');
        $config['remote_directory'] = trim($_POST['remote_directory'] ?? $config['remote_directory'] ?? '/ampass-backups');
        $config['passive_mode'] = isset($_POST['passive_mode']);
        $config['folder_path'] = trim($_POST['folder_path'] ?? $config['folder_path'] ?? 'AMPass Backups');
        $config['client_id'] = trim($_POST['client_id'] ?? $config['client_id'] ?? '');

        // Only update password/secret if new value provided
        $newPassword = $_POST['password'] ?? '';
        if (!empty($newPassword)) $config['password'] = $newPassword;

        $newSecret = $_POST['client_secret'] ?? '';
        if (!empty($newSecret)) $config['client_secret'] = $newSecret;

        try {
            $encryptedConfig = RemoteBackupService::encryptConfig($config);
        } catch (\RuntimeException $e) {
            Session::flash('error', 'Cannot save: ' . $e->getMessage());
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }
        Database::execute("UPDATE remote_backup_destinations SET name = ?, enabled = ?, encrypted_config = ? WHERE id = ?", [$name, $enabled, $encryptedConfig, $id]);

        AuditLog::log('remote_backup_destination_updated', Session::getUserId(), 'destination', $id);
        Session::flash('success', "Destination '{$name}' updated.");
        header('Location: ' . APP_URL . '/admin/backup-destinations');
        exit;
    }

    private function backupDestinationsSave(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }
        CSRF::validateOrFail();

        $name = Security::sanitize($_POST['name'] ?? '');
        $provider = $_POST['provider'] ?? '';
        if (!in_array($provider, ['ftp', 'ftps', 'sftp', 'onedrive'], true)) { Session::flash('error', 'Invalid provider.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $config = [
            'host' => trim($_POST['host'] ?? ''),
            'port' => (int)($_POST['port'] ?? ($provider === 'sftp' ? 22 : 21)),
            'username' => trim($_POST['username'] ?? ''),
            'password' => $_POST['password'] ?? '',
            'remote_directory' => trim($_POST['remote_directory'] ?? '/ampass-backups'),
            'passive_mode' => isset($_POST['passive_mode']),
            'use_tls' => $provider === 'ftps',
            'client_id' => trim($_POST['client_id'] ?? ''),
            'client_secret' => $_POST['client_secret'] ?? '',
            'refresh_token' => $_POST['refresh_token'] ?? '',
            'folder_path' => trim($_POST['folder_path'] ?? 'AMPass Backups')
        ];

        $encryptedConfig = null;
        try {
            $encryptedConfig = RemoteBackupService::encryptConfig($config);
        } catch (\RuntimeException $e) {
            Session::flash('error', 'Cannot save destination: ' . $e->getMessage());
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }

        Database::insert(
            "INSERT INTO remote_backup_destinations (name, provider, enabled, encrypted_config, created_by_user_id, created_at) VALUES (?, ?, 1, ?, ?, NOW())",
            [$name, $provider, $encryptedConfig, Session::getUserId()]
        );

        AuditLog::log('remote_backup_destination_created', Session::getUserId(), null, null, ['name' => $name, 'provider' => $provider]);
        Session::flash('success', "Destination '{$name}' ({$provider}) added.");
        header('Location: ' . APP_URL . '/admin/backup-destinations');
        exit;
    }

    private function backupDestinationsTest(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }
        CSRF::validateOrFail();
        $id = (int)($_POST['id'] ?? 0);
        $dest = Database::fetchOne("SELECT * FROM remote_backup_destinations WHERE id = ?", [$id]);
        if (!$dest) { Session::flash('error', 'Destination not found.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $config = RemoteBackupService::decryptConfigPublic($dest['encrypted_config']);
        $result = RemoteBackupService::testConnection($config ?: [], $dest['provider']);

        Database::execute("UPDATE remote_backup_destinations SET last_test_at = NOW() WHERE id = ?", [$id]);
        if ($result['success']) { Session::flash('success', 'Connection test passed: ' . ($result['message'] ?? '')); }
        else { Session::flash('error', 'Connection test failed: ' . ($result['error'] ?? 'Unknown')); }
        header('Location: ' . APP_URL . '/admin/backup-destinations');
        exit;
    }

    private function backupDestinationsDelete(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }
        CSRF::validateOrFail();
        $id = (int)($_POST['id'] ?? 0);
        if ($id) {
            Database::execute("DELETE FROM remote_backup_destinations WHERE id = ?", [$id]);
            AuditLog::log('remote_backup_destination_deleted', Session::getUserId(), 'destination', $id);
            Session::flash('success', 'Destination deleted.');
        }
        header('Location: ' . APP_URL . '/admin/backup-destinations');
        exit;
    }

    private function backupDestinationsUpload(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }
        CSRF::validateOrFail();
        $backupId = (int)($_POST['backup_id'] ?? 0);
        $destId = (int)($_POST['destination_id'] ?? 0);
        if (!$backupId || !$destId) { Session::flash('error', 'Select a backup and destination.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $result = RemoteBackupService::upload($backupId, $destId);
        if ($result['success']) {
            AuditLog::log('remote_backup_uploaded', Session::getUserId(), 'backup', $backupId, ['destination' => $destId]);
            Session::flash('success', 'Backup uploaded to remote destination.');
        } else {
            Session::flash('error', 'Upload failed: ' . ($result['error'] ?? 'Unknown'));
        }
        header('Location: ' . APP_URL . '/admin/backup-destinations');
        exit;
    }

    // ================================================================
    // ONEDRIVE OAUTH CONNECT/CALLBACK
    // ================================================================

    /**
     * Initiate OneDrive OAuth flow.
     * Generates state token, stores in session, redirects to Microsoft authorize URL.
     */
    private function onedriveConnect(): void {
        $destId = (int)($_GET['id'] ?? $_POST['id'] ?? 0);
        if (!$destId) { Session::flash('error', 'Destination ID required.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $dest = Database::fetchOne("SELECT * FROM remote_backup_destinations WHERE id = ? AND provider = 'onedrive'", [$destId]);
        if (!$dest) { Session::flash('error', 'OneDrive destination not found.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $config = RemoteBackupService::decryptConfigPublic($dest['encrypted_config']);
        if (!$config || empty($config['client_id'])) {
            Session::flash('error', 'OneDrive is not configured yet. Please open Edit and enter your Microsoft Azure Client ID and Client Secret first.');
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }

        // Generate OAuth state token
        $state = bin2hex(random_bytes(32));
        $_SESSION['onedrive_oauth_state'] = $state;
        $_SESSION['onedrive_oauth_dest_id'] = $destId;

        $redirectUri = rtrim(APP_URL, '/') . '/admin/backup-destinations/onedrive-callback';
        $params = http_build_query([
            'client_id' => $config['client_id'],
            'response_type' => 'code',
            'redirect_uri' => $redirectUri,
            'scope' => 'offline_access Files.ReadWrite',
            'state' => $state,
            'response_mode' => 'query'
        ]);

        $authorizeUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' . $params;
        header('Location: ' . $authorizeUrl);
        exit;
    }

    /**
     * Handle OneDrive OAuth callback.
     * Verifies state, exchanges code for tokens, stores refresh_token encrypted.
     */
    private function onedriveCallback(): void {
        $state = $_GET['state'] ?? '';
        $code = $_GET['code'] ?? '';
        $error = $_GET['error'] ?? '';

        // Check for OAuth error
        if ($error) {
            $errorDesc = $_GET['error_description'] ?? $error;
            Session::flash('error', 'OneDrive authorization failed: ' . htmlspecialchars($errorDesc));
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }

        // Verify state token
        $expectedState = $_SESSION['onedrive_oauth_state'] ?? '';
        $destId = (int)($_SESSION['onedrive_oauth_dest_id'] ?? 0);

        // Clear session state immediately
        unset($_SESSION['onedrive_oauth_state'], $_SESSION['onedrive_oauth_dest_id']);

        if (empty($state) || !hash_equals($expectedState, $state)) {
            Session::flash('error', 'OneDrive OAuth state mismatch. Possible CSRF attack. Try again.');
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }

        if (empty($code) || !$destId) {
            Session::flash('error', 'OneDrive authorization code missing.');
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }

        // Load destination config
        $dest = Database::fetchOne("SELECT * FROM remote_backup_destinations WHERE id = ? AND provider = 'onedrive'", [$destId]);
        if (!$dest) { Session::flash('error', 'Destination not found.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        $config = RemoteBackupService::decryptConfigPublic($dest['encrypted_config']);
        if (!$config) { Session::flash('error', 'Cannot decrypt destination config.'); header('Location: ' . APP_URL . '/admin/backup-destinations'); exit; }

        // Exchange code for tokens
        $redirectUri = rtrim(APP_URL, '/') . '/admin/backup-destinations/onedrive-callback';
        $tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

        $ch = curl_init($tokenUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'] ?? '',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
                'scope' => 'offline_access Files.ReadWrite'
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $tokenData = json_decode($response, true);

        if ($httpCode !== 200 || empty($tokenData['refresh_token'])) {
            $errorMsg = $tokenData['error_description'] ?? $tokenData['error'] ?? 'Token exchange failed (HTTP ' . $httpCode . ')';
            Session::flash('error', 'OneDrive token exchange failed: ' . htmlspecialchars($errorMsg));
            header('Location: ' . APP_URL . '/admin/backup-destinations');
            exit;
        }

        // Store refresh_token encrypted in destination config (NEVER log tokens)
        $config['refresh_token'] = $tokenData['refresh_token'];
        $config['onedrive_connected_at'] = date('c');
        $encryptedConfig = RemoteBackupService::encryptConfig($config);

        Database::execute("UPDATE remote_backup_destinations SET encrypted_config = ?, last_test_at = NOW(), last_error = NULL WHERE id = ?", [$encryptedConfig, $destId]);

        AuditLog::log('onedrive_connected', Session::getUserId(), 'destination', $destId);
        Session::flash('success', 'OneDrive connected successfully! Refresh token stored encrypted.');
        header('Location: ' . APP_URL . '/admin/backup-destinations');
        exit;
    }
}
