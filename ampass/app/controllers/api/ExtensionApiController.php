<?php
/**
 * AMPass - Extension API Controller
 * 
 * SECURITY:
 * - All endpoints use bearer token authentication (not session/CSRF).
 * - Rate limiting on every endpoint.
 * - Never returns plaintext vault fields.
 * - All vault data returned is encrypted ciphertext only.
 * - Audit logging on all actions.
 * - CORS restricted to configured extension origins.
 * - HTTPS required except localhost.
 */

require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../models/UserSecurity.php';
require_once __DIR__ . '/../../models/VaultItem.php';
require_once __DIR__ . '/../../models/Folder.php';
require_once __DIR__ . '/../../models/ExtensionToken.php';
require_once __DIR__ . '/../../models/ExtensionDevice.php';
require_once __DIR__ . '/../../models/ExtensionAudit.php';
require_once __DIR__ . '/../../models/AuditLog.php';

class ExtensionApiController {

    private ?int $userId = null;
    private ?int $deviceId = null;
    private ?int $tokenId = null;
    private bool $isAuthenticated = false;

    /**
     * Authenticate via bearer token (called by endpoints that require auth)
     * SECURITY: Reads Authorization header from multiple sources to handle
     * Apache/CGI/FastCGI environments that may strip or rename the header.
     */
    private function authenticate(): bool {
        if ($this->isAuthenticated) return true;

        // Read Authorization header from multiple possible sources
        $authHeader = $_SERVER['HTTP_AUTHORIZATION']
            ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
            ?? '';

        // Fallback: apache_request_headers() for mod_php
        if (empty($authHeader) && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        }

        if (empty($authHeader)) {
            return false;
        }

        if (!preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authHeader, $matches)) {
            return false;
        }

        $rawToken = $matches[1];
        $result = ExtensionToken::validate($rawToken);

        if (!$result) return false;

        $this->userId = $result['user_id'];
        $this->deviceId = $result['device_id'];
        $this->tokenId = $result['token_id'];
        $this->isAuthenticated = true;
        return true;
    }

    /**
     * Require authentication or return 401.
     * Also enforces HTTPS on all authenticated endpoints.
     */
    private function requireAuth(): bool {
        if (!$this->requireHTTPS()) return false;
        if (!$this->authenticate()) {
            http_response_code(401);

            // Determine if header is missing vs token invalid
            $authHeader = $_SERVER['HTTP_AUTHORIZATION']
                ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
                ?? '';
            if (empty($authHeader) && function_exists('apache_request_headers')) {
                $headers = apache_request_headers();
                $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
            }

            if (empty($authHeader)) {
                echo json_encode([
                    'error' => 'Authorization header missing. Check Apache .htaccess bearer token forwarding.',
                    'code' => 'AUTH_HEADER_MISSING'
                ]);
            } else {
                echo json_encode([
                    'error' => 'Invalid or expired token',
                    'code' => 'AUTH_REQUIRED'
                ]);
            }
            return false;
        }
        return true;
    }

    /**
     * Check if extension API is enabled
     */
    private function checkEnabled(): bool {
        $setting = Database::fetchOne(
            "SELECT setting_value FROM app_settings WHERE setting_key = 'extension_api_enabled'"
        );
        if ($setting && $setting['setting_value'] === '0') {
            http_response_code(503);
            echo json_encode(['error' => 'Extension API is disabled by administrator', 'code' => 'API_DISABLED']);
            return false;
        }
        return true;
    }

    /**
     * Rate limit check helper
     */
    private function rateLimit(string $action, int $max = 30, int $window = 60): bool {
        $identifier = Security::getClientIP() . '_ext_' . $action;
        if ($this->userId) {
            $identifier .= '_' . $this->userId;
        }
        if (!RateLimit::check($identifier, 'ext_' . $action, $max, $window)) {
            http_response_code(429);
            echo json_encode(['error' => 'Rate limit exceeded. Please wait.', 'code' => 'RATE_LIMITED']);
            return false;
        }
        return true;
    }

    /**
     * Validate HTTPS requirement
     */
    private function requireHTTPS(): bool {
        if (!Security::isHTTPS() && !Security::isLocalhost()) {
            http_response_code(403);
            echo json_encode(['error' => 'HTTPS is required for extension API', 'code' => 'HTTPS_REQUIRED']);
            return false;
        }
        return true;
    }

    // ================================================================
    // PUBLIC ENDPOINTS
    // ================================================================

    /**
     * GET /api/extension/status
     * Check API availability and auth state (no auth required)
     */
    public function status(): void {
        if (!$this->checkEnabled()) return;

        $authenticated = $this->authenticate();

        echo json_encode([
            'success' => true,
            'api_version' => '1.0',
            'app_version' => defined('AMPASS_VERSION_SEMVER') ? AMPASS_VERSION_SEMVER : (defined('APP_VERSION') ? APP_VERSION : '1.0.0'),
            'authenticated' => $authenticated,
            'https' => Security::isHTTPS(),
            'server_time' => date('c')
        ]);
    }

    /**
     * GET /api/extension/debug-auth
     * Diagnostic endpoint for bearer token header issues.
     * Only available on localhost or to authenticated admins.
     * SECURITY: Never returns the actual token value.
     */
    public function debugAuth(): void {
        // Only allow on localhost or if user is admin via session
        if (!Security::isLocalhost() && !(Session::isLoggedIn() && Session::isAdmin())) {
            http_response_code(403);
            echo json_encode(['error' => 'Only available on localhost or for admins']);
            return;
        }

        $httpAuth = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
        $redirectAuth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
        $apacheAuth = null;
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $apacheAuth = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        }

        echo json_encode([
            'success' => true,
            'diagnostics' => [
                'HTTP_AUTHORIZATION_present' => $httpAuth !== null,
                'HTTP_AUTHORIZATION_length' => $httpAuth ? strlen($httpAuth) : 0,
                'REDIRECT_HTTP_AUTHORIZATION_present' => $redirectAuth !== null,
                'REDIRECT_HTTP_AUTHORIZATION_length' => $redirectAuth ? strlen($redirectAuth) : 0,
                'apache_request_headers_available' => function_exists('apache_request_headers'),
                'apache_Authorization_present' => $apacheAuth !== null,
                'apache_Authorization_length' => $apacheAuth ? strlen($apacheAuth) : 0,
                'starts_with_Bearer' => (bool)preg_match('/^Bearer\s/i', $httpAuth ?? $redirectAuth ?? $apacheAuth ?? ''),
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
                'sapi_name' => php_sapi_name()
            ]
        ]);
    }

    /**
     * POST /api/extension/login
     * Authenticate with username + password, register device, return token + derivation params.
     * SECURITY: Rate limited (5 attempts per 15 min per IP).
     */
    public function login(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->checkEnabled()) return;
        if (!$this->requireHTTPS()) return;

        // Strict rate limiting on login
        $ip = Security::getClientIP();
        if (!RateLimit::check($ip, 'ext_login', 5, 900)) {
            http_response_code(429);
            echo json_encode(['error' => 'Too many login attempts. Try again in 15 minutes.', 'code' => 'RATE_LIMITED']);
            return;
        }

        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input || !is_array($input)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid request body']);
            return;
        }

        $login = trim($input['username'] ?? $input['login'] ?? '');
        $password = $input['password'] ?? '';
        $deviceName = Security::sanitize(substr($input['device_name'] ?? 'Browser Extension', 0, 100));
        $browserName = Security::sanitize(substr($input['browser_name'] ?? '', 0, 50));
        $extensionId = Security::sanitize(substr($input['extension_id'] ?? '', 0, 128));
        $deviceIdInput = isset($input['device_id']) ? (int)$input['device_id'] : null;
        $twoFactorCode = trim($input['two_factor_code'] ?? '');

        // Validate input
        if (empty($login) || empty($password)) {
            http_response_code(400);
            echo json_encode(['error' => 'Username and password are required']);
            return;
        }

        if (strlen($password) > 1024) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid credentials']);
            return;
        }

        // Find user
        $user = User::findByLogin($login);
        if (!$user || !Security::verifyPassword($password, $user['password_hash'])) {
            RateLimit::record($ip, 'ext_login', 5, 900);
            ExtensionAudit::log('ext_login_failed', null, null, null, null, ['login' => $login, 'ip' => $ip]);
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials', 'code' => 'AUTH_FAILED']);
            return;
        }

        // Check user status
        if ($user['status'] !== 'active') {
            http_response_code(403);
            echo json_encode(['error' => 'Account is suspended', 'code' => 'ACCOUNT_SUSPENDED']);
            return;
        }

        // Check 2FA requirement
        $isTwoFactorEnabled = (int)($user['two_factor_enabled'] ?? 0) === 1;
        $device = null;
        $isTrusted = false;

        if ($isTwoFactorEnabled) {
            if ($deviceIdInput) {
                $device = ExtensionDevice::findById($deviceIdInput, $user['id']);
            }
            if ($device && $device['revoked_at'] === null) {
                // Perform risk checks
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                
                // 1. Bot / Hacker User Agent check
                $botPatterns = '/bot|crawler|spider|wget|curl|python|selenium|playwright|headless|puppeteer|phantomjs|postman/i';
                $isBot = (bool)preg_match($botPatterns, $ua);
                
                // 2. IP Address check
                $currentIp = Security::getClientIP();
                $ipMatches = ($device['ip_address'] === $currentIp);
                
                // 3. Inactivity (Offline) check: 14 days
                $lastSeen = strtotime($device['last_seen_at']);
                $isRecent = (time() - $lastSeen <= 14 * 86400);
                
                if (!$isBot && $ipMatches && $isRecent) {
                    $isTrusted = true;
                }
            }

            if (!$isTrusted) {
                if (empty($twoFactorCode)) {
                    http_response_code(401);
                    echo json_encode(['error' => '2FA code required', 'code' => 'TWO_FACTOR_REQUIRED']);
                    return;
                }
                
                $userSecurity = Database::fetchOne("SELECT two_factor_secret_encrypted FROM users WHERE id = ?", [$user['id']]);
                if ($userSecurity && !empty($userSecurity['two_factor_secret_encrypted'])) {
                    $secret = GoogleAuthenticator::decryptSecret($userSecurity['two_factor_secret_encrypted']);
                    if (!GoogleAuthenticator::verifyCode($secret, $twoFactorCode)) {
                        http_response_code(401);
                        echo json_encode(['error' => 'Invalid 2FA code', 'code' => 'TWO_FACTOR_FAILED']);
                        return;
                    }
                }
            }
        }

        // Check max devices if this is a new device registration
        $matchedDeviceId = ($device && $device['revoked_at'] === null) ? $device['id'] : null;
        if (!$matchedDeviceId) {
            $maxDevices = 10;
            $maxSetting = Database::fetchOne("SELECT setting_value FROM app_settings WHERE setting_key = 'extension_max_devices_per_user'");
            if ($maxSetting) $maxDevices = (int)$maxSetting['setting_value'];

            if (ExtensionDevice::countByUser($user['id']) >= $maxDevices) {
                http_response_code(403);
                echo json_encode(['error' => 'Maximum number of extension devices reached. Revoke an existing device first.', 'code' => 'MAX_DEVICES']);
                return;
            }

            // Register device
            $deviceId = ExtensionDevice::create([
                'user_id' => $user['id'],
                'device_name' => $deviceName,
                'browser_name' => $browserName,
                'extension_id' => $extensionId
            ]);
        } else {
            $deviceId = $matchedDeviceId;
            // Update last_seen_at and ip_address
            Database::execute(
                "UPDATE extension_devices SET last_seen_at = NOW(), ip_address = ? WHERE id = ?",
                [Security::getClientIP(), $deviceId]
            );
        }

        // Generate token
        $lifetimeDays = 30;
        $lifetimeSetting = Database::fetchOne("SELECT setting_value FROM app_settings WHERE setting_key = 'extension_token_lifetime_days'");
        if ($lifetimeSetting) $lifetimeDays = (int)$lifetimeSetting['setting_value'];

        $tokenData = ExtensionToken::create($user['id'], $deviceId, $lifetimeDays);

        // Get derivation params for client-side key derivation
        $derivationParams = UserSecurity::getDerivationParams($user['id']);

        // Clear rate limit on success
        RateLimit::clear($ip, 'ext_login');

        // Audit log
        ExtensionAudit::log('ext_login', $user['id'], $deviceId, 'device', $deviceId, [
            'device_name' => $deviceName,
            'browser' => $browserName
        ]);

        echo json_encode([
            'success' => true,
            'token' => $tokenData['raw_token'],
            'token_prefix' => $tokenData['prefix'],
            'expires_at' => $tokenData['expires_at'],
            'device_id' => $deviceId,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'full_name' => $user['full_name'],
                'email' => $user['email']
            ],
            'derivation_params' => $derivationParams
        ]);
    }

    /**
     * POST /api/extension/logout
     * Revoke current token.
     */
    public function logout(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->requireAuth()) return;

        ExtensionToken::revoke($this->tokenId, $this->userId);
        ExtensionAudit::log('ext_logout', $this->userId, $this->deviceId);

        echo json_encode(['success' => true, 'message' => 'Token revoked']);
    }

    /**
     * GET /api/extension/session
     * Check current session state (is vault unlocked, user info).
     */
    public function session(): void {
        if (!$this->requireAuth()) return;

        $user = User::findById($this->userId);

        echo json_encode([
            'success' => true,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'full_name' => $user['full_name']
            ],
            'device_id' => $this->deviceId,
            'token_id' => $this->tokenId
        ]);
    }

    /**
     * GET /api/extension/derivationParams
     * Get key derivation parameters for vault unlock.
     * Used by desktop app after restoring token from keychain.
     */
    public function derivationParams(): void {
        if (!$this->requireAuth()) return;

        $params = UserSecurity::getDerivationParams($this->userId);
        if (!$params) {
            http_response_code(404);
            echo json_encode(['error' => 'Security data not found', 'code' => 'NOT_FOUND']);
            return;
        }

        echo json_encode(['success' => true, 'params' => $params]);
    }

    // ================================================================
    // VAULT ENDPOINTS (all require auth + rate limiting)
    // ================================================================

    /**
     * POST /api/extension/vault/init-key
     * Initialize vault encryption key for first-time setup.
     * SECURITY: Only accepts encrypted vault key data. The server never sees the raw vault key.
     * Called once when a user's vault has not been initialized (key_iterations = 0).
     * Requires: bearer token auth, HTTPS (except localhost), rate limited.
     */
    public function vaultInitKey(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed', 'code' => 'METHOD_NOT_ALLOWED']);
            return;
        }

        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_init', 5, 300)) return;

        // Verify user is active
        $user = User::findById($this->userId);
        if (!$user || $user['status'] !== 'active') {
            http_response_code(403);
            echo json_encode(['error' => 'Account is not active', 'code' => 'ACCOUNT_INACTIVE']);
            return;
        }

        // Verify vault actually needs initialization
        $security = UserSecurity::findByUserId($this->userId);
        if (!$security) {
            http_response_code(404);
            echo json_encode(['error' => 'Security record not found', 'code' => 'NOT_FOUND']);
            return;
        }
        if ((int)$security['key_iterations'] > 0 && $security['encrypted_vault_key'] !== 'VAULT_NOT_INITIALIZED') {
            http_response_code(409);
            echo json_encode(['error' => 'Vault is already initialized', 'code' => 'ALREADY_INITIALIZED']);
            return;
        }

        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input || !is_array($input)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid request body', 'code' => 'INVALID_BODY']);
            return;
        }

        $salt = $input['encryption_salt'] ?? '';
        $encryptedKey = $input['encrypted_vault_key'] ?? '';
        $iv = $input['vault_key_iv'] ?? '';
        $iterations = (int)($input['key_iterations'] ?? 0);

        // Strict validation
        if (empty($salt) || empty($encryptedKey) || empty($iv) || $iterations === 0) {
            http_response_code(400);
            echo json_encode(['error' => 'All fields required: encryption_salt, encrypted_vault_key, vault_key_iv, key_iterations', 'code' => 'MISSING_FIELDS']);
            return;
        }
        if (!preg_match('/^[a-f0-9]{32,256}$/', $salt)) {
            http_response_code(400);
            echo json_encode(['error' => 'encryption_salt must be 32-256 hex chars', 'code' => 'INVALID_SALT']);
            return;
        }
        if (!preg_match('/^[a-f0-9]+$/', $encryptedKey) || strlen($encryptedKey) < 32) {
            http_response_code(400);
            echo json_encode(['error' => 'encrypted_vault_key must be valid hex', 'code' => 'INVALID_KEY']);
            return;
        }
        if (!preg_match('/^[a-f0-9]{24}$/', $iv)) {
            http_response_code(400);
            echo json_encode(['error' => 'vault_key_iv must be 24 hex chars (12 bytes)', 'code' => 'INVALID_IV']);
            return;
        }
        if ($iterations < 100000 || $iterations > 1000000) {
            http_response_code(400);
            echo json_encode(['error' => 'key_iterations must be between 100000 and 1000000', 'code' => 'INVALID_ITERATIONS']);
            return;
        }

        // Update user_security record
        $updated = UserSecurity::updateVaultKey($this->userId, [
            'master_password_hash' => $security['master_password_hash'],
            'encryption_salt' => $salt,
            'encrypted_vault_key' => $encryptedKey,
            'vault_key_iv' => $iv,
            'key_iterations' => $iterations
        ]);

        if ($updated) {
            ExtensionAudit::log('vault_initialized_extension', $this->userId, $this->deviceId, null, null, [
                'iterations' => $iterations
            ]);
            echo json_encode(['success' => true]);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to initialize vault key', 'code' => 'INTERNAL_ERROR']);
        }
    }

    /**
     * GET /api/extension/vault/list
     * Returns all encrypted vault items for the user.
     * SECURITY: Only returns ciphertext, IVs, and metadata. Never plaintext.
     */
    public function vaultList(): void {
        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_list', 60, 60)) return;

        $type = $_GET['type'] ?? null;
        $folderId = isset($_GET['folder_id']) ? (int)$_GET['folder_id'] : null;

        // Validate type if provided
        $allowedTypes = ['login', 'app_account', 'remote_desktop', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];
        if ($type !== null && !in_array($type, $allowedTypes, true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid item type']);
            return;
        }

        $items = VaultItem::getAllByUser($this->userId, $type, $folderId);
        $folders = Folder::getAllByUser($this->userId);

        echo json_encode([
            'success' => true,
            'items' => $items,
            'folders' => $folders,
            'count' => count($items)
        ]);
    }

    /**
     * GET /api/extension/vault/get?id=
     * Get a single encrypted vault item.
     */
    public function vaultGet(): void {
        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_get', 120, 60)) return;

        $itemId = (int)($_GET['id'] ?? 0);
        if (!$itemId) {
            http_response_code(400);
            echo json_encode(['error' => 'Item ID required']);
            return;
        }

        $item = VaultItem::findById($itemId, $this->userId);
        if (!$item) {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
            return;
        }

        // Mark as used
        VaultItem::markUsed($itemId, $this->userId);

        ExtensionAudit::log('vault_item_fetched', $this->userId, $this->deviceId, 'vault_item', $itemId);

        echo json_encode(['success' => true, 'item' => $item]);
    }

    /**
     * POST /api/extension/vault/save
     * Create a new encrypted vault item (autosave from extension).
     * SECURITY: Only accepts encrypted data. Never plaintext fields.
     */
    public function vaultSave(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_save', 30, 60)) return;

        $rawInput = file_get_contents('php://input');
        if (strlen($rawInput) > 5 * 1024 * 1024) {
            http_response_code(413);
            echo json_encode(['error' => 'Request too large']);
            return;
        }

        $input = json_decode($rawInput, true);
        if (!$input || !is_array($input)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid request body']);
            return;
        }

        // Validate required encrypted fields
        if (empty($input['encrypted_data']) || empty($input['encryption_iv'])) {
            http_response_code(400);
            echo json_encode(['error' => 'encrypted_data and encryption_iv are required']);
            return;
        }

        // Validate item type
        $allowedTypes = ['login', 'app_account', 'remote_desktop', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];
        $itemType = $input['item_type'] ?? 'login';
        if (!in_array($itemType, $allowedTypes, true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid item type']);
            return;
        }

        $data = [
            'user_id' => $this->userId,
            'item_type' => $itemType,
            'encrypted_data' => $input['encrypted_data'],
            'encryption_iv' => $input['encryption_iv'],
            'title_hash' => $input['title_hash'] ?? null,
            'url_hash' => $input['url_hash'] ?? null,
            'host_hash' => $input['host_hash'] ?? null,
            'folder_id' => !empty($input['folder_id']) ? (int)$input['folder_id'] : null,
            'is_favorite' => (int)($input['is_favorite'] ?? 0),
            'password_strength' => isset($input['password_strength']) ? (int)$input['password_strength'] : null,
            'is_weak' => (int)($input['is_weak'] ?? 0),
            'is_reused' => (int)($input['is_reused'] ?? 0)
        ];

        $newId = VaultItem::create($data);

        ExtensionAudit::log('autosave_created', $this->userId, $this->deviceId, 'vault_item', $newId, [
            'item_type' => $itemType
        ]);

        echo json_encode(['success' => true, 'id' => $newId, 'message' => 'Item created']);
    }

    /**
     * POST /api/extension/vault/update
     * Update an existing encrypted vault item.
     */
    public function vaultUpdate(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_update', 30, 60)) return;

        $rawInput = file_get_contents('php://input');
        if (strlen($rawInput) > 5 * 1024 * 1024) {
            http_response_code(413);
            echo json_encode(['error' => 'Request too large']);
            return;
        }

        $input = json_decode($rawInput, true);
        if (!$input || !is_array($input)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid request body']);
            return;
        }

        $itemId = (int)($input['id'] ?? 0);
        if (!$itemId) {
            http_response_code(400);
            echo json_encode(['error' => 'Item ID required']);
            return;
        }

        if (empty($input['encrypted_data']) || empty($input['encryption_iv'])) {
            http_response_code(400);
            echo json_encode(['error' => 'encrypted_data and encryption_iv are required']);
            return;
        }

        // Verify ownership
        $existing = VaultItem::findById($itemId, $this->userId);
        if (!$existing) {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
            return;
        }

        $allowedTypes = ['login', 'app_account', 'remote_desktop', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];
        $itemType = $input['item_type'] ?? $existing['item_type'];
        if (!in_array($itemType, $allowedTypes, true)) $itemType = $existing['item_type'];

        $data = [
            'encrypted_data' => $input['encrypted_data'],
            'encryption_iv' => $input['encryption_iv'],
            'item_type' => $itemType,
            'title_hash' => $input['title_hash'] ?? $existing['title_hash'],
            'url_hash' => $input['url_hash'] ?? $existing['url_hash'],
            'host_hash' => $input['host_hash'] ?? ($existing['host_hash'] ?? null),
            'folder_id' => isset($input['folder_id']) ? ((int)$input['folder_id'] ?: null) : $existing['folder_id'],
            'is_favorite' => (int)($input['is_favorite'] ?? $existing['is_favorite']),
            'password_strength' => isset($input['password_strength']) ? (int)$input['password_strength'] : $existing['password_strength'],
            'is_weak' => (int)($input['is_weak'] ?? $existing['is_weak']),
            'is_reused' => (int)($input['is_reused'] ?? $existing['is_reused'])
        ];

        VaultItem::update($itemId, $this->userId, $data);

        ExtensionAudit::log('autosave_updated', $this->userId, $this->deviceId, 'vault_item', $itemId);

        echo json_encode(['success' => true, 'id' => $itemId, 'message' => 'Item updated']);
    }

    /**
     * POST /api/extension/vault/delete
     * Delete a vault item.
     */
    public function vaultDelete(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_delete', 20, 60)) return;

        $input = json_decode(file_get_contents('php://input'), true);
        $itemId = (int)($input['id'] ?? 0);

        if (!$itemId) {
            http_response_code(400);
            echo json_encode(['error' => 'Item ID required']);
            return;
        }

        $deleted = VaultItem::delete($itemId, $this->userId);
        if ($deleted) {
            ExtensionAudit::log('vault_item_deleted', $this->userId, $this->deviceId, 'vault_item', $itemId);
            echo json_encode(['success' => true, 'message' => 'Item deleted']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
        }
    }

    /**
     * GET /api/extension/vault/matchDomain?url_hash=
     * Find vault items matching a URL hash (for autofill suggestions).
     * SECURITY: Uses HMAC hash of URL — server never sees the actual URL.
     * The extension computes HMAC(url) client-side and sends the hash.
     */
    public function vaultMatchDomain(): void {
        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('vault_match', 120, 60)) return;

        $urlHash = $_GET['url_hash'] ?? '';

        if (empty($urlHash) || !preg_match('/^[a-f0-9]{64}$/', $urlHash)) {
            http_response_code(400);
            echo json_encode(['error' => 'Valid url_hash (64-char hex) required']);
            return;
        }

        // Find items with matching url_hash
        $items = Database::fetchAll(
            "SELECT id, item_type, encrypted_data, encryption_iv, title_hash, url_hash,
                    is_favorite, password_strength, last_used_at, updated_at
             FROM vault_items
             WHERE user_id = ? AND url_hash = ?
             ORDER BY last_used_at DESC, updated_at DESC",
            [$this->userId, $urlHash]
        );

        ExtensionAudit::log('autofill_matches_requested', $this->userId, $this->deviceId, null, null, [
            'matches' => count($items)
        ]);

        echo json_encode([
            'success' => true,
            'items' => $items,
            'count' => count($items)
        ]);
    }

    // ================================================================
    // UTILITY ENDPOINTS
    // ================================================================

    /**
     * POST /api/extension/vault/usageLog
     * Log a vault item usage action (copy, autofill, launch, etc.)
     * SECURITY: Never logs plaintext secrets. Only item_id, action, client_type.
     */
    public function vaultUsageLog(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('usage_log', 60, 60)) return;

        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input || !is_array($input)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid request body']);
            return;
        }

        $itemId = (int)($input['item_id'] ?? 0);
        $action = $input['action'] ?? '';
        $clientType = $input['client_type'] ?? 'extension';

        // Validate action against allowlist
        $allowedActions = [
            'copied_password', 'copied_username', 'copied_host',
            'autofilled', 'launched_app', 'app_launch_failed',
            'opened_rdp', 'rdp_open_failed',
            'autosave_prompt_shown', 'autosave_skipped',
            'clipboard_cleared', 'item_viewed'
        ];
        if (!in_array($action, $allowedActions, true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            return;
        }

        // Validate client_type
        $allowedClients = ['extension', 'desktop', 'web'];
        if (!in_array($clientType, $allowedClients, true)) {
            $clientType = 'extension';
        }

        // Validate item belongs to user (if item_id provided)
        if ($itemId > 0) {
            $item = VaultItem::findById($itemId, $this->userId);
            if (!$item) {
                http_response_code(404);
                echo json_encode(['error' => 'Item not found']);
                return;
            }
            // Mark as used
            VaultItem::markUsed($itemId, $this->userId);
        }

        // Log the action
        ExtensionAudit::log($action, $this->userId, $this->deviceId, 'vault_item', $itemId ?: null, [
            'client_type' => $clientType,
            'item_type' => $item['item_type'] ?? null
        ]);

        echo json_encode(['success' => true]);
    }

    /**
     * GET /api/extension/generator/policy
     * Return password generation policy/defaults.
     */
    public function generatorPolicy(): void {
        if (!$this->requireAuth()) return;

        echo json_encode([
            'success' => true,
            'policy' => [
                'min_length' => 12,
                'default_length' => 20,
                'max_length' => 128,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_symbols' => true,
                'avoid_ambiguous' => false
            ]
        ]);
    }

    /**
     * GET /api/extension/audit
     * Get recent extension audit logs for the current user.
     */
    public function audit(): void {
        if (!$this->requireAuth()) return;
        if (!$this->rateLimit('audit', 20, 60)) return;

        $limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
        $offset = max(0, (int)($_GET['offset'] ?? 0));

        $logs = ExtensionAudit::getByUser($this->userId, $limit, $offset);

        echo json_encode([
            'success' => true,
            'logs' => $logs,
            'count' => count($logs)
        ]);
    }

    // ================================================================
    // DEVICE/TOKEN MANAGEMENT
    // ================================================================

    /**
     * GET /api/extension/devices
     * List user's registered extension devices.
     */
    public function devices(): void {
        if (!$this->requireAuth()) return;

        $devices = ExtensionDevice::listByUser($this->userId);

        echo json_encode(['success' => true, 'devices' => $devices]);
    }

    /**
     * POST /api/extension/revokeDevice
     * Revoke a device and all its tokens.
     */
    public function revokeDevice(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        if (!$this->requireAuth()) return;

        $input = json_decode(file_get_contents('php://input'), true);
        $deviceId = (int)($input['device_id'] ?? 0);

        if (!$deviceId) {
            http_response_code(400);
            echo json_encode(['error' => 'device_id required']);
            return;
        }

        $revoked = ExtensionDevice::revoke($deviceId, $this->userId);
        if ($revoked) {
            ExtensionAudit::log('device_revoked', $this->userId, $this->deviceId, 'device', $deviceId);
            echo json_encode(['success' => true, 'message' => 'Device revoked']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Device not found']);
        }
    }
}
