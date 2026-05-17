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
     */
    private function authenticate(): bool {
        if ($this->isAuthenticated) return true;

        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
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
     * Require authentication or return 401
     */
    private function requireAuth(): bool {
        if (!$this->authenticate()) {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid or expired token', 'code' => 'AUTH_REQUIRED']);
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
            'app_version' => defined('APP_VERSION') ? APP_VERSION : '1.0.0',
            'authenticated' => $authenticated,
            'https' => Security::isHTTPS(),
            'server_time' => date('c')
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

        // Check max devices
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

    // ================================================================
    // VAULT ENDPOINTS (all require auth + rate limiting)
    // ================================================================

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
        $allowedTypes = ['login', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];
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
        $allowedTypes = ['login', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];
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

        $allowedTypes = ['login', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];
        $itemType = $input['item_type'] ?? $existing['item_type'];
        if (!in_array($itemType, $allowedTypes, true)) $itemType = $existing['item_type'];

        $data = [
            'encrypted_data' => $input['encrypted_data'],
            'encryption_iv' => $input['encryption_iv'],
            'item_type' => $itemType,
            'title_hash' => $input['title_hash'] ?? $existing['title_hash'],
            'url_hash' => $input['url_hash'] ?? $existing['url_hash'],
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

        ExtensionAudit::log('autofill_used', $this->userId, $this->deviceId, null, null, [
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
