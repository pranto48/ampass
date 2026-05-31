<?php
/**
 * AMPass - Vault API Controller
 * SECURITY: All vault data is encrypted client-side. This API only handles ciphertext.
 * CSRF validation on all state-changing operations.
 */

require_once __DIR__ . '/../../models/VaultItem.php';
require_once __DIR__ . '/../../models/Folder.php';
require_once __DIR__ . '/../../models/AuditLog.php';

class VaultApiController {

    private int $userId;

    public function __construct() {
        $this->userId = Session::getUserId();
        if (!Session::isVaultUnlocked()) {
            http_response_code(403);
            echo json_encode(['error' => 'Vault is locked']);
            exit;
        }
    }

    /**
     * GET /api/vault/list - Get all vault items
     */
    public function list(): void {
        $type = $_GET['type'] ?? null;
        $folderId = isset($_GET['folder']) ? (int)$_GET['folder'] : null;

        $items = VaultItem::getAllByUser($this->userId, $type, $folderId);
        echo json_encode(['success' => true, 'items' => $items]);
    }

    /**
     * GET /api/vault/get/{id} - Get single item
     */
    public function get(?string $id = null): void {
        $itemId = (int)($id ?? $_GET['id'] ?? 0);
        $item = VaultItem::findById($itemId, $this->userId);

        if (!$item) {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
            return;
        }

        VaultItem::markUsed($itemId, $this->userId);
        echo json_encode(['success' => true, 'item' => $item]);
    }

    /**
     * POST /api/vault/save - Create or update vault item
     */
    public function save(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        CSRF::validateOrFail($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        // SECURITY: Limit request body size to prevent memory exhaustion
        $rawInput = file_get_contents('php://input');
        if (strlen($rawInput) > 5 * 1024 * 1024) { // 5MB max
            http_response_code(413);
            echo json_encode(['error' => 'Request too large']);
            return;
        }

        $input = json_decode($rawInput, true);
        if (!$input) {
            $input = $_POST;
        }

        // Validate required encrypted fields
        if (empty($input['encrypted_data']) || empty($input['encryption_iv'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Encrypted data and IV are required']);
            return;
        }

        // SECURITY: Validate item_type against allowlist
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

        $itemId = isset($input['id']) ? (int)$input['id'] : 0;

        if ($itemId > 0) {
            // Update existing
            $existing = VaultItem::findById($itemId, $this->userId);
            if (!$existing) {
                http_response_code(404);
                echo json_encode(['error' => 'Item not found']);
                return;
            }
            VaultItem::update($itemId, $this->userId, $data);
            AuditLog::log('vault_item_updated', $this->userId, 'vault_item', $itemId);
            echo json_encode(['success' => true, 'id' => $itemId, 'message' => 'Item updated']);
        } else {
            // Create new
            $newId = VaultItem::create($data);
            AuditLog::log('vault_item_created', $this->userId, 'vault_item', $newId);
            echo json_encode(['success' => true, 'id' => $newId, 'message' => 'Item created']);
        }
    }

    /**
     * POST /api/vault/delete - Delete vault item
     */
    public function delete(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        CSRF::validateOrFail($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $itemId = (int)($input['id'] ?? 0);

        if (!$itemId) {
            http_response_code(400);
            echo json_encode(['error' => 'Item ID required']);
            return;
        }

        $deleted = VaultItem::delete($itemId, $this->userId);
        if ($deleted) {
            AuditLog::log('vault_item_deleted', $this->userId, 'vault_item', $itemId);
            echo json_encode(['success' => true, 'message' => 'Item deleted']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
        }
    }

    /**
     * POST /api/vault/favorite - Toggle favorite
     */
    public function favorite(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        CSRF::validateOrFail($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $itemId = (int)($input['id'] ?? 0);

        VaultItem::toggleFavorite($itemId, $this->userId);
        echo json_encode(['success' => true]);
    }

    /**
     * GET /api/vault/stats - Get vault statistics
     */
    public function stats(): void {
        $stats = VaultItem::getStats($this->userId);
        echo json_encode(['success' => true, 'stats' => $stats]);
    }

    /**
     * GET /api/vault/export - Export encrypted vault data
     * SECURITY: Requires CSRF token in header to prevent cross-site export triggers.
     */
    public function export(): void {
        // Validate CSRF even on GET to prevent cross-site triggered downloads
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_GET['csrf_token'] ?? '';
        if (!CSRF::validate($csrfToken)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid security token']);
            return;
        }

        $items = VaultItem::getAllByUser($this->userId);
        $folders = Folder::getAllByUser($this->userId);

        $export = [
            'version' => defined('AMPASS_VERSION_SEMVER') ? AMPASS_VERSION_SEMVER : APP_VERSION,
            'exported_at' => date('c'),
            'items' => $items,
            'folders' => $folders
        ];

        AuditLog::log('vault_exported', $this->userId);

        header('Content-Disposition: attachment; filename="ampass_backup_' . date('Y-m-d') . '.json"');
        echo json_encode($export, JSON_PRETTY_PRINT);
    }

    /**
     * POST /api/vault/import - Import encrypted vault data
     */
    public function import(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        CSRF::validateOrFail($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        // SECURITY: Limit import size to prevent memory exhaustion
        $rawInput = file_get_contents('php://input');
        if (strlen($rawInput) > 50 * 1024 * 1024) { // 50MB max for imports
            http_response_code(413);
            echo json_encode(['error' => 'Import file too large (max 50MB)']);
            return;
        }

        $input = json_decode($rawInput, true);
        if (!$input || !isset($input['items'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid import data']);
            return;
        }

        $imported = 0;
        Database::beginTransaction();

        // Allowlist for imported item types
        $allowedImportTypes = ['login', 'app_account', 'remote_desktop', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];

        try {
            foreach ($input['items'] as $item) {
                if (empty($item['encrypted_data']) || empty($item['encryption_iv'])) {
                    continue;
                }

                // Validate item_type — default to 'custom' if invalid
                $itemType = $item['item_type'] ?? 'login';
                if (!in_array($itemType, $allowedImportTypes, true)) {
                    $itemType = 'custom';
                }

                VaultItem::create([
                    'user_id' => $this->userId,
                    'item_type' => $itemType,
                    'encrypted_data' => $item['encrypted_data'],
                    'encryption_iv' => $item['encryption_iv'],
                    'title_hash' => $item['title_hash'] ?? null,
                    'url_hash' => $item['url_hash'] ?? null,
                    'host_hash' => $item['host_hash'] ?? null,
                    'folder_id' => null, // Don't import folder references
                    'is_favorite' => (int)($item['is_favorite'] ?? 0),
                    'password_strength' => $item['password_strength'] ?? null,
                    'is_weak' => (int)($item['is_weak'] ?? 0),
                    'is_reused' => (int)($item['is_reused'] ?? 0)
                ]);
                $imported++;
            }

            Database::commit();
            AuditLog::log('vault_imported', $this->userId, null, null, ['count' => $imported]);
            echo json_encode(['success' => true, 'imported' => $imported]);

        } catch (Exception $e) {
            Database::rollback();
            http_response_code(500);
            echo json_encode(['error' => 'Import failed']);
        }
    }

    /**
     * POST /api/vault/importBulk - Bulk import encrypted vault items from password manager export.
     * SECURITY: Only accepts pre-encrypted items. Plaintext parsing happens client-side.
     * Never logs plaintext passwords.
     */
    public function importBulk(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            return;
        }

        CSRF::validateOrFail($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        $rawInput = file_get_contents('php://input');
        if (strlen($rawInput) > 20 * 1024 * 1024) {
            http_response_code(413);
            echo json_encode(['error' => 'Request too large (max 20MB)']);
            return;
        }

        $input = json_decode($rawInput, true);
        if (!$input || !isset($input['items']) || !is_array($input['items'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid import data. Expected {items: [...], source: "..."}']);
            return;
        }

        $items = $input['items'];
        $source = $input['source'] ?? 'unknown';
        $allowedSources = ['sticky_password', 'chrome', 'edge', 'brave', 'firefox', 'generic_csv', 'lastpass', 'bitwarden', '1password', 'keepass', 'unknown'];
        if (!in_array($source, $allowedSources, true)) $source = 'unknown';

        // Limit batch size
        if (count($items) > 1000) {
            http_response_code(400);
            echo json_encode(['error' => 'Maximum 1000 items per batch']);
            return;
        }

        $allowedTypes = ['login', 'app_account', 'remote_desktop', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom'];

        // Record import start (bypassed if migration not run yet)
        $importId = null;
        try {
            $importId = Database::insert(
                "INSERT INTO import_history (user_id, source, item_count_total, status, created_at) VALUES (?, ?, ?, 'started', NOW())",
                [$this->userId, $source, count($items)]
            );
        } catch (\Exception $e) {
            error_log("AMPass import history logging bypassed: " . $e->getMessage());
        }

        $imported = 0;
        $skipped = 0;
        $failed = 0;
        $failedErrors = [];

        // Process items in smaller batches with independent transactions.
        // This ensures that a single bad item doesn't roll back ALL successfully imported items.
        $batchSize = 50;
        $totalItems = count($items);

        for ($batchStart = 0; $batchStart < $totalItems; $batchStart += $batchSize) {
            $batch = array_slice($items, $batchStart, $batchSize);

            Database::beginTransaction();
            $batchOk = true;

            try {
                foreach ($batch as $item) {
                    if (empty($item['encrypted_data']) || empty($item['encryption_iv'])) {
                        $skipped++;
                        continue;
                    }

                    $itemType = $item['item_type'] ?? 'login';
                    if (!in_array($itemType, $allowedTypes, true)) $itemType = 'login';

                    try {
                        VaultItem::create([
                            'user_id' => $this->userId,
                            'item_type' => $itemType,
                            'encrypted_data' => $item['encrypted_data'],
                            'encryption_iv' => $item['encryption_iv'],
                            'title_hash' => $item['title_hash'] ?? null,
                            'url_hash' => $item['url_hash'] ?? null,
                            'host_hash' => $item['host_hash'] ?? null,
                            'folder_id' => !empty($item['folder_id']) ? (int)$item['folder_id'] : null,
                            'is_favorite' => 0,
                            'password_strength' => $item['password_strength'] ?? null,
                            'is_weak' => (int)($item['is_weak'] ?? 0),
                            'is_reused' => 0
                        ]);
                        $imported++;
                    } catch (\Exception $e) {
                        $failed++;
                        $errMsg = $e->getMessage();
                        // Truncate long error messages
                        if (strlen($errMsg) > 200) $errMsg = substr($errMsg, 0, 200) . '...';
                        $failedErrors[] = $errMsg;
                    }
                }

                Database::commit();
            } catch (\Exception $e) {
                // Batch-level failure — try to rollback gracefully
                try { Database::rollback(); } catch (\Exception $rbEx) {}
                $batchFailed = count($batch);
                $failed += $batchFailed;
                $failedErrors[] = 'Batch error (items ' . ($batchStart + 1) . '-' . ($batchStart + count($batch)) . '): ' . $e->getMessage();
            }
        }

        // Update import history
        if ($importId !== null) {
            try {
                Database::execute(
                    "UPDATE import_history SET status = 'completed', item_count_imported = ?, item_count_skipped = ?, item_count_failed = ?, completed_at = NOW() WHERE id = ?",
                    [$imported, $skipped, $failed, $importId]
                );
            } catch (\Exception $e) {
                error_log("AMPass import history update failed: " . $e->getMessage());
            }
        }

        AuditLog::log('bulk_import_completed', $this->userId, null, null, [
            'source' => $source, 'imported' => $imported, 'skipped' => $skipped, 'failed' => $failed
        ]);

        echo json_encode([
            'success' => true,
            'import_id' => $importId,
            'imported' => $imported,
            'skipped' => $skipped,
            'failed' => $failed,
            'total' => count($items),
            'errors' => array_slice(array_unique($failedErrors), 0, 5)
        ]);
    }
}
