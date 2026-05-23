<?php
/**
 * AMPass - Import Controller
 * Handles password import from Sticky Password, Chrome, Edge, Firefox, etc.
 * 
 * SECURITY:
 * - Import files contain plaintext passwords
 * - Parsing happens client-side in the browser (never uploaded to server)
 * - Items are encrypted client-side before sending to server API
 * - Server only receives encrypted_data/encryption_iv
 * - Never logs plaintext passwords
 */

require_once __DIR__ . '/../models/VaultItem.php';
require_once __DIR__ . '/../models/Folder.php';
require_once __DIR__ . '/../models/AuditLog.php';

class ImportController {

    public function index(): void {
        $userId = Session::getUserId();
        $folders = Folder::getAllByUser($userId);
        $csrfToken = CSRF::generateToken();

        // Get import history
        $history = [];
        try {
            $history = Database::fetchAll(
                "SELECT * FROM import_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
                [$userId]
            );
        } catch (\Exception $e) {
            // Table may not exist yet
        }

        $data = [
            'folders' => $folders,
            'history' => $history,
            'csrfToken' => $csrfToken
        ];

        require __DIR__ . '/../views/import/index.php';
    }
}
