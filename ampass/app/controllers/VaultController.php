<?php
/**
 * AMPass - Vault Controller
 * Handles vault item listing, creation, editing, and deletion.
 * SECURITY: All data is encrypted client-side. Server only stores ciphertext.
 */

require_once __DIR__ . '/../models/VaultItem.php';
require_once __DIR__ . '/../models/Folder.php';
require_once __DIR__ . '/../models/AuditLog.php';

class VaultController {

    public function index(): void {
        $userId = Session::getUserId();
        $type = $_GET['type'] ?? null;
        $folderId = isset($_GET['folder']) ? (int)$_GET['folder'] : null;

        // Pagination setup
        $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
        $limit = 50; // 50 items per page
        $offset = ($page - 1) * $limit;

        $totalItems = VaultItem::countAllByUser($userId, $type, $folderId);
        $totalPages = (int)ceil($totalItems / $limit);

        $items = VaultItem::getAllByUser($userId, $type, $folderId, $limit, $offset);
        $folders = Folder::getAllByUser($userId);
        $csrfToken = CSRF::generateToken();

        $data = [
            'items' => $items,
            'folders' => $folders,
            'currentType' => $type,
            'currentFolder' => $folderId,
            'csrfToken' => $csrfToken,
            'page' => $page,
            'totalPages' => $totalPages,
            'totalItems' => $totalItems
        ];

        require __DIR__ . '/../views/layouts/app.php';
    }

    public function add(): void {
        $userId = Session::getUserId();
        $folders = Folder::getAllByUser($userId);
        $csrfToken = CSRF::generateToken();
        $itemType = $_GET['type'] ?? 'login';

        $data = [
            'folders' => $folders,
            'csrfToken' => $csrfToken,
            'itemType' => $itemType,
            'item' => null
        ];

        require __DIR__ . '/../views/vault/form.php';
    }

    public function import(): void {
        header('Location: ' . APP_URL . '/import');
        exit;
    }

    public function edit(?string $id = null): void {
        $userId = Session::getUserId();
        $itemId = (int)($id ?? $_GET['id'] ?? 0);

        $item = VaultItem::findById($itemId, $userId);
        if (!$item) {
            http_response_code(404);
            require __DIR__ . '/../views/errors/404.php';
            return;
        }

        $folders = Folder::getAllByUser($userId);
        $csrfToken = CSRF::generateToken();

        $data = [
            'folders' => $folders,
            'csrfToken' => $csrfToken,
            'itemType' => $item['item_type'],
            'item' => $item
        ];

        require __DIR__ . '/../views/vault/form.php';
    }

    public function view(?string $id = null): void {
        $userId = Session::getUserId();
        $itemId = (int)($id ?? $_GET['id'] ?? 0);

        $item = VaultItem::findById($itemId, $userId);
        if (!$item) {
            http_response_code(404);
            require __DIR__ . '/../views/errors/404.php';
            return;
        }

        // Mark as used
        VaultItem::markUsed($itemId, $userId);

        $csrfToken = CSRF::generateToken();
        $data = ['item' => $item, 'csrfToken' => $csrfToken];

        require __DIR__ . '/../views/vault/view.php';
    }
}
