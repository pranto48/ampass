<?php
/**
 * AMPass - Vault Item Model
 * SECURITY: All vault item data is encrypted client-side before storage.
 * The server only stores ciphertext, IVs, and metadata flags.
 * Decryption happens exclusively in the browser using Web Crypto API.
 */

class VaultItem {

    /**
     * Get all vault items for a user (encrypted data) with optional pagination
     */
    public static function getAllByUser(int $userId, ?string $type = null, ?int $folderId = null, ?int $limit = null, ?int $offset = null): array {
        $sql = "SELECT vi.*, f.name as folder_name 
                FROM vault_items vi 
                LEFT JOIN folders f ON vi.folder_id = f.id 
                WHERE vi.user_id = ?";
        $params = [$userId];

        if ($type) {
            $sql .= " AND vi.item_type = ?";
            $params[] = $type;
        }

        if ($folderId !== null) {
            $sql .= " AND vi.folder_id = ?";
            $params[] = $folderId;
        }

        $sql .= " ORDER BY vi.is_favorite DESC, vi.updated_at DESC";

        if ($limit !== null && $offset !== null) {
            $sql .= " LIMIT " . (int)$limit . " OFFSET " . (int)$offset;
        }

        return Database::fetchAll($sql, $params);
    }

    /**
     * Count all vault items for a user matching parameters (for pagination)
     */
    public static function countAllByUser(int $userId, ?string $type = null, ?int $folderId = null): int {
        $sql = "SELECT COUNT(*) as cnt FROM vault_items WHERE user_id = ?";
        $params = [$userId];

        if ($type) {
            $sql .= " AND item_type = ?";
            $params[] = $type;
        }

        if ($folderId !== null) {
            $sql .= " AND folder_id = ?";
            $params[] = $folderId;
        }

        $res = Database::fetchOne($sql, $params);
        return (int)($res['cnt'] ?? 0);
    }

    /**
     * Get a single vault item
     */
    public static function findById(int $id, int $userId): ?array {
        return Database::fetchOne(
            "SELECT vi.*, f.name as folder_name 
             FROM vault_items vi 
             LEFT JOIN folders f ON vi.folder_id = f.id 
             WHERE vi.id = ? AND vi.user_id = ?",
            [$id, $userId]
        );
    }

    /**
     * Create a new vault item
     */
    public static function create(array $data): int {
        return Database::insert(
            "INSERT INTO vault_items 
             (user_id, item_type, encrypted_data, encryption_iv, title_hash, url_hash, host_hash,
              folder_id, is_favorite, password_strength, is_weak, is_reused, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
            [
                $data['user_id'],
                $data['item_type'] ?? 'login',
                $data['encrypted_data'],
                $data['encryption_iv'],
                $data['title_hash'] ?? null,
                $data['url_hash'] ?? null,
                $data['host_hash'] ?? null,
                $data['folder_id'] ?? null,
                $data['is_favorite'] ?? 0,
                $data['password_strength'] ?? null,
                $data['is_weak'] ?? 0,
                $data['is_reused'] ?? 0
            ]
        );
    }

    /**
     * Update a vault item
     */
    public static function update(int $id, int $userId, array $data): int {
        return Database::execute(
            "UPDATE vault_items SET 
             encrypted_data = ?,
             encryption_iv = ?,
             item_type = ?,
             title_hash = ?,
             url_hash = ?,
             host_hash = ?,
             folder_id = ?,
             is_favorite = ?,
             password_strength = ?,
             is_weak = ?,
             is_reused = ?,
             updated_at = NOW()
             WHERE id = ? AND user_id = ?",
            [
                $data['encrypted_data'],
                $data['encryption_iv'],
                $data['item_type'] ?? 'login',
                $data['title_hash'] ?? null,
                $data['url_hash'] ?? null,
                $data['host_hash'] ?? null,
                $data['folder_id'] ?? null,
                $data['is_favorite'] ?? 0,
                $data['password_strength'] ?? null,
                $data['is_weak'] ?? 0,
                $data['is_reused'] ?? 0,
                $id,
                $userId
            ]
        );
    }

    /**
     * Delete a vault item
     */
    public static function delete(int $id, int $userId): int {
        return Database::execute(
            "DELETE FROM vault_items WHERE id = ? AND user_id = ?",
            [$id, $userId]
        );
    }

    /**
     * Toggle favorite
     */
    public static function toggleFavorite(int $id, int $userId): int {
        return Database::execute(
            "UPDATE vault_items SET is_favorite = NOT is_favorite, updated_at = NOW() 
             WHERE id = ? AND user_id = ?",
            [$id, $userId]
        );
    }

    /**
     * Update last used timestamp
     */
    public static function markUsed(int $id, int $userId): void {
        Database::execute(
            "UPDATE vault_items SET last_used_at = NOW() WHERE id = ? AND user_id = ?",
            [$id, $userId]
        );
    }

    /**
     * Get vault statistics for dashboard
     */
    public static function getStats(int $userId): array {
        $total = Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE user_id = ?", [$userId]
        );
        $weak = Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE user_id = ? AND is_weak = 1", [$userId]
        );
        $reused = Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE user_id = ? AND is_reused = 1", [$userId]
        );
        $favorites = Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE user_id = ? AND is_favorite = 1", [$userId]
        );

        $totalCount = (int)($total['cnt'] ?? 0);
        $weakCount = (int)($weak['cnt'] ?? 0);
        $reusedCount = (int)($reused['cnt'] ?? 0);

        // Calculate security score (simple formula)
        $score = 100;
        if ($totalCount > 0) {
            $problemRatio = ($weakCount + $reusedCount) / $totalCount;
            $score = max(0, (int)(100 - ($problemRatio * 100)));
        }

        return [
            'total' => $totalCount,
            'weak' => $weakCount,
            'reused' => $reusedCount,
            'favorites' => (int)($favorites['cnt'] ?? 0),
            'security_score' => $score
        ];
    }

    /**
     * Get recently used items
     */
    public static function getRecentlyUsed(int $userId, int $limit = 5): array {
        return Database::fetchAll(
            "SELECT * FROM vault_items 
             WHERE user_id = ? AND last_used_at IS NOT NULL 
             ORDER BY last_used_at DESC LIMIT ?",
            [$userId, $limit]
        );
    }

    /**
     * Get favorites
     */
    public static function getFavorites(int $userId): array {
        return Database::fetchAll(
            "SELECT * FROM vault_items WHERE user_id = ? AND is_favorite = 1 ORDER BY updated_at DESC",
            [$userId]
        );
    }

    /**
     * Count items by type
     */
    public static function countByType(int $userId): array {
        return Database::fetchAll(
            "SELECT item_type, COUNT(*) as cnt FROM vault_items WHERE user_id = ? GROUP BY item_type",
            [$userId]
        );
    }

    /**
     * Move items to folder
     */
    public static function moveToFolder(array $itemIds, ?int $folderId, int $userId): int {
        if (empty($itemIds)) return 0;
        
        $placeholders = implode(',', array_fill(0, count($itemIds), '?'));
        $params = array_merge([$folderId], $itemIds, [$userId]);
        
        return Database::execute(
            "UPDATE vault_items SET folder_id = ?, updated_at = NOW() 
             WHERE id IN ({$placeholders}) AND user_id = ?",
            $params
        );
    }
}
