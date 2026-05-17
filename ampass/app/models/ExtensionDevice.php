<?php
/**
 * AMPass - Extension Device Model
 * Tracks registered browser extension instances.
 */

class ExtensionDevice {

    /**
     * Register a new device
     */
    public static function create(array $data): int {
        return Database::insert(
            "INSERT INTO extension_devices (user_id, device_name, browser_name, extension_id, ip_address, last_seen_at, created_at)
             VALUES (?, ?, ?, ?, ?, NOW(), NOW())",
            [
                $data['user_id'],
                $data['device_name'],
                $data['browser_name'] ?? null,
                $data['extension_id'] ?? null,
                Security::getClientIP()
            ]
        );
    }

    /**
     * Find device by ID and user
     */
    public static function findById(int $id, int $userId): ?array {
        return Database::fetchOne(
            "SELECT * FROM extension_devices WHERE id = ? AND user_id = ?",
            [$id, $userId]
        );
    }

    /**
     * List active devices for a user
     */
    public static function listByUser(int $userId): array {
        return Database::fetchAll(
            "SELECT ed.*, 
                    (SELECT COUNT(*) FROM extension_tokens et WHERE et.device_id = ed.id AND et.revoked_at IS NULL AND et.expires_at > NOW()) as active_tokens
             FROM extension_devices ed
             WHERE ed.user_id = ? AND ed.revoked_at IS NULL
             ORDER BY ed.last_seen_at DESC",
            [$userId]
        );
    }

    /**
     * List all devices (admin)
     */
    public static function listAll(int $limit = 50, int $offset = 0): array {
        return Database::fetchAll(
            "SELECT ed.*, u.username, u.email
             FROM extension_devices ed
             JOIN users u ON ed.user_id = u.id
             ORDER BY ed.last_seen_at DESC
             LIMIT ? OFFSET ?",
            [$limit, $offset]
        );
    }

    /**
     * Revoke a device (also revokes all its tokens)
     */
    public static function revoke(int $deviceId, int $userId): bool {
        $affected = Database::execute(
            "UPDATE extension_devices SET revoked_at = NOW() WHERE id = ? AND user_id = ?",
            [$deviceId, $userId]
        );
        if ($affected > 0) {
            // Revoke all tokens for this device
            Database::execute(
                "UPDATE extension_tokens SET revoked_at = NOW() WHERE device_id = ? AND revoked_at IS NULL",
                [$deviceId]
            );
            return true;
        }
        return false;
    }

    /**
     * Admin revoke (no user_id check)
     */
    public static function adminRevoke(int $deviceId): bool {
        $affected = Database::execute(
            "UPDATE extension_devices SET revoked_at = NOW() WHERE id = ?",
            [$deviceId]
        );
        if ($affected > 0) {
            Database::execute(
                "UPDATE extension_tokens SET revoked_at = NOW() WHERE device_id = ? AND revoked_at IS NULL",
                [$deviceId]
            );
            return true;
        }
        return false;
    }

    /**
     * Count active devices for a user
     */
    public static function countByUser(int $userId): int {
        $result = Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM extension_devices WHERE user_id = ? AND revoked_at IS NULL",
            [$userId]
        );
        return (int)($result['cnt'] ?? 0);
    }
}
