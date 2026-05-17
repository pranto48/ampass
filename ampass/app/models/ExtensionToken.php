<?php
/**
 * AMPass - Extension Token Model
 * SECURITY: Tokens are SHA-256 hashed before storage. A database leak does not expose raw tokens.
 * Tokens are tied to devices and have configurable expiry.
 */

class ExtensionToken {

    /**
     * Generate a new token for a device
     * Returns the raw token (shown to user once) and the device/token IDs
     */
    public static function create(int $userId, int $deviceId, int $lifetimeDays = 30): array {
        $rawToken = bin2hex(random_bytes(32)); // 64-char hex token
        $tokenHash = hash('sha256', $rawToken);
        $tokenPrefix = substr($rawToken, 0, 8);
        $expiresAt = date('Y-m-d H:i:s', time() + ($lifetimeDays * 86400));
        $ip = Security::getClientIP();

        $id = Database::insert(
            "INSERT INTO extension_tokens (user_id, device_id, token_hash, token_prefix, ip_address, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())",
            [$userId, $deviceId, $tokenHash, $tokenPrefix, $ip, $expiresAt]
        );

        return [
            'token_id' => $id,
            'raw_token' => $rawToken,
            'prefix' => $tokenPrefix,
            'expires_at' => $expiresAt
        ];
    }

    /**
     * Validate a bearer token
     * Returns user_id and device_id if valid, null if invalid/expired/revoked
     */
    public static function validate(string $rawToken): ?array {
        if (empty($rawToken) || strlen($rawToken) !== 64) {
            return null;
        }

        $tokenHash = hash('sha256', $rawToken);

        $record = Database::fetchOne(
            "SELECT et.id, et.user_id, et.device_id, et.expires_at, et.revoked_at,
                    ed.revoked_at as device_revoked_at, u.status as user_status
             FROM extension_tokens et
             JOIN extension_devices ed ON et.device_id = ed.id
             JOIN users u ON et.user_id = u.id
             WHERE et.token_hash = ?",
            [$tokenHash]
        );

        if (!$record) return null;
        if ($record['revoked_at'] !== null) return null;
        if ($record['device_revoked_at'] !== null) return null;
        if ($record['user_status'] !== 'active') return null;
        if (strtotime($record['expires_at']) < time()) return null;

        // Update last_used_at
        Database::execute(
            "UPDATE extension_tokens SET last_used_at = NOW() WHERE id = ?",
            [$record['id']]
        );
        Database::execute(
            "UPDATE extension_devices SET last_seen_at = NOW(), ip_address = ? WHERE id = ?",
            [Security::getClientIP(), $record['device_id']]
        );

        return [
            'token_id' => (int)$record['id'],
            'user_id' => (int)$record['user_id'],
            'device_id' => (int)$record['device_id']
        ];
    }

    /**
     * Revoke a specific token
     */
    public static function revoke(int $tokenId, int $userId): bool {
        $affected = Database::execute(
            "UPDATE extension_tokens SET revoked_at = NOW() WHERE id = ? AND user_id = ?",
            [$tokenId, $userId]
        );
        return $affected > 0;
    }

    /**
     * Revoke all tokens for a device
     */
    public static function revokeByDevice(int $deviceId, int $userId): int {
        return Database::execute(
            "UPDATE extension_tokens SET revoked_at = NOW() WHERE device_id = ? AND user_id = ? AND revoked_at IS NULL",
            [$deviceId, $userId]
        );
    }

    /**
     * List active tokens for a user
     */
    public static function listByUser(int $userId): array {
        return Database::fetchAll(
            "SELECT et.id, et.token_prefix, et.ip_address, et.last_used_at, et.expires_at, et.created_at,
                    ed.device_name, ed.browser_name
             FROM extension_tokens et
             JOIN extension_devices ed ON et.device_id = ed.id
             WHERE et.user_id = ? AND et.revoked_at IS NULL AND et.expires_at > NOW()
             ORDER BY et.last_used_at DESC",
            [$userId]
        );
    }

    /**
     * Cleanup expired tokens
     */
    public static function cleanupExpired(): int {
        return Database::execute(
            "DELETE FROM extension_tokens WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
        );
    }
}
