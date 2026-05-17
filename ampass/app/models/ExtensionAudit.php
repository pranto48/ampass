<?php
/**
 * AMPass - Extension Audit Log Model
 * SECURITY: Logs all extension API actions for accountability.
 * Never logs plaintext secrets.
 */

class ExtensionAudit {

    /**
     * Log an extension action
     */
    public static function log(string $action, ?int $userId = null, ?int $deviceId = null, ?string $resourceType = null, ?int $resourceId = null, ?array $details = null): void {
        Database::insert(
            "INSERT INTO extension_audit_logs (user_id, device_id, action, resource_type, resource_id, ip_address, user_agent, details, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())",
            [
                $userId,
                $deviceId,
                $action,
                $resourceType,
                $resourceId,
                Security::getClientIP(),
                substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
                $details ? json_encode($details) : null
            ]
        );
    }

    /**
     * Get logs for a user
     */
    public static function getByUser(int $userId, int $limit = 50, int $offset = 0): array {
        return Database::fetchAll(
            "SELECT eal.*, ed.device_name
             FROM extension_audit_logs eal
             LEFT JOIN extension_devices ed ON eal.device_id = ed.id
             WHERE eal.user_id = ?
             ORDER BY eal.created_at DESC
             LIMIT ? OFFSET ?",
            [$userId, $limit, $offset]
        );
    }

    /**
     * Get all logs (admin)
     */
    public static function getAll(int $limit = 100, int $offset = 0): array {
        return Database::fetchAll(
            "SELECT eal.*, u.username, ed.device_name
             FROM extension_audit_logs eal
             LEFT JOIN users u ON eal.user_id = u.id
             LEFT JOIN extension_devices ed ON eal.device_id = ed.id
             ORDER BY eal.created_at DESC
             LIMIT ? OFFSET ?",
            [$limit, $offset]
        );
    }

    /**
     * Get logs for a device
     */
    public static function getByDevice(int $deviceId, int $limit = 50): array {
        return Database::fetchAll(
            "SELECT * FROM extension_audit_logs WHERE device_id = ? ORDER BY created_at DESC LIMIT ?",
            [$deviceId, $limit]
        );
    }

    /**
     * Cleanup old logs (keep 90 days)
     */
    public static function cleanup(int $daysToKeep = 90): int {
        return Database::execute(
            "DELETE FROM extension_audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$daysToKeep]
        );
    }
}
