<?php
/**
 * AMPass - Audit Log Model
 * SECURITY: Records all security-relevant actions for accountability.
 */

class AuditLog {

    /**
     * Log an action
     */
    public static function log(string $action, ?int $userId = null, ?string $resourceType = null, ?int $resourceId = null, ?array $details = null): void {
        Database::insert(
            "INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW())",
            [
                $userId ?? Session::getUserId(),
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
     * Count failed logins for a specific login username or email in the last N hours
     */
    public static function countRecentFailedLogins(string $username, string $email, int $hours = 24): int {
        $result = Database::fetchOne(
            "SELECT COUNT(*) as total FROM audit_logs 
             WHERE action = 'login_failed' 
             AND (details LIKE ? OR details LIKE ?)
             AND created_at > DATE_SUB(NOW(), INTERVAL ? HOUR)",
            ['%"login":"' . $username . '"%', '%"login":"' . $email . '"%', $hours]
        );
        return (int) ($result['total'] ?? 0);
    }

    /**
     * Get logs for a user
     */
    public static function getByUser(int $userId, int $limit = 50, int $offset = 0): array {
        return Database::fetchAll(
            "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [$userId, $limit, $offset]
        );
    }

    /**
     * Get all logs (admin)
     */
    public static function getAll(int $limit = 100, int $offset = 0, ?string $action = null): array {
        $sql = "SELECT al.*, u.username FROM audit_logs al 
                LEFT JOIN users u ON al.user_id = u.id";
        $params = [];

        if ($action) {
            $sql .= " WHERE al.action = ?";
            $params[] = $action;
        }

        $sql .= " ORDER BY al.created_at DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;

        return Database::fetchAll($sql, $params);
    }

    /**
     * Get logs for a specific resource
     */
    public static function getByResource(string $resourceType, int $resourceId): array {
        return Database::fetchAll(
            "SELECT al.*, u.username FROM audit_logs al 
             LEFT JOIN users u ON al.user_id = u.id 
             WHERE al.resource_type = ? AND al.resource_id = ? 
             ORDER BY al.created_at DESC",
            [$resourceType, $resourceId]
        );
    }

    /**
     * Clean old logs (keep last 90 days)
     */
    public static function cleanup(int $daysToKeep = 90): int {
        return Database::execute(
            "DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$daysToKeep]
        );
    }
}
