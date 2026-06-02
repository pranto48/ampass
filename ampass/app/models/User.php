<?php
/**
 * AMPass - User Model
 * Handles user CRUD operations, authentication, and security data.
 * SECURITY: All queries use prepared statements.
 */

class User {

    /**
     * Find user by ID
     */
    public static function findById(int $id): ?array {
        return Database::fetchOne(
            "SELECT id, username, email, full_name, role, status, force_password_reset, 
                    two_factor_enabled, two_factor_new_device, two_factor_failed_logins, 
                    avatar_url, created_at, updated_at, last_login_at 
             FROM users WHERE id = ?",
            [$id]
        );
    }

    /**
     * Find user by username
     */
    public static function findByUsername(string $username): ?array {
        return Database::fetchOne(
            "SELECT * FROM users WHERE username = ?",
            [$username]
        );
    }

    /**
     * Find user by email
     */
    public static function findByEmail(string $email): ?array {
        return Database::fetchOne(
            "SELECT * FROM users WHERE email = ?",
            [$email]
        );
    }

    /**
     * Find user by username or email (for login)
     */
    public static function findByLogin(string $login): ?array {
        return Database::fetchOne(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            [$login, $login]
        );
    }

    /**
     * Create a new user
     */
    public static function create(array $data): int {
        return Database::insert(
            "INSERT INTO users (username, email, full_name, password_hash, role, status, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, NOW())",
            [
                $data['username'],
                $data['email'],
                $data['full_name'],
                $data['password_hash'],
                $data['role'] ?? 'user',
                $data['status'] ?? 'active'
            ]
        );
    }

    /**
     * Update user profile
     */
    public static function update(int $id, array $data): int {
        $fields = [];
        $values = [];
        
        $allowedFields = ['full_name', 'email', 'avatar_url', 'status', 'force_password_reset'];
        
        foreach ($allowedFields as $field) {
            if (isset($data[$field])) {
                $fields[] = "{$field} = ?";
                $values[] = $data[$field];
            }
        }

        if (empty($fields)) return 0;
        
        $values[] = $id;
        return Database::execute(
            "UPDATE users SET " . implode(', ', $fields) . ", updated_at = NOW() WHERE id = ?",
            $values
        );
    }

    /**
     * Update password hash
     */
    public static function updatePassword(int $id, string $passwordHash): int {
        return Database::execute(
            "UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?",
            [$passwordHash, $id]
        );
    }

    /**
     * Update last login timestamp
     */
    public static function updateLastLogin(int $id): void {
        Database::execute(
            "UPDATE users SET last_login_at = NOW() WHERE id = ?",
            [$id]
        );
    }

    /**
     * Get all users (admin)
     */
    public static function getAll(int $limit = 50, int $offset = 0): array {
        return Database::fetchAll(
            "SELECT id, username, email, full_name, role, status, created_at, last_login_at 
             FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [$limit, $offset]
        );
    }

    /**
     * Count total users
     */
    public static function count(): int {
        $result = Database::fetchOne("SELECT COUNT(*) as total FROM users");
        return (int) ($result['total'] ?? 0);
    }

    /**
     * Check if username exists
     */
    public static function usernameExists(string $username, ?int $excludeId = null): bool {
        $sql = "SELECT COUNT(*) as cnt FROM users WHERE username = ?";
        $params = [$username];
        
        if ($excludeId) {
            $sql .= " AND id != ?";
            $params[] = $excludeId;
        }
        
        $result = Database::fetchOne($sql, $params);
        return ($result['cnt'] ?? 0) > 0;
    }

    /**
     * Check if email exists
     */
    public static function emailExists(string $email, ?int $excludeId = null): bool {
        $sql = "SELECT COUNT(*) as cnt FROM users WHERE email = ?";
        $params = [$email];
        
        if ($excludeId) {
            $sql .= " AND id != ?";
            $params[] = $excludeId;
        }
        
        $result = Database::fetchOne($sql, $params);
        return ($result['cnt'] ?? 0) > 0;
    }

    /**
     * Suspend a user
     */
    public static function suspend(int $id): int {
        return Database::execute(
            "UPDATE users SET status = 'suspended', updated_at = NOW() WHERE id = ?",
            [$id]
        );
    }

    /**
     * Activate a user
     */
    public static function activate(int $id): int {
        return Database::execute(
            "UPDATE users SET status = 'active', updated_at = NOW() WHERE id = ?",
            [$id]
        );
    }

    /**
     * Delete a user (cascades to all related data)
     */
    public static function delete(int $id): int {
        return Database::execute("DELETE FROM users WHERE id = ?", [$id]);
    }
}
