<?php
/**
 * AMPass - Database Connection (PDO)
 * SECURITY: Uses prepared statements exclusively. Never concatenate user input into queries.
 */

class Database {
    private static ?PDO $instance = null;

    /**
     * Get PDO database connection (singleton)
     */
    public static function getInstance(): PDO {
        if (self::$instance === null) {
            try {
                $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
                $options = [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false, // Use real prepared statements
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
                ];
                self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
                
                // Self-healing database schema updates for 2FA settings
                try {
                    $stmt = self::$instance->query("SHOW COLUMNS FROM users");
                    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    $hasNewDeviceCol = false;
                    $hasFailedLoginsCol = false;
                    foreach ($columns as $col) {
                        if ($col['Field'] === 'two_factor_new_device') $hasNewDeviceCol = true;
                        if ($col['Field'] === 'two_factor_failed_logins') $hasFailedLoginsCol = true;
                    }
                    if (!$hasNewDeviceCol) {
                        self::$instance->exec("ALTER TABLE users ADD COLUMN two_factor_new_device TINYINT(1) DEFAULT 0");
                    }
                    if (!$hasFailedLoginsCol) {
                        self::$instance->exec("ALTER TABLE users ADD COLUMN two_factor_failed_logins TINYINT(1) DEFAULT 0");
                    }
                } catch (\Exception $schemaEx) {
                    // Ignore schema checking errors
                }
            } catch (PDOException $e) {
                if (defined('DEBUG_MODE') && DEBUG_MODE) {
                    // SECURITY: Only show details in debug mode (NEVER enable in production)
                    error_log('AMPass DB Error: ' . $e->getMessage());
                    die('Database connection failed (debug): ' . htmlspecialchars($e->getMessage()));
                }
                error_log('AMPass DB Error: ' . $e->getMessage());
                die('Database connection failed. Please check your configuration.');
            }
        }
        return self::$instance;
    }

    /**
     * Execute a prepared query and return statement
     */
    public static function query(string $sql, array $params = []): PDOStatement {
        $stmt = self::getInstance()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * Fetch single row
     */
    public static function fetchOne(string $sql, array $params = []): ?array {
        $stmt = self::query($sql, $params);
        $result = $stmt->fetch();
        return $result ?: null;
    }

    /**
     * Fetch all rows
     */
    public static function fetchAll(string $sql, array $params = []): array {
        $stmt = self::query($sql, $params);
        return $stmt->fetchAll();
    }

    /**
     * Insert and return last insert ID
     */
    public static function insert(string $sql, array $params = []): int {
        self::query($sql, $params);
        return (int) self::getInstance()->lastInsertId();
    }

    /**
     * Update/delete and return affected rows
     */
    public static function execute(string $sql, array $params = []): int {
        $stmt = self::query($sql, $params);
        return $stmt->rowCount();
    }

    /**
     * Begin transaction
     */
    public static function beginTransaction(): bool {
        return self::getInstance()->beginTransaction();
    }

    /**
     * Commit transaction
     */
    public static function commit(): bool {
        return self::getInstance()->commit();
    }

    /**
     * Rollback transaction
     */
    public static function rollback(): bool {
        return self::getInstance()->rollBack();
    }
}
