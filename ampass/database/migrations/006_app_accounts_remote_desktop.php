<?php
/**
 * AMPass Migration 006: Add app_account and remote_desktop vault item types.
 *
 * PHP migration because:
 * - DELIMITER/CREATE PROCEDURE is not supported by PDO::exec()
 * - We need INFORMATION_SCHEMA checks for idempotency
 * - Must be safe to run on partially-applied databases
 *
 * SECURITY: All sensitive data remains inside encrypted_data (client-side encrypted).
 *
 * This file must return true on success or throw an Exception on failure.
 */

$pdo = Database::getInstance();
$dbName = $pdo->query("SELECT DATABASE()")->fetchColumn();

// Step 1: ALTER item_type enum to include new types.
// This is safe to re-run — it replaces the enum definition.
$pdo->exec("ALTER TABLE `vault_items` MODIFY COLUMN `item_type` ENUM(
    'login',
    'app_account',
    'remote_desktop',
    'secure_note',
    'identity',
    'payment_card',
    'wifi',
    'server_ssh',
    'software_license',
    'bank_account',
    'custom'
) NOT NULL DEFAULT 'login'");

// Step 2: Add host_hash column if it does not already exist.
$stmt = $pdo->prepare(
    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'vault_items' AND COLUMN_NAME = 'host_hash'"
);
$stmt->execute([$dbName]);
if ((int)$stmt->fetchColumn() === 0) {
    $pdo->exec("ALTER TABLE `vault_items` ADD COLUMN `host_hash` VARCHAR(64) NULL DEFAULT NULL COMMENT 'HMAC of host for remote desktop matching' AFTER `url_hash`");
}

// Step 3: Add index on host_hash if it does not already exist.
$stmt = $pdo->prepare(
    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'vault_items' AND INDEX_NAME = 'idx_vault_host_hash'"
);
$stmt->execute([$dbName]);
if ((int)$stmt->fetchColumn() === 0) {
    $pdo->exec("ALTER TABLE `vault_items` ADD INDEX `idx_vault_host_hash` (`host_hash`)");
}

// Step 4: Add composite index on (user_id, last_used_at) if it does not already exist.
$stmt = $pdo->prepare(
    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'vault_items' AND INDEX_NAME = 'idx_vault_last_used'"
);
$stmt->execute([$dbName]);
if ((int)$stmt->fetchColumn() === 0) {
    $pdo->exec("ALTER TABLE `vault_items` ADD INDEX `idx_vault_last_used` (`user_id`, `last_used_at` DESC)");
}

// All steps succeeded
return true;
