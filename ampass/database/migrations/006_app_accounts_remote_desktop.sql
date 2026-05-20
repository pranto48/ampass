-- AMPass Migration 006: Add app_account and remote_desktop vault item types
-- For existing installations. Fresh installs already include these in schema.sql.
-- SECURITY: All sensitive data remains inside encrypted_data (client-side encrypted).
-- This migration is designed to be as idempotent as practical for MySQL/MariaDB.

-- Step 1: Alter item_type enum to include new types.
-- MySQL ALTER MODIFY is safe to re-run (replaces the enum definition).
ALTER TABLE `vault_items` MODIFY COLUMN `item_type` ENUM(
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
) NOT NULL DEFAULT 'login';

-- Step 2: Add host_hash column if it does not already exist.
-- MySQL does not support IF NOT EXISTS on ALTER TABLE ADD COLUMN,
-- so we use a procedure to check first.
DROP PROCEDURE IF EXISTS `_ampass_migration_006_add_host_hash`;
DELIMITER //
CREATE PROCEDURE `_ampass_migration_006_add_host_hash`()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'vault_items'
          AND COLUMN_NAME = 'host_hash'
    ) THEN
        ALTER TABLE `vault_items` ADD COLUMN `host_hash` VARCHAR(64) NULL DEFAULT NULL COMMENT 'HMAC of host for remote desktop matching' AFTER `url_hash`;
    END IF;
END //
DELIMITER ;
CALL `_ampass_migration_006_add_host_hash`();
DROP PROCEDURE IF EXISTS `_ampass_migration_006_add_host_hash`;

-- Step 3: Add index on host_hash if it does not already exist.
DROP PROCEDURE IF EXISTS `_ampass_migration_006_add_idx_host_hash`;
DELIMITER //
CREATE PROCEDURE `_ampass_migration_006_add_idx_host_hash`()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'vault_items'
          AND INDEX_NAME = 'idx_vault_host_hash'
    ) THEN
        ALTER TABLE `vault_items` ADD INDEX `idx_vault_host_hash` (`host_hash`);
    END IF;
END //
DELIMITER ;
CALL `_ampass_migration_006_add_idx_host_hash`();
DROP PROCEDURE IF EXISTS `_ampass_migration_006_add_idx_host_hash`;

-- Step 4: Add composite index on (user_id, last_used_at) if it does not already exist.
DROP PROCEDURE IF EXISTS `_ampass_migration_006_add_idx_last_used`;
DELIMITER //
CREATE PROCEDURE `_ampass_migration_006_add_idx_last_used`()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'vault_items'
          AND INDEX_NAME = 'idx_vault_last_used'
    ) THEN
        ALTER TABLE `vault_items` ADD INDEX `idx_vault_last_used` (`user_id`, `last_used_at` DESC);
    END IF;
END //
DELIMITER ;
CALL `_ampass_migration_006_add_idx_last_used`();
DROP PROCEDURE IF EXISTS `_ampass_migration_006_add_idx_last_used`;
