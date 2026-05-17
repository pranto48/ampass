-- AMPass Extension API Tables
-- Run this migration after initial schema.sql installation.
-- These tables support browser extension authentication and audit logging.

SET NAMES utf8mb4;

-- Extension devices (registered browser extensions)
CREATE TABLE IF NOT EXISTS `extension_devices` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `device_name` VARCHAR(100) NOT NULL COMMENT 'User-friendly name (e.g. Chrome on Windows)',
    `browser_name` VARCHAR(50) NULL COMMENT 'Chrome, Edge, Firefox, etc.',
    `extension_id` VARCHAR(128) NULL COMMENT 'Browser extension ID for origin validation',
    `public_key` TEXT NULL COMMENT 'Reserved for future key exchange',
    `ip_address` VARCHAR(45) NULL,
    `last_seen_at` DATETIME NULL,
    `revoked_at` DATETIME NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_ext_devices_user` (`user_id`),
    INDEX `idx_ext_devices_revoked` (`revoked_at`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Extension tokens (bearer tokens for API auth)
CREATE TABLE IF NOT EXISTS `extension_tokens` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `device_id` INT UNSIGNED NOT NULL,
    `token_hash` VARCHAR(64) NOT NULL COMMENT 'SHA-256 hash of the bearer token',
    `token_prefix` VARCHAR(8) NOT NULL COMMENT 'First 8 chars of token for identification',
    `ip_address` VARCHAR(45) NULL,
    `last_used_at` DATETIME NULL,
    `expires_at` DATETIME NOT NULL,
    `revoked_at` DATETIME NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX `idx_ext_token_hash` (`token_hash`),
    INDEX `idx_ext_token_user` (`user_id`),
    INDEX `idx_ext_token_device` (`device_id`),
    INDEX `idx_ext_token_expires` (`expires_at`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`device_id`) REFERENCES `extension_devices`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Extension audit logs (separate from main audit for performance)
CREATE TABLE IF NOT EXISTS `extension_audit_logs` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NULL,
    `device_id` INT UNSIGNED NULL,
    `action` VARCHAR(50) NOT NULL COMMENT 'ext_login, ext_unlock, autofill_used, autosave_created, etc.',
    `resource_type` VARCHAR(30) NULL COMMENT 'vault_item, token, device',
    `resource_id` INT UNSIGNED NULL,
    `ip_address` VARCHAR(45) NULL,
    `user_agent` VARCHAR(500) NULL,
    `details` JSON NULL COMMENT 'Additional context (domain, item_type, etc.)',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_ext_audit_user` (`user_id`),
    INDEX `idx_ext_audit_device` (`device_id`),
    INDEX `idx_ext_audit_action` (`action`),
    INDEX `idx_ext_audit_created` (`created_at`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`device_id`) REFERENCES `extension_devices`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add extension-related app_settings
INSERT IGNORE INTO `app_settings` (`setting_key`, `setting_value`) VALUES
('extension_api_enabled', '1'),
('extension_allowed_origins', ''),
('extension_token_lifetime_days', '30'),
('extension_max_devices_per_user', '10');
