-- AMPass Database Schema
-- MySQL 5.7+ / MariaDB 10.3+
-- SECURITY: All sensitive data is stored encrypted. Server never sees plaintext vault data.

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Application settings
CREATE TABLE IF NOT EXISTS `app_settings` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `setting_key` VARCHAR(100) NOT NULL UNIQUE,
    `setting_value` TEXT,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Users table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `full_name` VARCHAR(100) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL COMMENT 'Argon2id/bcrypt hash of login password',
    `role` ENUM('admin', 'user') DEFAULT 'user',
    `status` ENUM('active', 'suspended', 'pending') DEFAULT 'active',
    `force_password_reset` TINYINT(1) DEFAULT 0,
    `two_factor_enabled` TINYINT(1) DEFAULT 0,
    `two_factor_secret_encrypted` TEXT NULL COMMENT 'Encrypted 2FA secret',
    `avatar_url` VARCHAR(500) NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `last_login_at` DATETIME NULL,
    INDEX `idx_users_email` (`email`),
    INDEX `idx_users_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User security data (encryption keys, salts)
CREATE TABLE IF NOT EXISTS `user_security` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL UNIQUE,
    `master_password_hash` VARCHAR(255) NOT NULL COMMENT 'Separate hash for vault unlock (bcrypt/argon2id)',
    `encryption_salt` VARCHAR(128) NOT NULL COMMENT 'Salt for deriving encryption key from master password',
    `encrypted_vault_key` TEXT NOT NULL COMMENT 'Vault key encrypted with derived key - only user can decrypt',
    `vault_key_iv` VARCHAR(64) NOT NULL COMMENT 'IV/nonce for vault key encryption',
    `recovery_key_hash` VARCHAR(255) NULL COMMENT 'Hash of recovery key',
    `encrypted_recovery_data` TEXT NULL COMMENT 'Recovery data encrypted with recovery key',
    `recovery_iv` VARCHAR(64) NULL,
    `key_iterations` INT UNSIGNED DEFAULT 100000 COMMENT 'PBKDF2 iterations for key derivation',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vault items (all sensitive fields encrypted client-side)
CREATE TABLE IF NOT EXISTS `vault_items` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `item_type` ENUM('login', 'app_account', 'remote_desktop', 'secure_note', 'identity', 'payment_card', 'wifi', 'server_ssh', 'software_license', 'bank_account', 'custom') NOT NULL DEFAULT 'login',
    `encrypted_data` LONGTEXT NOT NULL COMMENT 'AES-GCM encrypted JSON blob of all item fields',
    `encryption_iv` VARCHAR(64) NOT NULL COMMENT 'IV/nonce for this item',
    `title_hash` VARCHAR(64) NULL COMMENT 'HMAC of title for server-side search without decryption',
    `url_hash` VARCHAR(64) NULL COMMENT 'HMAC of URL for matching',
    `host_hash` VARCHAR(64) NULL COMMENT 'HMAC of host for remote desktop matching',
    `folder_id` INT UNSIGNED NULL,
    `is_favorite` TINYINT(1) DEFAULT 0,
    `password_strength` TINYINT UNSIGNED NULL COMMENT 'Score 0-100, calculated client-side',
    `is_weak` TINYINT(1) DEFAULT 0,
    `is_reused` TINYINT(1) DEFAULT 0,
    `is_breached` TINYINT(1) DEFAULT 0,
    `last_used_at` DATETIME NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_vault_user` (`user_id`),
    INDEX `idx_vault_type` (`item_type`),
    INDEX `idx_vault_folder` (`folder_id`),
    INDEX `idx_vault_favorite` (`is_favorite`),
    INDEX `idx_vault_weak` (`is_weak`),
    INDEX `idx_vault_host_hash` (`host_hash`),
    INDEX `idx_vault_last_used` (`user_id`, `last_used_at` DESC),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`folder_id`) REFERENCES `folders`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vault item fields (for structured encrypted data)
CREATE TABLE IF NOT EXISTS `vault_item_fields` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `vault_item_id` INT UNSIGNED NOT NULL,
    `field_name_encrypted` VARCHAR(500) NOT NULL COMMENT 'Encrypted field name',
    `field_value_encrypted` TEXT NOT NULL COMMENT 'Encrypted field value',
    `field_iv` VARCHAR(64) NOT NULL,
    `field_type` ENUM('text', 'password', 'url', 'email', 'number', 'date', 'textarea', 'hidden') DEFAULT 'text',
    `sort_order` INT DEFAULT 0,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`vault_item_id`) REFERENCES `vault_items`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Folders/categories
CREATE TABLE IF NOT EXISTS `folders` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `icon` VARCHAR(50) NULL,
    `color` VARCHAR(7) NULL,
    `parent_id` INT UNSIGNED NULL,
    `sort_order` INT DEFAULT 0,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_folders_user` (`user_id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`parent_id`) REFERENCES `folders`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tags
CREATE TABLE IF NOT EXISTS `tags` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `name` VARCHAR(50) NOT NULL,
    `color` VARCHAR(7) NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_tags_user` (`user_id`),
    UNIQUE KEY `unique_user_tag` (`user_id`, `name`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vault item tags (many-to-many)
CREATE TABLE IF NOT EXISTS `vault_item_tags` (
    `vault_item_id` INT UNSIGNED NOT NULL,
    `tag_id` INT UNSIGNED NOT NULL,
    PRIMARY KEY (`vault_item_id`, `tag_id`),
    FOREIGN KEY (`vault_item_id`) REFERENCES `vault_items`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`tag_id`) REFERENCES `tags`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Shared items
CREATE TABLE IF NOT EXISTS `shared_items` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `vault_item_id` INT UNSIGNED NOT NULL,
    `shared_by_user_id` INT UNSIGNED NOT NULL,
    `shared_with_user_id` INT UNSIGNED NOT NULL,
    `encrypted_item_key` TEXT NOT NULL COMMENT 'Item key encrypted with recipient public key or shared secret',
    `item_key_iv` VARCHAR(64) NOT NULL,
    `permission` ENUM('view', 'edit') DEFAULT 'view',
    `status` ENUM('pending', 'accepted', 'revoked') DEFAULT 'pending',
    `expires_at` DATETIME NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_shared_by` (`shared_by_user_id`),
    INDEX `idx_shared_with` (`shared_with_user_id`),
    FOREIGN KEY (`vault_item_id`) REFERENCES `vault_items`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`shared_by_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`shared_with_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sessions
CREATE TABLE IF NOT EXISTS `sessions` (
    `id` VARCHAR(128) PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(500) NULL,
    `payload` TEXT NULL,
    `is_vault_unlocked` TINYINT(1) DEFAULT 0,
    `last_activity` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_sessions_user` (`user_id`),
    INDEX `idx_sessions_activity` (`last_activity`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Devices (trusted devices)
CREATE TABLE IF NOT EXISTS `devices` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `device_name` VARCHAR(100) NULL,
    `device_type` VARCHAR(50) NULL,
    `browser` VARCHAR(100) NULL,
    `os` VARCHAR(100) NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `device_hash` VARCHAR(64) NOT NULL COMMENT 'Hash of device fingerprint',
    `is_trusted` TINYINT(1) DEFAULT 0,
    `last_seen_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_devices_user` (`user_id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit logs
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NULL,
    `action` VARCHAR(100) NOT NULL,
    `resource_type` VARCHAR(50) NULL,
    `resource_id` INT UNSIGNED NULL,
    `ip_address` VARCHAR(45) NULL,
    `user_agent` VARCHAR(500) NULL,
    `details` TEXT NULL COMMENT 'JSON details about the action',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_audit_user` (`user_id`),
    INDEX `idx_audit_action` (`action`),
    INDEX `idx_audit_created` (`created_at`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Password resets
CREATE TABLE IF NOT EXISTS `password_resets` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `token_hash` VARCHAR(255) NOT NULL COMMENT 'Hashed reset token',
    `expires_at` DATETIME NOT NULL,
    `used_at` DATETIME NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_resets_user` (`user_id`),
    INDEX `idx_resets_expires` (`expires_at`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Encrypted backups
CREATE TABLE IF NOT EXISTS `encrypted_backups` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `filename` VARCHAR(255) NOT NULL,
    `file_size` INT UNSIGNED NOT NULL,
    `encryption_method` VARCHAR(50) DEFAULT 'AES-256-GCM',
    `checksum` VARCHAR(128) NOT NULL COMMENT 'SHA-256 of encrypted file',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_backups_user` (`user_id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate limiting
CREATE TABLE IF NOT EXISTS `rate_limits` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `identifier` VARCHAR(255) NOT NULL COMMENT 'IP or user identifier',
    `action` VARCHAR(50) NOT NULL,
    `attempts` INT UNSIGNED DEFAULT 1,
    `first_attempt_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_attempt_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `locked_until` DATETIME NULL,
    INDEX `idx_rate_identifier` (`identifier`, `action`),
    INDEX `idx_rate_locked` (`locked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- Default app settings
INSERT INTO `app_settings` (`setting_key`, `setting_value`) VALUES
('site_name', 'AMPass'),
('registration_enabled', '1'),
('install_locked', '1'),
('vault_lock_timeout', '300'),
('max_login_attempts', '5'),
('lockout_duration', '900'),
('smtp_host', ''),
('smtp_port', '587'),
('smtp_username', ''),
('smtp_password_encrypted', ''),
('smtp_from_email', ''),
('smtp_from_name', 'AMPass'),
('smtp_encryption', 'tls');

-- ============================================================
-- Extension API Tables (browser extension & desktop app support)
-- ============================================================

-- Extension devices (registered browser extensions / desktop apps)
CREATE TABLE IF NOT EXISTS `extension_devices` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `device_name` VARCHAR(100) NOT NULL COMMENT 'User-friendly name (e.g. Chrome on Windows)',
    `browser_name` VARCHAR(50) NULL COMMENT 'Chrome, Edge, Firefox, Desktop, etc.',
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

-- Extension-related app settings
INSERT IGNORE INTO `app_settings` (`setting_key`, `setting_value`) VALUES
('extension_api_enabled', '1'),
('extension_allowed_origins', ''),
('extension_token_lifetime_days', '30'),
('extension_max_devices_per_user', '10');
