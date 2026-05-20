-- AMPass Migration 006: Add app_account and remote_desktop vault item types
-- Extends the vault_items.item_type to support desktop app accounts and remote desktop credentials.
-- SECURITY: All sensitive data remains inside encrypted_data (client-side encrypted).

-- Alter item_type enum to include new types
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

-- Add host_hash column for remote_desktop domain matching (optional, for future server-side search)
ALTER TABLE `vault_items` ADD COLUMN `host_hash` VARCHAR(64) NULL DEFAULT NULL AFTER `url_hash`;
ALTER TABLE `vault_items` ADD INDEX `idx_vault_host_hash` (`host_hash`);

-- Add last_used_at index for better sorting performance
ALTER TABLE `vault_items` ADD INDEX `idx_vault_last_used` (`user_id`, `last_used_at` DESC);
