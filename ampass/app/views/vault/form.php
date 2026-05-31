<?php
/**
 * AMPass - Add/Edit Vault Item Form
 * SECURITY: All encryption/decryption happens client-side via Web Crypto API.
 */
$item = $data['item'] ?? null;
$itemType = $data['itemType'] ?? 'login';
$folders = $data['folders'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$isEdit = $item !== null;
$pageTitle = $isEdit ? 'Edit Item' : 'Add New Item';

$typeLabels = [
    'login' => 'Web Account',
    'app_account' => 'App Account',
    'remote_desktop' => 'Remote Desktop',
    'secure_note' => 'Secure Note',
    'identity' => 'Identity',
    'payment_card' => 'Payment Card',
    'wifi' => 'Wi-Fi Password',
    'server_ssh' => 'Server/SSH',
    'software_license' => 'Software License',
    'bank_account' => 'Bank Account',
    'custom' => 'Custom Item'
];
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <script>
        (function() {
            const theme = localStorage.getItem('ampass_theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $pageTitle ?> - AMPass</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="form-page">
        <div class="form-page-header">
            <a href="<?= APP_URL ?>/vault" class="btn-back">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                Back to Vault
            </a>
            <h1 class="page-title"><?= $pageTitle ?></h1>
        </div>

        <form id="vaultItemForm" class="vault-form" data-item-id="<?= $isEdit ? $item['id'] : '' ?>" data-encrypted-data="<?= $isEdit ? htmlspecialchars($item['encrypted_data']) : '' ?>" data-iv="<?= $isEdit ? htmlspecialchars($item['encryption_iv']) : '' ?>">
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

            <!-- Item Type Selector -->
            <div class="form-group">
                <label class="form-label">Item Type</label>
                <select name="item_type" id="itemType" class="form-select">
                    <?php foreach ($typeLabels as $type => $label): ?>
                    <option value="<?= $type ?>" <?= $itemType === $type ? 'selected' : '' ?>><?= $label ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Dynamic fields based on type (rendered by JavaScript) -->
            <div id="dynamicFields">
                <!-- Login fields (default) -->
                <div class="form-group">
                    <label for="field_title" class="form-label">Title *</label>
                    <input type="text" id="field_title" class="form-input" placeholder="e.g., Gmail, Netflix" required>
                </div>

                <div class="form-group" data-show-for="login,server_ssh,wifi">
                    <label for="field_url" class="form-label">Website URL</label>
                    <input type="url" id="field_url" class="form-input" placeholder="https://example.com">
                </div>

                <!-- App Account Fields -->
                <div class="form-group" data-show-for="app_account">
                    <label for="field_application_name" class="form-label">Application Name</label>
                    <input type="text" id="field_application_name" class="form-input" placeholder="e.g., Microsoft Outlook, Zoom">
                </div>
                <div class="form-group" data-show-for="app_account">
                    <label for="field_executable_path" class="form-label">Executable Path</label>
                    <input type="text" id="field_executable_path" class="form-input" placeholder="C:\Program Files\...\app.exe">
                </div>
                <div class="form-group" data-show-for="app_account">
                    <label for="field_app_website" class="form-label">Website (optional)</label>
                    <input type="url" id="field_app_website" class="form-input" placeholder="https://outlook.office.com">
                </div>

                <!-- Remote Desktop Fields -->
                <div class="form-group" data-show-for="remote_desktop">
                    <label for="field_protocol" class="form-label">Protocol</label>
                    <select id="field_protocol" class="form-select">
                        <option value="rdp">RDP (Remote Desktop)</option>
                        <option value="vnc">VNC</option>
                        <option value="ssh">SSH</option>
                    </select>
                </div>
                <div class="form-row" data-show-for="remote_desktop">
                    <div class="form-group" style="flex:3;">
                        <label for="field_host" class="form-label">Host / IP Address</label>
                        <input type="text" id="field_host" class="form-input" placeholder="192.168.1.10 or server.example.com">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label for="field_port" class="form-label">Port</label>
                        <input type="number" id="field_port" class="form-input" value="3389">
                    </div>
                </div>
                <div class="form-group" data-show-for="remote_desktop">
                    <label for="field_rdp_domain" class="form-label">Domain (optional)</label>
                    <input type="text" id="field_rdp_domain" class="form-input" placeholder="WORKGROUP or domain.local">
                </div>
                <div class="form-group" data-show-for="remote_desktop">
                    <label for="field_gateway" class="form-label">Gateway (optional)</label>
                    <input type="text" id="field_gateway" class="form-input" placeholder="gateway.example.com">
                </div>
                <div class="alert alert-info" data-show-for="remote_desktop" style="margin:8px 0;">
                    💡 Use AMPass Desktop App to launch RDP connections. The web vault can create/edit accounts and copy credentials, but cannot launch local desktop apps.
                </div>

                <div class="form-group" data-show-for="login,identity,server_ssh,app_account,remote_desktop">
                    <label for="field_username" class="form-label">Username / Email</label>
                    <input type="text" id="field_username" class="form-input" placeholder="username or email" autocomplete="off">
                </div>

                <div class="form-group" data-show-for="login,wifi,server_ssh,app_account,remote_desktop">
                    <label for="field_password" class="form-label">Password</label>
                    <div class="input-wrapper">
                        <input type="password" id="field_password" class="form-input" placeholder="Enter password" autocomplete="new-password">
                        <button type="button" class="input-toggle-password" aria-label="Toggle visibility">
                            <svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            <svg class="eye-closed" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                        </button>
                        <button type="button" class="btn btn-sm btn-secondary" id="generatePasswordBtn" title="Generate password">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4"/></svg>
                        </button>
                    </div>
                    <div class="password-strength-bar" id="itemStrengthBar">
                        <div class="strength-fill"></div>
                    </div>
                </div>

                <!-- Payment Card Fields -->
                <div class="form-group" data-show-for="payment_card">
                    <label for="field_card_number" class="form-label">Card Number</label>
                    <input type="text" id="field_card_number" class="form-input" placeholder="1234 5678 9012 3456" maxlength="19">
                </div>
                <div class="form-row" data-show-for="payment_card">
                    <div class="form-group">
                        <label for="field_card_expiry" class="form-label">Expiry</label>
                        <input type="text" id="field_card_expiry" class="form-input" placeholder="MM/YY" maxlength="5">
                    </div>
                    <div class="form-group">
                        <label for="field_card_cvv" class="form-label">CVV</label>
                        <input type="password" id="field_card_cvv" class="form-input" placeholder="•••" maxlength="4">
                    </div>
                </div>
                <div class="form-group" data-show-for="payment_card">
                    <label for="field_card_holder" class="form-label">Cardholder Name</label>
                    <input type="text" id="field_card_holder" class="form-input" placeholder="Name on card">
                </div>

                <!-- Identity Fields -->
                <div class="form-group" data-show-for="identity">
                    <label for="field_first_name" class="form-label">First Name</label>
                    <input type="text" id="field_first_name" class="form-input">
                </div>
                <div class="form-group" data-show-for="identity">
                    <label for="field_last_name" class="form-label">Last Name</label>
                    <input type="text" id="field_last_name" class="form-input">
                </div>
                <div class="form-group" data-show-for="identity">
                    <label for="field_phone" class="form-label">Phone</label>
                    <input type="tel" id="field_phone" class="form-input">
                </div>
                <div class="form-group" data-show-for="identity">
                    <label for="field_address" class="form-label">Address</label>
                    <textarea id="field_address" class="form-textarea" rows="3"></textarea>
                </div>

                <!-- Notes (all types) -->
                <div class="form-group">
                    <label for="field_notes" class="form-label">Notes</label>
                    <textarea id="field_notes" class="form-textarea" rows="4" placeholder="Additional notes (encrypted)"></textarea>
                </div>

                <!-- Folder -->
                <div class="form-group">
                    <label for="field_folder" class="form-label">Folder</label>
                    <select id="field_folder" class="form-select">
                        <option value="">No Folder</option>
                        <?php foreach ($folders as $folder): ?>
                        <option value="<?= $folder['id'] ?>" <?= ($item && $item['folder_id'] == $folder['id']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($folder['name']) ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <!-- Favorite -->
                <div class="form-group form-check">
                    <label class="checkbox-label">
                        <input type="checkbox" id="field_favorite" <?= ($item && $item['is_favorite']) ? 'checked' : '' ?>>
                        <span>Mark as Favorite</span>
                    </label>
                </div>
            </div>

            <!-- Form Actions -->
            <div class="form-actions">
                <a href="<?= APP_URL ?>/vault" class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary" id="saveItemBtn">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    <span><?= $isEdit ? 'Update Item' : 'Save Item' ?></span>
                </button>
            </div>
        </form>
    </div>

    <script>
        window.AMPass = {
            baseUrl: '<?= APP_URL ?>',
            csrfToken: '<?= $csrfToken ?>',
            vaultUnlocked: <?= Session::isVaultUnlocked() ? 'true' : 'false' ?>,
            currentRoute: 'vault/form'
        };
    </script>
    <script src="<?= APP_URL ?>/public/js/crypto.js"></script>
    <script src="<?= APP_URL ?>/public/js/app.js"></script>
    <script src="<?= APP_URL ?>/public/js/vault-form.js"></script>
</body>
</html>
