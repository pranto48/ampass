<?php
$settings = $data['settings'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <script nonce="<?= Security::getNonce() ?>">
        (function() {
            const theme = localStorage.getItem('ampass_theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Settings - AMPass Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="admin-page">
        <div class="admin-header">
            <a href="<?= APP_URL ?>/admin" class="btn-back">← Back to Admin</a>
            <h1>Site Settings</h1>
        </div>

        <?php if ($success): ?>
        <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <div class="card">
            <div class="card-body">
                <form method="POST" action="<?= APP_URL ?>/admin/saveSettings">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                    <div class="form-group">
                        <label class="form-label">Site Name</label>
                        <input type="text" name="site_name" class="form-input" value="<?= htmlspecialchars($settings['site_name'] ?? 'AMPass') ?>">
                    </div>

                    <div class="form-group form-check">
                        <label class="checkbox-label">
                            <input type="checkbox" name="registration_enabled" value="1" <?= ($settings['registration_enabled'] ?? '1') === '1' ? 'checked' : '' ?>>
                            <span>Enable User Registration</span>
                        </label>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Vault Lock Timeout (seconds)</label>
                        <input type="number" name="vault_lock_timeout" class="form-input" value="<?= htmlspecialchars($settings['vault_lock_timeout'] ?? '300') ?>" min="60" max="7200">
                        <span class="form-hint">How long before the vault auto-locks (60-7200 seconds)</span>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Max Login Attempts</label>
                        <input type="number" name="max_login_attempts" class="form-input" value="<?= htmlspecialchars($settings['max_login_attempts'] ?? '5') ?>" min="3" max="20">
                    </div>

                    <div class="form-group">
                        <label class="form-label">Lockout Duration (seconds)</label>
                        <input type="number" name="lockout_duration" class="form-input" value="<?= htmlspecialchars($settings['lockout_duration'] ?? '900') ?>" min="60" max="86400">
                    </div>

                    <div class="form-divider"></div>
                    <h3>SMTP Settings (Email)</h3>
                    <p class="text-muted">Configure email for password resets and notifications.</p>

                    <div class="form-group">
                        <label class="form-label">SMTP Host</label>
                        <input type="text" name="smtp_host" class="form-input" value="<?= htmlspecialchars($settings['smtp_host'] ?? '') ?>" placeholder="smtp.example.com">
                    </div>
                    <div class="form-group">
                        <label class="form-label">SMTP Port</label>
                        <input type="number" name="smtp_port" class="form-input" value="<?= htmlspecialchars($settings['smtp_port'] ?? '587') ?>">
                    </div>

                    <button type="submit" class="btn btn-primary">Save Settings</button>
                </form>
            </div>
        </div>

        <!-- System Info -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">System Information</h2>
            </div>
            <div class="card-body">
                <div class="info-grid">
                    <div class="info-item"><span>PHP Version:</span> <strong><?= PHP_VERSION ?></strong></div>
                    <div class="info-item"><span>Server:</span> <strong><?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') ?></strong></div>
                    <div class="info-item"><span>HTTPS:</span> <strong><?= Security::isHTTPS() ? 'Yes ✅' : 'No ⚠️' ?></strong></div>
                    <div class="info-item"><span>Argon2id:</span> <strong><?= defined('PASSWORD_ARGON2ID') ? 'Available ✅' : 'Not available (using bcrypt)' ?></strong></div>
                    <div class="info-item"><span>Installer:</span> <strong><?= defined('INSTALL_LOCKED') && INSTALL_LOCKED ? 'Locked ✅' : 'UNLOCKED ⚠️ - Please lock it!' ?></strong></div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
