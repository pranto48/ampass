<?php
$settings = $data['settings'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
$maskedKey = !empty($settings['resend_api_key_encrypted']) ? 're_****' . substr($settings['resend_api_key_encrypted'], -4) : '';
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
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Settings - AMPass Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
<div class="admin-page">
    <div class="admin-header"><a href="<?= APP_URL ?>/admin" class="btn-back">← Admin</a><h1>Email Settings (Resend)</h1></div>

    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <div class="card">
        <div class="card-header"><h2 class="card-title">Resend API Configuration</h2></div>
        <div class="card-body">
            <form method="POST" action="<?= APP_URL ?>/admin/email/save">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="form-group">
                    <label class="form-label">Resend API Key</label>
                    <input type="password" name="resend_api_key" class="form-input" placeholder="<?= $maskedKey ?: 're_...' ?>" autocomplete="off">
                    <span class="form-hint"><?= $maskedKey ? "Current: {$maskedKey} — leave blank to keep" : 'Get your API key from resend.com/api-keys' ?></span>
                </div>
                <div class="form-row">
                    <div class="form-group"><label class="form-label">From Email</label><input type="email" name="resend_from_email" class="form-input" value="<?= htmlspecialchars($settings['resend_from_email'] ?? '') ?>" required></div>
                    <div class="form-group"><label class="form-label">From Name</label><input type="text" name="resend_from_name" class="form-input" value="<?= htmlspecialchars($settings['resend_from_name'] ?? 'AMPass') ?>"></div>
                </div>
                <div class="form-group"><label class="form-label">Reply-To (optional)</label><input type="email" name="resend_reply_to" class="form-input" value="<?= htmlspecialchars($settings['resend_reply_to'] ?? '') ?>"></div>

                <div class="form-divider"></div>
                <h3 style="margin-bottom:12px;">Email Notifications</h3>
                <label class="checkbox-label"><input type="checkbox" name="security_email_enabled" <?= ($settings['security_email_enabled'] ?? '0') === '1' ? 'checked' : '' ?>> Security alerts (login, device changes)</label>
                <label class="checkbox-label"><input type="checkbox" name="password_reset_email_enabled" <?= ($settings['password_reset_email_enabled'] ?? '0') === '1' ? 'checked' : '' ?>> Password reset emails</label>
                <label class="checkbox-label"><input type="checkbox" name="new_device_email_enabled" <?= ($settings['new_device_email_enabled'] ?? '0') === '1' ? 'checked' : '' ?>> New device login alerts</label>
                <label class="checkbox-label"><input type="checkbox" name="two_factor_email_enabled" <?= ($settings['two_factor_email_enabled'] ?? '0') === '1' ? 'checked' : '' ?>> Email 2FA / OTP codes</label>
                <label class="checkbox-label"><input type="checkbox" name="backup_restore_email_enabled" <?= ($settings['backup_restore_email_enabled'] ?? '0') === '1' ? 'checked' : '' ?>> Backup/restore alerts</label>

                <button type="submit" class="btn btn-primary" style="margin-top:16px;">Save Email Settings</button>
            </form>
        </div>
    </div>

    <!-- Test Email -->
    <div class="card">
        <div class="card-header"><h2 class="card-title">Test Email</h2></div>
        <div class="card-body">
            <form method="POST" action="<?= APP_URL ?>/admin/email/test">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <p class="text-muted" style="margin-bottom:8px;">Send a test email to your admin email address.</p>
                <button type="submit" class="btn btn-secondary">Send Test Email</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
