<?php
/**
 * AMPass - Admin: Browser Extensions Management
 */
$devices = $data['devices'] ?? [];
$logs = $data['logs'] ?? [];
$settings = $data['settings'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
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
    <title>Browser Extensions - AMPass Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="admin-page">
        <div class="admin-header">
            <a href="<?= APP_URL ?>/admin" class="btn-back">← Back to Admin</a>
            <h1>Browser Extensions</h1>
        </div>

        <!-- Admin Nav -->
        <div class="admin-nav">
            <a href="<?= APP_URL ?>/admin" class="admin-nav-item">Overview</a>
            <a href="<?= APP_URL ?>/admin/users" class="admin-nav-item">Users</a>
            <a href="<?= APP_URL ?>/admin/extensions" class="admin-nav-item active">Extensions</a>
            <a href="<?= APP_URL ?>/admin/settings" class="admin-nav-item">Settings</a>
            <a href="<?= APP_URL ?>/admin/logs" class="admin-nav-item">Audit Logs</a>
        </div>

        <?php if ($success): ?>
        <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Extension API Settings -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Extension API Settings</h2>
            </div>
            <div class="card-body">
                <form method="POST" action="<?= APP_URL ?>/admin/saveExtensionSettings">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                    <div class="form-group form-check">
                        <label class="checkbox-label">
                            <input type="checkbox" name="extension_api_enabled" value="1" <?= ($settings['extension_api_enabled'] ?? '1') === '1' ? 'checked' : '' ?>>
                            <span>Enable Extension API</span>
                        </label>
                        <span class="form-hint">When disabled, all browser extensions will be unable to connect.</span>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Allowed Extension Origins</label>
                        <textarea name="extension_allowed_origins" class="form-textarea" rows="3" placeholder="chrome-extension://your-extension-id&#10;moz-extension://your-firefox-id"><?= htmlspecialchars($settings['extension_allowed_origins'] ?? '') ?></textarea>
                        <span class="form-hint">One origin per line. Leave empty to allow any extension origin on localhost (dev mode only). For production, specify exact extension IDs.</span>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Token Lifetime (days)</label>
                            <input type="number" name="extension_token_lifetime_days" class="form-input" value="<?= htmlspecialchars($settings['extension_token_lifetime_days'] ?? '30') ?>" min="1" max="365">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Max Devices Per User</label>
                            <input type="number" name="extension_max_devices_per_user" class="form-input" value="<?= htmlspecialchars($settings['extension_max_devices_per_user'] ?? '10') ?>" min="1" max="50">
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">Save Settings</button>
                </form>
            </div>
        </div>

        <!-- Connected Devices -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Connected Extension Devices</h2>
                <span class="badge"><?= count($devices) ?> active</span>
            </div>
            <div class="card-body">
                <?php if (empty($devices)): ?>
                <p class="text-muted">No extension devices connected.</p>
                <?php else: ?>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Device</th>
                            <th>Browser</th>
                            <th>IP</th>
                            <th>Last Seen</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($devices as $device): ?>
                        <tr>
                            <td><?= htmlspecialchars($device['username'] ?? 'Unknown') ?></td>
                            <td><?= htmlspecialchars($device['device_name']) ?></td>
                            <td><?= htmlspecialchars($device['browser_name'] ?? '-') ?></td>
                            <td><code><?= htmlspecialchars($device['ip_address'] ?? '-') ?></code></td>
                            <td><?= $device['last_seen_at'] ? date('M j, g:i A', strtotime($device['last_seen_at'])) : 'Never' ?></td>
                            <td><?= date('M j, Y', strtotime($device['created_at'])) ?></td>
                            <td>
                                <form method="POST" action="<?= APP_URL ?>/admin/revokeExtensionDevice" style="display:inline">
                                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                    <input type="hidden" name="device_id" value="<?= $device['id'] ?>">
                                    <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Revoke this device? The user will need to re-authenticate.')">Revoke</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Extension Audit Logs -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Extension Activity Log</h2>
            </div>
            <div class="card-body">
                <?php if (empty($logs)): ?>
                <p class="text-muted">No extension activity recorded yet.</p>
                <?php else: ?>
                <div class="audit-log-list">
                    <?php foreach (array_slice($logs, 0, 25) as $log): ?>
                    <div class="audit-log-item">
                        <div class="log-action"><?= htmlspecialchars($log['action']) ?></div>
                        <div class="log-details">
                            <span><?= htmlspecialchars($log['username'] ?? 'System') ?></span>
                            <span><?= htmlspecialchars($log['device_name'] ?? '-') ?></span>
                            <span><?= htmlspecialchars($log['ip_address'] ?? '') ?></span>
                            <span><?= date('M j g:i A', strtotime($log['created_at'])) ?></span>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
