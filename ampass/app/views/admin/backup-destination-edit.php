<?php
$dest = $data['dest'] ?? [];
$config = $data['config'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
$provider = $dest['provider'] ?? 'ftp';
$redirectUri = htmlspecialchars(rtrim(APP_URL, '/')) . '/admin/backup-destinations/onedrive-callback';
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Destination - AMPass Admin</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css"></head>
<body>
<div class="admin-page">
    <div class="admin-header"><a href="<?= APP_URL ?>/admin/backup-destinations" class="btn-back">&larr; Destinations</a><h1>Edit: <?= htmlspecialchars($dest['name']) ?></h1></div>

    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <div class="card">
        <div class="card-header"><h2 class="card-title"><?= strtoupper(htmlspecialchars($provider)) ?> Destination</h2></div>
        <div class="card-body">
            <form method="POST" action="<?= APP_URL ?>/admin/backup-destinations/update">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <input type="hidden" name="id" value="<?= $dest['id'] ?>">

                <div class="form-group"><label class="form-label">Name</label><input type="text" name="name" class="form-input" value="<?= htmlspecialchars($dest['name']) ?>" required></div>
                <label class="checkbox-label"><input type="checkbox" name="enabled" <?= $dest['enabled'] ? 'checked' : '' ?>> Enabled</label>

                <?php if ($provider === 'onedrive'): ?>
                <!-- OneDrive fields -->
                <div class="form-row" style="margin-top:12px;">
                    <div class="form-group"><label class="form-label">Client ID</label><input type="text" name="client_id" class="form-input" value="<?= htmlspecialchars($config['client_id'] ?? '') ?>"></div>
                    <div class="form-group"><label class="form-label">Client Secret</label><input type="password" name="client_secret" class="form-input" placeholder="<?= ($config['_has_client_secret'] ?? false) ? 'Leave blank to keep existing' : 'Enter secret' ?>"></div>
                </div>
                <div class="form-group"><label class="form-label">OneDrive Folder</label><input type="text" name="folder_path" class="form-input" value="<?= htmlspecialchars($config['folder_path'] ?? 'AMPass Backups') ?>"></div>
                <div class="form-group"><label class="form-label">Redirect URI (readonly)</label><input type="text" readonly value="<?= $redirectUri ?>" class="form-input" style="opacity:0.7;"></div>

                <?php if ($config['_has_refresh_token'] ?? false): ?>
                <div class="alert alert-success" style="margin-top:8px;">&#10003; OneDrive is connected (refresh token stored encrypted).</div>
                <?php else: ?>
                <div class="alert alert-warning" style="margin-top:8px;">OneDrive not connected yet. Save settings, then click "Connect" on the destinations page.</div>
                <?php endif; ?>

                <?php else: ?>
                <!-- FTP/FTPS/SFTP fields -->
                <div class="form-row" style="margin-top:12px;">
                    <div class="form-group"><label class="form-label">Host</label><input type="text" name="host" class="form-input" value="<?= htmlspecialchars($config['host'] ?? '') ?>"></div>
                    <div class="form-group"><label class="form-label">Port</label><input type="number" name="port" class="form-input" value="<?= (int)($config['port'] ?? ($provider === 'sftp' ? 22 : 21)) ?>"></div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label class="form-label">Username</label><input type="text" name="username" class="form-input" value="<?= htmlspecialchars($config['username'] ?? '') ?>"></div>
                    <div class="form-group"><label class="form-label">Password</label><input type="password" name="password" class="form-input" placeholder="<?= ($config['_has_password'] ?? false) ? 'Leave blank to keep existing' : 'Enter password' ?>"></div>
                </div>
                <div class="form-group"><label class="form-label">Remote Directory</label><input type="text" name="remote_directory" class="form-input" value="<?= htmlspecialchars($config['remote_directory'] ?? '/ampass-backups') ?>"></div>
                <?php if ($provider === 'sftp'): ?>
                <div class="form-group"><label class="form-label">SFTP Host Fingerprint</label><input type="text" name="host_fingerprint" class="form-input" value="<?= htmlspecialchars($config['host_fingerprint'] ?? '') ?>" placeholder="SHA1 or MD5 fingerprint from a trusted machine"></div>
                <div class="alert alert-warning" style="margin-top:8px;">SFTP backups require a saved host fingerprint. Connections are refused if the server fingerprint changes.</div>
                <?php endif; ?>
                <label class="checkbox-label"><input type="checkbox" name="passive_mode" <?= ($config['passive_mode'] ?? true) ? 'checked' : '' ?>> Passive mode</label>
                <?php endif; ?>

                <div style="margin-top:16px;display:flex;gap:8px;">
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                    <a href="<?= APP_URL ?>/admin/backup-destinations" class="btn btn-ghost">Cancel</a>
                </div>
            </form>
        </div>
    </div>
</div>
</body>
</html>
