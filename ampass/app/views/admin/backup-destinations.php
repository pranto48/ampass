<?php
$destinations = $data['destinations'] ?? [];
$backups = $data['backups'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
$preselectedBackup = $data['preselected_backup'] ?? null;
$redirectUri = htmlspecialchars(rtrim(APP_URL, '/')) . '/admin/backup-destinations/onedrive-callback';
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Backup Destinations - AMPass Admin</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css"></head>
<body>
<div class="admin-page">
    <div class="admin-header"><a href="<?= APP_URL ?>/admin" class="btn-back">&larr; Admin</a><h1>Remote Backup Destinations</h1></div>

    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($preselectedBackup): ?>
    <div class="alert alert-info">Selected backup for upload. Choose a destination below and click "Upload to Remote".</div>
    <?php endif; ?>

    <!-- Existing Destinations -->
    <div class="card">
        <div class="card-header"><h2 class="card-title">Destinations</h2><span class="badge"><?= count($destinations) ?></span></div>
        <div class="card-body">
            <?php if (empty($destinations)): ?><p class="text-muted">No remote destinations configured. Add one below.</p>
            <?php else: ?>
            <table class="data-table"><thead><tr><th>Name</th><th>Provider</th><th>Status</th><th>Last Success</th><th>Actions</th></tr></thead><tbody>
            <?php foreach ($destinations as $d): ?>
            <tr>
                <td><?= htmlspecialchars($d['name']) ?></td>
                <td><span class="badge"><?= strtoupper(htmlspecialchars($d['provider'])) ?></span></td>
                <td><?php
                    if ($d['provider'] === 'onedrive') {
                        if ($d['_status'] === 'not_configured') echo '<span style="color:var(--warning);">Not configured</span>';
                        elseif ($d['_status'] === 'ready_to_connect') echo '<span style="color:#d97706;">Ready to connect</span>';
                        elseif ($d['_status'] === 'connected') echo '<span style="color:var(--success);">Connected &#10003;</span>';
                    } else {
                        echo $d['enabled'] ? '&#10003; Enabled' : '&#10007; Disabled';
                    }
                    if (!empty($d['_has_error'])) echo ' <span style="color:var(--danger);" title="' . htmlspecialchars($d['last_error'] ?? '') . '">&#9888;</span>';
                ?></td>
                <td><?= $d['last_success_at'] ? date('M j g:i A', strtotime($d['last_success_at'])) : '—' ?></td>
                <td style="white-space:nowrap;">
                    <a href="<?= APP_URL ?>/admin/backup-destinations/edit?id=<?= $d['id'] ?>" class="btn btn-sm btn-ghost">Edit</a>
                    <?php if ($d['provider'] === 'onedrive' && $d['_status'] !== 'not_configured'): ?>
                    <a href="<?= APP_URL ?>/admin/backup-destinations/onedrive-connect?id=<?= $d['id'] ?>" class="btn btn-sm btn-primary"><?= $d['_status'] === 'connected' ? 'Reconnect' : 'Connect' ?></a>
                    <?php endif; ?>
                    <form method="POST" action="<?= APP_URL ?>/admin/backup-destinations/test" style="display:inline;"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><input type="hidden" name="id" value="<?= $d['id'] ?>"><button type="submit" class="btn btn-sm btn-ghost">Test</button></form>
                    <form method="POST" action="<?= APP_URL ?>/admin/backup-destinations/delete" style="display:inline;" onsubmit="return confirm('Delete this destination?')"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><input type="hidden" name="id" value="<?= $d['id'] ?>"><button type="submit" class="btn btn-sm btn-danger">Delete</button></form>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody></table>
            <?php endif; ?>
        </div>
    </div>

    <!-- Upload to Remote -->
    <?php if (!empty($destinations) && !empty($backups)): ?>
    <div class="card">
        <div class="card-header"><h2 class="card-title">Upload Backup to Remote</h2></div>
        <div class="card-body">
            <form method="POST" action="<?= APP_URL ?>/admin/backup-destinations/upload">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="form-row">
                    <div class="form-group"><label class="form-label">Backup</label><select name="backup_id" class="form-select"><?php foreach ($backups as $b): ?><option value="<?= $b['id'] ?>" <?= $preselectedBackup == $b['id'] ? 'selected' : '' ?>><?= htmlspecialchars($b['filename']) ?></option><?php endforeach; ?></select></div>
                    <div class="form-group"><label class="form-label">Destination</label><select name="destination_id" class="form-select"><?php foreach ($destinations as $d): ?><?php if ($d['enabled'] || ($d['provider'] === 'onedrive' && $d['_status'] === 'connected')): ?><option value="<?= $d['id'] ?>"><?= htmlspecialchars($d['name']) ?> (<?= strtoupper($d['provider']) ?>)</option><?php endif; ?><?php endforeach; ?></select></div>
                </div>
                <button type="submit" class="btn btn-primary">Upload to Remote</button>
            </form>
        </div>
    </div>
    <?php endif; ?>

    <!-- OneDrive Setup Guide -->
    <div class="card" id="onedrive-setup">
        <div class="card-header"><h2 class="card-title">OneDrive Backup Setup</h2></div>
        <div class="card-body">
            <p style="color:#a1a1aa;margin-bottom:16px;">Upload encrypted AMPass backups to Microsoft OneDrive. Only encrypted <code>.ampass-backup</code> files are uploaded — OneDrive never receives plaintext data.</p>

            <details style="margin-bottom:12px;">
                <summary style="cursor:pointer;font-weight:500;color:#fafafa;">Step 1 — Create Microsoft Azure App</summary>
                <ol style="padding-left:20px;margin-top:8px;color:#a1a1aa;font-size:0.85rem;">
                    <li>Open <a href="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" target="_blank" style="color:#818cf8;">Azure App Registrations</a></li>
                    <li>Click "New registration"</li>
                    <li>Name: <strong>AMPass Backup</strong></li>
                    <li>Supported account types: Personal + organizational accounts</li>
                    <li>Redirect URI type: <strong>Web</strong></li>
                    <li>Redirect URI: <input type="text" readonly value="<?= $redirectUri ?>" class="form-input" style="font-size:0.8rem;margin-top:4px;" onclick="this.select();document.execCommand('copy');"></li>
                </ol>
            </details>

            <details style="margin-bottom:12px;">
                <summary style="cursor:pointer;font-weight:500;color:#fafafa;">Step 2 — Add API Permissions</summary>
                <ol style="padding-left:20px;margin-top:8px;color:#a1a1aa;font-size:0.85rem;">
                    <li>In your Azure App, go to "API permissions"</li>
                    <li>Add: Microsoft Graph &rarr; Delegated &rarr; <strong>Files.ReadWrite</strong></li>
                    <li>Add: Microsoft Graph &rarr; Delegated &rarr; <strong>offline_access</strong></li>
                </ol>
            </details>

            <details style="margin-bottom:12px;">
                <summary style="cursor:pointer;font-weight:500;color:#fafafa;">Step 3 — Create Client Secret</summary>
                <ol style="padding-left:20px;margin-top:8px;color:#a1a1aa;font-size:0.85rem;">
                    <li>Go to "Certificates &amp; secrets"</li>
                    <li>Click "New client secret"</li>
                    <li>Copy the <strong>Value</strong> immediately (it won't be shown again)</li>
                </ol>
            </details>

            <details open style="margin-bottom:12px;">
                <summary style="cursor:pointer;font-weight:500;color:#fafafa;">Step 4 — Save OneDrive Destination</summary>
                <form method="POST" action="<?= APP_URL ?>/admin/backup-destinations/save" style="margin-top:8px;">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="provider" value="onedrive">
                    <div class="form-row">
                        <div class="form-group"><label class="form-label">Destination Name</label><input type="text" name="name" class="form-input" value="OneDrive Backup" required></div>
                        <div class="form-group"><label class="form-label">OneDrive Folder</label><input type="text" name="folder_path" class="form-input" value="AMPass Backups"></div>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label class="form-label">Client ID (from Azure)</label><input type="text" name="client_id" class="form-input" required placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div>
                        <div class="form-group"><label class="form-label">Client Secret</label><input type="password" name="client_secret" class="form-input" required placeholder="Paste secret value"></div>
                    </div>
                    <div class="form-group"><label class="form-label">Redirect URI (readonly)</label><input type="text" readonly value="<?= $redirectUri ?>" class="form-input" style="opacity:0.7;"></div>
                    <button type="submit" class="btn btn-primary">Save OneDrive Settings</button>
                </form>
            </details>
            <p class="text-muted" style="font-size:0.75rem;">After saving, click "Connect" on the destination to authorize your Microsoft account.</p>
        </div>
    </div>

    <!-- Add FTP/SFTP Destination -->
    <div class="card">
        <div class="card-header"><h2 class="card-title">Add FTP/SFTP Destination</h2></div>
        <div class="card-body">
            <div class="alert alert-warning" style="margin-bottom:12px;">Plain FTP is not recommended. PHP ftp_ssl_connect does not always verify TLS certificates. Use SFTP or OneDrive for stronger transport security.</div>
            <form method="POST" action="<?= APP_URL ?>/admin/backup-destinations/save">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="form-row">
                    <div class="form-group"><label class="form-label">Name</label><input type="text" name="name" class="form-input" required placeholder="My Backup Server"></div>
                    <div class="form-group"><label class="form-label">Provider</label><select name="provider" class="form-select" required><option value="ftps">FTPS</option><option value="ftp">FTP (insecure)</option><option value="sftp">SFTP</option></select></div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label class="form-label">Host</label><input type="text" name="host" class="form-input" placeholder="ftp.example.com"></div>
                    <div class="form-group"><label class="form-label">Port</label><input type="number" name="port" class="form-input" value="21"></div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label class="form-label">Username</label><input type="text" name="username" class="form-input"></div>
                    <div class="form-group"><label class="form-label">Password</label><input type="password" name="password" class="form-input"></div>
                </div>
                <div class="form-group"><label class="form-label">Remote Directory</label><input type="text" name="remote_directory" class="form-input" value="/ampass-backups"></div>
                <div class="form-group"><label class="form-label">SFTP Host Fingerprint</label><input type="text" name="host_fingerprint" class="form-input" placeholder="Required for SFTP: SHA1 or MD5 fingerprint"></div>
                <label class="checkbox-label"><input type="checkbox" name="passive_mode" checked> Passive mode (FTP/FTPS)</label>
                <button type="submit" class="btn btn-primary" style="margin-top:12px;">Add Destination</button>
            </form>
        </div>
    </div>

    <p class="text-muted" style="margin-top:16px;font-size:0.72rem;">&#9888; AMPass backup and remote upload features require professional security audit before real credential storage.</p>
</div>
</body>
</html>
