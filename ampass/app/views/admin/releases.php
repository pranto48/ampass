<?php
/**
 * AMPass Admin — Release Downloads Manager
 */
$releases = $data['releases'] ?? [];
$settings = $data['settings'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
$maxUpload = min((int)ini_get('upload_max_filesize'), (int)ini_get('post_max_size'));
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
    <title>Release Downloads - AMPass Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="admin-page">
        <div class="admin-header">
            <a href="<?= APP_URL ?>/admin" class="btn-back">← Back to Admin</a>
            <h1>Release Downloads</h1>
        </div>

        <div class="admin-nav">
            <a href="<?= APP_URL ?>/admin" class="admin-nav-item">Overview</a>
            <a href="<?= APP_URL ?>/admin/users" class="admin-nav-item">Users</a>
            <a href="<?= APP_URL ?>/admin/extensions" class="admin-nav-item">Extensions</a>
            <a href="<?= APP_URL ?>/admin/releases" class="admin-nav-item active">Downloads</a>
            <a href="<?= APP_URL ?>/admin/settings" class="admin-nav-item">Settings</a>
            <a href="<?= APP_URL ?>/admin/logs" class="admin-nav-item">Audit Logs</a>
        </div>

        <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

        <!-- Downloads Page Toggle -->
        <div class="card">
            <div class="card-header"><h2 class="card-title">Downloads Page</h2></div>
            <div class="card-body">
                <form method="POST" action="<?= APP_URL ?>/admin/releases/toggle">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="setting" value="downloads_enabled">
                    <input type="hidden" name="value" value="<?= ($settings['downloads_enabled'] ?? '1') === '1' ? '0' : '1' ?>">
                    <label class="checkbox-label">
                        <input type="checkbox" <?= ($settings['downloads_enabled'] ?? '1') === '1' ? 'checked' : '' ?> onchange="this.form.submit()">
                        <span>Public downloads page enabled at <a href="<?= APP_URL ?>/downloads" target="_blank">/downloads</a></span>
                    </label>
                </form>
            </div>
        </div>

        <!-- Upload New Release -->
        <div class="card">
            <div class="card-header"><h2 class="card-title">Upload Release</h2></div>
            <div class="card-body">
                <div class="alert alert-warning" style="margin-bottom:12px;">⚠️ Only upload release files that you built yourself. Never upload untrusted executables.</div>
                <form method="POST" action="<?= APP_URL ?>/admin/releases/upload" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Product Type</label>
                            <select name="product_type" class="form-select" required>
                                <option value="windows_exe">Windows EXE</option>
                                <option value="windows_msi">Windows MSI</option>
                                <option value="chrome_extension">Chrome Extension</option>
                                <option value="edge_extension">Microsoft Edge Extension</option>
                                <option value="firefox_extension">Firefox Extension</option>
                                <option value="pwa">PWA Package</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Version</label>
                            <input type="text" name="version" class="form-input" placeholder="1.0.0" required maxlength="20" pattern="[0-9a-zA-Z.\-]+">
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Release File (max <?= $maxUpload ?>MB)</label>
                        <input type="file" name="release_file" class="form-input" required accept=".exe,.msi,.zip,.xpi">
                        <span class="form-hint">Allowed: .exe, .msi, .zip, .xpi only</span>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Release Notes (optional)</label>
                        <textarea name="release_notes" class="form-textarea" rows="3" maxlength="2000"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Upload Release</button>
                </form>
            </div>
        </div>

        <!-- Existing Releases -->
        <div class="card">
            <div class="card-header"><h2 class="card-title">Releases</h2><span class="badge"><?= count($releases) ?></span></div>
            <div class="card-body">
                <?php if (empty($releases)): ?>
                <p class="text-muted">No releases uploaded yet.</p>
                <?php else: ?>
                <table class="data-table">
                    <thead><tr><th>Type</th><th>Version</th><th>File</th><th>Size</th><th>SHA-256</th><th>Status</th><th>Downloads</th><th>Date</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($releases as $r): ?>
                    <tr>
                        <td><span class="badge"><?= htmlspecialchars($r['product_type']) ?></span></td>
                        <td><?= htmlspecialchars($r['version']) ?></td>
                        <td title="Stored: <?= htmlspecialchars($r['filename_stored']) ?>"><?= htmlspecialchars(substr($r['filename_original'], 0, 25)) ?></td>
                        <td><?= number_format($r['file_size'] / 1048576, 1) ?> MB</td>
                        <td><code title="<?= htmlspecialchars($r['sha256_checksum']) ?>"><?= substr($r['sha256_checksum'], 0, 12) ?>…</code></td>
                        <td><span class="badge badge-<?= $r['is_active'] ? 'active' : 'suspended' ?>"><?= $r['is_active'] ? 'Active' : 'Inactive' ?></span></td>
                        <td><?= (int)$r['download_count'] ?></td>
                        <td><?= date('M j, Y', strtotime($r['created_at'])) ?></td>
                        <td style="white-space:nowrap;">
                            <button class="btn btn-sm btn-ghost" onclick="navigator.clipboard.writeText('<?= APP_URL ?>/downloads/file/<?= $r['id'] ?>');this.textContent='Copied!';setTimeout(()=>this.textContent='URL',1500)" title="Copy public download URL">URL</button>
                            <form method="POST" action="<?= APP_URL ?>/admin/releases/toggle" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                <input type="hidden" name="id" value="<?= $r['id'] ?>">
                                <input type="hidden" name="active" value="<?= $r['is_active'] ? '0' : '1' ?>">
                                <button type="submit" class="btn btn-sm btn-ghost"><?= $r['is_active'] ? 'Disable' : 'Enable' ?></button>
                            </form>
                            <form method="POST" action="<?= APP_URL ?>/admin/releases/delete" style="display:inline;" onsubmit="return confirm('Delete this release permanently?')">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                <input type="hidden" name="id" value="<?= $r['id'] ?>">
                                <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
