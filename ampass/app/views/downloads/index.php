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
    <title>Download AMPass Apps</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body class="auth-body" style="min-height:100vh;align-items:flex-start;padding:40px 20px;">
    <div style="max-width:800px;width:100%;margin:0 auto;">
        <div style="text-align:center;margin-bottom:32px;">
            <svg width="48" height="48" viewBox="0 0 32 32" fill="none" style="margin:0 auto 12px;display:block;"><rect width="32" height="32" rx="8" fill="url(#dg)"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/><defs><linearGradient id="dg" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#4f46e5"/><stop offset="1" stop-color="#7c3aed"/></linearGradient></defs></svg>
            <h1 style="font-size:1.8rem;font-weight:700;margin-bottom:4px;">Download AMPass Apps</h1>
            <p style="color:var(--text-muted);font-size:0.9rem;">Use AMPass on web, desktop, and browser.</p>
        </div>

        <div class="alert alert-warning" style="margin-bottom:24px;">
            ⚠️ AMPass is not professionally audited. Do not store real production credentials until audited.
        </div>

        <!-- Windows Desktop App -->
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header"><h2 class="card-title">🖥️ Windows Desktop App</h2></div>
            <div class="card-body">
                <?php if (!empty($grouped['windows_exe']) || !empty($grouped['windows_msi'])): ?>
                    <?php foreach (($grouped['windows_exe'] ?? []) as $r): ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                        <div>
                            <strong><?= htmlspecialchars($r['filename_original']) ?></strong>
                            <span style="color:var(--text-muted);font-size:0.8rem;margin-left:8px;">v<?= htmlspecialchars($r['version']) ?> • <?= number_format($r['file_size']/1048576, 1) ?> MB</span>
                        </div>
                        <a href="<?= APP_URL ?>/downloads/file/<?= $r['id'] ?>" class="btn btn-primary btn-sm">Download .exe</a>
                    </div>
                    <p style="font-size:0.75rem;color:var(--text-muted);">SHA-256: <code><?= htmlspecialchars($r['sha256_checksum']) ?></code></p>
                    <?php endforeach; ?>
                    <?php foreach (($grouped['windows_msi'] ?? []) as $r): ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-top:12px;">
                        <div>
                            <strong><?= htmlspecialchars($r['filename_original']) ?></strong>
                            <span style="color:var(--text-muted);font-size:0.8rem;margin-left:8px;">v<?= htmlspecialchars($r['version']) ?></span>
                        </div>
                        <a href="<?= APP_URL ?>/downloads/file/<?= $r['id'] ?>" class="btn btn-secondary btn-sm">Download .msi</a>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p style="color:var(--text-muted);margin-bottom:8px;">No Windows installer uploaded yet. Requirements: Windows 10/11 64-bit.</p>
                    <?php if (Session::isLoggedIn() && Session::isAdmin()): ?>
                    <a href="<?= APP_URL ?>/admin/releases" class="btn btn-secondary btn-sm">Upload Windows Installer</a>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- Chrome/Edge Extension -->
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header"><h2 class="card-title">🌐 Chrome / Edge Extension</h2></div>
            <div class="card-body">
                <?php if (!empty($grouped['chrome_extension']) || !empty($grouped['edge_extension'])): ?>
                    <?php foreach (array_merge($grouped['chrome_extension'] ?? [], $grouped['edge_extension'] ?? []) as $ext): ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                        <div><strong><?= htmlspecialchars($ext['filename_original']) ?></strong> <span style="color:var(--text-muted);font-size:0.8rem;">v<?= htmlspecialchars($ext['version']) ?> • <?= htmlspecialchars($ext['product_type'] === 'edge_extension' ? 'Edge' : 'Chrome') ?></span></div>
                        <a href="<?= APP_URL ?>/downloads/file/<?= $ext['id'] ?>" class="btn btn-primary btn-sm">Download ZIP</a>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p style="margin-bottom:8px;color:var(--text-muted);">No browser extension package uploaded yet.</p>
                    <?php if (Session::isLoggedIn() && Session::isAdmin()): ?>
                    <a href="<?= APP_URL ?>/admin/releases" class="btn btn-secondary btn-sm">Upload Browser Extension</a>
                    <?php endif; ?>
                <?php endif; ?>
                <details style="margin-top:12px;">
                    <summary style="cursor:pointer;font-size:0.85rem;font-weight:500;">How to install (Developer Mode)</summary>
                    <ol style="margin-top:8px;padding-left:20px;font-size:0.82rem;color:var(--text-secondary);line-height:1.8;">
                        <li>Download and extract the extension ZIP</li>
                        <li>Open <code>chrome://extensions</code> or <code>edge://extensions</code></li>
                        <li>Enable <strong>Developer mode</strong> (top right toggle)</li>
                        <li>Click <strong>Load unpacked</strong></li>
                        <li>Select the extracted folder</li>
                        <li>Note your extension ID</li>
                        <li>In AMPass Admin → Browser Extensions, add your extension origin</li>
                    </ol>
                </details>
            </div>
        </div>

        <!-- Firefox -->
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header"><h2 class="card-title">🦊 Firefox Extension</h2></div>
            <div class="card-body">
                <?php if (!empty($grouped['firefox_extension'])): ?>
                    <?php $ff = $grouped['firefox_extension'][0]; ?>
                    <a href="<?= APP_URL ?>/downloads/file/<?= $ff['id'] ?>" class="btn btn-primary btn-sm">Download</a>
                <?php else: ?>
                    <p style="color:var(--text-muted);">Firefox extension support coming soon.</p>
                <?php endif; ?>
            </div>
        </div>

        <!-- PWA -->
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header"><h2 class="card-title">📱 Web App (PWA)</h2></div>
            <div class="card-body">
                <p style="margin-bottom:8px;">AMPass works as a Progressive Web App. Install it directly from your browser:</p>
                <ol style="padding-left:20px;font-size:0.82rem;color:var(--text-secondary);line-height:1.8;">
                    <li>Open <a href="<?= APP_URL ?>/login"><?= APP_URL ?></a> in Chrome/Edge</li>
                    <li>Click the install icon in the address bar (or Menu → Install App)</li>
                    <li>AMPass appears as a standalone app on your device</li>
                </ol>
            </div>
        </div>

        <p style="text-align:center;margin-top:24px;"><a href="<?= APP_URL ?>/login" style="font-size:0.85rem;">← Back to AMPass</a></p>
    </div>
</body>
</html>
