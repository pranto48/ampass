<?php
/**
 * AMPass - Admin Panel
 */
$totalUsers = $data['totalUsers'] ?? 0;
$users = $data['users'] ?? [];
$recentLogs = $data['recentLogs'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$updateAvailable = $data['updateAvailable'] ?? false;
$latestVersion = $data['latestVersion'] ?? '';
$lastBackupDate = $data['lastBackupDate'] ?? null;
$lastRemoteBackupStatus = $data['lastRemoteBackupStatus'] ?? null;
$lastRemoteBackupDate = $data['lastRemoteBackupDate'] ?? null;
$emailConfigured = $data['emailConfigured'] ?? false;
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
    <title>Admin Panel - AMPass</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
    <style>
    .update-notify-banner {
        display: flex; align-items: center; justify-content: space-between;
        gap: 16px; flex-wrap: wrap;
        background: linear-gradient(135deg, #1e1b4b 0%, #2d2a70 100%);
        border: 1px solid #6366f1; border-left: 4px solid #818cf8;
        border-radius: 10px; padding: 14px 20px; margin-bottom: 18px;
        animation: shimmer-b 2.5s ease-in-out infinite alternate;
    }
    @keyframes shimmer-b {
        from { border-color: #6366f1; box-shadow: 0 0 0 rgba(99,102,241,0); }
        to   { border-color: #a78bfa; box-shadow: 0 0 16px rgba(99,102,241,0.3); }
    }
    .upn-left { display: flex; align-items: center; gap: 12px; }
    .upn-dot {
        width: 10px; height: 10px; border-radius: 50%; background: #f59e0b; flex-shrink: 0;
        box-shadow: 0 0 0 0 rgba(245,158,11,.6);
        animation: pulse-upn 1.6s ease-out infinite;
    }
    @keyframes pulse-upn {
        0%  { box-shadow: 0 0 0 0 rgba(245,158,11,.6); }
        70% { box-shadow: 0 0 0 8px rgba(245,158,11,0); }
        100%{ box-shadow: 0 0 0 0 rgba(245,158,11,0); }
    }
    .upn-text { font-size: 0.9rem; color: #e2e8f0; }
    .upn-text strong { color: #fff; }
    .upn-ver {
        display: inline-flex; align-items: center; gap: 6px;
        background: rgba(255,255,255,0.08); border-radius: 6px;
        padding: 3px 10px; font-family: monospace; font-size: 0.88rem;
        color: #fbbf24; font-weight: 700; margin-left: 4px;
    }
    .upn-ver .arr { color: rgba(255,255,255,0.4); font-family: sans-serif; }
    .btn-upn {
        display: inline-flex; align-items: center; gap: 6px;
        background: linear-gradient(135deg, #6366f1, #7c3aed);
        color: #fff; font-weight: 600; font-size: 0.88rem;
        padding: 9px 18px; border-radius: 7px; border: none;
        cursor: pointer; text-decoration: none; white-space: nowrap;
        box-shadow: 0 2px 12px rgba(99,102,241,0.4);
        transition: transform .15s, box-shadow .15s;
    }
    .btn-upn:hover { transform: translateY(-1px); box-shadow: 0 4px 18px rgba(99,102,241,0.55); }
    </style>
</head>
<body>
    <div class="admin-page">
        <div class="admin-header">
            <a href="<?= APP_URL ?>/dashboard" class="btn-back">← Back to Dashboard</a>
            <h1>Admin Panel</h1>
        </div>

        <?php if ($success): ?>
        <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if ($updateAvailable): ?>
        <?php
            $installedLabel = defined('AMPASS_VERSION_DISPLAY') ? AMPASS_VERSION_DISPLAY : 'current';
            $latestDisplayBanner = '';
            if (class_exists('UpdateService')) {
                $latestDisplayBanner = UpdateService::getSetting('latest_version_display', '');
            }
            if (empty($latestDisplayBanner) && !empty($latestVersion)) {
                $parts = explode('.', $latestVersion);
                $latestDisplayBanner = 'V1.' . ($parts[1] ?? $latestVersion);
            }
        ?>
        <div class="update-notify-banner" role="alert">
            <div class="upn-left">
                <div class="upn-dot"></div>
                <div class="upn-text">
                    <strong>Update Available</strong> — a newer version is ready
                    <?php if ($installedLabel || $latestDisplayBanner): ?>
                    <span class="upn-ver">
                        <?= htmlspecialchars($installedLabel) ?>
                        <span class="arr">→</span>
                        <?= htmlspecialchars($latestDisplayBanner ?: $latestVersion) ?>
                    </span>
                    <?php endif; ?>
                </div>
            </div>
            <a href="<?= APP_URL ?>/admin/updates" class="btn-upn">⚡ Update Now</a>
        </div>
        <?php endif; ?>

        <!-- Admin Nav -->
        <div class="admin-nav">
            <a href="<?= APP_URL ?>/admin" class="admin-nav-item active">Overview</a>
            <a href="<?= APP_URL ?>/admin/users" class="admin-nav-item">Users</a>
            <a href="<?= APP_URL ?>/admin/settings" class="admin-nav-item">Settings</a>
            <a href="<?= APP_URL ?>/admin/logs" class="admin-nav-item">Audit Logs</a>
            <a href="<?= APP_URL ?>/admin/extensions" class="admin-nav-item">Extensions</a>
            <a href="<?= APP_URL ?>/admin/updates" class="admin-nav-item">Updates</a>
            <a href="<?= APP_URL ?>/admin/backups" class="admin-nav-item">Backups</a>
            <a href="<?= APP_URL ?>/admin/backup-destinations" class="admin-nav-item">Remote Backup</a>
            <a href="<?= APP_URL ?>/admin/releases" class="admin-nav-item">Releases</a>
            <a href="<?= APP_URL ?>/admin/email" class="admin-nav-item">Email</a>
        </div>

        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= $totalUsers ?></span>
                    <span class="stat-label">Total Users</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= defined('INSTALL_LOCKED') && INSTALL_LOCKED ? '🔒 Locked' : '⚠️ Open' ?></span>
                    <span class="stat-label">Installer Status</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= Security::isHTTPS() ? '✅ Active' : '⚠️ Off' ?></span>
                    <span class="stat-label">HTTPS</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= PHP_VERSION ?></span>
                    <span class="stat-label">PHP Version</span>
                </div>
            </div>
            <div class="stat-card" <?= $updateAvailable ? 'style="border-color:#6366f1;"' : '' ?>>
                <div class="stat-content">
                    <span class="stat-value">
                        <?php if ($updateAvailable && !empty($latestVersion)): ?>
                            <?php $lv = explode('.', $latestVersion); ?>
                            <a href="<?= APP_URL ?>/admin/updates" style="color:#fbbf24;text-decoration:none;font-size:0.85rem;">⬆ V1.<?= htmlspecialchars($lv[1] ?? $latestVersion) ?></a>
                        <?php elseif ($updateAvailable): ?>
                            <a href="<?= APP_URL ?>/admin/updates" style="color:#fbbf24;text-decoration:none;">⬆ Update</a>
                        <?php else: ?>
                            ✅ Current
                        <?php endif; ?>
                    </span>
                    <span class="stat-label"><a href="<?= APP_URL ?>/admin/updates" style="color:inherit;text-decoration:none;">Updates</a></span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= $lastBackupDate ? date('M j', strtotime($lastBackupDate)) : '—' ?></span>
                    <span class="stat-label"><a href="<?= APP_URL ?>/admin/backups" style="color:inherit;text-decoration:none;">Last Backup</a></span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= $lastRemoteBackupStatus === 'uploaded' ? '✅ OK' : ($lastRemoteBackupStatus === 'failed' ? '❌ Failed' : '—') ?></span>
                    <span class="stat-label"><a href="<?= APP_URL ?>/admin/backup-destinations" style="color:inherit;text-decoration:none;">Remote Backup</a></span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-content">
                    <span class="stat-value"><?= $emailConfigured ? '✅ Active' : '⚠️ Not Set' ?></span>
                    <span class="stat-label"><a href="<?= APP_URL ?>/admin/email" style="color:inherit;text-decoration:none;">Email</a></span>
                </div>
            </div>
        </div>

        <!-- Recent Users -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Recent Users</h2>
                <a href="<?= APP_URL ?>/admin/users" class="card-link">View All</a>
            </div>
            <div class="card-body">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Joined</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_slice($users, 0, 10) as $u): ?>
                        <tr>
                            <td><?= htmlspecialchars($u['username']) ?></td>
                            <td><?= htmlspecialchars($u['email']) ?></td>
                            <td><span class="badge badge-<?= $u['role'] ?>"><?= ucfirst($u['role']) ?></span></td>
                            <td><span class="badge badge-<?= $u['status'] ?>"><?= ucfirst($u['status']) ?></span></td>
                            <td><?= date('M j, Y', strtotime($u['created_at'])) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recent Audit Logs -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Recent Activity</h2>
                <a href="<?= APP_URL ?>/admin/logs" class="card-link">View All</a>
            </div>
            <div class="card-body">
                <div class="audit-log-list">
                    <?php foreach (array_slice($recentLogs, 0, 10) as $log): ?>
                    <div class="audit-log-item">
                        <div class="log-action"><?= htmlspecialchars($log['action']) ?></div>
                        <div class="log-details">
                            <span class="log-user"><?= htmlspecialchars($log['username'] ?? 'System') ?></span>
                            <span class="log-ip"><?= htmlspecialchars($log['ip_address'] ?? '') ?></span>
                            <span class="log-time"><?= date('M j g:i A', strtotime($log['created_at'])) ?></span>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
