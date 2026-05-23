<?php
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
$sourceType = $data['source_type'] ?? 'github_branch_zip';
$sourceLabel = $sourceType === 'github_branch_zip' ? 'Branch ZIP' : 'GitHub Release';
$hasBlockers = !empty(array_filter($data['preflight_checks'] ?? [], fn($c) => $c['status'] === 'blocker'));
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Updates - AMPass Admin</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css"></head>
<body>
<div class="admin-page">
    <div class="admin-header"><a href="<?= APP_URL ?>/admin" class="btn-back">&larr; Admin</a><h1>Updates</h1></div>

    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <!-- cPanel One-Click Update — always visible at top -->
    <div class="card" style="border:1px solid #6366f1;">
        <div class="card-header"><h2 class="card-title">&#9889; cPanel One-Click Update</h2></div>
        <div class="card-body">
            <p style="color:#a1a1aa;margin-bottom:12px;">Downloads latest AMPass code from GitHub as ZIP. No SSH or Git required. Checks GitHub, creates encrypted backup, updates files, runs migrations automatically.</p>
            <?php if ($hasBlockers): ?>
            <p style="color:var(--danger);margin-bottom:8px;">&#10007; Preflight blockers detected. Fix issues below before updating.</p>
            <?php endif; ?>
            <form method="POST" action="<?= APP_URL ?>/admin/updates/one-click">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="form-group"><label class="form-label">Backup Password</label><input type="password" name="backup_password" class="form-input" minlength="8" placeholder="Enter backup password (min 8 chars)"></div>
                <button type="submit" class="btn btn-primary" style="font-size:1rem;padding:12px 24px;" <?= $hasBlockers ? 'disabled' : '' ?> onclick="if(!this.disabled){this.textContent='Updating... please wait';this.disabled=true;this.form.submit();}">&#9889; One-Click Update AMPass</button>
            </form>
            <p class="text-muted" style="font-size:0.72rem;margin-top:8px;">One-click update checks GitHub internally. If no newer commit exists, it shows "already up to date". Do not close this page during update.</p>
        </div>
    </div>

    <!-- Version Status -->
    <div class="card">
        <div class="card-header"><h2 class="card-title">Version Status</h2><span class="badge"><?= htmlspecialchars($sourceLabel) ?></span></div>
        <div class="card-body">
            <div class="info-grid">
                <div class="info-item"><span>Installed Version:</span><strong><?= htmlspecialchars(defined('AMPASS_VERSION_DISPLAY') ? AMPASS_VERSION_DISPLAY : 'v' . $data['current_version']) ?></strong></div>
                <div class="info-item"><span>Installed Commit:</span><strong><code><?= htmlspecialchars(substr($data['installed_sha'], 0, 8) ?: 'not set') ?></code><?php if (defined('AMPASS_COMMIT_COUNT') && AMPASS_COMMIT_COUNT > 0): ?> <span class="text-muted">(#<?= AMPASS_COMMIT_COUNT ?>)</span><?php endif; ?></strong></div>
                <div class="info-item"><span>Latest GitHub Commit:</span><strong><code><?= htmlspecialchars(substr($data['latest_sha'], 0, 8) ?: '— check GitHub first') ?></code></strong></div>
                <?php if (!empty($data['commit_message'])): ?>
                <div class="info-item"><span>Commit Message:</span><strong><?= htmlspecialchars(substr($data['commit_message'], 0, 100)) ?></strong></div>
                <?php endif; ?>
                <div class="info-item"><span>Status:</span><strong><?php
                    if ($data['update_available']) {
                        echo '<span style="color:var(--warning);">Update available</span>';
                    } elseif (empty($data['latest_sha'])) {
                        echo '<span style="color:#64748b;">Unknown — check GitHub</span>';
                    } else {
                        echo 'Up to date &#10003;';
                    }
                ?></strong></div>
                <div class="info-item"><span>Last Checked:</span><strong><?= htmlspecialchars($data['last_checked']) ?></strong></div>
                <?php if (!empty($data['check_error'])): ?>
                <div class="info-item"><span>Last Error:</span><strong style="color:var(--danger);"><?= htmlspecialchars(substr($data['check_error'], 0, 150)) ?></strong></div>
                <?php endif; ?>
            </div>

            <!-- Action Buttons -->
            <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;">
                <form method="POST" action="<?= APP_URL ?>/admin/updates/check" style="display:inline;"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><button type="submit" class="btn btn-secondary">Check GitHub</button></form>
                <form method="POST" action="<?= APP_URL ?>/admin/updates/sync-version" style="display:inline;"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><button type="submit" class="btn btn-ghost btn-sm" title="Reads latest GitHub version. Does NOT mark as installed.">Check Latest Version</button></form>
                <?php if (!empty($data['latest_sha'])): ?>
                <form method="POST" action="<?= APP_URL ?>/admin/updates/mark-installed" style="display:inline;" onsubmit="return confirm('Mark current code as installed? Use ONLY after manual file upload or git pull.')"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><button type="submit" class="btn btn-ghost btn-sm">Mark as Installed</button></form>
                <?php endif; ?>
                <form method="POST" action="<?= APP_URL ?>/admin/updates/reset-installed" style="display:inline;" onsubmit="return confirm('Reset installed commit? This forces the next check to show update available.')"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><button type="submit" class="btn btn-ghost btn-sm" style="color:#d97706;">Reset Installed Commit</button></form>
            </div>

            <p class="text-muted" style="font-size:0.72rem;margin-top:10px;">One-click update works when GitHub main has a newer commit than installed. If code was changed locally, push to GitHub first, then check.</p>
        </div>
    </div>

    <?php if ($data['update_available']): ?>
    <!-- Advanced: Manual Apply -->
    <details style="margin-bottom:16px;">
        <summary style="cursor:pointer;color:#a1a1aa;font-size:0.85rem;">Advanced: Manual Update with Confirmation</summary>
        <div class="card" style="margin-top:8px;">
            <div class="card-body">
                <?php if (!empty($data['download_url'])): ?>
                <p class="text-muted" style="font-size:0.8rem;margin-bottom:12px;">Download: <?= htmlspecialchars(substr($data['download_url'], 0, 120)) ?></p>
                <?php endif; ?>
                <form method="POST" action="<?= APP_URL ?>/admin/updates/apply">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <div class="form-group"><label class="form-label">Backup Password</label><input type="password" name="backup_password" class="form-input" required minlength="8"></div>
                    <div class="form-group"><label class="form-label">Type <code>UPDATE AMPASS</code> to confirm</label><input type="text" name="confirmation" class="form-input" required pattern="UPDATE AMPASS" placeholder="UPDATE AMPASS"></div>
                    <button type="submit" class="btn btn-secondary">Manual Update</button>
                </form>
            </div>
        </div>
    </details>
    <?php endif; ?>

    <!-- Debug Info -->
    <details style="margin-bottom:16px;">
        <summary style="cursor:pointer;color:#64748b;font-size:0.8rem;">Debug: Version Details</summary>
        <div class="card" style="margin-top:8px;">
            <div class="card-body" style="font-size:0.78rem;font-family:monospace;">
                <div>installed_commit_sha: <?= htmlspecialchars($data['installed_sha'] ?: '(empty)') ?></div>
                <div>latest_commit_sha: <?= htmlspecialchars($data['latest_sha'] ?: '(empty)') ?></div>
                <div>update_available (db): <?= $data['update_available'] ? '1' : '0' ?></div>
                <div>update_source_type: <?= htmlspecialchars($sourceType) ?></div>
                <div>github_branch: <?= htmlspecialchars($data['github_branch']) ?></div>
                <div>download_url: <?= htmlspecialchars($data['download_url'] ?: '(none)') ?></div>
                <div>check_error: <?= htmlspecialchars($data['check_error'] ?: '(none)') ?></div>
                <div>SHAs match: <?= ($data['installed_sha'] && $data['latest_sha'] && $data['installed_sha'] === $data['latest_sha']) ? 'YES' : 'NO' ?></div>
            </div>
        </div>
    </details>

    <!-- Update Settings -->
    <details style="margin-bottom:16px;">
        <summary style="cursor:pointer;color:#a1a1aa;font-size:0.85rem;">Update Settings</summary>
        <div class="card" style="margin-top:8px;">
            <div class="card-body">
                <form method="POST" action="<?= APP_URL ?>/admin/updates/settings">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <div class="form-group">
                        <label class="form-label">Update Source</label>
                        <select name="update_source_type" class="form-select">
                            <option value="github_branch_zip" <?= $sourceType === 'github_branch_zip' ? 'selected' : '' ?>>Latest Branch ZIP (development/commits)</option>
                            <option value="github_release" <?= $sourceType === 'github_release' ? 'selected' : '' ?>>Stable Releases (tagged versions)</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label class="form-label">Owner</label><input type="text" name="github_repo_owner" class="form-input" value="<?= htmlspecialchars($data['github_repo_owner']) ?>" required></div>
                        <div class="form-group"><label class="form-label">Repo</label><input type="text" name="github_repo_name" class="form-input" value="<?= htmlspecialchars($data['github_repo_name']) ?>" required></div>
                    </div>
                    <div class="form-group"><label class="form-label">Branch</label><input type="text" name="github_branch" class="form-input" value="<?= htmlspecialchars($data['github_branch']) ?>"></div>
                    <div class="form-group">
                        <label class="form-label">GitHub Token (optional)</label>
                        <input type="password" name="github_token" class="form-input" placeholder="<?= $data['github_token_set'] ? '••••••••' : 'ghp_...' ?>">
                        <?php if ($data['github_token_set']): ?><label class="checkbox-label" style="margin-top:4px;"><input type="checkbox" name="github_token_clear" value="1"> Remove token</label><?php endif; ?>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Settings</button>
                </form>
            </div>
        </div>
    </details>

    <!-- Preflight Checks -->
    <?php if (!empty($data['preflight_checks'])): ?>
    <details style="margin-bottom:16px;" <?= $hasBlockers ? 'open' : '' ?>>
        <summary style="cursor:pointer;color:#a1a1aa;font-size:0.85rem;">Preflight Checks <?= $hasBlockers ? '<span style="color:var(--danger);">(blockers found)</span>' : '' ?></summary>
        <div class="card" style="margin-top:8px;">
            <div class="card-body">
                <div style="display:grid;gap:4px;font-size:0.82rem;">
                <?php foreach ($data['preflight_checks'] as $check): ?>
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span><?= $check['status'] === 'ok' ? '&#10003;' : ($check['status'] === 'warning' ? '&#9888;' : '&#10007;') ?></span>
                        <span style="color:<?= $check['status'] === 'ok' ? '#16a34a' : ($check['status'] === 'warning' ? '#d97706' : '#dc2626') ?>;"><?= htmlspecialchars($check['name']) ?></span>
                        <span style="color:#64748b;"><?= htmlspecialchars($check['detail']) ?></span>
                    </div>
                <?php endforeach; ?>
                </div>
            </div>
        </div>
    </details>
    <?php endif; ?>

    <!-- Pending Migrations -->
    <?php if (!empty($data['pending_migrations'])): ?>
    <div class="card">
        <div class="card-header"><h2 class="card-title">Pending Migrations</h2><span class="badge badge-warning"><?= count($data['pending_migrations']) ?></span></div>
        <div class="card-body">
            <ul style="padding-left:20px;font-size:0.85rem;"><?php foreach ($data['pending_migrations'] as $m): ?><li><?= htmlspecialchars($m) ?></li><?php endforeach; ?></ul>
            <form method="POST" action="<?= APP_URL ?>/admin/updates/migrations" style="margin-top:8px;"><input type="hidden" name="csrf_token" value="<?= $csrfToken ?>"><button type="submit" class="btn btn-secondary btn-sm">Run Pending Migrations</button></form>
        </div>
    </div>
    <?php endif; ?>

    <!-- Update History -->
    <div class="card">
        <div class="card-header"><h2 class="card-title">Update History</h2></div>
        <div class="card-body">
            <?php if (empty($data['history'])): ?><p class="text-muted">No updates applied yet.</p>
            <?php else: ?>
            <table class="data-table"><thead><tr><th>From</th><th>To</th><th>Status</th><th>Date</th></tr></thead><tbody>
            <?php foreach ($data['history'] as $h): ?>
            <tr><td>v<?= htmlspecialchars($h['from_version']) ?></td><td>v<?= htmlspecialchars($h['to_version']) ?></td><td><span class="badge badge-<?= $h['status'] === 'completed' ? 'active' : 'suspended' ?>"><?= htmlspecialchars($h['status']) ?></span></td><td><?= date('M j, Y', strtotime($h['started_at'])) ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
            <?php endif; ?>
        </div>
    </div>

    <p class="text-muted" style="margin-top:16px;font-size:0.72rem;">Source: github.com/<?= htmlspecialchars($data['github_repo_owner'] . '/' . $data['github_repo_name']) ?> &bull; &#9888; AMPass updater requires professional security audit before production use.</p>
</div>
</body>
</html>
