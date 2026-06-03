<?php
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
$sourceType = $data['source_type'] ?? 'github_branch_zip';
$hasBlockers = !empty(array_filter($data['preflight_checks'] ?? [], fn($c) => $c['status'] === 'blocker'));

// Version labels
$installedDisplay = $data['installed_version_display'] ?? (defined('AMPASS_VERSION_DISPLAY') ? AMPASS_VERSION_DISPLAY : 'v' . $data['current_version']);
$latestDisplay    = $data['latest_version_display'] ?? '';
$latestSha        = $data['latest_sha'] ?? '';
$installedSha     = $data['installed_sha'] ?? '';
$updateAvailable  = $data['update_available'] ?? false;
$lastChecked      = $data['last_checked'] ?? 'Never';
$commitMsg        = $data['commit_message'] ?? '';
$checkError       = $data['check_error'] ?? '';

// Derive a nice latest label
if (empty($latestDisplay) && !empty($data['latest_commit_count'])) {
    $latestDisplay = 'V1.' . $data['latest_commit_count'];
}
if (empty($latestDisplay) && !empty($latestSha)) {
    $latestDisplay = substr($latestSha, 0, 8);
}
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
<title>Updates — AMPass Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
<style>
/* ── Update Banner ─────────────────────────────────────── */
.update-hero {
    background: linear-gradient(135deg, #1e1b4b 0%, #312e81 40%, #4c1d95 100%);
    border: 1px solid #6366f1;
    border-radius: 12px;
    padding: 28px 28px 24px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}
.update-hero::before {
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 200px; height: 200px;
    background: radial-gradient(circle, rgba(99,102,241,0.25) 0%, transparent 70%);
    pointer-events: none;
}
.update-hero.up-to-date {
    background: linear-gradient(135deg, #052e16 0%, #14532d 50%, #1a3a2a 100%);
    border-color: #16a34a;
}
.update-hero.unknown {
    background: linear-gradient(135deg, #1c1917 0%, #292524 100%);
    border-color: #3f3f46;
}

.update-hero-head {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 18px;
    flex-wrap: wrap;
}
.update-pulse {
    width: 12px; height: 12px;
    border-radius: 50%;
    background: #f59e0b;
    box-shadow: 0 0 0 0 rgba(245,158,11,0.6);
    animation: pulse-ring 1.6s ease-out infinite;
    flex-shrink: 0;
}
.up-to-date .update-pulse { background: #22c55e; box-shadow: 0 0 0 0 rgba(34,197,94,0.6); }
.unknown .update-pulse { background: #52525b; animation: none; }

@keyframes pulse-ring {
    0%   { box-shadow: 0 0 0 0 rgba(245,158,11,.6); }
    70%  { box-shadow: 0 0 0 10px rgba(245,158,11,0); }
    100% { box-shadow: 0 0 0 0 rgba(245,158,11,0); }
}

.update-hero-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: #fff;
}
.update-hero-subtitle {
    font-size: 0.82rem;
    color: rgba(255,255,255,0.55);
    margin-top: 2px;
}

/* Version pill row */
.version-compare {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}
.ver-pill {
    display: inline-flex;
    flex-direction: column;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 8px;
    padding: 8px 16px;
    min-width: 110px;
}
.ver-pill-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: .06em; color: rgba(255,255,255,0.45); margin-bottom: 4px; }
.ver-pill-value { font-size: 1.1rem; font-weight: 700; color: #fff; font-family: monospace; }
.ver-pill.latest .ver-pill-value { color: #fbbf24; }
.up-to-date .ver-pill.latest .ver-pill-value { color: #4ade80; }
.ver-arrow { font-size: 1.4rem; color: rgba(255,255,255,0.35); }

/* Commit message strip */
.commit-strip {
    background: rgba(0,0,0,0.25);
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 0.8rem;
    color: rgba(255,255,255,0.65);
    margin-bottom: 16px;
    border-left: 3px solid #6366f1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* One-click button */
.btn-one-click {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: linear-gradient(135deg, #6366f1, #7c3aed);
    color: #fff;
    font-weight: 700;
    font-size: 1rem;
    padding: 13px 28px;
    border-radius: 9px;
    border: none;
    cursor: pointer;
    transition: transform .15s, box-shadow .15s, opacity .15s;
    box-shadow: 0 4px 20px rgba(99,102,241,0.45);
    letter-spacing: .01em;
}
.btn-one-click:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 8px 28px rgba(99,102,241,0.55);
}
.btn-one-click:active:not(:disabled) { transform: translateY(0); }
.btn-one-click:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.btn-one-click .spinner { display: none; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,.4); border-top-color: #fff; border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.update-hero-actions {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}
.update-meta {
    font-size: 0.74rem;
    color: rgba(255,255,255,0.4);
    margin-top: 12px;
}

/* Auto-check status bar */
.check-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.8rem;
    color: #a1a1aa;
    padding: 8px 0 0;
}
.check-bar .spinner-sm {
    width: 13px; height: 13px;
    border: 2px solid #3f3f46;
    border-top-color: #6366f1;
    border-radius: 50%;
    animation: spin .7s linear infinite;
    display: none;
}

/* Error alert */
.check-error-strip {
    background: rgba(220,38,38,0.12);
    border: 1px solid rgba(220,38,38,0.3);
    border-radius: 6px;
    padding: 8px 14px;
    font-size: 0.8rem;
    color: #fca5a5;
    margin-bottom: 16px;
}

/* Info grid micro-card */
.ver-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin-bottom: 16px;
}
@media(max-width:540px){ .ver-grid { grid-template-columns: 1fr; } }
.ver-grid-item {
    background: rgba(0,0,0,0.2);
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 0.8rem;
}
.ver-grid-item span { color: #71717a; display: block; margin-bottom: 2px; font-size: 0.72rem; }
.ver-grid-item strong code { font-size: 0.82rem; color: #a78bfa; }
</style>
</head>
<body>
<div class="admin-page">
    <div class="admin-header">
        <a href="<?= APP_URL ?>/admin" class="btn-back">&larr; Admin</a>
        <h1>Updates</h1>
    </div>

    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <!-- ── ONE-CLICK UPDATE HERO BANNER ──────────────────────────── -->
    <div class="update-hero <?= $updateAvailable ? '' : ($lastChecked === 'Never' ? 'unknown' : 'up-to-date') ?>" id="updateHero">

        <div class="update-hero-head">
            <div class="update-pulse" id="heroPulse"></div>
            <div>
                <div class="update-hero-title" id="heroTitle">
                    <?php if ($updateAvailable): ?>
                        ⬆ Update Available
                    <?php elseif ($lastChecked === 'Never'): ?>
                        ⚡ Checking for updates…
                    <?php else: ?>
                        ✅ AMPass is up to date
                    <?php endif; ?>
                </div>
                <div class="update-hero-subtitle" id="heroSub">
                    <?php if ($updateAvailable): ?>
                        A newer version is ready to install — no SSH or Git required
                    <?php elseif ($lastChecked === 'Never'): ?>
                        Fetching latest version from GitHub
                    <?php else: ?>
                        You are running the latest version
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Version comparison -->
        <div class="version-compare" id="versionCompare">
            <div class="ver-pill current">
                <span class="ver-pill-label">Installed</span>
                <span class="ver-pill-value" id="pillInstalled"><?= htmlspecialchars($installedDisplay ?: 'Unknown') ?></span>
            </div>
            <?php if ($updateAvailable && !empty($latestDisplay)): ?>
            <span class="ver-arrow">→</span>
            <div class="ver-pill latest">
                <span class="ver-pill-label">Latest on GitHub</span>
                <span class="ver-pill-value" id="pillLatest"><?= htmlspecialchars($latestDisplay) ?></span>
            </div>
            <?php elseif (!$updateAvailable && !empty($latestDisplay)): ?>
            <span class="ver-arrow" style="color:rgba(255,255,255,0.2)">≡</span>
            <div class="ver-pill latest" style="border-color:rgba(74,222,128,0.3)">
                <span class="ver-pill-label">GitHub</span>
                <span class="ver-pill-value" id="pillLatest" style="color:#4ade80"><?= htmlspecialchars($latestDisplay) ?></span>
            </div>
            <?php else: ?>
            <span class="ver-arrow" id="pillArrow" style="display:none">→</span>
            <div class="ver-pill latest" id="pillLatestWrap" style="display:none">
                <span class="ver-pill-label">Latest on GitHub</span>
                <span class="ver-pill-value" id="pillLatest">—</span>
            </div>
            <?php endif; ?>
        </div>

        <?php if (!empty($commitMsg)): ?>
        <div class="commit-strip">💬 <?= htmlspecialchars($commitMsg) ?></div>
        <?php else: ?>
        <div class="commit-strip" id="commitStrip" style="display:none"></div>
        <?php endif; ?>

        <?php if (!empty($checkError)): ?>
        <div class="check-error-strip">⚠ GitHub check error: <?= htmlspecialchars(substr($checkError, 0, 200)) ?></div>
        <?php endif; ?>

        <!-- One-Click Update Form -->
        <form method="POST" action="<?= APP_URL ?>/admin/updates/one-click" id="oneClickForm">
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
            <!-- Backup password is optional: if omitted, server uses stored password or generates one -->
            <input type="hidden" name="backup_password" value="auto-<?= bin2hex(random_bytes(8)) ?>">

            <div class="update-hero-actions">
                <button type="submit" class="btn-one-click" id="btnOneClick"
                    <?= ($hasBlockers) ? 'disabled title="Fix preflight blockers first"' : '' ?>
                    <?= (!$updateAvailable) ? 'style="display:none"' : '' ?>
                    onclick="return startOneClick(this)">
                    <span class="spinner" id="oneClickSpinner"></span>
                    <span id="oneClickLabel">⚡ One-Click Update to <?= htmlspecialchars($latestDisplay ?: 'latest') ?></span>
                </button>

                <!-- Check button — always visible -->
                <form method="POST" action="<?= APP_URL ?>/admin/updates/check" style="display:inline;" id="checkForm">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <button type="submit" class="btn btn-secondary" id="btnCheck"
                        onclick="this.textContent='Checking…';this.disabled=true;">
                        🔍 Check GitHub
                    </button>
                </form>
            </div>
        </form>

        <div class="check-bar">
            <div class="spinner-sm" id="checkSpinner"></div>
            <span id="checkBarText">Last checked: <?= htmlspecialchars($lastChecked === 'Never' ? 'Never' : date('M j, Y g:i A', strtotime($lastChecked))) ?></span>
        </div>

        <?php if ($hasBlockers): ?>
        <div style="margin-top:10px;font-size:0.78rem;color:#fca5a5;">⛔ Preflight blockers detected — expand "Preflight Checks" below and fix before updating.</div>
        <?php endif; ?>

        <div class="update-meta">
            Source: github.com/<?= htmlspecialchars($data['github_repo_owner'] . '/' . $data['github_repo_name']) ?> &bull; branch: <?= htmlspecialchars($data['github_branch']) ?> &bull; No SSH or Git required
        </div>
    </div>
    <!-- ── END HERO ────────────────────────────────────────────────── -->

    <!-- Version Detail Grid -->
    <div class="card" style="margin-bottom:16px;">
        <div class="card-header">
            <h2 class="card-title">Version Details</h2>
            <span class="badge"><?= htmlspecialchars($sourceType === 'github_branch_zip' ? 'Branch ZIP' : 'GitHub Release') ?></span>
        </div>
        <div class="card-body">
            <div class="ver-grid">
                <div class="ver-grid-item">
                    <span>Installed Version</span>
                    <strong><?= htmlspecialchars($installedDisplay ?: ('v' . $data['current_version'])) ?></strong>
                </div>
                <div class="ver-grid-item">
                    <span>Latest on GitHub</span>
                    <strong id="detailLatest"><?= htmlspecialchars($latestDisplay ?: '—') ?></strong>
                </div>
                <div class="ver-grid-item">
                    <span>Installed Commit</span>
                    <strong><code><?= htmlspecialchars(substr($installedSha, 0, 8) ?: 'not set') ?></code></strong>
                </div>
                <div class="ver-grid-item">
                    <span>Latest Commit</span>
                    <strong><code id="detailLatestSha"><?= htmlspecialchars(substr($latestSha, 0, 8) ?: '—') ?></code></strong>
                </div>
                <div class="ver-grid-item">
                    <span>Status</span>
                    <strong id="detailStatus">
                        <?php if ($updateAvailable): ?>
                            <span style="color:#f59e0b">Update available ⬆</span>
                        <?php elseif (empty($latestSha)): ?>
                            <span style="color:#52525b">Unknown — check GitHub</span>
                        <?php else: ?>
                            <span style="color:#22c55e">Up to date ✓</span>
                        <?php endif; ?>
                    </strong>
                </div>
                <div class="ver-grid-item">
                    <span>Last Checked</span>
                    <strong><?= htmlspecialchars($lastChecked === 'Never' ? 'Never' : date('M j, Y g:i A', strtotime($lastChecked))) ?></strong>
                </div>
            </div>

            <!-- Utility buttons -->
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <?php if (!empty($data['latest_sha'])): ?>
                <form method="POST" action="<?= APP_URL ?>/admin/updates/mark-installed" style="display:inline;"
                      onsubmit="return confirm('Mark current code as installed? Use ONLY after manual file upload or git pull.')">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <button type="submit" class="btn btn-ghost btn-sm">Mark as Installed</button>
                </form>
                <?php endif; ?>
                <form method="POST" action="<?= APP_URL ?>/admin/updates/reset-installed" style="display:inline;"
                      onsubmit="return confirm('Reset installed commit? Forces next check to show update available.')">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <button type="submit" class="btn btn-ghost btn-sm" style="color:#d97706">Reset Installed</button>
                </form>
            </div>
        </div>
    </div>

    <!-- Update History -->
    <div class="card" style="margin-bottom:16px;">
        <div class="card-header"><h2 class="card-title">Update History</h2></div>
        <div class="card-body">
            <?php if (empty($data['history'])): ?>
            <p class="text-muted">No updates applied yet.</p>
            <?php else: ?>
            <table class="data-table"><thead><tr><th>From</th><th>To</th><th>Files</th><th>Status</th><th>Date</th></tr></thead><tbody>
            <?php foreach ($data['history'] as $h): ?>
            <tr>
                <td style="font-family:monospace">v<?= htmlspecialchars($h['from_version']) ?></td>
                <td style="font-family:monospace">v<?= htmlspecialchars($h['to_version']) ?></td>
                <td><?= htmlspecialchars($h['notes'] ?? '—') ?></td>
                <td><span class="badge badge-<?= $h['status'] === 'completed' ? 'active' : 'suspended' ?>"><?= htmlspecialchars($h['status']) ?></span></td>
                <td><?= date('M j, Y', strtotime($h['started_at'])) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody></table>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!empty($data['pending_migrations'])): ?>
    <div class="card" style="margin-bottom:16px;">
        <div class="card-header"><h2 class="card-title">Pending Migrations</h2><span class="badge badge-warning"><?= count($data['pending_migrations']) ?></span></div>
        <div class="card-body">
            <ul style="padding-left:20px;font-size:0.85rem;"><?php foreach ($data['pending_migrations'] as $m): ?><li><?= htmlspecialchars($m) ?></li><?php endforeach; ?></ul>
            <form method="POST" action="<?= APP_URL ?>/admin/updates/migrations" style="margin-top:8px;">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <button type="submit" class="btn btn-secondary btn-sm">Run Pending Migrations</button>
            </form>
        </div>
    </div>
    <?php endif; ?>

    <!-- Preflight Checks -->
    <?php if (!empty($data['preflight_checks'])): ?>
    <details style="margin-bottom:16px;" <?= $hasBlockers ? 'open' : '' ?>>
        <summary style="cursor:pointer;color:#a1a1aa;font-size:0.85rem;">
            Preflight Checks <?= $hasBlockers ? '<span style="color:var(--danger)">(blockers found)</span>' : '' ?>
        </summary>
        <div class="card" style="margin-top:8px;"><div class="card-body">
            <div style="display:grid;gap:4px;font-size:0.82rem;">
            <?php foreach ($data['preflight_checks'] as $check): ?>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span><?= $check['status'] === 'ok' ? '&#10003;' : ($check['status'] === 'warning' ? '&#9888;' : '&#10007;') ?></span>
                    <span style="color:<?= $check['status'] === 'ok' ? '#16a34a' : ($check['status'] === 'warning' ? '#d97706' : '#dc2626') ?>;"><?= htmlspecialchars($check['name']) ?></span>
                    <span style="color:#64748b;"><?= htmlspecialchars($check['detail']) ?></span>
                </div>
            <?php endforeach; ?>
            </div>
        </div></div>
    </details>
    <?php endif; ?>

    <!-- Advanced / Manual -->
    <?php if ($updateAvailable): ?>
    <details style="margin-bottom:16px;">
        <summary style="cursor:pointer;color:#a1a1aa;font-size:0.85rem;">Advanced: Manual Update with Full Confirmation</summary>
        <div class="card" style="margin-top:8px;"><div class="card-body">
            <?php if (!empty($data['download_url'])): ?>
            <p class="text-muted" style="font-size:0.8rem;margin-bottom:12px;">Download: <?= htmlspecialchars(substr($data['download_url'], 0, 120)) ?></p>
            <?php endif; ?>
            <form method="POST" action="<?= APP_URL ?>/admin/updates/apply">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="form-group"><label class="form-label">Backup Password</label><input type="password" name="backup_password" class="form-input" required minlength="8"></div>
                <div class="form-group"><label class="form-label">Type <code>UPDATE AMPASS</code> to confirm</label><input type="text" name="confirmation" class="form-input" required pattern="UPDATE AMPASS" placeholder="UPDATE AMPASS"></div>
                <button type="submit" class="btn btn-secondary">Apply Update</button>
            </form>
        </div></div>
    </details>
    <?php endif; ?>

    <!-- Update Settings -->
    <details style="margin-bottom:16px;">
        <summary style="cursor:pointer;color:#a1a1aa;font-size:0.85rem;">Update Settings</summary>
        <div class="card" style="margin-top:8px;"><div class="card-body">
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
                    <label class="form-label">GitHub Token (optional — raises API rate limit)</label>
                    <input type="password" name="github_token" class="form-input" placeholder="<?= $data['github_token_set'] ? '••••••••' : 'ghp_...' ?>">
                    <?php if ($data['github_token_set']): ?><label class="checkbox-label" style="margin-top:4px;"><input type="checkbox" name="github_token_clear" value="1"> Remove token</label><?php endif; ?>
                </div>
                <button type="submit" class="btn btn-primary">Save Settings</button>
            </form>
        </div></div>
    </details>

    <!-- Debug -->
    <details style="margin-bottom:16px;">
        <summary style="cursor:pointer;color:#52525b;font-size:0.78rem;">Debug: Raw Version State</summary>
        <div class="card" style="margin-top:8px;"><div class="card-body" style="font-size:0.78rem;font-family:monospace;">
            <div>installed_commit_sha: <?= htmlspecialchars($installedSha ?: '(empty)') ?></div>
            <div>latest_commit_sha: <?= htmlspecialchars($latestSha ?: '(empty)') ?></div>
            <div>update_available: <?= $updateAvailable ? '1' : '0' ?></div>
            <div>source_type: <?= htmlspecialchars($sourceType) ?></div>
            <div>branch: <?= htmlspecialchars($data['github_branch']) ?></div>
            <div>SHAs match: <?= ($installedSha && $latestSha && $installedSha === $latestSha) ? 'YES' : 'NO' ?></div>
        </div></div>
    </details>
</div>

<script nonce="<?= Security::getNonce() ?>">
// ── One-click update handler ─────────────────────────────
function startOneClick(btn) {
    const label = document.getElementById('oneClickLabel');
    const spinner = document.getElementById('oneClickSpinner');
    btn.disabled = true;
    spinner.style.display = 'block';
    label.textContent = 'Updating… do not close this page';
    return true; // Allow form submit
}

// ── Auto-check on first load if never checked ────────────
(function() {
    const lastChecked = <?= json_encode($lastChecked) ?>;
    if (lastChecked === 'Never') {
        // Auto-submit the check form silently after a short delay
        setTimeout(() => {
            const bar = document.getElementById('checkBarText');
            const spinner = document.getElementById('checkSpinner');
            if (bar) bar.textContent = 'Checking GitHub for latest version…';
            if (spinner) spinner.style.display = 'block';
            // Small delay then submit
            setTimeout(() => {
                document.getElementById('checkForm')?.submit();
            }, 800);
        }, 600);
    }
})();
</script>
</body>
</html>
