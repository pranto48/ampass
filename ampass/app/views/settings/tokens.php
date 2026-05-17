<?php
/**
 * AMPass - User Settings: Extension Devices & Tokens
 */
$devices = $devices ?? [];
$tokens = $tokens ?? [];
$csrfToken = $csrfToken ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
?>

<div class="page-header">
    <a href="<?= APP_URL ?>/settings" class="btn-back">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
        Back
    </a>
    <h1 class="page-title">Browser Extensions</h1>
</div>

<?php if ($success): ?>
<div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
<?php endif; ?>
<?php if ($error): ?>
<div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">Connected Devices</h2>
    </div>
    <div class="card-body">
        <?php if (empty($devices)): ?>
        <div class="empty-state" style="padding:30px;">
            <p class="text-muted">No browser extensions connected yet.</p>
            <p class="text-muted" style="font-size:0.8rem;margin-top:8px;">
                Install the AMPass browser extension and log in to connect it to your vault.
            </p>
        </div>
        <?php else: ?>
        <div class="vault-list">
            <?php foreach ($devices as $device): ?>
            <div class="vault-item">
                <div class="vault-item-icon" style="background:var(--info-subtle);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--info);"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                </div>
                <div class="vault-item-info">
                    <span class="vault-item-title"><?= htmlspecialchars($device['device_name']) ?></span>
                    <span class="vault-item-subtitle">
                        <?= htmlspecialchars($device['browser_name'] ?? 'Unknown browser') ?>
                        • Last seen: <?= $device['last_seen_at'] ? date('M j, g:i A', strtotime($device['last_seen_at'])) : 'Never' ?>
                        • <?= $device['active_tokens'] ?> active token(s)
                    </span>
                </div>
                <div class="vault-item-actions" style="opacity:1;">
                    <form method="POST" action="<?= APP_URL ?>/settings/revokeDevice" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="device_id" value="<?= $device['id'] ?>">
                        <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Revoke this device? You will need to log in again from that browser.')">Revoke</button>
                    </form>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<div class="card card-info">
    <div class="card-body">
        <p><strong>How it works:</strong> When you log in from the AMPass browser extension, a device is registered here. 
        Each device has a token that allows the extension to access your encrypted vault data. 
        Revoking a device immediately disconnects that extension — it will need to log in again.</p>
    </div>
</div>
