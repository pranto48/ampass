<?php
/**
 * AMPass - Dashboard View
 */
$stats = $stats ?? ['total' => 0, 'weak' => 0, 'reused' => 0, 'favorites' => 0, 'security_score' => 100];
$recentItems = $recentItems ?? [];
$favorites = $favorites ?? [];
?>

<div class="page-header">
    <h1 class="page-title">Dashboard</h1>
    <p class="page-subtitle">Welcome back, <?= htmlspecialchars(Session::get('full_name', 'User')) ?></p>
</div>

<!-- Stats Cards -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-icon stat-icon-primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        </div>
        <div class="stat-content">
            <span class="stat-value"><?= $stats['total'] ?></span>
            <span class="stat-label">Total Items</span>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-success">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="stat-content">
            <span class="stat-value"><?= $stats['security_score'] ?>%</span>
            <span class="stat-label">Security Score</span>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-warning">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div class="stat-content">
            <span class="stat-value"><?= $stats['weak'] ?></span>
            <span class="stat-label">Weak Passwords</span>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-danger">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
        </div>
        <div class="stat-content">
            <span class="stat-value"><?= $stats['reused'] ?></span>
            <span class="stat-label">Reused Passwords</span>
        </div>
    </div>
</div>

<!-- Security Score Bar -->
<div class="card">
    <div class="card-header">
        <h2 class="card-title">Security Health</h2>
    </div>
    <div class="card-body">
        <div class="security-score-bar">
            <div class="score-fill" style="width: <?= $stats['security_score'] ?>%; background: <?= $stats['security_score'] >= 80 ? '#10b981' : ($stats['security_score'] >= 50 ? '#f59e0b' : '#ef4444') ?>"></div>
        </div>
        <div class="score-details">
            <span class="score-label">
                <?php if ($stats['security_score'] >= 80): ?>
                    ✅ Your vault security is strong
                <?php elseif ($stats['security_score'] >= 50): ?>
                    ⚠️ Some passwords need attention
                <?php else: ?>
                    🚨 Critical: Many weak or reused passwords
                <?php endif; ?>
            </span>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<div class="card">
    <div class="card-header">
        <h2 class="card-title">Quick Actions</h2>
    </div>
    <div class="card-body">
        <div class="quick-actions">
            <a href="<?= APP_URL ?>/vault/add" class="quick-action-btn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>Add Login</span>
            </a>
            <a href="<?= APP_URL ?>/vault/add?type=secure_note" class="quick-action-btn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>
                <span>Secure Note</span>
            </a>
            <a href="<?= APP_URL ?>/generator" class="quick-action-btn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4"/></svg>
                <span>Generate Password</span>
            </a>
            <a href="<?= APP_URL ?>/vault/add?type=payment_card" class="quick-action-btn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
                <span>Add Card</span>
            </a>
        </div>
    </div>
</div>

<!-- Recent Items -->
<?php if (!empty($recentItems)): ?>
<div class="card">
    <div class="card-header">
        <h2 class="card-title">Recently Used</h2>
        <a href="<?= APP_URL ?>/vault" class="card-link">View All</a>
    </div>
    <div class="card-body">
        <div class="vault-list" id="recentItemsList">
            <?php foreach ($recentItems as $item): ?>
            <div class="vault-item" data-id="<?= $item['id'] ?>" data-type="<?= $item['item_type'] ?>" data-encrypted="<?= htmlspecialchars($item['encrypted_data']) ?>" data-iv="<?= htmlspecialchars($item['encryption_iv']) ?>">
                <div class="vault-item-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                </div>
                <div class="vault-item-info">
                    <span class="vault-item-title" data-decrypt="title">Encrypted Item</span>
                    <span class="vault-item-subtitle" data-decrypt="username">••••••••</span>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-icon btn-copy-username" title="Copy username" data-action="copy-username">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </button>
                    <button class="btn-icon btn-copy-password" title="Copy password" data-action="copy-password">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    </button>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Favorites -->
<?php if (!empty($favorites)): ?>
<div class="card">
    <div class="card-header">
        <h2 class="card-title">⭐ Favorites</h2>
    </div>
    <div class="card-body">
        <div class="vault-list" id="favoritesList">
            <?php foreach ($favorites as $item): ?>
            <div class="vault-item" data-id="<?= $item['id'] ?>" data-type="<?= $item['item_type'] ?>" data-encrypted="<?= htmlspecialchars($item['encrypted_data']) ?>" data-iv="<?= htmlspecialchars($item['encryption_iv']) ?>">
                <div class="vault-item-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                </div>
                <div class="vault-item-info">
                    <span class="vault-item-title" data-decrypt="title">Encrypted Item</span>
                    <span class="vault-item-subtitle" data-decrypt="username">••••••••</span>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-icon btn-copy-password" title="Copy password" data-action="copy-password">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                    </button>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Autofill Notice -->
<div class="card card-info">
    <div class="card-body">
        <p><strong>💡 Tip:</strong> Full browser-wide autofill requires a browser extension or mobile autofill integration. 
        Use the copy buttons to quickly fill credentials on other websites. A browser extension is planned for future releases.</p>
    </div>
</div>
