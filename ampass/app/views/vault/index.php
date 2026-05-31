<?php
/**
 * AMPass - Vault List View
 */
$items = $items ?? [];
$folders = $folders ?? [];
$currentType = $currentType ?? null;
$currentFolder = $currentFolder ?? null;
$csrfToken = $csrfToken ?? CSRF::generateToken();

$typeLabels = [
    'login' => 'Web Accounts',
    'app_account' => 'App Accounts',
    'remote_desktop' => 'Remote Desktop',
    'secure_note' => 'Secure Notes',
    'identity' => 'Identities',
    'payment_card' => 'Payment Cards',
    'wifi' => 'Wi-Fi',
    'server_ssh' => 'Servers/SSH',
    'software_license' => 'Software Licenses',
    'bank_account' => 'Bank Accounts',
    'custom' => 'Custom Items'
];
?>

<div class="page-header">
    <div class="page-header-left">
        <h1 class="page-title"><?= $currentType ? ($typeLabels[$currentType] ?? 'Vault') : 'All Items' ?></h1>
        <span class="item-count"><?= count($items) ?> items</span>
    </div>
    <div class="page-header-right">
        <a href="<?= APP_URL ?>/vault/add<?= $currentType ? '?type=' . $currentType : '' ?>" class="btn btn-primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            <span>Add Item</span>
        </a>
        <a href="<?= APP_URL ?>/import" class="btn btn-secondary" style="margin-left:8px;">Import</a>
    </div>
</div>

<!-- Filters -->
<div class="filters-bar">
    <div class="filter-tabs">
        <a href="<?= APP_URL ?>/vault" class="filter-tab <?= !$currentType ? 'active' : '' ?>">All</a>
        <a href="<?= APP_URL ?>/vault?type=login" class="filter-tab <?= $currentType === 'login' ? 'active' : '' ?>">Web</a>
        <a href="<?= APP_URL ?>/vault?type=app_account" class="filter-tab <?= $currentType === 'app_account' ? 'active' : '' ?>">Apps</a>
        <a href="<?= APP_URL ?>/vault?type=remote_desktop" class="filter-tab <?= $currentType === 'remote_desktop' ? 'active' : '' ?>">RDP</a>
        <a href="<?= APP_URL ?>/vault?type=secure_note" class="filter-tab <?= $currentType === 'secure_note' ? 'active' : '' ?>">Notes</a>
        <a href="<?= APP_URL ?>/vault?type=payment_card" class="filter-tab <?= $currentType === 'payment_card' ? 'active' : '' ?>">Cards</a>
        <a href="<?= APP_URL ?>/vault?type=identity" class="filter-tab <?= $currentType === 'identity' ? 'active' : '' ?>">Identity</a>
    </div>
    
    <?php if (!empty($folders)): ?>
    <select class="form-select filter-folder" id="folderFilter" onchange="window.location.href=this.value">
        <option value="<?= APP_URL ?>/vault<?= $currentType ? '?type=' . $currentType : '' ?>">All Folders</option>
        <?php foreach ($folders as $folder): ?>
        <option value="<?= APP_URL ?>/vault?folder=<?= $folder['id'] ?><?= $currentType ? '&type=' . $currentType : '' ?>" <?= $currentFolder == $folder['id'] ? 'selected' : '' ?>>
            <?= htmlspecialchars($folder['name']) ?> (<?= $folder['item_count'] ?>)
        </option>
        <?php endforeach; ?>
    </select>
    <?php endif; ?>
</div>

<!-- Vault Items List -->
<div class="vault-list" id="vaultList">
    <?php if (empty($items)): ?>
    <div class="empty-state">
        <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
        <h3>No items yet</h3>
        <p>Add your first credential to get started</p>
        <a href="<?= APP_URL ?>/vault/add" class="btn btn-primary">Add First Item</a>
    </div>
    <?php else: ?>
        <?php foreach ($items as $item): ?>
        <div class="vault-item" data-id="<?= $item['id'] ?>" data-type="<?= $item['item_type'] ?>" data-encrypted="<?= htmlspecialchars($item['encrypted_data']) ?>" data-iv="<?= htmlspecialchars($item['encryption_iv']) ?>">
            <div class="vault-item-icon vault-icon-<?= $item['item_type'] ?>">
                <?php if ($item['item_type'] === 'login'): ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                <?php elseif ($item['item_type'] === 'app_account'): ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                <?php elseif ($item['item_type'] === 'remote_desktop'): ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/><circle cx="12" cy="10" r="2"/></svg>
                <?php elseif ($item['item_type'] === 'secure_note'): ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>
                <?php elseif ($item['item_type'] === 'payment_card'): ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
                <?php elseif ($item['item_type'] === 'identity'): ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                <?php else: ?>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <?php endif; ?>
            </div>
            
            <div class="vault-item-info" onclick="window.location.href='<?= APP_URL ?>/vault/view/<?= $item['id'] ?>'">
                <span class="vault-item-title" data-decrypt="title">Loading...</span>
                <span class="vault-item-subtitle" data-decrypt="username">••••••••</span>
            </div>

            <div class="vault-item-meta">
                <?php if ($item['is_favorite']): ?>
                <span class="badge badge-star" title="Favorite">⭐</span>
                <?php endif; ?>
                <?php if ($item['is_weak']): ?>
                <span class="badge badge-warning" title="Weak password">Weak</span>
                <?php endif; ?>
                <?php if ($item['is_reused']): ?>
                <span class="badge badge-danger" title="Reused password">Reused</span>
                <?php endif; ?>
            </div>

            <div class="vault-item-actions">
                <button class="btn-icon" title="Copy username" data-action="copy-username">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </button>
                <button class="btn-icon" title="Copy password" data-action="copy-password">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                </button>
                <button class="btn-icon" title="Open website" data-action="launch-url">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                </button>
                <div class="dropdown">
                    <button class="btn-icon dropdown-toggle" title="More actions">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="12" cy="5" r="1"/><circle cx="12" cy="19" r="1"/></svg>
                    </button>
                    <div class="dropdown-menu">
                        <a href="<?= APP_URL ?>/vault/edit/<?= $item['id'] ?>" class="dropdown-item">Edit</a>
                        <button class="dropdown-item" data-action="toggle-favorite">
                            <?= $item['is_favorite'] ? 'Remove from Favorites' : 'Add to Favorites' ?>
                        </button>
                        <button class="dropdown-item text-danger" data-action="delete-item">Delete</button>
                    </div>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
    <?php endif; ?>
</div>

<!-- Pagination Controls -->
<?php if (isset($totalPages) && $totalPages > 1): ?>
<div class="pagination">
    <?php if ($page > 1): ?>
        <a href="<?= APP_URL ?>/vault?page=<?= $page - 1 ?><?= $currentType ? '&type=' . $currentType : '' ?><?= $currentFolder ? '&folder=' . $currentFolder : '' ?>" class="btn btn-secondary btn-sm">&larr; Previous</a>
    <?php else: ?>
        <button class="btn btn-secondary btn-sm" disabled>&larr; Previous</button>
    <?php endif; ?>

    <span class="pagination-info">Page <strong><?= $page ?></strong> of <?= $totalPages ?> (Total: <?= $totalItems ?> items)</span>

    <?php if ($page < $totalPages): ?>
        <a href="<?= APP_URL ?>/vault?page=<?= $page + 1 ?><?= $currentType ? '&type=' . $currentType : '' ?><?= $currentFolder ? '&folder=' . $currentFolder : '' ?>" class="btn btn-secondary btn-sm">Next &rarr;</a>
    <?php else: ?>
        <button class="btn btn-secondary btn-sm" disabled>Next &rarr;</button>
    <?php endif; ?>
</div>
<?php endif; ?>
