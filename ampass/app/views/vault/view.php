<?php
/**
 * AMPass - View Single Vault Item
 */
$item = $data['item'] ?? null;
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
if (!$item) { header('Location: ' . APP_URL . '/vault'); exit; }
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
    <title>View Item - AMPass</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="form-page">
        <div class="form-page-header">
            <a href="<?= APP_URL ?>/vault" class="btn-back">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                Back to Vault
            </a>
            <div class="header-actions">
                <a href="<?= APP_URL ?>/vault/edit/<?= $item['id'] ?>" class="btn btn-secondary btn-sm">Edit</a>
                <button class="btn btn-danger btn-sm" id="deleteItemBtn" data-id="<?= $item['id'] ?>">Delete</button>
            </div>
        </div>

        <div class="item-view" id="itemView" data-id="<?= $item['id'] ?>" data-encrypted="<?= htmlspecialchars($item['encrypted_data']) ?>" data-iv="<?= htmlspecialchars($item['encryption_iv']) ?>" data-type="<?= $item['item_type'] ?>">
            
            <div class="item-view-header">
                <div class="item-type-badge"><?= ucfirst(str_replace('_', ' ', $item['item_type'])) ?></div>
                <h1 class="item-title" id="viewTitle">Decrypting...</h1>
                <?php if ($item['is_favorite']): ?>
                <span class="badge badge-star">⭐ Favorite</span>
                <?php endif; ?>
            </div>

            <div class="item-fields" id="itemFields">
                <!-- Fields populated by JavaScript after decryption -->
                <div class="loading-state">
                    <div class="spinner"></div>
                    <p>Decrypting vault item...</p>
                </div>
            </div>

            <div class="item-meta">
                <div class="meta-item">
                    <span class="meta-label">Created</span>
                    <span class="meta-value"><?= date('M j, Y g:i A', strtotime($item['created_at'])) ?></span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Updated</span>
                    <span class="meta-value"><?= date('M j, Y g:i A', strtotime($item['updated_at'])) ?></span>
                </div>
                <?php if ($item['last_used_at']): ?>
                <div class="meta-item">
                    <span class="meta-label">Last Used</span>
                    <span class="meta-value"><?= date('M j, Y g:i A', strtotime($item['last_used_at'])) ?></span>
                </div>
                <?php endif; ?>
                <?php if ($item['password_strength'] !== null): ?>
                <div class="meta-item">
                    <span class="meta-label">Password Strength</span>
                    <span class="meta-value"><?= $item['password_strength'] ?>%</span>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script nonce="<?= Security::getNonce() ?>">
        window.AMPass = {
            baseUrl: '<?= APP_URL ?>',
            csrfToken: '<?= $csrfToken ?>',
            vaultUnlocked: <?= Session::isVaultUnlocked() ? 'true' : 'false' ?>,
            currentRoute: 'vault/view'
        };
    </script>
    <script src="<?= APP_URL ?>/public/js/crypto.js?v=<?= time() ?>"></script>
    <script src="<?= APP_URL ?>/public/js/app.js?v=<?= time() ?>"></script>
    <script src="<?= APP_URL ?>/public/js/vault-view.js?v=<?= time() ?>"></script>
</body>
</html>
