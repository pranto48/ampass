<?php
/**
 * AMPass - Main Application Layout
 * Includes sidebar navigation, top bar, and content area.
 */
$currentRoute = trim($_GET['route'] ?? 'dashboard', '/');
$userName = Session::get('full_name', 'User');
$userRole = Session::getUserRole();
$csrfToken = CSRF::generateToken();
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AMPass - Secure Password Vault">
    <meta name="theme-color" content="#1e1b4b">
    <title><?= htmlspecialchars($data['pageTitle'] ?? 'AMPass - Secure Vault') ?></title>
    <link rel="manifest" href="<?= APP_URL ?>/manifest.webmanifest">
    <link rel="icon" href="<?= APP_URL ?>/public/assets/favicon.svg" type="image/svg+xml">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="app-container">
        <!-- Sidebar (Desktop) -->
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="brand">
                    <svg class="brand-icon" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <rect width="32" height="32" rx="8" fill="url(#brand-gradient)"/>
                        <path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/>
                        <defs><linearGradient id="brand-gradient" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#4f46e5"/><stop offset="1" stop-color="#7c3aed"/></linearGradient></defs>
                    </svg>
                    <span class="brand-name">AMPass</span>
                </div>
                <button class="sidebar-close" id="sidebarClose" aria-label="Close menu">×</button>
            </div>

            <nav class="sidebar-nav">
                <a href="<?= APP_URL ?>/dashboard" class="nav-item <?= $currentRoute === 'dashboard' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
                    <span>Dashboard</span>
                </a>

                <div class="nav-divider"></div>
                <span class="nav-label">Vault</span>

                <a href="<?= APP_URL ?>/vault?type=login" class="nav-item <?= ($_GET['type'] ?? '') === 'login' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M13.8 12H3"/></svg>
                    <span>Web Accounts</span>
                </a>
                <a href="<?= APP_URL ?>/vault?type=identity" class="nav-item <?= ($_GET['type'] ?? '') === 'identity' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    <span>Identities</span>
                </a>
                <a href="<?= APP_URL ?>/vault?type=secure_note" class="nav-item <?= ($_GET['type'] ?? '') === 'secure_note' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>
                    <span>Secure Memos</span>
                </a>
                <a href="<?= APP_URL ?>/vault?type=payment_card" class="nav-item <?= ($_GET['type'] ?? '') === 'payment_card' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
                    <span>Cards</span>
                </a>
                <a href="<?= APP_URL ?>/vault" class="nav-item <?= ($currentRoute === 'vault' && empty($_GET['type'])) ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    <span>All Items</span>
                </a>

                <div class="nav-divider"></div>
                <span class="nav-label">Tools</span>

                <a href="<?= APP_URL ?>/generator" class="nav-item <?= $currentRoute === 'generator' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4"/></svg>
                    <span>Password Generator</span>
                </a>
                <a href="<?= APP_URL ?>/downloads" class="nav-item <?= $currentRoute === 'downloads' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    <span>Apps & Downloads</span>
                </a>

                <div class="nav-divider"></div>

                <a href="<?= APP_URL ?>/settings" class="nav-item <?= strpos($currentRoute, 'settings') === 0 ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4"/></svg>
                    <span>Settings</span>
                </a>

                <?php if ($userRole === 'admin'): ?>
                <a href="<?= APP_URL ?>/admin" class="nav-item <?= $currentRoute === 'admin' ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>Admin Panel</span>
                </a>
                <a href="<?= APP_URL ?>/admin/releases" class="nav-item <?= strpos($currentRoute, 'admin/releases') !== false ? 'active' : '' ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    <span>Release Downloads</span>
                </a>
                <?php endif; ?>
            </nav>

            <div class="sidebar-footer">
                <div class="user-info">
                    <div class="user-avatar"><?= strtoupper(substr($userName, 0, 1)) ?></div>
                    <div class="user-details">
                        <span class="user-name"><?= htmlspecialchars($userName) ?></span>
                        <span class="user-role"><?= ucfirst($userRole) ?></span>
                    </div>
                </div>
                <div class="sidebar-actions">
                    <a href="<?= APP_URL ?>/lock" class="btn-icon" title="Lock Vault">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    </a>
                    <a href="<?= APP_URL ?>/logout" class="btn-icon" title="Logout">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>
                    </a>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Top Bar -->
            <header class="top-bar">
                <button class="menu-toggle" id="menuToggle" aria-label="Open menu">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
                </button>
                <div class="search-bar">
                    <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    <input type="text" id="globalSearch" placeholder="Search vault..." class="search-input" autocomplete="off">
                </div>
                <div class="top-bar-actions">
                    <button class="btn btn-primary btn-sm" id="quickAddBtn">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        <span class="btn-text">Add Item</span>
                    </button>
                    <button class="btn-icon theme-toggle" id="themeToggle" title="Toggle theme">
                        <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                        <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
                    </button>
                </div>
            </header>

            <!-- Page Content -->
            <div class="page-content">
                <?php
                // SECURITY: Show HTTPS warning if not using SSL
                $httpsWarning = Security::getHTTPSWarning();
                if ($httpsWarning): ?>
                <div class="alert alert-error" style="margin-bottom:16px;">
                    <strong>🔓 INSECURE CONNECTION:</strong> <?= htmlspecialchars($httpsWarning) ?>
                </div>
                <?php endif; ?>
                <?php
                // Determine which view to load based on route
                $routeParts = explode('/', $currentRoute ?: 'dashboard');
                $section = $routeParts[0] ?? 'dashboard';
                $subPage = $routeParts[1] ?? 'index';

                // Convert camelCase to kebab-case for file lookup
                $subPageFile = strtolower(preg_replace('/([a-z])([A-Z])/', '$1-$2', $subPage));

                // Try: section/subpage.php, section/index.php, dashboard/index.php
                $candidates = [
                    __DIR__ . '/../' . $section . '/' . $subPageFile . '.php',
                    __DIR__ . '/../' . $section . '/index.php',
                    __DIR__ . '/../dashboard/index.php'
                ];

                if (isset($data) && is_array($data)) {
                    extract($data);
                }

                $loaded = false;
                foreach ($candidates as $candidate) {
                    if (file_exists($candidate)) {
                        require $candidate;
                        $loaded = true;
                        break;
                    }
                }
                if (!$loaded) {
                    echo '<p class="empty-hint">Page not found.</p>';
                }
                ?>
            </div>
        </main>

        <!-- Mobile Bottom Navigation -->
        <nav class="mobile-nav">
            <a href="<?= APP_URL ?>/dashboard" class="mobile-nav-item <?= $currentRoute === 'dashboard' ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
                <span>Home</span>
            </a>
            <a href="<?= APP_URL ?>/vault" class="mobile-nav-item <?= strpos($currentRoute, 'vault') === 0 ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                <span>Vault</span>
            </a>
            <a href="<?= APP_URL ?>/vault/add" class="mobile-nav-item mobile-nav-add">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>Add</span>
            </a>
            <a href="<?= APP_URL ?>/generator" class="mobile-nav-item <?= $currentRoute === 'generator' ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4"/></svg>
                <span>Generate</span>
            </a>
            <a href="<?= APP_URL ?>/settings" class="mobile-nav-item <?= strpos($currentRoute, 'settings') === 0 ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15 1.65 1.65 0 003.17 14H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9"/></svg>
                <span>Settings</span>
            </a>
        </nav>
    </div>

    <!-- Toast notifications created dynamically by JS -->

    <!-- Global data for JavaScript -->
    <?php $nonce = base64_encode(random_bytes(16)); ?>
    <script nonce="<?= $nonce ?>">
        window.AMPass = {
            baseUrl: '<?= APP_URL ?>',
            csrfToken: '<?= $csrfToken ?>',
            vaultUnlocked: <?= Session::isVaultUnlocked() ? 'true' : 'false' ?>,
            lockTimeout: <?= defined('VAULT_LOCK_TIMEOUT') ? VAULT_LOCK_TIMEOUT : 300 ?>
        };
    </script>
    <script src="<?= APP_URL ?>/public/js/crypto.js"></script>
    <script src="<?= APP_URL ?>/public/js/app.js"></script>
    <script src="<?= APP_URL ?>/public/js/vault.js"></script>
    <?php if (strpos($currentRoute, 'generator') !== false): ?>
    <script src="<?= APP_URL ?>/public/js/generator.js"></script>
    <?php endif; ?>
    <!-- Register service worker -->
    <script>
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('<?= APP_URL ?>/sw.js').catch(() => {});
    }
    </script>
</body>
</html>
