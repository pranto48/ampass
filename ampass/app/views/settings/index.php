<?php
/**
 * AMPass - User Settings View
 */
$user = $user ?? [];
$csrfToken = $csrfToken ?? CSRF::generateToken();
$success = Session::flash('success');
$error = Session::flash('error');
?>

<div class="page-header">
    <h1 class="page-title">Settings</h1>
</div>

<?php if ($success): ?>
<div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
<?php endif; ?>
<?php if ($error): ?>
<div class="alert alert-error"><?= $error ?></div>
<?php endif; ?>

<div class="settings-grid">
    <!-- Profile Settings -->
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">Profile</h2>
        </div>
        <div class="card-body">
            <form method="POST" action="<?= APP_URL ?>/settings/profile">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                
                <div class="form-group">
                    <label class="form-label">Full Name</label>
                    <input type="text" name="full_name" class="form-input" value="<?= htmlspecialchars($user['full_name'] ?? '') ?>" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Email</label>
                    <input type="email" name="email" class="form-input" value="<?= htmlspecialchars($user['email'] ?? '') ?>" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-input" value="<?= htmlspecialchars($user['username'] ?? '') ?>" disabled>
                    <span class="form-hint">Username cannot be changed</span>
                </div>
                <button type="submit" class="btn btn-primary">Save Profile</button>
            </form>
        </div>
    </div>

    <!-- Security Settings -->
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">Security</h2>
        </div>
        <div class="card-body">
            <div class="settings-links">
                <a href="<?= APP_URL ?>/settings/changePassword" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Change Login Password</span>
                        <span class="settings-link-desc">Update your account login password</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
                <a href="<?= APP_URL ?>/settings/twoFactor" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Two-Factor Authentication (2FA)</span>
                        <span class="settings-link-desc">Set up Google Authenticator or configure 2FA login triggers</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
                <a href="<?= APP_URL ?>/settings/security" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Security Log</span>
                        <span class="settings-link-desc">View recent account activity</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
                <a href="<?= APP_URL ?>/settings/tokens" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Browser Extensions</span>
                        <span class="settings-link-desc">Manage connected extension devices</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
                <a href="<?= APP_URL ?>/downloads" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Apps & Downloads</span>
                        <span class="settings-link-desc">Desktop app, browser extension, PWA</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
                <a href="<?= APP_URL ?>/lock" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Lock Vault Now</span>
                        <span class="settings-link-desc">Immediately lock your vault</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
            </div>
        </div>
    </div>

    <!-- Import/Export -->
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">Data</h2>
        </div>
        <div class="card-body">
            <div class="settings-links">
                <button class="settings-link" id="exportVaultBtn">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Export Encrypted Backup</span>
                        <span class="settings-link-desc">Download your vault data (encrypted)</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                </button>
                <button class="settings-link" id="importVaultBtn">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Import Backup</span>
                        <span class="settings-link-desc">Restore from an encrypted backup file</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                </button>
                <a href="<?= APP_URL ?>/import" class="settings-link">
                    <div class="settings-link-info">
                        <span class="settings-link-title">Import External Data</span>
                        <span class="settings-link-desc">Import from Sticky Password, Chrome, Edge, Firefox (CSV/TXT)</span>
                    </div>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </a>
            </div>
            <input type="file" id="importFileInput" accept=".json" style="display:none">
        </div>
    </div>

    <!-- About -->
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">About</h2>
        </div>
        <div class="card-body">
            <div class="about-info">
                <p><strong>AMPass</strong> <?= htmlspecialchars(defined('AMPASS_VERSION_DISPLAY') ? AMPASS_VERSION_DISPLAY : ('v' . APP_VERSION)) ?></p>
                <p>Secure Password Vault</p>
                <p class="text-muted">Your vault data is encrypted end-to-end. The server never sees your plaintext passwords.</p>
            </div>
        </div>
    </div>
</div>
