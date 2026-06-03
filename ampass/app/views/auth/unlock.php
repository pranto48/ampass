<?php
$pageTitle = 'Unlock Vault';
$pageSubtitle = 'Enter your master password to access your vault';
require __DIR__ . '/../layouts/auth.php';
?>

            <form method="POST" action="<?= APP_URL ?>/unlock/submit" class="auth-form" id="unlockForm">
                <?= CSRF::tokenField() ?>
                
                <div class="form-group">
                    <label for="master_password" class="form-label">Master Password</label>
                    <div class="input-wrapper">
                        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                        <input type="password" id="master_password" name="master_password" class="form-input" placeholder="Enter your master password" required autofocus autocomplete="current-password">
                        <button type="button" class="input-toggle-password" aria-label="Toggle password visibility">
                            <svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            <svg class="eye-closed" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                        </button>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-full">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    <span>Unlock Vault</span>
                </button>
            </form>

            <div class="auth-footer">
                <p><a href="<?= APP_URL ?>/logout">Sign out</a> and use a different account</p>
            </div>

            <!-- Hidden derivation params for client-side key derivation -->
            <script nonce="<?= Security::getNonce() ?>">
                window.AMPass = {
                    baseUrl: '<?= APP_URL ?>',
                    derivationParams: <?= Security::jsonEncodeForHTML($derivationParams ?? []) ?>
                };
            </script>

        </div>
    </div>

    <script src="<?= APP_URL ?>/public/js/crypto.js?v=<?= time() ?>"></script>
    <script src="<?= APP_URL ?>/public/js/unlock.js?v=<?= time() ?>"></script>
    <script src="<?= APP_URL ?>/public/js/app.js?v=<?= time() ?>"></script>
</body>
</html>
