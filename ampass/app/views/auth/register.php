<?php
$pageTitle = 'Create Account';
$pageSubtitle = 'Set up your secure vault';
require __DIR__ . '/../layouts/auth.php';
?>

            <form method="POST" action="<?= APP_URL ?>/register/submit" class="auth-form" id="registerForm">
                <?= CSRF::tokenField() ?>
                
                <div class="form-group">
                    <label for="full_name" class="form-label">Full Name</label>
                    <input type="text" id="full_name" name="full_name" class="form-input" placeholder="Your full name" required autocomplete="name">
                </div>

                <div class="form-group">
                    <label for="email" class="form-label">Email</label>
                    <input type="email" id="email" name="email" class="form-input" placeholder="your@email.com" required autocomplete="email">
                </div>

                <div class="form-group">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" id="username" name="username" class="form-input" placeholder="Choose a username" required autocomplete="username" pattern="[a-zA-Z0-9_]+" minlength="3">
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Master Password</label>
                    <input type="password" id="password" name="password" class="form-input" placeholder="Min 12 characters, mixed case, numbers, symbols" required autocomplete="new-password" minlength="12">
                    <div class="password-strength-bar" id="strengthBar">
                        <div class="strength-fill"></div>
                    </div>
                    <span class="strength-text" id="strengthText"></span>
                </div>

                <div class="form-group">
                    <label for="confirm_password" class="form-label">Confirm Master Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" class="form-input" placeholder="Re-enter your master password" required autocomplete="new-password">
                </div>

                <!-- Hidden fields for client-side encryption setup -->
                <input type="hidden" name="encryption_salt" id="encryptionSalt">
                <input type="hidden" name="encrypted_vault_key" id="encryptedVaultKey">
                <input type="hidden" name="vault_key_iv" id="vaultKeyIv">

                <div class="alert alert-info">
                    <strong>Important:</strong> Your master password cannot be recovered. It is used to encrypt your vault. 
                    If you forget it, all vault data will be permanently inaccessible.
                </div>

                <button type="submit" class="btn btn-primary btn-full" id="registerBtn">
                    <span>Create Account & Set Up Vault</span>
                </button>
            </form>

            <div class="auth-footer">
                <p>Already have an account? <a href="<?= APP_URL ?>/login">Sign in</a></p>
            </div>

        </div>
    </div>

    <script nonce="<?= Security::getNonce() ?>">
        window.AMPass = { baseUrl: '<?= APP_URL ?>' };
    </script>
    <script src="<?= APP_URL ?>/public/js/crypto.js?v=<?= time() ?>"></script>
    <script src="<?= APP_URL ?>/public/js/register.js?v=<?= time() ?>"></script>
    <script src="<?= APP_URL ?>/public/js/app.js?v=<?= time() ?>"></script>
</body>
</html>
