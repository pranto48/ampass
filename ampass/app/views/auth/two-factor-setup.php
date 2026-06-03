<?php
$pageTitle = 'Two-Factor Setup';
$pageSubtitle = 'Google Authenticator setup is required to login';
$error = Session::flash('error');
require __DIR__ . '/../layouts/auth.php';
?>

            <div style="display: flex; flex-direction: column; gap: 20px; font-size: 0.9rem; line-height: 1.4; color: var(--text-color);">
                <div style="background: rgba(99, 102, 241, 0.05); border: 1px solid rgba(99, 102, 241, 0.15); padding: 12px; border-radius: 8px; font-size: 0.85rem; color: #4f46e5;">
                    🔒 Administrator accounts require 2FA to complete login from untrusted devices.
                </div>

                <div>
                    <h3 style="font-size: 0.95rem; font-weight: 600; margin-bottom: 6px;">1. Scan the QR Code</h3>
                    <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 12px;">Open Google Authenticator or any TOTP app and scan this code:</p>
                    
                    <div style="background: white; padding: 10px; border-radius: 8px; width: 170px; border: 1px solid var(--border-color); margin: 0 auto 12px;">
                        <img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=<?= urlencode($qrCodeUrl) ?>" alt="2FA QR Code" style="width:150px; height:150px; display:block;">
                    </div>
                    
                    <p style="color: var(--text-muted); font-size: 0.8rem; text-align: center; margin-bottom: 4px;">Manual secret key:</p>
                    <div style="text-align: center;">
                        <code style="display: inline-block; background: var(--bg-hover); padding: 6px 10px; border-radius: 4px; font-family: monospace; font-size: 0.88rem; border: 1px solid var(--border-color); font-weight: 600; letter-spacing: 0.5px;"><?= chunk_split($secret, 4, ' ') ?></code>
                    </div>
                </div>

                <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 0;">

                <form method="POST" action="<?= APP_URL ?>/login/verifyTwoFactor" class="auth-form" id="twoFactorSetupForm">
                    <?= CSRF::tokenField() ?>
                    
                    <div class="form-group" style="margin-bottom: 16px;">
                        <label for="code" class="form-label">2. Enter Verification Code</label>
                        <div class="input-wrapper">
                            <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                            <input type="text" id="code" name="code" class="form-input" placeholder="e.g. 123456" required autofocus autocomplete="one-time-code" maxlength="6" style="letter-spacing: 4px; text-align: center; font-size: 1.2rem; font-weight: 600;">
                        </div>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label class="check-label" style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 0.85rem; color: var(--text-muted);">
                            <input type="checkbox" name="trust_device" value="1" checked>
                            <span>Trust this device for 30 days</span>
                        </label>
                    </div>

                    <button type="submit" class="btn btn-primary btn-full">
                        <span>Verify & Save</span>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                    </button>
                </form>
            </div>

            <div class="auth-footer" style="margin-top: 16px;">
                <p><a href="<?= APP_URL ?>/login">Cancel and go back</a></p>
            </div>

        </div>
    </div>

    <script nonce="<?= Security::getNonce() ?>">
        window.AMPass = { baseUrl: '<?= APP_URL ?>' };
    </script>
</body>
</html>
