<?php
$pageTitle = 'Two-Factor Verification';
$pageSubtitle = 'Enter the 2FA code from your authenticator app';
$error = Session::flash('error');
require __DIR__ . '/../layouts/auth.php';
?>

            <form method="POST" action="<?= APP_URL ?>/login/verifyTwoFactor" class="auth-form" id="twoFactorForm">
                <?= CSRF::tokenField() ?>
                
                <div class="form-group" style="margin-bottom: 20px;">
                    <label for="code" class="form-label">Authenticator Code</label>
                    <div class="input-wrapper">
                        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                        <input type="text" id="code" name="code" class="form-input" placeholder="Enter 6-digit code" required autofocus autocomplete="one-time-code" maxlength="6" style="letter-spacing: 4px; text-align: center; font-size: 1.25rem; font-weight: 600;">
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 24px;">
                    <label class="check-label" style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 0.88rem; color: var(--text-muted);">
                        <input type="checkbox" name="trust_device" value="1" checked>
                        <span>Trust this device for 30 days</span>
                    </label>
                </div>

                <button type="submit" class="btn btn-primary btn-full">
                    <span>Verify Code</span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                </button>
            </form>

            <div class="auth-footer">
                <p><a href="<?= APP_URL ?>/login">Cancel and go back</a></p>
            </div>

        </div>
    </div>

    <script>
        window.AMPass = { baseUrl: '<?= APP_URL ?>' };
    </script>
</body>
</html>
