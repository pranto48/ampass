<?php
$pageTitle = 'Sign In';
$pageSubtitle = 'Access your secure vault';
$success = Session::flash('success');
require __DIR__ . '/../layouts/auth.php';
?>

            <form method="POST" action="<?= APP_URL ?>/login/submit" class="auth-form" id="loginForm">
                <?= CSRF::tokenField() ?>
                
                <div class="form-group">
                    <label for="login" class="form-label">Username or Email</label>
                    <div class="input-wrapper">
                        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        <input type="text" id="login" name="login" class="form-input" placeholder="Enter username or email" required autofocus autocomplete="username">
                    </div>
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-wrapper">
                        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Enter your password" required autocomplete="current-password">
                        <button type="button" class="input-toggle-password" aria-label="Toggle password visibility">
                            <svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            <svg class="eye-closed" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                        </button>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-full">
                    <span>Sign In</span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                </button>
            </form>

            <?php if (defined('REGISTRATION_ENABLED') && REGISTRATION_ENABLED): ?>
            <div class="auth-footer">
                <p>Don't have an account? <a href="<?= APP_URL ?>/register">Create one</a></p>
            </div>
            <?php endif; ?>

        </div>
    </div>

    <script nonce="<?= Security::getNonce() ?>">
        window.AMPass = { baseUrl: '<?= APP_URL ?>' };
    </script>
    <script src="<?= APP_URL ?>/public/js/app.js?v=<?= time() ?>"></script>
</body>
</html>
