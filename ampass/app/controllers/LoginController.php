<?php
/**
 * AMPass - Login Controller
 * SECURITY: Implements rate limiting, secure password verification, and session management.
 */

require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../models/AuditLog.php';

class LoginController {

    public function index(): void {
        if (Session::isLoggedIn()) {
            header('Location: ' . APP_URL . '/dashboard');
            exit;
        }

        // Prevent browser caching of login page (stale CSRF tokens)
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');

        $error = Session::flash('error');
        $success = Session::flash('success');
        $csrfToken = CSRF::generateToken();

        // Check HTTPS warning
        $httpsWarning = !Security::isHTTPS() && !Security::isLocalhost();

        require __DIR__ . '/../views/auth/login.php';
    }

    public function submit(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        // Validate CSRF — redirects to /login with friendly message on failure
        CSRF::validateOrRedirect(APP_URL . '/login');

        $login = trim($_POST['login'] ?? '');
        $password = $_POST['password'] ?? '';
        $ip = Security::getClientIP();

        // Rate limiting check
        $maxAttempts = defined('LOGIN_MAX_ATTEMPTS') ? LOGIN_MAX_ATTEMPTS : 5;
        $lockoutTime = defined('LOGIN_LOCKOUT_TIME') ? LOGIN_LOCKOUT_TIME : 900;

        if (!RateLimit::check($ip, 'login', $maxAttempts, $lockoutTime)) {
            $remaining = RateLimit::getLockoutRemaining($ip, 'login');
            Session::flash('error', "Too many login attempts. Please try again in " . ceil($remaining / 60) . " minutes.");
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        // Validate input
        if (empty($login) || empty($password)) {
            Session::flash('error', 'Please enter your username/email and password.');
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        // Find user
        $user = User::findByLogin($login);

        if (!$user || !Security::verifyPassword($password, $user['password_hash'])) {
            RateLimit::record($ip, 'login', $maxAttempts, $lockoutTime);
            AuditLog::log('login_failed', null, 'user', null, ['login' => $login]);
            Session::flash('error', 'Invalid username/email or password.');
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        // Check user status
        if ($user['status'] === 'suspended') {
            Session::flash('error', 'Your account has been suspended. Contact an administrator.');
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        // Check 2FA requirement
        $require2FA = false;
        $isTwoFactorEnabled = (int) ($user['two_factor_enabled'] ?? 0) === 1;
        $isTrusted = self::isCurrentDeviceTrusted($user['id']);

        if ($isTwoFactorEnabled) {
            $requireNewDevice = (int) ($user['two_factor_new_device'] ?? 0) === 1;
            $requireFailedLogins = (int) ($user['two_factor_failed_logins'] ?? 0) === 1;
            
            if ($requireNewDevice && !$isTrusted) {
                $require2FA = true;
            }
            if ($requireFailedLogins) {
                // Count failed logins for this user in the last 24 hours
                $failedAttempts = AuditLog::countRecentFailedLogins($user['username']);
                if ($failedAttempts >= 10) {
                    $require2FA = true;
                }
            }
            if (!$requireNewDevice && !$requireFailedLogins) {
                // If 2FA is enabled but neither sub-option is turned on, 2FA is always required
                $require2FA = true;
            }
        }

        // Admin MUST verify 2FA for untrusted device login
        if ($user['role'] === 'admin' && !$isTrusted) {
            $require2FA = true;
        }

        if ($require2FA) {
            Session::set('2fa_pending_user_id', $user['id']);
            header('Location: ' . APP_URL . '/login/twoFactor');
            exit;
        }

        // Successful login
        RateLimit::clear($ip, 'login');
        Session::regenerate();
        CSRF::regenerate(); // SECURITY: Prevent session fixation + CSRF attacks

        // Set session data
        Session::set('user_id', $user['id']);
        Session::set('user_role', $user['role']);
        Session::set('username', $user['username']);
        Session::set('full_name', $user['full_name']);

        // Update last login
        User::updateLastLogin($user['id']);

        // Rehash if needed
        if (Security::needsRehash($user['password_hash'])) {
            User::updatePassword($user['id'], Security::hashPassword($password));
        }

        // Log successful login
        AuditLog::log('login_success', $user['id']);

        // Check if force password reset
        if ($user['force_password_reset']) {
            header('Location: ' . APP_URL . '/settings/change-password');
            exit;
        }

        // Redirect to vault unlock
        header('Location: ' . APP_URL . '/unlock');
        exit;
    }

    public function logout(): void {
        $userId = Session::getUserId();
        if ($userId) {
            AuditLog::log('logout', $userId);
        }
        Session::destroy();
        // Start a new session for flash message
        Session::start();
        Session::flash('success', 'You have been logged out successfully.');
        header('Location: ' . APP_URL . '/login');
        exit;
    }

    public function twoFactor(): void {
        $userId = Session::get('2fa_pending_user_id');
        if (!$userId) {
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        $user = User::findById($userId);
        if (!$user) {
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        $csrfToken = CSRF::generateToken();

        // Check if 2FA secret exists in database
        $userSecurity = Database::fetchOne("SELECT two_factor_secret_encrypted FROM users WHERE id = ?", [$userId]);
        $hasSecret = !empty($userSecurity['two_factor_secret_encrypted']);

        if ($hasSecret) {
            // Render Verification View
            require __DIR__ . '/../views/auth/two-factor-verify.php';
        } else {
            // Render Setup View (required for admin untrusted device setup on first login)
            $secret = Session::get('pending_2fa_secret');
            if (empty($secret)) {
                $secret = GoogleAuthenticator::generateSecret();
                Session::set('pending_2fa_secret', $secret);
            }
            $qrCodeUrl = GoogleAuthenticator::getQRCodeUrl($user['username'], $secret);
            require __DIR__ . '/../views/auth/two-factor-setup.php';
        }
    }

    public function verifyTwoFactor(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: ' . APP_URL . '/login');
            exit;
        }
        CSRF::validateOrRedirect(APP_URL . '/login/twoFactor');

        $userId = Session::get('2fa_pending_user_id');
        if (!$userId) {
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        $user = User::findById($userId);
        if (!$user) {
            header('Location: ' . APP_URL . '/login');
            exit;
        }

        $code = trim($_POST['code'] ?? '');
        $trustDevice = isset($_POST['trust_device']) ? 1 : 0;

        // Fetch user's encrypted secret
        $userSecurity = Database::fetchOne("SELECT two_factor_secret_encrypted FROM users WHERE id = ?", [$userId]);
        $hasSecret = !empty($userSecurity['two_factor_secret_encrypted']);
        
        $verified = false;
        $secretToSave = '';

        if ($hasSecret) {
            $secret = GoogleAuthenticator::decryptSecret($userSecurity['two_factor_secret_encrypted']);
            $verified = GoogleAuthenticator::verifyCode($secret, $code);
        } else {
            // First time setup verification
            $secret = Session::get('pending_2fa_secret');
            if (!empty($secret)) {
                $verified = GoogleAuthenticator::verifyCode($secret, $code);
                if ($verified) {
                    $secretToSave = GoogleAuthenticator::encryptSecret($secret);
                }
            }
        }

        if (!$verified) {
            Session::flash('error', 'Invalid verification code. Please try again.');
            header('Location: ' . APP_URL . '/login/twoFactor');
            exit;
        }

        // Setup complete: save secret if setup phase
        if (!empty($secretToSave)) {
            Database::execute(
                "UPDATE users SET two_factor_enabled = 1, two_factor_secret_encrypted = ? WHERE id = ?",
                [$secretToSave, $userId]
            );
            Session::set('pending_2fa_secret', null);
        }

        // Successful 2FA verification: Log user in
        Session::set('2fa_pending_user_id', null);

        // Trust device if selected or if user is admin (admin requires trust device cookie so they are remembered next time)
        if ($trustDevice || $user['role'] === 'admin') {
            self::trustCurrentDevice($userId);
        }

        $ip = Security::getClientIP();
        RateLimit::clear($ip, 'login');
        Session::regenerate();
        CSRF::regenerate();

        // Set session data
        Session::set('user_id', $user['id']);
        Session::set('user_role', $user['role']);
        Session::set('username', $user['username']);
        Session::set('full_name', $user['full_name']);

        // Update last login
        User::updateLastLogin($user['id']);

        // Log successful login
        AuditLog::log('login_success_2fa', $user['id']);

        // Check if force password reset
        if ($user['force_password_reset']) {
            header('Location: ' . APP_URL . '/settings/change-password');
            exit;
        }

        header('Location: ' . APP_URL . '/unlock');
        exit;
    }

    private static function isCurrentDeviceTrusted(int $userId): bool {
        $token = $_COOKIE['ampass_device_trust'] ?? '';
        if (empty($token)) return false;
        
        $hash = hash('sha256', $token);
        $device = Database::fetchOne(
            "SELECT id FROM devices WHERE user_id = ? AND device_hash = ? AND is_trusted = 1",
            [$userId, $hash]
        );
        return $device !== null;
    }

    private static function trustCurrentDevice(int $userId): void {
        $token = Security::generateToken();
        $hash = hash('sha256', $token);
        
        // Set cookie for 30 days
        setcookie('ampass_device_trust', $token, [
            'expires' => time() + 30 * 86400,
            'path' => '/',
            'secure' => Security::isHTTPS(),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        // Extract OS/browser info
        $os = 'Unknown OS';
        if (preg_match('/Windows/i', $ua)) $os = 'Windows';
        elseif (preg_match('/Macintosh|Mac OS X/i', $ua)) $os = 'macOS';
        elseif (preg_match('/Linux/i', $ua)) $os = 'Linux';
        elseif (preg_match('/Android/i', $ua)) $os = 'Android';
        elseif (preg_match('/iPhone|iPad/i', $ua)) $os = 'iOS';
        
        $browser = 'Unknown Browser';
        if (preg_match('/Chrome/i', $ua)) $browser = 'Chrome';
        elseif (preg_match('/Safari/i', $ua)) $browser = 'Safari';
        elseif (preg_match('/Firefox/i', $ua)) $browser = 'Firefox';
        elseif (preg_match('/Edge/i', $ua)) $browser = 'Edge';
        
        Database::insert(
            "INSERT INTO devices (user_id, device_name, device_type, browser, os, ip_address, device_hash, is_trusted, last_seen_at, created_at) 
             VALUES (?, ?, 'web', ?, ?, ?, ?, 1, NOW(), NOW())",
            [
                $userId,
                $browser . ' on ' . $os,
                $browser,
                $os,
                Security::getClientIP(),
                $hash
            ]
        );
    }
}
