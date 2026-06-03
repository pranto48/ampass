<?php
/**
 * AMPass - Security Utilities
 * SECURITY: Centralized security functions including headers, input sanitization,
 * password hashing, and encryption helpers.
 */

class Security {

    public static ?string $nonce = null;

    /**
     * Get or generate CSP script nonce
     */
    public static function getNonce(): string {
        if (self::$nonce === null) {
            self::$nonce = base64_encode(random_bytes(16));
        }
        return self::$nonce;
    }

    /**
     * Set security HTTP headers
     */
    public static function setHeaders(): void {
        $nonce = self::getNonce();
        // Content Security Policy - strict policy
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://api.qrserver.com https://www.google.com https://*.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';");
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()");
        header("Cross-Origin-Opener-Policy: same-origin");
        header("Cross-Origin-Resource-Policy: same-origin");
        header("X-Permitted-Cross-Domain-Policies: none");
        
        // Remove PHP version exposure
        header_remove('X-Powered-By');
        
        // HSTS for HTTPS connections
        if (self::isHTTPS()) {
            header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
        }
    }

    /**
     * Check if running on localhost
     */
    public static function isLocalhost(): bool {
        $localIPs = ['127.0.0.1', '::1', 'localhost'];
        return in_array($_SERVER['REMOTE_ADDR'] ?? '', $localIPs) || 
               in_array($_SERVER['SERVER_NAME'] ?? '', $localIPs);
    }

    /**
     * Check if HTTPS is active
     */
    public static function isHTTPS(): bool {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               ($_SERVER['SERVER_PORT'] ?? 80) == 443 ||
               (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    }

    /**
     * Hash a password using Argon2id (preferred) or bcrypt (fallback)
     * SECURITY: Always use this for login passwords and master passwords.
     */
    public static function hashPassword(string $password): string {
        if (defined('PASSWORD_ARGON2ID')) {
            return password_hash($password, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536, // 64MB
                'time_cost' => 4,
                'threads' => 3
            ]);
        }
        // Fallback to bcrypt if Argon2id not available
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Verify a password against a hash
     */
    public static function verifyPassword(string $password, string $hash): bool {
        return password_verify($password, $hash);
    }

    /**
     * Check if password hash needs rehashing
     */
    public static function needsRehash(string $hash): bool {
        if (defined('PASSWORD_ARGON2ID')) {
            return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 3
            ]);
        }
        return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Generate a cryptographically secure random token
     */
    public static function generateToken(int $length = 32): string {
        return bin2hex(random_bytes($length));
    }

    /**
     * Generate a secure random key (hex encoded)
     */
    public static function generateKey(int $bytes = 32): string {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Sanitize string input (XSS prevention)
     */
    public static function sanitize(string $input): string {
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }

    /**
     * Sanitize email
     */
    public static function sanitizeEmail(string $email): string {
        return filter_var(trim($email), FILTER_SANITIZE_EMAIL);
    }

    /**
     * Validate email format
     */
    public static function isValidEmail(string $email): bool {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validate password strength (server-side check)
     */
    public static function isStrongPassword(string $password): array {
        $errors = [];
        
        if (strlen($password) < 12) {
            $errors[] = 'Password must be at least 12 characters long';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character';
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }

    /**
     * Get client IP address
     * SECURITY: Only trusts proxy headers if explicitly configured.
     * In shared hosting, REMOTE_ADDR is the most reliable.
     * Only trust X-Forwarded-For if behind a known reverse proxy (Cloudflare, etc.)
     */
    public static function getClientIP(): string {
        // Trust Cloudflare's header if present (Cloudflare validates this)
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        
        // Default: use REMOTE_ADDR (cannot be spoofed at TCP level)
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        
        return '0.0.0.0';
    }

    /**
     * HMAC for server-side searchable hashes (e.g., title_hash, url_hash)
     * SECURITY: Uses APP_SECRET so hashes can't be computed without the key
     */
    public static function hmacHash(string $data): string {
        return hash_hmac('sha256', $data, APP_SECRET);
    }

    /**
     * Constant-time string comparison
     */
    public static function constantTimeCompare(string $a, string $b): bool {
        return hash_equals($a, $b);
    }

    /**
     * Check if running without HTTPS (security risk)
     * Returns a warning message if not secure, null if OK.
     */
    public static function getHTTPSWarning(): ?string {
        if (self::isHTTPS() || self::isLocalhost()) {
            return null;
        }
        return 'WARNING: You are accessing AMPass without HTTPS. Your master password and session can be intercepted by network attackers. Enable SSL/TLS immediately for production use. A password manager without HTTPS provides NO security.';
    }

    /**
     * Validate that a string contains only expected characters (anti-injection)
     */
    public static function isAlphanumeric(string $input): bool {
        return preg_match('/^[a-zA-Z0-9_]+$/', $input) === 1;
    }

    /**
     * Sanitize output for JSON embedding in HTML (prevent XSS via </script>)
     */
    public static function jsonEncodeForHTML($data): string {
        return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }
}
