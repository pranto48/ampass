<?php
/**
 * AMPass - Installation Wizard
 * SECURITY: This file MUST be deleted or locked after installation.
 * It creates the database, config file, and first admin user.
 * 
 * Defense layers:
 * 1. INSTALL_LOCKED constant in config.php
 * 2. Lock file at config/.install_lock
 * 3. .htaccess rule blocking /install/ directory
 * 4. CSRF protection on forms
 * 5. Rate limiting on installation attempts
 */

session_start();

// ============================================================
// INSTALLATION LOCK CHECKS (defense-in-depth)
// ============================================================

// Check 1: Config file with INSTALL_LOCKED constant
if (file_exists(__DIR__ . '/../config/config.php')) {
    require_once __DIR__ . '/../config/config.php';
    if (defined('INSTALL_LOCKED') && INSTALL_LOCKED) {
        http_response_code(403);
        die('<!DOCTYPE html><html><head><title>Forbidden</title></head><body><h2>AMPass is already installed.</h2><p>The installer is locked. Delete the <code>/install/</code> directory for security.</p><p><a href="../">Go to AMPass</a></p></body></html>');
    }
}

// Check 2: Lock file exists
if (file_exists(__DIR__ . '/../config/.install_lock')) {
    http_response_code(403);
    die('<!DOCTYPE html><html><head><title>Forbidden</title></head><body><h2>Installation is locked.</h2><p>Remove <code>config/.install_lock</code> to re-run the installer (not recommended).</p></body></html>');
}

// ============================================================
// RATE LIMITING (prevent brute-force installer abuse)
// ============================================================
$installAttemptFile = sys_get_temp_dir() . '/ampass_install_attempts_' . md5($_SERVER['REMOTE_ADDR'] ?? '');
$maxInstallAttempts = 10;
$installLockoutTime = 3600; // 1 hour

if (file_exists($installAttemptFile)) {
    $attemptData = json_decode(file_get_contents($installAttemptFile), true);
    if ($attemptData && $attemptData['count'] >= $maxInstallAttempts) {
        if (time() - $attemptData['first'] < $installLockoutTime) {
            http_response_code(429);
            die('Too many installation attempts. Please wait 1 hour.');
        }
        // Reset after lockout period
        unlink($installAttemptFile);
    }
}

// ============================================================
// CSRF TOKEN for installer
// ============================================================
if (empty($_SESSION['install_csrf'])) {
    $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
}

function validateInstallerCSRF(): bool {
    $token = $_POST['_csrf'] ?? '';
    return !empty($token) && hash_equals($_SESSION['install_csrf'] ?? '', $token);
}

function recordInstallAttempt(): void {
    global $installAttemptFile;
    $data = ['count' => 1, 'first' => time()];
    if (file_exists($installAttemptFile)) {
        $existing = json_decode(file_get_contents($installAttemptFile), true);
        if ($existing) {
            $data['count'] = $existing['count'] + 1;
            $data['first'] = $existing['first'];
        }
    }
    file_put_contents($installAttemptFile, json_encode($data));
}

// ============================================================
// HANDLE FORM SUBMISSION
// ============================================================
$step = (int)($_GET['step'] ?? 1);
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF on all POST requests
    if (!validateInstallerCSRF()) {
        $error = 'Security token invalid. Please refresh and try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'install') {
            recordInstallAttempt();
            $error = performInstallation($_POST);
            if (!$error) {
                $step = 3; // Success
                // Regenerate CSRF after successful install
                $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
            }
        } elseif ($action === 'step2') {
            // Store DB credentials in session (not in hidden form fields)
            $_SESSION['install_db'] = [
                'db_host' => trim($_POST['db_host'] ?? ''),
                'db_name' => trim($_POST['db_name'] ?? ''),
                'db_user' => trim($_POST['db_user'] ?? ''),
                'db_pass' => $_POST['db_pass'] ?? '',
                'site_name' => trim($_POST['site_name'] ?? 'AMPass'),
                'site_url' => rtrim(trim($_POST['site_url'] ?? ''), '/')
            ];
            
            // Validate DB connection before proceeding
            try {
                $testDsn = "mysql:host=" . $_SESSION['install_db']['db_host'] . ";charset=utf8mb4";
                new PDO($testDsn, $_SESSION['install_db']['db_user'], $_SESSION['install_db']['db_pass'], [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_TIMEOUT => 5
                ]);
                $step = 2;
            } catch (PDOException $e) {
                $error = 'Database connection failed. Please check your credentials.';
                $step = 1;
            }
        }
    }
}

function performInstallation(array $data): string {
    // Get DB credentials from session (not from form hidden fields)
    $dbConfig = $_SESSION['install_db'] ?? [];
    if (empty($dbConfig)) {
        return 'Session expired. Please start the installation again.';
    }

    $dbHost = $dbConfig['db_host'];
    $dbName = $dbConfig['db_name'];
    $dbUser = $dbConfig['db_user'];
    $dbPass = $dbConfig['db_pass'];
    $siteName = $dbConfig['site_name'];
    $siteUrl = $dbConfig['site_url'];

    $adminName = trim($data['admin_name'] ?? '');
    $adminEmail = trim($data['admin_email'] ?? '');
    $adminUsername = trim($data['admin_username'] ?? '');
    $adminPassword = $data['admin_password'] ?? '';

    // ============================================================
    // INPUT VALIDATION
    // ============================================================
    if (empty($dbHost) || empty($dbName) || empty($dbUser)) {
        return 'Database configuration is missing. Please restart installation.';
    }
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $dbName)) {
        return 'Database name must contain only letters, numbers, and underscores.';
    }
    if (empty($adminName) || empty($adminEmail) || empty($adminUsername) || empty($adminPassword)) {
        return 'All admin fields are required.';
    }
    if (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
        return 'Invalid email address.';
    }
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $adminUsername) || strlen($adminUsername) < 3) {
        return 'Username must be at least 3 characters (letters, numbers, underscores only).';
    }
    if (strlen($adminPassword) < 12) return 'Password must be at least 12 characters.';
    if (!preg_match('/[A-Z]/', $adminPassword)) return 'Password must contain at least one uppercase letter.';
    if (!preg_match('/[a-z]/', $adminPassword)) return 'Password must contain at least one lowercase letter.';
    if (!preg_match('/[0-9]/', $adminPassword)) return 'Password must contain at least one number.';
    if (!preg_match('/[^A-Za-z0-9]/', $adminPassword)) return 'Password must contain at least one special character.';

    // ============================================================
    // DATABASE CONNECTION
    // ============================================================
    try {
        $dsn = "mysql:host={$dbHost};charset=utf8mb4";
        $pdo = new PDO($dsn, $dbUser, $dbPass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 10
        ]);
    } catch (PDOException $e) {
        return 'Database connection failed. Please check credentials.';
    }

    try {
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("USE `{$dbName}`");
    } catch (PDOException $e) {
        return 'Failed to create database. Ensure the user has CREATE privileges.';
    }

    // ============================================================
    // RUN MAIN SCHEMA
    // ============================================================
    try {
        $schema = file_get_contents(__DIR__ . '/../database/schema.sql');
        $pdo->exec($schema);
    } catch (PDOException $e) {
        return 'Failed to create tables: ' . $e->getMessage();
    }

    // ============================================================
    // MIGRATION RUNNER — run all files in database/migrations/ in order
    // ============================================================
    $migrationError = runMigrations($pdo);
    if ($migrationError) {
        return $migrationError;
    }

    // ============================================================
    // GENERATE SECURITY KEYS
    // ============================================================
    $appSecret = bin2hex(random_bytes(32));
    $encryptionKey = bin2hex(random_bytes(32));
    $csrfSecret = bin2hex(random_bytes(16));

    // ============================================================
    // CREATE ADMIN USER
    // ============================================================
    if (defined('PASSWORD_ARGON2ID')) {
        $passwordHash = password_hash($adminPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, 'time_cost' => 4, 'threads' => 3
        ]);
    } else {
        $passwordHash = password_hash($adminPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO users (username, email, full_name, password_hash, role, status, created_at) 
             VALUES (?, ?, ?, ?, 'admin', 'active', NOW())"
        );
        $stmt->execute([$adminUsername, $adminEmail, $adminName, $passwordHash]);
        $adminId = $pdo->lastInsertId();
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'Duplicate') !== false) {
            return 'Username or email already exists.';
        }
        return 'Failed to create admin user.';
    }

    // ============================================================
    // CREATE USER SECURITY RECORD
    // SECURITY: We store a placeholder encrypted_vault_key. The admin's first
    // login will detect this (key_iterations = 0 flag) and trigger the browser-side
    // vault initialization flow that generates a real vault key via Web Crypto API.
    // The server NEVER generates or sees the real vault key in plaintext.
    // ============================================================
    $masterHash = $passwordHash; // Same hash for master password initially
    $placeholderSalt = bin2hex(random_bytes(32));
    // Mark as uninitialized: key_iterations = 0 signals "needs vault setup"
    $placeholderKey = 'VAULT_NOT_INITIALIZED';
    $placeholderIv = bin2hex(random_bytes(12));

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO user_security (user_id, master_password_hash, encryption_salt, encrypted_vault_key, vault_key_iv, key_iterations) 
             VALUES (?, ?, ?, ?, ?, 0)"
        );
        $stmt->execute([$adminId, $masterHash, $placeholderSalt, $placeholderKey, $placeholderIv]);
    } catch (PDOException $e) {
        return 'Failed to create security record.';
    }

    // ============================================================
    // AUTO-DETECT SITE URL
    // ============================================================
    if (empty($siteUrl)) {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $path = dirname(dirname($_SERVER['SCRIPT_NAME']));
        $siteUrl = $protocol . '://' . $host . rtrim($path, '/');
    }

    // ============================================================
    // WRITE CONFIG FILE
    // ============================================================
    $configContent = "<?php\n";
    $configContent .= "/**\n * AMPass Configuration\n * Generated by installer on " . date('Y-m-d H:i:s') . "\n * SECURITY: Never expose this file publicly. Set permissions to 640.\n */\n\n";
    $configContent .= "define('DB_HOST', " . var_export($dbHost, true) . ");\n";
    $configContent .= "define('DB_NAME', " . var_export($dbName, true) . ");\n";
    $configContent .= "define('DB_USER', " . var_export($dbUser, true) . ");\n";
    $configContent .= "define('DB_PASS', " . var_export($dbPass, true) . ");\n";
    $configContent .= "define('DB_CHARSET', 'utf8mb4');\n\n";
    $configContent .= "define('APP_NAME', " . var_export($siteName, true) . ");\n";
    $configContent .= "define('APP_URL', " . var_export($siteUrl, true) . ");\n";
    $configContent .= "define('APP_VERSION', '1.0.0');\n\n";
    $configContent .= "define('APP_SECRET', '{$appSecret}');\n";
    $configContent .= "define('ENCRYPTION_KEY', '{$encryptionKey}');\n";
    $configContent .= "define('CSRF_SECRET', '{$csrfSecret}');\n\n";
    $configContent .= "define('SESSION_LIFETIME', 3600);\n";
    $configContent .= "define('SESSION_NAME', 'ampass_session');\n";
    $configContent .= "define('VAULT_LOCK_TIMEOUT', 300);\n\n";
    $configContent .= "define('LOGIN_MAX_ATTEMPTS', 5);\n";
    $configContent .= "define('LOGIN_LOCKOUT_TIME', 900);\n\n";
    $configContent .= "define('REGISTRATION_ENABLED', true);\n";
    $configContent .= "define('INSTALL_LOCKED', true);\n";
    $configContent .= "define('DEBUG_MODE', false);\n";
    $configContent .= "define('APP_TIMEZONE', 'UTC');\n";
    $configContent .= "\ndate_default_timezone_set(APP_TIMEZONE);\n";

    $configPath = __DIR__ . '/../config/config.php';
    if (file_put_contents($configPath, $configContent) === false) {
        return 'Failed to write config file. Check directory permissions (config/ needs to be writable).';
    }

    // Create lock file
    file_put_contents(__DIR__ . '/../config/.install_lock', 'installed:' . date('c') . "\n");

    // Clear session install data
    unset($_SESSION['install_db']);

    return ''; // No error = success
}

/**
 * Run all migration files in database/migrations/ that haven't been run yet.
 * Creates a schema_migrations table to track which migrations have been applied.
 * Supports both .sql and .php migrations. PHP takes precedence if both exist.
 *
 * SECURITY:
 * - Failed migrations are NEVER marked as applied.
 * - On failure, returns error string and stops installation.
 * - PHP migrations are used for conditional/idempotent logic (DELIMITER not supported by PDO).
 */
function runMigrations(PDO $pdo): string {
    // Create migrations tracking table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `schema_migrations` (
            `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `filename` VARCHAR(255) NOT NULL UNIQUE,
            `applied_at` DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $migrationsDir = __DIR__ . '/../database/migrations';
    if (!is_dir($migrationsDir)) {
        return ''; // No migrations directory — that's fine
    }

    // Collect all migration files, PHP takes precedence over SQL
    $sqlFiles = glob($migrationsDir . '/*.sql') ?: [];
    $phpFiles = glob($migrationsDir . '/*.php') ?: [];

    $migrations = [];
    foreach ($sqlFiles as $file) {
        $base = pathinfo($file, PATHINFO_FILENAME);
        $migrations[$base] = ['file' => $file, 'type' => 'sql', 'filename' => basename($file)];
    }
    foreach ($phpFiles as $file) {
        $base = pathinfo($file, PATHINFO_FILENAME);
        // PHP takes precedence over SQL
        $migrations[$base] = ['file' => $file, 'type' => 'php', 'filename' => basename($file)];
    }
    ksort($migrations);

    foreach ($migrations as $base => $migration) {
        $filename = $migration['filename'];

        // Check if any variant is already applied
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM schema_migrations WHERE filename IN (?, ?, ?)");
        $stmt->execute([$filename, $base . '.sql', $base . '.php']);
        $alreadyApplied = (int)$stmt->fetchColumn() > 0;

        // Special safety for migration 006: verify actual DB state even if marked applied
        if ($base === '006_app_accounts_remote_desktop' && $alreadyApplied) {
            if (!verifyMigration006State($pdo)) {
                // DB state is incomplete — re-run the PHP migration
                $alreadyApplied = false;
                // Use the PHP file regardless of what was recorded
                $phpFile = $migrationsDir . '/006_app_accounts_remote_desktop.php';
                if (file_exists($phpFile)) {
                    $migration = ['file' => $phpFile, 'type' => 'php', 'filename' => '006_app_accounts_remote_desktop.php'];
                    $filename = '006_app_accounts_remote_desktop.php';
                }
            }
        }

        if ($alreadyApplied) {
            continue;
        }

        // Run the migration
        try {
            if ($migration['type'] === 'php') {
                // PHP migration: include the file, it must return true
                $migrationResult = require $migration['file'];
                if ($migrationResult !== true) {
                    return "Migration failed: {$filename}: PHP migration did not return true";
                }
            } else {
                // SQL migration — skip if empty/comment-only (stub for PHP companion)
                $sql = file_get_contents($migration['file']);
                $stripped = trim(preg_replace('/--[^\n]*/', '', $sql));
                if (empty($stripped)) {
                    // Empty SQL stub — skip silently (PHP companion handles it)
                    continue;
                }
                $pdo->exec($sql);
            }

            // ONLY mark as applied after successful execution
            $stmt = $pdo->prepare("INSERT INTO schema_migrations (filename) VALUES (?)");
            $stmt->execute([$filename]);

        } catch (PDOException $e) {
            // NEVER mark failed migration as applied
            $safeMsg = substr($e->getMessage(), 0, 300);
            error_log("AMPass migration FAILED ({$filename}): " . $safeMsg);
            return "Migration failed: {$filename}: " . $safeMsg;
        } catch (\Exception $e) {
            // NEVER mark failed migration as applied
            $safeMsg = substr($e->getMessage(), 0, 300);
            error_log("AMPass migration FAILED ({$filename}): " . $safeMsg);
            return "Migration failed: {$filename}: " . $safeMsg;
        }
    }

    return ''; // Success
}

/**
 * Verify that migration 006 actually applied correctly to the database.
 * Returns true if all expected changes are present, false if incomplete.
 */
function verifyMigration006State(PDO $pdo): bool {
    $dbName = $pdo->query("SELECT DATABASE()")->fetchColumn();

    // Check item_type enum includes app_account
    $stmt = $pdo->prepare(
        "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'vault_items' AND COLUMN_NAME = 'item_type'"
    );
    $stmt->execute([$dbName]);
    $columnType = $stmt->fetchColumn();
    if (!$columnType || !str_contains($columnType, 'app_account') || !str_contains($columnType, 'remote_desktop')) {
        return false;
    }

    // Check host_hash column exists
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'vault_items' AND COLUMN_NAME = 'host_hash'"
    );
    $stmt->execute([$dbName]);
    if ((int)$stmt->fetchColumn() === 0) {
        return false;
    }

    // Check idx_vault_host_hash index exists
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'vault_items' AND INDEX_NAME = 'idx_vault_host_hash'"
    );
    $stmt->execute([$dbName]);
    if ((int)$stmt->fetchColumn() === 0) {
        return false;
    }

    return true;
}

$csrfToken = $_SESSION['install_csrf'];
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <script>
        (function() {
            const theme = localStorage.getItem('ampass_theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Install AMPass</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="../public/css/app.css">
</head>
<body class="auth-body">
    <div class="install-container">
        <div class="install-card">
            <div class="auth-header">
                <svg class="auth-logo" viewBox="0 0 48 48" fill="none">
                    <rect width="48" height="48" rx="12" fill="url(#ig)"/>
                    <path d="M24 12L15 18v6c0 6.6 3.9 12.75 9 15 5.1-2.25 9-8.4 9-15v-6l-9-6z" fill="white" opacity="0.9"/>
                    <defs><linearGradient id="ig" x1="0" y1="0" x2="48" y2="48"><stop stop-color="#4f46e5"/><stop offset="1" stop-color="#7c3aed"/></linearGradient></defs>
                </svg>
                <h1 class="auth-title">Install AMPass</h1>
                <p class="auth-subtitle">Set up your secure password vault</p>
            </div>

            <div class="install-steps">
                <div class="install-step <?= $step >= 1 ? ($step > 1 ? 'done' : 'active') : '' ?>"></div>
                <div class="install-step <?= $step >= 2 ? ($step > 2 ? 'done' : 'active') : '' ?>"></div>
                <div class="install-step <?= $step >= 3 ? 'done' : '' ?>"></div>
            </div>

            <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <?php if ($step === 3): ?>
            <div class="alert alert-success">
                <strong>✅ Installation Complete!</strong><br>
                AMPass has been installed successfully.
            </div>
            <div class="alert alert-warning">
                <strong>⚠️ Critical Security Steps:</strong>
                <ol style="margin-top:8px;padding-left:20px;">
                    <li><strong>Delete the entire <code>/install/</code> directory NOW</strong></li>
                    <li>Enable HTTPS on your server (required for security)</li>
                    <li>Uncomment the HTTPS redirect in <code>.htaccess</code></li>
                    <li>Set <code>config/config.php</code> permissions to 640</li>
                    <li>Verify the installer is inaccessible by visiting <code>/install/</code></li>
                </ol>
            </div>
            <a href="../login" class="btn btn-primary btn-full">Go to Login →</a>

            <?php elseif ($step === 2): ?>
            <h2 style="margin-bottom:16px;">Admin Account</h2>
            <form method="POST">
                <input type="hidden" name="_csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="action" value="install">

                <div class="form-group">
                    <label class="form-label">Admin Full Name</label>
                    <input type="text" name="admin_name" class="form-input" required placeholder="John Doe" maxlength="100">
                </div>
                <div class="form-group">
                    <label class="form-label">Admin Email</label>
                    <input type="email" name="admin_email" class="form-input" required placeholder="admin@example.com" maxlength="255">
                </div>
                <div class="form-group">
                    <label class="form-label">Admin Username</label>
                    <input type="text" name="admin_username" class="form-input" required placeholder="admin" pattern="[a-zA-Z0-9_]+" minlength="3" maxlength="50">
                </div>
                <div class="form-group">
                    <label class="form-label">Admin Master Password</label>
                    <input type="password" name="admin_password" class="form-input" required minlength="12" maxlength="256" placeholder="Min 12 chars: uppercase, lowercase, number, symbol">
                    <span class="form-hint">Must include uppercase, lowercase, number, and special character</span>
                </div>
                <button type="submit" class="btn btn-primary btn-full">Install AMPass</button>
            </form>
            <p style="margin-top:12px;font-size:0.75rem;color:#6b6580;">Database: <?= htmlspecialchars($_SESSION['install_db']['db_host'] ?? '') ?> / <?= htmlspecialchars($_SESSION['install_db']['db_name'] ?? '') ?></p>

            <?php else: ?>
            <h2 style="margin-bottom:16px;">Database Configuration</h2>
            <form method="POST">
                <input type="hidden" name="_csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="action" value="step2">

                <div class="form-group">
                    <label class="form-label">Database Host</label>
                    <input type="text" name="db_host" class="form-input" value="localhost" required maxlength="255">
                </div>
                <div class="form-group">
                    <label class="form-label">Database Name</label>
                    <input type="text" name="db_name" class="form-input" required placeholder="ampass_db" pattern="[a-zA-Z0-9_]+" maxlength="64">
                    <span class="form-hint">Letters, numbers, and underscores only</span>
                </div>
                <div class="form-group">
                    <label class="form-label">Database Username</label>
                    <input type="text" name="db_user" class="form-input" required placeholder="root" maxlength="255">
                </div>
                <div class="form-group">
                    <label class="form-label">Database Password</label>
                    <input type="password" name="db_pass" class="form-input" placeholder="Leave empty for XAMPP default" maxlength="255">
                </div>
                <div class="form-divider"></div>
                <div class="form-group">
                    <label class="form-label">Site Name</label>
                    <input type="text" name="site_name" class="form-input" value="AMPass" maxlength="100">
                </div>
                <div class="form-group">
                    <label class="form-label">Site URL (auto-detected if empty)</label>
                    <input type="url" name="site_url" class="form-input" placeholder="https://yourdomain.com/ampass" maxlength="500">
                </div>
                <button type="submit" class="btn btn-primary btn-full">Test Connection & Continue →</button>
            </form>
            <?php endif; ?>
        </div>

        <p style="text-align:center;margin-top:16px;font-size:0.8rem;color:#6b6580;">
            AMPass v1.0.0 • Requires PHP 8.0+ and MySQL 5.7+
        </p>
    </div>
</body>
</html>
