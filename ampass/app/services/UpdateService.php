<?php
/**
 * AMPass - Update Service
 * Checks GitHub for updates and applies them safely.
 * 
 * SECURITY:
 * - Admin only
 * - Creates encrypted backup before update
 * - Maintenance mode during update
 * - Validates ZIP structure (rejects path traversal, symlinks, absolute paths)
 * - Rollback on failure
 * - Never overwrites config/config.php or app_storage/
 * - Never marks update completed unless files were actually copied and migrations succeeded
 * - Never logs GitHub token
 */

class UpdateService {

    const GITHUB_API = 'https://api.github.com';
    const USER_AGENT = 'AMPass-Updater/1.0';

    /** Paths that must NEVER be overwritten by an update */
    const SKIP_PATHS = [
        'config/config.php', 'config/.install_lock', 'config/.env',
        'app_storage/', 'install/.install_lock', '.git/', 'node_modules/', 'vendor/'
    ];

    /** Paths allowed to be updated */
    const ALLOWED_PREFIXES = [
        'app/', 'public/', 'database/migrations/', 'docs/', 'release/', 'clients/', 'scripts/',
        'index.php', 'sw.js', 'manifest.webmanifest', 'README.md'
    ];

    // ================================================================
    // CHECK FOR UPDATES
    // ================================================================

    public static function checkForUpdates(): array {
        $owner = self::getSetting('github_repo_owner', 'pranto48');
        $repo = self::getSetting('github_repo_name', 'ampass-secure-vault');
        $sourceType = self::getSetting('update_source_type', 'github_release');
        $branch = self::getSetting('github_branch', 'main');
        $token = self::getGitHubToken();

        $result = [
            'update_available' => false,
            'current_version' => self::getInstalledVersion(),
            'installed_commit_sha' => self::getSetting('installed_commit_sha', ''),
            'source_type' => $sourceType,
            'owner' => $owner,
            'repo' => $repo,
            'branch' => $branch,
            'latest_version' => '',
            'latest_commit_sha' => '',
            'commit_message' => '',
            'download_url' => '',
            'warning' => '',
            'error' => ''
        ];

        try {
            if ($sourceType === 'github_release') {
                $release = self::fetchGitHubRelease($owner, $repo, $token);
                if ($release) {
                    $latestVersion = ltrim($release['tag_name'] ?? '', 'v');
                    $result['latest_version'] = $latestVersion;
                    $result['latest_commit_sha'] = $release['target_commitish'] ?? '';
                    $result['release_notes'] = $release['body'] ?? '';
                    $result['download_url'] = $release['zipball_url'] ?? '';
                    $result['update_available'] = version_compare($latestVersion, $result['current_version'], '>');

                    // If same version but different commit, show informational note
                    if (!$result['update_available'] && !empty($result['latest_commit_sha']) && !empty($result['installed_commit_sha'])) {
                        if ($result['latest_commit_sha'] !== $result['installed_commit_sha']) {
                            $result['warning'] = 'New commits may exist on GitHub, but release mode only updates from tagged releases. Switch to "Branch ZIP" mode for development updates.';
                        }
                    }
                } else {
                    // No release found — helpful warning
                    $result['warning'] = 'No GitHub release found for ' . $owner . '/' . $repo . '. Switch to "Latest Branch ZIP" mode for development updates, or create a GitHub release.';
                }
            } else {
                // Branch ZIP mode — compare commit SHAs
                $commit = self::fetchLatestCommit($owner, $repo, $branch, $token);
                if ($commit) {
                    $result['latest_commit_sha'] = $commit['sha'] ?? '';
                    $result['latest_version'] = $result['current_version'];
                    $result['commit_message'] = substr($commit['commit']['message'] ?? '', 0, 200);
                    $result['download_url'] = "https://github.com/{$owner}/{$repo}/archive/refs/heads/{$branch}.zip";

                    $installedSha = self::getSetting('installed_commit_sha', '');
                    // Update available if: latest SHA exists AND (installed SHA is empty OR different)
                    $result['update_available'] = !empty($result['latest_commit_sha']) &&
                        (empty($installedSha) || $result['latest_commit_sha'] !== $installedSha);
                } else {
                    $result['error'] = "Could not fetch latest commit for branch '{$branch}'. Check repo settings and token.";
                }
            }
        } catch (\Exception $e) {
            $result['error'] = $e->getMessage();
        }

        // Save state
        self::saveSetting('last_update_check_at', date('c'));
        self::saveSetting('latest_version', $result['latest_version'] ?? '');
        self::saveSetting('latest_commit_sha', $result['latest_commit_sha'] ?? '');
        self::saveSetting('latest_commit_message', $result['commit_message'] ?? '');
        self::saveSetting('latest_download_url', $result['download_url'] ?? '');
        self::saveSetting('update_available', $result['update_available'] ? '1' : '0');
        self::saveSetting('last_check_error', $result['error'] ?? '');

        return $result;
    }

    // ================================================================
    // APPLY UPDATE
    // ================================================================

    public static function applyUpdate(string $backupPassword, int $adminUserId): array {
        $currentVersion = self::getInstalledVersion();
        $latestVersion = self::getSetting('latest_version', $currentVersion);
        $downloadUrl = self::getDownloadUrl();

        if (!$downloadUrl) {
            return ['success' => false, 'error' => 'No download URL available. Run update check first.'];
        }

        $appRoot = realpath(__DIR__ . '/../..');
        if (!$appRoot) return ['success' => false, 'error' => 'Cannot determine app root path'];

        $tempBase = $appRoot . '/app_storage/temp/updates/' . time();
        $zipPath = $tempBase . '/package.zip';
        $stagingDir = $tempBase . '/staging';
        $rollbackDir = $tempBase . '/rollback';

        // Record update start
        $updateId = Database::insert(
            "INSERT INTO update_history (from_version, to_version, from_commit_sha, to_commit_sha, update_source, status, started_by_user_id, started_at) VALUES (?, ?, ?, ?, ?, 'started', ?, NOW())",
            [$currentVersion, $latestVersion, self::getSetting('installed_commit_sha', ''), self::getSetting('latest_commit_sha', ''), self::getSetting('update_source_type', 'github_release'), $adminUserId]
        );

        try {
            // Step 1: Create pre-update encrypted backup
            require_once __DIR__ . '/BackupService.php';
            $backup = BackupService::create($backupPassword, ['include_database' => true]);
            $backupId = Database::insert(
                "INSERT INTO backup_files (filename, file_path, file_size, sha256_checksum, backup_type, includes_database, created_by_user_id, notes, created_at) VALUES (?, ?, ?, ?, 'database_only', 1, ?, 'Pre-update automatic backup', NOW())",
                [$backup['filename'], $backup['file_path'], $backup['file_size'], $backup['sha256_checksum'], $adminUserId]
            );
            Database::execute("UPDATE update_history SET backup_file_id = ? WHERE id = ?", [$backupId, $updateId]);

            // Step 2: Enable maintenance mode
            self::saveSetting('maintenance_mode', '1');

            // Step 3: Download
            self::ensureDir($tempBase);
            $downloaded = self::downloadFile($downloadUrl, $zipPath);
            if (!$downloaded) throw new \Exception('Failed to download update package from GitHub');

            // Step 4: Safe ZIP extraction (validates all entries BEFORE extracting)
            self::ensureDir($stagingDir);
            $extracted = self::safeExtractZip($zipPath, $stagingDir);
            if (!$extracted) throw new \Exception('Failed to extract update package');

            // Step 5: Find project root inside extracted ZIP
            $sourceRoot = self::findProjectRoot($stagingDir);
            if (!$sourceRoot) throw new \Exception('Update package does not contain valid AMPass structure');

            // Step 6: Validate package (no path traversal, has expected files)
            self::validatePackage($sourceRoot);

            // Step 7: Copy files with rollback support
            self::ensureDir($rollbackDir);
            $copyResult = self::copyUpdateFiles($sourceRoot, $appRoot, $rollbackDir);

            // Step 8: Run migrations
            $migrationResult = self::runPendingMigrations();
            if ($migrationResult['failed']) {
                // Migration failed — full rollback including newly-created files
                self::restoreRollback($rollbackDir, $appRoot, $copyResult['created'], $copyResult['created_dirs']);
                throw new \Exception('Migration failed: ' . $migrationResult['failed'] . '. Files rolled back.');
            }

            // Step 9: Update version info (ONLY after successful copy + migrations)
            self::saveSetting('installed_version', $latestVersion);
            self::saveSetting('installed_commit_sha', self::getSetting('latest_commit_sha', ''));
            self::saveSetting('installed_at', date('c'));
            self::saveSetting('update_available', '0');

            // Step 10: Disable maintenance mode
            self::saveSetting('maintenance_mode', '0');

            // Step 11: Record success
            $totalFiles = count($copyResult['copied']);
            Database::execute("UPDATE update_history SET status = 'completed', completed_at = NOW(), notes = ? WHERE id = ?",
                ['Updated ' . $totalFiles . ' files (' . count($copyResult['overwritten']) . ' overwritten, ' . count($copyResult['created']) . ' new). Migrations: ' . count($migrationResult['applied']) . ' applied.', $updateId]);

            // Cleanup temp
            self::deleteDir($tempBase);

            return ['success' => true, 'version' => $latestVersion, 'files_updated' => $totalFiles, 'migrations_applied' => $migrationResult['applied']];

        } catch (\Exception $e) {
            self::saveSetting('maintenance_mode', '0');
            Database::execute("UPDATE update_history SET status = 'failed', error_message = ?, completed_at = NOW() WHERE id = ?", [substr($e->getMessage(), 0, 1000), $updateId]);
            // Attempt rollback if copyResult is available
            if (isset($copyResult)) {
                self::restoreRollback($rollbackDir, $appRoot, $copyResult['created'] ?? [], $copyResult['created_dirs'] ?? []);
            }
            self::deleteDir($tempBase);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    // ================================================================
    // FILE EXTRACTION & VALIDATION
    // ================================================================

    /**
     * Safe ZIP extraction — validates EVERY entry BEFORE extraction.
     * Rejects: path traversal, absolute paths, null bytes, drive letters, symlinks, empty names.
     * Never calls extractTo() on untrusted ZIP.
     */
    private static function safeExtractZip(string $zipPath, string $destDir): bool {
        if (!class_exists('ZipArchive')) return false;
        $zip = new \ZipArchive();
        if ($zip->open($zipPath) !== true) return false;

        $destDir = rtrim(str_replace('\\', '/', $destDir), '/');
        $realDest = realpath($destDir);
        if (!$realDest) { $zip->close(); return false; }
        $realDest = str_replace('\\', '/', $realDest);

        // PASS 1: Validate ALL entries before extracting anything
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            if ($stat === false) { $zip->close(); return false; }

            $entryName = $stat['name'];

            // Reject empty names
            if (empty($entryName)) {
                $zip->close();
                throw new \Exception("ZIP entry #{$i} has empty name");
            }

            // Reject null bytes
            if (str_contains($entryName, "\0")) {
                $zip->close();
                throw new \Exception("ZIP entry contains null byte: " . bin2hex($entryName));
            }

            // Normalize slashes
            $normalized = str_replace('\\', '/', $entryName);

            // Reject path traversal
            if (str_contains($normalized, '../') || str_contains($normalized, '/..')) {
                $zip->close();
                throw new \Exception("ZIP path traversal rejected: {$entryName}");
            }

            // Reject absolute paths
            if (str_starts_with($normalized, '/') || str_starts_with($normalized, '\\')) {
                $zip->close();
                throw new \Exception("ZIP absolute path rejected: {$entryName}");
            }

            // Reject drive letters (C:, D:, etc.)
            if (preg_match('/^[a-zA-Z]:/', $normalized)) {
                $zip->close();
                throw new \Exception("ZIP drive letter path rejected: {$entryName}");
            }

            // Reject symlinks (check external attributes for Unix symlink flag)
            $externalAttr = $stat['external_attributes'] ?? 0;
            // Unix symlink: (attr >> 16) & 0xF000 === 0xA000
            if (($externalAttr >> 16 & 0xF000) === 0xA000) {
                $zip->close();
                throw new \Exception("ZIP symlink entry rejected: {$entryName}");
            }
        }

        // PASS 2: Extract each file manually
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $entryName = str_replace('\\', '/', $stat['name']);

            $targetPath = $destDir . '/' . $entryName;

            // Directory entry (ends with /)
            if (str_ends_with($entryName, '/')) {
                if (!is_dir($targetPath)) {
                    mkdir($targetPath, 0755, true);
                }
                continue;
            }

            // Ensure parent directory exists
            $parentDir = dirname($targetPath);
            if (!is_dir($parentDir)) {
                mkdir($parentDir, 0755, true);
            }

            // Final safety check: resolved path must be inside destination
            $realParent = realpath($parentDir);
            if (!$realParent || !str_starts_with(str_replace('\\', '/', $realParent), $realDest)) {
                $zip->close();
                throw new \Exception("ZIP extraction path escape detected: {$entryName}");
            }

            // Extract file content via stream
            $stream = $zip->getStream($stat['name']);
            if (!$stream) {
                $zip->close();
                throw new \Exception("Cannot read ZIP entry: {$entryName}");
            }

            $outFile = fopen($targetPath, 'wb');
            if (!$outFile) {
                fclose($stream);
                $zip->close();
                throw new \Exception("Cannot write file: {$targetPath}");
            }

            while (!feof($stream)) {
                fwrite($outFile, fread($stream, 8192));
            }
            fclose($stream);
            fclose($outFile);
        }

        $zip->close();
        return true;
    }

    /**
     * Find the AMPass project root inside extracted ZIP.
     * GitHub ZIPs have a top-level directory like "ampass-secure-vault-main/"
     */
    private static function findProjectRoot(string $stagingDir): ?string {
        // Check if staging dir itself is the root
        if (file_exists($stagingDir . '/index.php') && file_exists($stagingDir . '/app/core/App.php')) {
            return $stagingDir;
        }
        // Check if there's an ampass/ subdirectory
        if (file_exists($stagingDir . '/ampass/index.php')) {
            return $stagingDir . '/ampass';
        }
        // Check first subdirectory (GitHub archive pattern)
        $dirs = glob($stagingDir . '/*', GLOB_ONLYDIR);
        foreach ($dirs as $dir) {
            if (file_exists($dir . '/ampass/index.php')) return $dir . '/ampass';
            if (file_exists($dir . '/index.php') && file_exists($dir . '/app/core/App.php')) return $dir;
        }
        return null;
    }

    /**
     * Validate extracted package for safety
     */
    private static function validatePackage(string $sourceRoot): void {
        if (!file_exists($sourceRoot . '/index.php')) {
            throw new \Exception('Package missing index.php');
        }
        // Scan for dangerous paths
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($sourceRoot, \RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            $relative = str_replace($sourceRoot . DIRECTORY_SEPARATOR, '', $file->getPathname());
            $relative = str_replace('\\', '/', $relative);
            // Reject path traversal
            if (str_contains($relative, '..') || str_contains($relative, "\0")) {
                throw new \Exception("Dangerous path in package: {$relative}");
            }
            // Reject symlinks
            if (is_link($file->getPathname())) {
                throw new \Exception("Symlink not allowed in package: {$relative}");
            }
        }
    }

    /**
     * Copy update files to app root, creating rollback copies.
     * Returns structured result tracking overwritten, created files, and created directories.
     */
    private static function copyUpdateFiles(string $sourceRoot, string $appRoot, string $rollbackDir): array {
        $result = [
            'copied' => [],
            'overwritten' => [],
            'created' => [],
            'created_dirs' => []
        ];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($sourceRoot, \RecursiveDirectoryIterator::SKIP_DOTS));

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;

            $relative = str_replace($sourceRoot . DIRECTORY_SEPARATOR, '', $file->getPathname());
            $relative = str_replace('\\', '/', $relative);

            // Check if this path should be skipped
            if (self::shouldSkipPath($relative)) continue;

            // Check if this path is in allowed prefixes
            if (!self::isAllowedPath($relative)) continue;

            $destPath = $appRoot . '/' . $relative;
            $rollbackPath = $rollbackDir . '/' . $relative;

            // Track whether destination exists (overwrite vs create)
            $isOverwrite = file_exists($destPath);

            if ($isOverwrite) {
                // Backup existing file for rollback
                $rollbackParent = dirname($rollbackPath);
                if (!is_dir($rollbackParent)) mkdir($rollbackParent, 0755, true);
                copy($destPath, $rollbackPath);
                $result['overwritten'][] = $relative;
            } else {
                // Track as newly created
                $result['created'][] = $relative;
            }

            // Ensure destination directory exists, track new directories
            $destParent = dirname($destPath);
            if (!is_dir($destParent)) {
                // Track all new directories created (for rollback cleanup)
                $dirsToCreate = [];
                $checkDir = $destParent;
                while (!is_dir($checkDir) && $checkDir !== $appRoot) {
                    $dirsToCreate[] = str_replace('\\', '/', str_replace($appRoot . DIRECTORY_SEPARATOR, '', $checkDir));
                    $dirsToCreate[] = str_replace('\\', '/', str_replace($appRoot . '/', '', $checkDir));
                    $checkDir = dirname($checkDir);
                }
                // Deduplicate and record
                $dirsToCreate = array_unique($dirsToCreate);
                foreach ($dirsToCreate as $d) {
                    if (!in_array($d, $result['created_dirs'])) {
                        $result['created_dirs'][] = $d;
                    }
                }
                mkdir($destParent, 0755, true);
            }

            // Copy new file
            if (copy($file->getPathname(), $destPath)) {
                $result['copied'][] = $relative;
            }
        }

        return $result;
    }

    private static function shouldSkipPath(string $relative): bool {
        foreach (self::SKIP_PATHS as $skip) {
            if (str_starts_with($relative, $skip) || $relative === rtrim($skip, '/')) return true;
        }
        return false;
    }

    private static function isAllowedPath(string $relative): bool {
        foreach (self::ALLOWED_PREFIXES as $prefix) {
            if (str_starts_with($relative, $prefix) || $relative === $prefix) return true;
        }
        return false;
    }

    /**
     * Full rollback: restore overwritten files AND delete newly-created files/dirs.
     * @param string $rollbackDir Directory containing backed-up originals
     * @param string $appRoot Application root directory
     * @param array $createdFiles Files that were newly created (not overwrites)
     * @param array $createdDirs Directories that were newly created
     */
    private static function restoreRollback(string $rollbackDir, string $appRoot, array $createdFiles = [], array $createdDirs = []): void {
        $realAppRoot = realpath($appRoot);
        if (!$realAppRoot) return;
        $realAppRoot = str_replace('\\', '/', $realAppRoot);

        $rollbackLog = [];

        // 1. Restore overwritten files from rollback directory
        if (is_dir($rollbackDir)) {
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($rollbackDir, \RecursiveDirectoryIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if ($file->isDir()) continue;
                $relative = str_replace($rollbackDir . DIRECTORY_SEPARATOR, '', $file->getPathname());
                $relative = str_replace('\\', '/', $relative);
                $destPath = $appRoot . '/' . $relative;
                if (@copy($file->getPathname(), $destPath)) {
                    $rollbackLog[] = "Restored: {$relative}";
                }
            }
        }

        // 2. Delete newly-created files (these didn't exist before the update)
        foreach ($createdFiles as $relative) {
            $filePath = $appRoot . '/' . $relative;
            $realFile = realpath($filePath);
            // Safety: only delete if inside app root
            if ($realFile && str_starts_with(str_replace('\\', '/', $realFile), $realAppRoot) && file_exists($filePath)) {
                @unlink($filePath);
                $rollbackLog[] = "Deleted new file: {$relative}";
            }
        }

        // 3. Remove empty directories created during update (deepest first)
        // Sort by depth descending so we remove deepest dirs first
        usort($createdDirs, function($a, $b) {
            return substr_count($b, '/') - substr_count($a, '/');
        });

        foreach ($createdDirs as $relative) {
            $dirPath = $appRoot . '/' . $relative;
            $realDir = realpath($dirPath);
            // Safety: only remove if inside app root and empty
            if ($realDir && str_starts_with(str_replace('\\', '/', $realDir), $realAppRoot) && is_dir($dirPath)) {
                // Only remove if directory is empty
                $contents = @scandir($dirPath);
                if ($contents !== false && count($contents) <= 2) { // . and ..
                    @rmdir($dirPath);
                    $rollbackLog[] = "Removed empty dir: {$relative}";
                }
            }
        }

        // Log rollback summary
        if (!empty($rollbackLog)) {
            error_log("AMPass rollback summary: " . count($rollbackLog) . " operations — " . implode('; ', array_slice($rollbackLog, 0, 10)));
        }
    }

    // ================================================================
    // MIGRATION RUNNER (FIXED — never marks failed as applied)
    // ================================================================

    /**
     * Run pending database migrations.
     * Returns: ['applied' => [...], 'skipped' => [...], 'failed' => null|string]
     * SECURITY: Failed migrations are NEVER marked as applied.
     *
     * Supports two migration formats:
     * 1. Pure SQL (.sql files) — executed via PDO::exec()
     * 2. PHP migrations (.php files) — for complex/conditional logic that SQL alone cannot handle
     *    (e.g., INFORMATION_SCHEMA checks, conditional ALTER TABLE)
     *
     * If both 006_example.sql and 006_example.php exist, the .php file takes precedence.
     * PHP migration files must return true on success or throw an exception on failure.
     *
     * NOTE: SQL migrations containing DELIMITER or CREATE PROCEDURE are NOT supported
     * by the PDO runner. Use PHP migrations for conditional/complex logic.
     */
    public static function runPendingMigrations(): array {
        $result = ['applied' => [], 'skipped' => [], 'failed' => null];
        $migrationsDir = __DIR__ . '/../../database/migrations';
        if (!is_dir($migrationsDir)) return $result;

        $pdo = Database::getInstance();

        // Ensure schema_migrations table exists
        $pdo->exec("CREATE TABLE IF NOT EXISTS `schema_migrations` (
            `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `filename` VARCHAR(255) NOT NULL UNIQUE,
            `applied_at` DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // Collect all migration files (.sql and .php), deduplicate by base name
        $sqlFiles = glob($migrationsDir . '/*.sql') ?: [];
        $phpFiles = glob($migrationsDir . '/*.php') ?: [];

        // Build ordered list: if .php exists for a migration, it takes precedence over .sql
        $migrations = [];
        foreach ($sqlFiles as $file) {
            $base = pathinfo($file, PATHINFO_FILENAME);
            $migrations[$base] = ['file' => $file, 'type' => 'sql', 'filename' => basename($file)];
        }
        foreach ($phpFiles as $file) {
            $base = pathinfo($file, PATHINFO_FILENAME);
            // PHP takes precedence — overwrite SQL entry
            $migrations[$base] = ['file' => $file, 'type' => 'php', 'filename' => basename($file)];
        }
        ksort($migrations); // Sort by filename prefix (001_, 002_, etc.)

        foreach ($migrations as $migration) {
            $filename = $migration['filename'];

            // Check if already applied (check both .sql and .php variants)
            $baseName = pathinfo($filename, PATHINFO_FILENAME);
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM schema_migrations WHERE filename = ? OR filename = ? OR filename = ?");
            $stmt->execute([$filename, $baseName . '.sql', $baseName . '.php']);
            if ($stmt->fetchColumn() > 0) {
                $result['skipped'][] = $filename;
                continue;
            }

            // Run migration
            try {
                if ($migration['type'] === 'php') {
                    // PHP migration: include the file which must return true or throw
                    $migrationResult = require $migration['file'];
                    if ($migrationResult !== true) {
                        throw new \Exception("PHP migration did not return true");
                    }
                } else {
                    // SQL migration: execute via PDO
                    $sql = file_get_contents($migration['file']);
                    if (empty(trim($sql))) {
                        $result['skipped'][] = $filename;
                        continue;
                    }
                    $pdo->exec($sql);
                }

                // ONLY mark as applied after successful execution
                $stmt = $pdo->prepare("INSERT INTO schema_migrations (filename) VALUES (?)");
                $stmt->execute([$filename]);
                $result['applied'][] = $filename;

            } catch (\PDOException $e) {
                // DO NOT mark as applied — this is the critical fix
                $result['failed'] = $filename . ': ' . $e->getMessage();
                error_log("AMPass migration FAILED ({$filename}): " . $e->getMessage());
                return $result; // Stop on first failure
            } catch (\Exception $e) {
                $result['failed'] = $filename . ': ' . $e->getMessage();
                error_log("AMPass migration FAILED ({$filename}): " . $e->getMessage());
                return $result;
            }
        }

        return $result;
    }

    // ================================================================
    // HELPERS
    // ================================================================

    public static function getInstalledVersion(): string {
        return defined('APP_VERSION') ? APP_VERSION : (self::getSetting('installed_version', '1.0.0'));
    }

    public static function getUpdateHistory(int $limit = 10): array {
        return Database::fetchAll("SELECT * FROM update_history ORDER BY started_at DESC LIMIT ?", [$limit]);
    }

    public static function getPendingMigrations(): array {
        $migrationsDir = __DIR__ . '/../../database/migrations';
        if (!is_dir($migrationsDir)) return [];

        // Collect all migration files, PHP takes precedence over SQL
        $sqlFiles = glob($migrationsDir . '/*.sql') ?: [];
        $phpFiles = glob($migrationsDir . '/*.php') ?: [];

        $migrations = [];
        foreach ($sqlFiles as $file) {
            $base = pathinfo($file, PATHINFO_FILENAME);
            $migrations[$base] = basename($file);
        }
        foreach ($phpFiles as $file) {
            $base = pathinfo($file, PATHINFO_FILENAME);
            $migrations[$base] = basename($file); // PHP overrides SQL
        }
        ksort($migrations);

        $pending = [];
        foreach ($migrations as $base => $filename) {
            // Check if any variant is already applied
            $applied = Database::fetchOne(
                "SELECT COUNT(*) as cnt FROM schema_migrations WHERE filename IN (?, ?, ?)",
                [$filename, $base . '.sql', $base . '.php']
            );
            if (($applied['cnt'] ?? 0) == 0) $pending[] = $filename;
        }
        return $pending;
    }

    private static function getDownloadUrl(): string {
        $owner = self::getSetting('github_repo_owner', 'pranto48');
        $repo = self::getSetting('github_repo_name', 'ampass-secure-vault');
        $sourceType = self::getSetting('update_source_type', 'github_release');
        if ($sourceType === 'github_release') {
            $v = self::getSetting('latest_version', '');
            return $v ? "https://github.com/{$owner}/{$repo}/archive/refs/tags/v{$v}.zip" : '';
        }
        $branch = self::getSetting('github_branch', 'main');
        return "https://github.com/{$owner}/{$repo}/archive/refs/heads/{$branch}.zip";
    }

    // ===== GitHub API =====

    private static function fetchGitHubRelease(string $owner, string $repo, ?string $token): ?array {
        return self::githubRequest(self::GITHUB_API . "/repos/{$owner}/{$repo}/releases/latest", $token);
    }

    private static function fetchLatestCommit(string $owner, string $repo, string $branch, ?string $token): ?array {
        return self::githubRequest(self::GITHUB_API . "/repos/{$owner}/{$repo}/commits/{$branch}", $token);
    }

    private static function githubRequest(string $url, ?string $token): ?array {
        $headers = ['User-Agent: ' . self::USER_AGENT, 'Accept: application/vnd.github.v3+json'];
        if ($token) $headers[] = 'Authorization: token ' . $token;
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => 15, CURLOPT_FOLLOWLOCATION => true]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($httpCode === 403) throw new \Exception('GitHub API rate limited. Add a token or try later.');
        if ($httpCode === 404) return null;
        if ($httpCode !== 200) throw new \Exception("GitHub API error (HTTP {$httpCode})");
        return json_decode($response, true);
    }

    private static function downloadFile(string $url, string $destPath): bool {
        $token = self::getGitHubToken();
        $headers = ['User-Agent: ' . self::USER_AGENT];
        if ($token) $headers[] = 'Authorization: token ' . $token;
        $ch = curl_init($url);
        $fp = fopen($destPath, 'wb');
        curl_setopt_array($ch, [CURLOPT_FILE => $fp, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => 120, CURLOPT_FOLLOWLOCATION => true]);
        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fp);
        return $httpCode === 200 && filesize($destPath) > 1000;
    }

    private static function getGitHubToken(): ?string {
        $encrypted = self::getSetting('github_token_encrypted', '');
        if (empty($encrypted) || !defined('APP_SECRET')) return null;
        $data = base64_decode($encrypted);
        if (strlen($data) < 28) return null;
        $key = hash('sha256', APP_SECRET, true);
        $iv = substr($data, 0, 12); $tag = substr($data, 12, 16); $ct = substr($data, 28);
        $decrypted = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $decrypted ?: null;
    }

    // ===== Settings =====

    public static function getSetting(string $key, string $default = ''): string {
        $row = Database::fetchOne("SELECT setting_value FROM app_settings WHERE setting_key = ?", [$key]);
        return $row ? ($row['setting_value'] ?? $default) : $default;
    }

    public static function saveSetting(string $key, string $value): void {
        Database::execute("INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?", [$key, $value, $value]);
    }

    // ===== Filesystem =====

    private static function ensureDir(string $path): void {
        if (!is_dir($path)) mkdir($path, 0755, true);
    }

    private static function deleteDir(string $dir): void {
        if (!is_dir($dir)) return;
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $f) { $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname()); }
        @rmdir($dir);
    }
}
