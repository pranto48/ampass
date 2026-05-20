<?php
/**
 * AMPass - Remote Backup Upload Service
 * Uploads encrypted .ampass-backup files to FTP/FTPS/SFTP/OneDrive.
 * 
 * SECURITY:
 * - Only uploads encrypted backup files
 * - Remote credentials encrypted at rest
 * - Never uploads plaintext database dumps
 * - Validates local file path before upload
 */

class RemoteBackupService {

    /**
     * Upload a backup file to a remote destination
     */
    public static function upload(int $backupId, int $destinationId): array {
        $backup = Database::fetchOne("SELECT * FROM backup_files WHERE id = ?", [$backupId]);
        if (!$backup) return ['success' => false, 'error' => 'Backup not found'];

        $dest = Database::fetchOne("SELECT * FROM remote_backup_destinations WHERE id = ? AND enabled = 1", [$destinationId]);
        if (!$dest) return ['success' => false, 'error' => 'Destination not found or disabled'];

        // Validate local file
        $basePath = realpath(__DIR__ . '/../../app_storage/backups');
        $filePath = realpath(__DIR__ . '/../../' . $backup['file_path']);
        if (!$basePath || !$filePath || strpos($filePath, $basePath) !== 0 || !file_exists($filePath)) {
            return ['success' => false, 'error' => 'Backup file not accessible'];
        }

        // Only upload .ampass-backup files
        if (!str_ends_with($backup['filename'], '.ampass-backup')) {
            return ['success' => false, 'error' => 'Only encrypted .ampass-backup files can be uploaded remotely'];
        }

        // Decrypt destination config
        $config = self::decryptConfig($dest['encrypted_config']);
        if (!$config) return ['success' => false, 'error' => 'Failed to decrypt destination config'];

        // Record upload attempt
        $uploadId = Database::insert(
            "INSERT INTO remote_backup_uploads (backup_file_id, destination_id, provider, status, attempts, created_at) VALUES (?, ?, ?, 'uploading', 1, NOW())",
            [$backupId, $destinationId, $dest['provider']]
        );

        // Upload based on provider
        $remoteName = 'ampass-backup-' . date('Y-m-d-His') . '.ampass-backup';
        $result = match($dest['provider']) {
            'ftp', 'ftps' => self::uploadFtp($filePath, $remoteName, $config, $dest['provider'] === 'ftps'),
            'sftp' => self::uploadSftp($filePath, $remoteName, $config),
            'onedrive' => self::uploadOneDrive($filePath, $remoteName, $config),
            default => ['success' => false, 'error' => 'Unknown provider']
        };

        // Update records
        if ($result['success']) {
            Database::execute("UPDATE remote_backup_uploads SET status = 'uploaded', remote_path = ?, uploaded_at = NOW() WHERE id = ?", [$result['remote_path'] ?? $remoteName, $uploadId]);
            Database::execute("UPDATE remote_backup_destinations SET last_success_at = NOW(), last_error = NULL WHERE id = ?", [$destinationId]);
        } else {
            Database::execute("UPDATE remote_backup_uploads SET status = 'failed', last_error = ? WHERE id = ?", [substr($result['error'], 0, 500), $uploadId]);
            Database::execute("UPDATE remote_backup_destinations SET last_error = ? WHERE id = ?", [substr($result['error'], 0, 500), $destinationId]);
        }

        return $result;
    }

    /**
     * Test a destination connection
     */
    public static function testConnection(array $config, string $provider): array {
        return match($provider) {
            'ftp', 'ftps' => self::testFtp($config, $provider === 'ftps'),
            'sftp' => self::testSftp($config),
            'onedrive' => ['success' => true, 'message' => 'OneDrive connection test requires OAuth flow'],
            default => ['success' => false, 'error' => 'Unknown provider']
        };
    }

    // ===== FTP/FTPS =====

    /**
     * Validate and sanitize a remote path segment.
     * Rejects: .., null bytes, backslashes, empty segments.
     */
    private static function validateRemotePathPart(string $part): bool {
        if (empty($part)) return false;
        if ($part === '.' || $part === '..') return false;
        if (str_contains($part, "\0")) return false;
        if (str_contains($part, '\\')) return false;
        if (str_contains($part, '..')) return false;
        return true;
    }

    /**
     * Sanitize remote backup filename.
     * Enforces pattern: ampass-backup-YYYY-mm-dd-HHMMSS.ampass-backup
     */
    private static function sanitizeRemoteFilename(string $name): ?string {
        if (preg_match('/^ampass-backup-\d{4}-\d{2}-\d{2}-\d{6}\.ampass-backup$/', $name)) {
            return $name;
        }
        return null;
    }

    /**
     * Recursively create remote FTP directories.
     * Splits path by / and creates each missing part.
     */
    private static function ftpMkdirRecursive($conn, string $dir): bool {
        if (empty($dir) || $dir === '/') return true;

        $parts = explode('/', trim($dir, '/'));
        $currentPath = '';

        foreach ($parts as $part) {
            if (!self::validateRemotePathPart($part)) {
                return false;
            }
            $currentPath .= '/' . $part;

            // Try to change to directory — if it works, it exists
            if (@ftp_chdir($conn, $currentPath)) {
                continue;
            }

            // Directory doesn't exist, create it
            if (!@ftp_mkdir($conn, $currentPath)) {
                // Could not create — might be permission issue
                return false;
            }
        }

        // Change to final directory
        return @ftp_chdir($conn, '/' . trim($dir, '/'));
    }

    private static function uploadFtp(string $localPath, string $remoteName, array $config, bool $ssl = false): array {
        $host = $config['host'] ?? '';
        $port = (int)($config['port'] ?? 21);
        $user = $config['username'] ?? '';
        $pass = $config['password'] ?? '';
        $dir = rtrim($config['remote_directory'] ?? '/', '/');
        $passive = ($config['passive_mode'] ?? true);

        if (!$host || !$user) return ['success' => false, 'error' => 'FTP host and username required'];

        // Validate remote filename pattern
        $sanitizedName = self::sanitizeRemoteFilename($remoteName);
        if (!$sanitizedName) {
            return ['success' => false, 'error' => 'Invalid remote filename pattern. Expected: ampass-backup-YYYY-mm-dd-HHMMSS.ampass-backup'];
        }
        $remoteName = $sanitizedName;

        $conn = $ssl ? @ftp_ssl_connect($host, $port, 15) : @ftp_connect($host, $port, 15);
        if (!$conn) return ['success' => false, 'error' => 'Cannot connect to FTP server'];

        if (!@ftp_login($conn, $user, $pass)) { ftp_close($conn); return ['success' => false, 'error' => 'FTP login failed']; }
        if ($passive) ftp_pasv($conn, true);

        // Recursively create remote directory
        if (!self::ftpMkdirRecursive($conn, $dir)) {
            ftp_close($conn);
            return ['success' => false, 'error' => 'Failed to create remote directory: ' . $dir . '. Check path for invalid characters.'];
        }

        $remotePath = $dir . '/' . $remoteName;
        $uploaded = @ftp_put($conn, $remoteName, $localPath, FTP_BINARY);

        if (!$uploaded) {
            ftp_close($conn);
            return ['success' => false, 'error' => 'FTP upload failed'];
        }

        // Verify remote file size matches local
        $localSize = filesize($localPath);
        $remoteSize = @ftp_size($conn, $remoteName);
        ftp_close($conn);

        if ($remoteSize >= 0 && $remoteSize !== $localSize) {
            return [
                'success' => false,
                'error' => "FTP upload size mismatch. Local: {$localSize} bytes, Remote: {$remoteSize} bytes. File may be corrupted."
            ];
        }

        return ['success' => true, 'remote_path' => $remotePath];
    }

    private static function testFtp(array $config, bool $ssl): array {
        $host = $config['host'] ?? '';
        $port = (int)($config['port'] ?? 21);
        $user = $config['username'] ?? '';
        $pass = $config['password'] ?? '';

        $conn = $ssl ? @ftp_ssl_connect($host, $port, 10) : @ftp_connect($host, $port, 10);
        if (!$conn) return ['success' => false, 'error' => 'Cannot connect to ' . ($ssl ? 'FTPS' : 'FTP') . ' server'];
        if (!@ftp_login($conn, $user, $pass)) { ftp_close($conn); return ['success' => false, 'error' => 'Login failed']; }
        ftp_close($conn);

        $message = 'Connection successful.';
        if ($ssl) {
            $message .= ' Warning: PHP ftp_ssl_connect does not always verify TLS certificates. Consider SFTP or OneDrive for stronger transport security.';
        } elseif (!$ssl) {
            $message .= ' Warning: Plain FTP transmits credentials in cleartext. Use FTPS, SFTP, or OneDrive.';
        }
        return ['success' => true, 'message' => $message];
    }

    // ===== SFTP =====

    private static function uploadSftp(string $localPath, string $remoteName, array $config): array {
        if (!function_exists('ssh2_connect')) {
            return ['success' => false, 'error' => 'PHP ssh2 extension not available on this server'];
        }

        $host = $config['host'] ?? '';
        $port = (int)($config['port'] ?? 22);
        $user = $config['username'] ?? '';
        $pass = $config['password'] ?? '';
        $dir = rtrim($config['remote_directory'] ?? '/', '/');

        $conn = @ssh2_connect($host, $port);
        if (!$conn) return ['success' => false, 'error' => 'Cannot connect to SFTP server'];
        if (!@ssh2_auth_password($conn, $user, $pass)) return ['success' => false, 'error' => 'SFTP authentication failed'];

        $sftp = @ssh2_sftp($conn);
        if (!$sftp) return ['success' => false, 'error' => 'Cannot initialize SFTP subsystem'];

        // Create directory
        @ssh2_sftp_mkdir($sftp, $dir, 0755, true);

        $remotePath = $dir . '/' . $remoteName;
        $stream = @fopen("ssh2.sftp://{$sftp}{$remotePath}", 'w');
        if (!$stream) return ['success' => false, 'error' => 'Cannot open remote file for writing'];

        $local = fopen($localPath, 'r');
        $bytes = stream_copy_to_stream($local, $stream);
        fclose($local);
        fclose($stream);

        if ($bytes === false || $bytes === 0) return ['success' => false, 'error' => 'SFTP upload failed'];
        return ['success' => true, 'remote_path' => $remotePath];
    }

    private static function testSftp(array $config): array {
        if (!function_exists('ssh2_connect')) return ['success' => false, 'error' => 'PHP ssh2 extension not installed'];
        $conn = @ssh2_connect($config['host'] ?? '', (int)($config['port'] ?? 22));
        if (!$conn) return ['success' => false, 'error' => 'Cannot connect'];
        if (!@ssh2_auth_password($conn, $config['username'] ?? '', $config['password'] ?? '')) return ['success' => false, 'error' => 'Auth failed'];
        return ['success' => true, 'message' => 'SFTP connection successful. Note: PHP ssh2 does not expose host key fingerprint verification. Verify server identity manually for production use.'];
    }

    // ===== OneDrive =====

    private static function uploadOneDrive(string $localPath, string $remoteName, array $config): array {
        $accessToken = self::getOneDriveAccessToken($config);
        if (!$accessToken) return ['success' => false, 'error' => 'OneDrive authentication failed. Reconnect in settings.'];

        $folder = $config['folder_path'] ?? 'AMPass Backups';
        $fileSize = filesize($localPath);

        // Small file upload (< 4MB)
        if ($fileSize < 4 * 1024 * 1024) {
            $url = "https://graph.microsoft.com/v1.0/me/drive/root:/{$folder}/{$remoteName}:/content";
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_PUT => true,
                CURLOPT_INFILE => fopen($localPath, 'r'),
                CURLOPT_INFILESIZE => $fileSize,
                CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $accessToken, 'Content-Type: application/octet-stream'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 60
            ]);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode >= 200 && $httpCode < 300) {
                $data = json_decode($response, true);
                return ['success' => true, 'remote_path' => $data['webUrl'] ?? $remoteName];
            }
            return ['success' => false, 'error' => 'OneDrive upload failed (HTTP ' . $httpCode . ')'];
        }

        // Large file: create upload session
        return self::uploadOneDriveLargeFile($localPath, $remoteName, $folder, $accessToken);
    }

    private static function uploadOneDriveLargeFile(string $localPath, string $remoteName, string $folder, string $accessToken): array {
        // Create upload session
        $url = "https://graph.microsoft.com/v1.0/me/drive/root:/{$folder}/{$remoteName}:/createUploadSession";
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode(['item' => ['name' => $remoteName]]),
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $accessToken, 'Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) return ['success' => false, 'error' => 'Failed to create OneDrive upload session'];

        $session = json_decode($response, true);
        $uploadUrl = $session['uploadUrl'] ?? '';
        if (!$uploadUrl) return ['success' => false, 'error' => 'No upload URL returned'];

        // Upload in 4MB chunks
        $fileSize = filesize($localPath);
        $chunkSize = 4 * 1024 * 1024;
        $handle = fopen($localPath, 'rb');
        $offset = 0;

        while ($offset < $fileSize) {
            $chunk = fread($handle, $chunkSize);
            $end = min($offset + strlen($chunk) - 1, $fileSize - 1);

            $ch = curl_init($uploadUrl);
            curl_setopt_array($ch, [
                CURLOPT_PUT => true,
                CURLOPT_POSTFIELDS => $chunk,
                CURLOPT_HTTPHEADER => [
                    "Content-Length: " . strlen($chunk),
                    "Content-Range: bytes {$offset}-{$end}/{$fileSize}"
                ],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 60
            ]);
            curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($code >= 400) { fclose($handle); return ['success' => false, 'error' => "Chunk upload failed at offset {$offset}"]; }
            $offset += strlen($chunk);
        }
        fclose($handle);

        return ['success' => true, 'remote_path' => "{$folder}/{$remoteName}"];
    }

    private static function getOneDriveAccessToken(array $config): ?string {
        $refreshToken = $config['refresh_token'] ?? '';
        $clientId = $config['client_id'] ?? '';
        $clientSecret = $config['client_secret'] ?? '';

        if (!$refreshToken || !$clientId || !$clientSecret) return null;

        $ch = curl_init('https://login.microsoftonline.com/common/oauth2/v2.0/token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'refresh_token' => $refreshToken,
                'grant_type' => 'refresh_token',
                'scope' => 'Files.ReadWrite offline_access'
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15
        ]);
        $response = curl_exec($ch);
        curl_close($ch);

        $data = json_decode($response, true);
        return $data['access_token'] ?? null;
    }

    // ===== Config Encryption =====

    /**
     * Encrypt destination config for storage.
     * SECURITY: MUST use APP_SECRET. Never falls back to plaintext base64.
     * @throws \RuntimeException if APP_SECRET is not defined
     */
    public static function encryptConfig(array $config): string {
        $json = json_encode($config);
        if (!defined('APP_SECRET') || empty(APP_SECRET)) {
            throw new \RuntimeException('APP_SECRET is not defined. Cannot encrypt remote backup config. Check config/config.php.');
        }
        $key = hash('sha256', APP_SECRET, true);
        $iv = random_bytes(12);
        $encrypted = openssl_encrypt($json, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encrypted === false) {
            throw new \RuntimeException('Config encryption failed. Check OpenSSL installation.');
        }
        return base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Decrypt destination config.
     * SECURITY: Requires APP_SECRET. Returns null if decryption fails.
     */
    private static function decryptConfig(string $encrypted): ?array {
        if (!defined('APP_SECRET') || empty(APP_SECRET)) {
            error_log('AMPass: Cannot decrypt remote backup config — APP_SECRET not defined');
            return null;
        }
        $data = base64_decode($encrypted);
        if ($data === false || strlen($data) < 28) return null;
        $key = hash('sha256', APP_SECRET, true);
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $ct = substr($data, 28);
        $json = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($json === false) return null;
        return json_decode($json, true);
    }

    /**
     * Public wrapper for decryptConfig (used by admin test/edit)
     */
    public static function decryptConfigPublic(string $encrypted): ?array {
        return self::decryptConfig($encrypted);
    }
}
