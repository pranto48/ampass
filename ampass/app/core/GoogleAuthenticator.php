<?php
/**
 * AMPass - Google Authenticator TOTP Helper
 * SECURITY: Handles generation and verification of Google Authenticator 2FA TOTP secrets and codes.
 * Uses AES-256-CBC to encrypt 2FA secrets stored in the database.
 */

class GoogleAuthenticator {

    /**
     * Generate a random 16-character base32 secret
     */
    public static function generateSecret(): string {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < 16; $i++) {
            $secret .= $chars[random_int(0, 31)];
        }
        return $secret;
    }

    /**
     * Get OTPAuth QR Code URL
     */
    public static function getQRCodeUrl(string $user, string $secret, string $title = 'AMPass'): string {
        return 'otpauth://totp/' . rawurlencode($title . ':' . $user) . '?secret=' . $secret . '&issuer=' . rawurlencode($title);
    }

    /**
     * Verify 6-digit TOTP code
     */
    public static function verifyCode(string $secret, string $code, int $discrepancy = 1): bool {
        $code = str_replace(' ', '', $code);
        if (!preg_match('/^[0-9]{6}$/', $code)) {
            return false;
        }

        $currentTimeSlice = floor(time() / 30);
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = self::getCode($secret, $currentTimeSlice + $i);
            if ($calculatedCode === $code) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate code for a specific time slice
     */
    private static function getCode(string $secret, int $timeSlice): string {
        $secretKey = self::base32Decode($secret);
        // Pack time slice to 8-byte big-endian binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
        $hm = hash_hmac('sha1', $time, $secretKey, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1];
        $value = $value & 0x7FFFFFFF;
        $modulo = 10 ** 6;
        return str_pad((string)($value % $modulo), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Decode a base32 string
     */
    private static function base32Decode(string $b32): string {
        $b32 = strtoupper($b32);
        if (!preg_match('/^[A-Z2-7]+$/', $b32)) {
            return '';
        }
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $buffer = 0;
        $bufferSize = 0;
        $result = '';
        for ($i = 0; $i < strlen($b32); $i++) {
            $val = strpos($chars, $b32[$i]);
            $buffer = ($buffer << 5) | $val;
            $bufferSize += 5;
            if ($bufferSize >= 8) {
                $bufferSize -= 8;
                $result .= chr(($buffer >> $bufferSize) & 0xFF);
            }
        }
        return $result;
    }

    /**
     * Encrypt 2FA secret for database storage using AES-256-CBC
     */
    public static function encryptSecret(string $secret): string {
        $key = hash('sha256', APP_SECRET, true);
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt($secret, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ciphertext);
    }

    /**
     * Decrypt 2FA secret from database storage
     */
    public static function decryptSecret(string $encrypted): string {
        $data = base64_decode($encrypted);
        if (strlen($data) <= 16) {
            return '';
        }
        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        $key = hash('sha256', APP_SECRET, true);
        return openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv) ?: '';
    }
}
