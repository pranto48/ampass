<?php
/**
 * AMPass - Auth Layout (Login, Register, Unlock)
 */
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <script nonce="<?= Security::getNonce() ?>">
        (function() {
            const theme = localStorage.getItem('ampass_theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AMPass - Secure Password Vault">
    <meta name="theme-color" content="#1e1b4b">
    <title><?= htmlspecialchars($pageTitle ?? 'AMPass') ?></title>
    <link rel="manifest" href="<?= APP_URL ?>/manifest.webmanifest">
    <link rel="icon" href="<?= APP_URL ?>/public/assets/favicon.svg" type="image/svg+xml">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body class="auth-body">
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <svg class="auth-logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect width="48" height="48" rx="12" fill="url(#auth-gradient)"/>
                    <path d="M24 12L15 18v6c0 6.6 3.9 12.75 9 15 5.1-2.25 9-8.4 9-15v-6l-9-6z" fill="white" opacity="0.9"/>
                    <defs><linearGradient id="auth-gradient" x1="0" y1="0" x2="48" y2="48"><stop stop-color="#4f46e5"/><stop offset="1" stop-color="#7c3aed"/></linearGradient></defs>
                </svg>
                <h1 class="auth-title"><?= htmlspecialchars($pageTitle ?? 'AMPass') ?></h1>
                <?php if (isset($pageSubtitle)): ?>
                <p class="auth-subtitle"><?= htmlspecialchars($pageSubtitle) ?></p>
                <?php endif; ?>
            </div>

            <?php if (!empty($error)): ?>
            <div class="alert alert-error"><?= $error ?></div>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>

            <?php if (isset($httpsWarning) && $httpsWarning): ?>
            <div class="alert alert-warning">
                <strong>⚠️ Security Warning:</strong> You are not using HTTPS. Your data may be intercepted. 
                Please enable SSL/TLS for production use.
            </div>
            <?php endif; ?>
