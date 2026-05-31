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
    <title>404 - Not Found | AMPass</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= defined('APP_URL') ? APP_URL : '' ?>/public/css/app.css">
</head>
<body class="error-body">
    <div class="error-container">
        <h1 class="error-code">404</h1>
        <p class="error-message">Page not found</p>
        <a href="<?= defined('APP_URL') ? APP_URL : '/' ?>/dashboard" class="btn btn-primary">Go to Dashboard</a>
    </div>
</body>
</html>
