<?php
$logs = $data['logs'] ?? [];
$currentPage = $data['currentPage'] ?? 1;
$actionFilter = $data['actionFilter'] ?? null;
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
    <title>Audit Logs - AMPass Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="admin-page">
        <div class="admin-header">
            <a href="<?= APP_URL ?>/admin" class="btn-back">← Back to Admin</a>
            <h1>Audit Logs</h1>
        </div>

        <div class="card">
            <div class="card-body">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>IP Address</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><?= date('M j, Y g:i A', strtotime($log['created_at'])) ?></td>
                            <td><?= htmlspecialchars($log['username'] ?? 'System') ?></td>
                            <td><span class="badge"><?= htmlspecialchars($log['action']) ?></span></td>
                            <td><?= htmlspecialchars($log['ip_address'] ?? '-') ?></td>
                            <td><?= htmlspecialchars(substr($log['details'] ?? '-', 0, 100)) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <div class="pagination">
                    <?php if ($currentPage > 1): ?>
                    <a href="<?= APP_URL ?>/admin/logs?page=<?= $currentPage - 1 ?>" class="pagination-link">← Prev</a>
                    <?php endif; ?>
                    <span class="pagination-current">Page <?= $currentPage ?></span>
                    <?php if (count($logs) >= 50): ?>
                    <a href="<?= APP_URL ?>/admin/logs?page=<?= $currentPage + 1 ?>" class="pagination-link">Next →</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
