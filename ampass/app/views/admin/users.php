<?php
$users = $data['users'] ?? [];
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$currentPage = $data['currentPage'] ?? 1;
$totalPages = $data['totalPages'] ?? 1;
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
    <title>Manage Users - AMPass Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
    <div class="admin-page">
        <div class="admin-header">
            <a href="<?= APP_URL ?>/admin" class="btn-back">← Back to Admin</a>
            <h1>Manage Users</h1>
        </div>

        <div class="card">
            <div class="card-body">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Name</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $u): ?>
                        <tr>
                            <td><?= $u['id'] ?></td>
                            <td><?= htmlspecialchars($u['username']) ?></td>
                            <td><?= htmlspecialchars($u['email']) ?></td>
                            <td><?= htmlspecialchars($u['full_name']) ?></td>
                            <td><span class="badge badge-<?= $u['role'] ?>"><?= ucfirst($u['role']) ?></span></td>
                            <td><span class="badge badge-<?= $u['status'] ?>"><?= ucfirst($u['status']) ?></span></td>
                            <td><?= $u['last_login_at'] ? date('M j, Y', strtotime($u['last_login_at'])) : 'Never' ?></td>
                            <td>
                                <?php if ($u['id'] !== Session::getUserId()): ?>
                                    <?php if ($u['status'] === 'active'): ?>
                                    <form method="POST" action="<?= APP_URL ?>/admin/suspendUser" style="display:inline">
                                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-warning" onclick="return confirm('Suspend this user?')">Suspend</button>
                                    </form>
                                    <?php else: ?>
                                    <form method="POST" action="<?= APP_URL ?>/admin/activateUser" style="display:inline">
                                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-success">Activate</button>
                                    </form>
                                    <?php endif; ?>
                                <?php else: ?>
                                    <span class="text-muted">Current user</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                    <a href="<?= APP_URL ?>/admin/users?page=<?= $i ?>" class="pagination-link <?= $i === $currentPage ? 'active' : '' ?>"><?= $i ?></a>
                    <?php endfor; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
