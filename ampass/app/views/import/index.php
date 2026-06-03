<?php
$csrfToken = $data['csrfToken'] ?? CSRF::generateToken();
$folders = $data['folders'] ?? [];
$history = $data['history'] ?? [];
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
    <title>Import Passwords - AMPass</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= APP_URL ?>/public/css/app.css">
</head>
<body>
<div class="form-page">
    <div class="form-page-header">
        <a href="<?= APP_URL ?>/vault" class="btn-back">&larr; Back to Vault</a>
        <h1 class="page-title">Import Passwords</h1>
    </div>

    <div class="alert alert-warning" style="margin-bottom:16px;">
        &#9888; <strong>Security Warning:</strong> Exported password files contain plaintext passwords. Import only on a trusted computer. Delete the export file immediately after importing.
    </div>

    <!-- Source Selection -->
    <div class="card">
        <div class="card-header"><h2 class="card-title">Select Import Source</h2></div>
        <div class="card-body">
            <div class="form-group">
                <select id="importSource" class="form-select">
                    <option value="">Choose source...</option>
                    <option value="sticky_password">Sticky Password (TXT export)</option>
                    <option value="lastpass">LastPass (CSV)</option>
                    <option value="bitwarden">Bitwarden (CSV)</option>
                    <option value="1password">1Password (CSV)</option>
                    <option value="keepass">KeePass (CSV)</option>
                    <option value="chrome">Google Chrome (CSV)</option>
                    <option value="edge">Microsoft Edge (CSV)</option>
                    <option value="brave">Brave Browser (CSV)</option>
                    <option value="firefox">Firefox (CSV)</option>
                    <option value="generic_csv">Generic CSV</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Upload File</label>
                <input type="file" id="importFile" class="form-input" accept=".txt,.csv" disabled>
                <small class="text-muted">Accepted: .txt (Sticky Password), .csv (browsers)</small>
            </div>
            <div class="form-group" id="importOptions" style="display:none;">
                <label class="form-label">Destination Folder (optional)</label>
                <select id="importFolder" class="form-select">
                    <option value="">No folder</option>
                    <?php foreach ($folders as $f): ?>
                    <option value="<?= $f['id'] ?>"><?= htmlspecialchars($f['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div id="importConfirm" style="display:none;margin-top:12px;">
                <label class="checkbox-label"><input type="checkbox" id="importAcknowledge"> I understand this file contains plaintext passwords</label>
            </div>
            <button id="btnPreview" class="btn btn-secondary" style="margin-top:12px;" disabled>Preview Import</button>
        </div>
    </div>

    <!-- Preview Table -->
    <div class="card" id="previewCard" style="display:none;">
        <div class="card-header">
            <h2 class="card-title">Preview (<span id="previewCount">0</span> items)</h2>
            <div style="display:flex;gap:8px;">
                <button id="btnSelectAll" class="btn btn-sm btn-ghost">Select All</button>
                <button id="btnUnselectAll" class="btn btn-sm btn-ghost">Unselect All</button>
            </div>
        </div>
        <div class="card-body">
            <div id="previewWarnings"></div>
            <div style="overflow-x:auto;">
                <table class="data-table" id="previewTable">
                    <thead><tr><th style="width:30px;"><input type="checkbox" id="checkAll" checked></th><th>Title</th><th>URL</th><th>Username</th><th>Password</th><th>Warnings</th></tr></thead>
                    <tbody id="previewBody"></tbody>
                </table>
            </div>
            <div style="margin-top:16px;display:flex;gap:8px;">
                <button id="btnImport" class="btn btn-primary" disabled>Import Selected</button>
                <button id="btnCancelImport" class="btn btn-ghost">Cancel</button>
            </div>
            <div id="importProgress" style="display:none;margin-top:12px;">
                <div style="background:#27272a;border-radius:6px;height:8px;overflow:hidden;">
                    <div id="importProgressBar" style="background:#6366f1;height:100%;width:0%;transition:width 0.3s;"></div>
                </div>
                <p id="importProgressText" class="text-muted" style="margin-top:4px;font-size:0.8rem;">Importing...</p>
            </div>
        </div>
    </div>

    <!-- Result -->
    <div class="card" id="resultCard" style="display:none;">
        <div class="card-header"><h2 class="card-title">Import Complete</h2></div>
        <div class="card-body">
            <div id="resultContent"></div>
            <div style="margin-top:12px;">
                <a href="<?= APP_URL ?>/vault" class="btn btn-primary">View Vault</a>
                <p class="text-muted" style="margin-top:8px;font-size:0.8rem;">For security, delete the exported password file from your computer now.</p>
            </div>
        </div>
    </div>

    <!-- Import History -->
    <?php if (!empty($history)): ?>
    <div class="card">
        <div class="card-header"><h2 class="card-title">Import History</h2></div>
        <div class="card-body">
            <table class="data-table">
                <thead><tr><th>Source</th><th>Imported</th><th>Skipped</th><th>Failed</th><th>Status</th><th>Date</th></tr></thead>
                <tbody>
                <?php foreach ($history as $h): ?>
                <tr>
                    <td><?= htmlspecialchars($h['source']) ?></td>
                    <td><?= (int)$h['item_count_imported'] ?></td>
                    <td><?= (int)$h['item_count_skipped'] ?></td>
                    <td><?= (int)$h['item_count_failed'] ?></td>
                    <td><span class="badge badge-<?= $h['status'] === 'completed' ? 'active' : 'suspended' ?>"><?= htmlspecialchars($h['status']) ?></span></td>
                    <td><?= date('M j, Y', strtotime($h['created_at'])) ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>

    <p class="text-muted" style="margin-top:16px;font-size:0.72rem;">&#9888; AMPass import feature handles plaintext password exports and requires professional security audit before real credential storage.</p>
</div>

<script nonce="<?= Security::getNonce() ?>">
window.AMPass = {
    baseUrl: '<?= APP_URL ?>',
    csrfToken: '<?= $csrfToken ?>',
    vaultUnlocked: <?= Session::isVaultUnlocked() ? 'true' : 'false' ?>,
    currentRoute: 'import'
};
</script>
<script src="<?= APP_URL ?>/public/js/crypto.js?v=<?= time() ?>"></script>
<script src="<?= APP_URL ?>/public/js/app.js?v=<?= time() ?>"></script>
<script src="<?= APP_URL ?>/public/js/import.js?v=<?= time() ?>"></script>
</body>
</html>
