/**
 * AMPass - Vault List JavaScript
 * Handles vault item interactions: copy, delete, favorite, launch URL.
 */

(function() {
    'use strict';

    // ===== Vault Item Actions =====
    document.addEventListener('click', async (e) => {
        const item = e.target.closest('.vault-item');
        if (!item) return;

        const action = e.target.closest('[data-action]');
        if (!action) return;

        e.preventDefault();
        e.stopPropagation();

        const itemId = item.getAttribute('data-id');
        const encrypted = item.getAttribute('data-encrypted');
        const iv = item.getAttribute('data-iv');
        const actionType = action.getAttribute('data-action');

        try {
            switch (actionType) {
                case 'copy-username':
                    await copyField(encrypted, iv, 'username', 'Username');
                    break;

                case 'copy-password':
                    await copyField(encrypted, iv, 'password', 'Password');
                    break;

                case 'launch-url':
                    await launchURL(encrypted, iv);
                    break;

                case 'toggle-favorite':
                    await toggleFavorite(itemId);
                    break;

                case 'delete-item':
                    await deleteItem(itemId);
                    break;
            }
        } catch (err) {
            console.error('Action failed:', err);
            if (window.AMPassToast) {
                AMPassToast.error('Action failed: ' + err.message);
            }
        }
    });

    /**
     * Copy a decrypted field to clipboard
     */
    async function copyField(encrypted, iv, field, label) {
        if (!encrypted || !iv) {
            AMPassToast.error('No encrypted data available');
            return;
        }

        const decrypted = await AMPassCrypto.decryptVaultItem(encrypted, iv);
        const value = decrypted[field];

        if (value) {
            await AMPassClipboard.copy(value, label);
        } else {
            AMPassToast.warning(`No ${label.toLowerCase()} stored for this item`);
        }
    }

    /**
     * Launch website URL
     */
    async function launchURL(encrypted, iv) {
        if (!encrypted || !iv) return;

        const decrypted = await AMPassCrypto.decryptVaultItem(encrypted, iv);
        let url = decrypted.url || decrypted.website;

        if (url) {
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            window.open(url, '_blank', 'noopener,noreferrer');
        } else {
            AMPassToast.warning('No URL stored for this item');
        }
    }

    /**
     * Toggle favorite status
     */
    async function toggleFavorite(itemId) {
        try {
            await AMPassAPI.post('/api/vault/favorite', { id: parseInt(itemId) });
            AMPassToast.success('Favorite updated');
            // Reload to reflect change
            setTimeout(() => location.reload(), 500);
        } catch (err) {
            AMPassToast.error('Failed to update favorite');
        }
    }

    /**
     * Delete a vault item
     */
    async function deleteItem(itemId) {
        AMPassConfirm.show(
            'Delete Item',
            'Are you sure you want to permanently delete this vault item? This action cannot be undone.',
            async () => {
                try {
                    await AMPassAPI.post('/api/vault/delete', { id: parseInt(itemId) });
                    AMPassToast.success('Item deleted successfully');
                    
                    const item = document.querySelector(`.vault-item[data-id="${itemId}"]`);
                    if (item) {
                        item.style.opacity = '0';
                        item.style.transform = 'translateX(-20px)';
                        setTimeout(() => item.remove(), 300);
                    }
                } catch (err) {
                    AMPassToast.error('Failed to delete item');
                }
            },
            { type: 'danger', confirmText: 'Delete' }
        );
    }

    // ===== Export/Import =====
    const exportBtn = document.getElementById('exportVaultBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            AMPassConfirm.show(
                'Export Vault Backup',
                'This will download an encrypted backup of your entire vault. The backup file contains your encrypted data and can only be restored with your master password.',
                async () => {
                    try {
                        let response = await fetch(window.AMPass.baseUrl + '/api/vault/export', {
                            headers: { 'X-CSRF-TOKEN': window.AMPass.csrfToken }
                        });
                        if (response.status === 403) {
                            if (typeof AMPassCrypto !== 'undefined') {
                                const unlocked = await AMPassCrypto.ensureVaultKeyUnlocked();
                                if (unlocked) {
                                    response = await fetch(window.AMPass.baseUrl + '/api/vault/export', {
                                        headers: { 'X-CSRF-TOKEN': window.AMPass.csrfToken }
                                    });
                                }
                            }
                        }
                        if (!response.ok) {
                            throw new Error('Export failed');
                        }
                        const blob = await response.blob();
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `ampass_backup_${new Date().toISOString().split('T')[0]}.json`;
                        a.click();
                        URL.revokeObjectURL(url);
                        AMPassToast.success('Backup exported successfully');
                    } catch (err) {
                        AMPassToast.error('Export failed');
                    }
                },
                { type: 'primary', confirmText: 'Export Backup' }
            );
        });
    }

    const importBtn = document.getElementById('importVaultBtn');
    const importInput = document.getElementById('importFileInput');
    if (importBtn && importInput) {
        importBtn.addEventListener('click', () => importInput.click());
        importInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                const text = await file.text();
                const data = JSON.parse(text);

                if (!data.items || !Array.isArray(data.items)) {
                    AMPassToast.error('Invalid backup file format');
                    return;
                }

                AMPassConfirm.show(
                    'Import Vault Backup',
                    `This will import <strong>${data.items.length} items</strong> into your vault. Existing items will not be affected.`,
                    async () => {
                        try {
                            const result = await AMPassAPI.post('/api/vault/import', data);
                            AMPassToast.success(`Imported ${result.imported} items successfully`);
                            setTimeout(() => location.reload(), 1000);
                        } catch (err) {
                            AMPassToast.error('Import failed: ' + err.message);
                        }
                    },
                    { type: 'primary', confirmText: 'Import' }
                );
            } catch (err) {
                AMPassToast.error('Invalid file: ' + err.message);
            }
            importInput.value = ''; // Reset file input
        });
    }

})();
