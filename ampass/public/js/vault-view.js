/**
 * AMPass - Vault Item View JavaScript
 * Decrypts and displays a single vault item.
 */

(function() {
    'use strict';

    const itemView = document.getElementById('itemView');
    if (!itemView) return;

    async function init() {
        const restored = await AMPassCrypto.ensureVaultKeyUnlocked();
        if (!restored) {
            window.location.href = window.AMPass.baseUrl + '/vault';
            return;
        }

        const encrypted = itemView.getAttribute('data-encrypted');
        const iv = itemView.getAttribute('data-iv');
        const type = itemView.getAttribute('data-type');

        if (!encrypted || !iv) {
            document.getElementById('itemFields').innerHTML = '<p class="text-danger">No encrypted data found.</p>';
            return;
        }

        try {
            const data = await AMPassCrypto.decryptVaultItem(encrypted, iv);
            renderItem(data, type);
        } catch (e) {
            document.getElementById('itemFields').innerHTML = '<p class="text-danger">Failed to decrypt item. Your vault key may have changed.</p>';
        }
    }

    function renderItem(data, type) {
        // Update title
        document.getElementById('viewTitle').textContent = data.title || 'Untitled';

        const fields = document.getElementById('itemFields');
        let html = '';

        // Render fields based on type
        if (data.url) {
            html += renderField('Website', data.url, 'url');
        }
        if (data.username) {
            html += renderField('Username', data.username, 'copy');
        }
        if (data.password) {
            html += renderField('Password', '••••••••••••', 'password', data.password);
        }
        if (data.card_number) {
            html += renderField('Card Number', maskCard(data.card_number), 'copy', data.card_number);
        }
        if (data.card_expiry) {
            html += renderField('Expiry', data.card_expiry, 'text');
        }
        if (data.card_cvv) {
            html += renderField('CVV', '•••', 'password', data.card_cvv);
        }
        if (data.card_holder) {
            html += renderField('Cardholder', data.card_holder, 'text');
        }
        if (data.first_name || data.last_name) {
            html += renderField('Name', `${data.first_name || ''} ${data.last_name || ''}`.trim(), 'text');
        }
        if (data.phone) {
            html += renderField('Phone', data.phone, 'text');
        }
        if (data.address) {
            html += renderField('Address', data.address, 'text');
        }
        if (data.notes) {
            html += `<div class="item-field">
                <span class="field-label">Notes</span>
                <div class="field-value field-notes">${escapeHtml(data.notes)}</div>
            </div>`;
        }

        fields.innerHTML = html || '<p class="text-muted">No fields stored.</p>';

        // Bind copy buttons
        fields.querySelectorAll('[data-copy-value]').forEach(btn => {
            btn.addEventListener('click', () => {
                const value = btn.getAttribute('data-copy-value');
                const label = btn.getAttribute('data-copy-label') || 'Value';
                AMPassClipboard.copy(value, label);
            });
        });

        // Bind show/hide password buttons
        fields.querySelectorAll('[data-toggle-reveal]').forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.closest('.field-value-row').querySelector('.field-display');
                const realValue = btn.getAttribute('data-toggle-reveal');
                if (target.textContent === '••••••••••••' || target.textContent === '•••') {
                    target.textContent = realValue;
                    btn.textContent = 'Hide';
                } else {
                    target.textContent = target.getAttribute('data-masked');
                    btn.textContent = 'Show';
                }
            });
        });
    }

    function renderField(label, displayValue, type, realValue) {
        let actions = '';

        if (type === 'copy' || type === 'password') {
            const copyVal = realValue || displayValue;
            actions += `<button class="btn btn-sm btn-ghost" data-copy-value="${escapeAttr(copyVal)}" data-copy-label="${label}">Copy</button>`;
        }
        if (type === 'password') {
            actions += `<button class="btn btn-sm btn-ghost" data-toggle-reveal="${escapeAttr(realValue)}">Show</button>`;
        }
        if (type === 'url') {
            let url = displayValue;
            if (!url.startsWith('http')) url = 'https://' + url;
            actions += `<a href="${escapeAttr(url)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-ghost">Open</a>`;
            actions += `<button class="btn btn-sm btn-ghost" data-copy-value="${escapeAttr(displayValue)}" data-copy-label="URL">Copy</button>`;
        }

        return `<div class="item-field">
            <span class="field-label">${escapeHtml(label)}</span>
            <div class="field-value-row">
                <span class="field-display" data-masked="${escapeAttr(displayValue)}">${escapeHtml(displayValue)}</span>
                <div class="field-actions">${actions}</div>
            </div>
        </div>`;
    }

    function maskCard(number) {
        if (number.length > 4) {
            return '•••• •••• •••• ' + number.slice(-4);
        }
        return number;
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Delete button
    const deleteBtn = document.getElementById('deleteItemBtn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            AMPassConfirm.show(
                'Delete Item',
                'Are you sure you want to permanently delete this vault item? This action cannot be undone.',
                async () => {
                    try {
                        await AMPassAPI.post('/api/vault/delete', { id: parseInt(deleteBtn.getAttribute('data-id')) });
                        window.location.href = window.AMPass.baseUrl + '/vault';
                    } catch (e) {
                        AMPassToast.error('Delete failed: ' + e.message);
                    }
                },
                { type: 'danger', confirmText: 'Delete Permanently' }
            );
        });
    }

    init();
})();
