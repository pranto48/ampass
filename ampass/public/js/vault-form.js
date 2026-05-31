/**
 * AMPass - Vault Item Form JavaScript
 * SECURITY: Encrypts all item data client-side before sending to server.
 */

(function() {
    'use strict';

    const form = document.getElementById('vaultItemForm');
    if (!form) return;

    const itemId = form.getAttribute('data-item-id');
    const isEdit = !!itemId;

    // ===== Initialize =====
    async function init() {
        // Restore vault key
        const restored = await AMPassCrypto.ensureVaultKeyUnlocked();
        if (!restored) {
            window.location.href = window.AMPass.baseUrl + '/vault';
            return;
        }

        // If editing, decrypt existing data
        if (isEdit) {
            const encrypted = form.getAttribute('data-encrypted-data');
            const iv = form.getAttribute('data-iv');
            if (encrypted && iv) {
                try {
                    const data = await AMPassCrypto.decryptVaultItem(encrypted, iv);
                    populateForm(data);
                } catch (e) {
                    console.error('Failed to decrypt item:', e);
                    alert('Failed to decrypt item. Your vault key may have changed.');
                }
            }
        }

        // Show/hide fields based on type
        updateFieldVisibility();
        document.getElementById('itemType').addEventListener('change', updateFieldVisibility);

        // Password generator button
        const genBtn = document.getElementById('generatePasswordBtn');
        if (genBtn) {
            genBtn.addEventListener('click', () => {
                const password = AMPassCrypto.generatePassword({ length: 20 });
                document.getElementById('field_password').value = password;
                document.getElementById('field_password').type = 'text';
                updatePasswordStrength(password);
            });
        }

        // Password strength on input
        const pwField = document.getElementById('field_password');
        if (pwField) {
            pwField.addEventListener('input', () => updatePasswordStrength(pwField.value));
        }
    }

    /**
     * Populate form fields from decrypted data
     */
    function populateForm(data) {
        const fieldMap = {
            'field_title': 'title',
            'field_url': 'url',
            'field_username': 'username',
            'field_password': 'password',
            'field_notes': 'notes',
            'field_card_number': 'card_number',
            'field_card_expiry': 'card_expiry',
            'field_card_cvv': 'card_cvv',
            'field_card_holder': 'card_holder',
            'field_first_name': 'first_name',
            'field_last_name': 'last_name',
            'field_phone': 'phone',
            'field_address': 'address'
        };

        for (const [fieldId, dataKey] of Object.entries(fieldMap)) {
            const el = document.getElementById(fieldId);
            if (el && data[dataKey]) {
                el.value = data[dataKey];
            }
        }
    }

    /**
     * Collect form data into an object
     */
    function collectFormData() {
        const type = document.getElementById('itemType').value;
        const data = {
            title: document.getElementById('field_title')?.value || '',
            notes: document.getElementById('field_notes')?.value || ''
        };

        switch (type) {
            case 'login':
            case 'server_ssh':
            case 'wifi':
                data.url = document.getElementById('field_url')?.value || '';
                data.username = document.getElementById('field_username')?.value || '';
                data.password = document.getElementById('field_password')?.value || '';
                break;
            case 'app_account':
                data.application_name = document.getElementById('field_application_name')?.value || '';
                data.executable_path = document.getElementById('field_executable_path')?.value || '';
                data.username = document.getElementById('field_username')?.value || '';
                data.password = document.getElementById('field_password')?.value || '';
                data.website = document.getElementById('field_app_website')?.value || '';
                break;
            case 'remote_desktop':
                data.protocol = document.getElementById('field_protocol')?.value || 'rdp';
                data.host = document.getElementById('field_host')?.value || '';
                data.port = parseInt(document.getElementById('field_port')?.value || '3389');
                data.domain = document.getElementById('field_rdp_domain')?.value || '';
                data.username = document.getElementById('field_username')?.value || '';
                data.password = document.getElementById('field_password')?.value || '';
                data.gateway = document.getElementById('field_gateway')?.value || '';
                break;
            case 'payment_card':
                data.card_number = document.getElementById('field_card_number')?.value || '';
                data.card_expiry = document.getElementById('field_card_expiry')?.value || '';
                data.card_cvv = document.getElementById('field_card_cvv')?.value || '';
                data.card_holder = document.getElementById('field_card_holder')?.value || '';
                break;
            case 'identity':
                data.username = document.getElementById('field_username')?.value || '';
                data.first_name = document.getElementById('field_first_name')?.value || '';
                data.last_name = document.getElementById('field_last_name')?.value || '';
                data.phone = document.getElementById('field_phone')?.value || '';
                data.address = document.getElementById('field_address')?.value || '';
                break;
            case 'secure_note':
                // Notes only - already captured
                break;
            default:
                data.url = document.getElementById('field_url')?.value || '';
                data.username = document.getElementById('field_username')?.value || '';
                data.password = document.getElementById('field_password')?.value || '';
        }

        return data;
    }

    /**
     * Show/hide fields based on item type
     */
    function updateFieldVisibility() {
        const type = document.getElementById('itemType').value;
        document.querySelectorAll('[data-show-for]').forEach(el => {
            const types = el.getAttribute('data-show-for').split(',');
            el.style.display = types.includes(type) ? '' : 'none';
        });
    }

    /**
     * Update password strength indicator
     */
    function updatePasswordStrength(password) {
        const bar = document.querySelector('#itemStrengthBar .strength-fill');
        if (!bar) return;

        const score = AMPassCrypto.calculateStrength(password);
        const info = AMPassCrypto.getStrengthLabel(score);
        bar.style.width = score + '%';
        bar.className = 'strength-fill ' + info.class;
    }

    // ===== Form Submission =====
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const saveBtn = document.getElementById('saveItemBtn');
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<span>Encrypting & Saving...</span>';

        try {
            const formData = collectFormData();
            const type = document.getElementById('itemType').value;

            if (!formData.title) {
                alert('Title is required.');
                saveBtn.disabled = false;
                saveBtn.innerHTML = '<span>Save Item</span>';
                return;
            }

            // Encrypt the item data client-side
            const encrypted = await AMPassCrypto.encryptVaultItem(formData);

            // Calculate password strength
            let passwordStrength = null;
            let isWeak = 0;
            if (formData.password) {
                passwordStrength = AMPassCrypto.calculateStrength(formData.password);
                isWeak = passwordStrength < 40 ? 1 : 0;
            }

            // Compute searchable hashes using vault-key-derived search key
            // SECURITY: Search key is derived from vault key locally — no server secret exposed
            const searchKey = await AMPassCrypto.deriveSearchKey();
            const titleHash = await AMPassCrypto.computeSearchHash(formData.title, searchKey);
            const urlHash = formData.url ? await AMPassCrypto.computeSearchHash(formData.url, searchKey) : null;
            const hostHash = formData.host ? await AMPassCrypto.computeSearchHash(formData.host, searchKey) : null;

            // Send to server
            const payload = {
                id: itemId ? parseInt(itemId) : undefined,
                item_type: type,
                encrypted_data: encrypted.ciphertext,
                encryption_iv: encrypted.iv,
                title_hash: titleHash,
                url_hash: urlHash,
                host_hash: hostHash,
                folder_id: document.getElementById('field_folder')?.value || null,
                is_favorite: document.getElementById('field_favorite')?.checked ? 1 : 0,
                password_strength: passwordStrength,
                is_weak: isWeak,
                is_reused: 0
            };

            const result = await AMPassAPI.post('/api/vault/save', payload);

            if (result.success) {
                window.location.href = window.AMPass.baseUrl + '/vault';
            }

        } catch (error) {
            console.error('Save failed:', error);
            alert('Failed to save item: ' + error.message);
            saveBtn.disabled = false;
            saveBtn.innerHTML = '<span>Save Item</span>';
        }
    });

    // Initialize
    init();

})();
