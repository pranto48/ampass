/**
 * AMPass - Main Application JavaScript
 * Handles UI interactions, theme toggle, sidebar, search, and common utilities.
 */

(function() {
    'use strict';

    // Clean window.AMPass.baseUrl to be relative to avoid cross-origin cookie issues
    if (typeof window !== 'undefined' && window.AMPass && window.AMPass.baseUrl) {
        let base = window.AMPass.baseUrl;
        if (base.startsWith('http://') || base.startsWith('https://')) {
            try {
                const urlObj = new URL(base);
                base = urlObj.pathname;
            } catch (e) {}
        }
        if (base === '/') base = '';
        if (base.endsWith('/')) base = base.slice(0, -1);
        window.AMPass.baseUrl = base;
    }

    // ===== Theme Management =====
    const ThemeManager = {
        init() {
            const saved = localStorage.getItem('ampass_theme') || 'light';
            document.documentElement.setAttribute('data-theme', saved);
            this.bindToggle();
        },

        bindToggle() {
            const toggle = document.getElementById('themeToggle');
            if (toggle) {
                toggle.addEventListener('click', () => {
                    const current = document.documentElement.getAttribute('data-theme') || 'light';
                    const next = current === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', next);
                    localStorage.setItem('ampass_theme', next);
                });
            }
        }
    };

    // ===== Sidebar Management =====
    const Sidebar = {
        init() {
            const toggle = document.getElementById('menuToggle');
            const close = document.getElementById('sidebarClose');
            const sidebar = document.getElementById('sidebar');

            if (toggle && sidebar) {
                toggle.addEventListener('click', () => sidebar.classList.add('open'));
            }
            if (close && sidebar) {
                close.addEventListener('click', () => sidebar.classList.remove('open'));
            }

            // Close on outside click (mobile)
            document.addEventListener('click', (e) => {
                if (sidebar && sidebar.classList.contains('open') && 
                    !sidebar.contains(e.target) && e.target !== toggle) {
                    sidebar.classList.remove('open');
                }
            });
        }
    };

    // ===== Password Toggle =====
    const PasswordToggle = {
        init() {
            document.querySelectorAll('.input-toggle-password').forEach(btn => {
                btn.addEventListener('click', () => {
                    const input = btn.parentElement.querySelector('input[type="password"], input[type="text"]');
                    if (input) {
                        const isPassword = input.type === 'password';
                        input.type = isPassword ? 'text' : 'password';
                        btn.classList.toggle('showing', !isPassword);
                    }
                });
            });
        }
    };

    // ===== Toast Notifications =====
    const Toast = {
        show(message, type = 'info', duration = 3000) {
            let container = document.getElementById('toastContainer');
            if (!container) {
                container = document.createElement('div');
                container.id = 'toastContainer';
                container.className = 'toast-container';
                document.body.appendChild(container);
            }

            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = `
                <span class="toast-message">${message}</span>
                <button class="toast-close" aria-label="Close">×</button>
            `;
            toast.querySelector('.toast-close').addEventListener('click', () => {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 300);
            });
            container.appendChild(toast);

            requestAnimationFrame(() => {
                requestAnimationFrame(() => toast.classList.add('show'));
            });

            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 350);
            }, duration);
        },

        success(msg) { this.show(msg, 'success', 3000); },
        error(msg) { this.show(msg, 'error', 5000); },
        warning(msg) { this.show(msg, 'warning', 4000); },
        info(msg) { this.show(msg, 'info', 3000); }
    };

    // ===== Confirmation Dialog =====
    const Confirm = {
        show(title, message, onConfirm, options = {}) {
            const type = options.type || 'danger';
            const confirmText = options.confirmText || 'Confirm';
            const cancelText = options.cancelText || 'Cancel';

            // Remove existing modal
            const existing = document.querySelector('.modal-overlay');
            if (existing) existing.remove();

            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay';
            overlay.innerHTML = `
                <div class="modal">
                    <div class="modal-title">${title}</div>
                    <div class="modal-body">${message}</div>
                    <div class="modal-actions">
                        <button class="btn btn-secondary modal-cancel">${cancelText}</button>
                        <button class="btn btn-${type} modal-confirm">${confirmText}</button>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);
            requestAnimationFrame(() => overlay.classList.add('show'));

            // Focus the cancel button for safety
            overlay.querySelector('.modal-cancel').focus();

            overlay.querySelector('.modal-cancel').addEventListener('click', () => {
                overlay.classList.remove('show');
                setTimeout(() => overlay.remove(), 300);
            });

            overlay.querySelector('.modal-confirm').addEventListener('click', () => {
                overlay.classList.remove('show');
                setTimeout(() => overlay.remove(), 300);
                if (onConfirm) onConfirm();
            });

            // Close on overlay click
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    overlay.classList.remove('show');
                    setTimeout(() => overlay.remove(), 300);
                }
            });

            // Close on Escape
            const escHandler = (e) => {
                if (e.key === 'Escape') {
                    overlay.classList.remove('show');
                    setTimeout(() => overlay.remove(), 300);
                    document.removeEventListener('keydown', escHandler);
                }
            };
            document.addEventListener('keydown', escHandler);
        }
    };

    // ===== Clipboard =====
    const Clipboard = {
        async copy(text, label = 'Text') {
            try {
                await navigator.clipboard.writeText(text);
                Toast.success(`${label} copied to clipboard`);

                // Auto-clear after 30 seconds for passwords
                if (label.toLowerCase().includes('password')) {
                    setTimeout(async () => {
                        try {
                            const current = await navigator.clipboard.readText();
                            if (current === text) {
                                await navigator.clipboard.writeText('');
                            }
                        } catch (e) {
                            // Can't read clipboard, that's fine
                        }
                    }, 30000);
                }
            } catch (err) {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                Toast.success(`${label} copied`);
            }
        }
    };

    // ===== Vault Lock Timer =====
    const LockTimer = {
        timer: null,
        timeout: (window.AMPass && window.AMPass.lockTimeout) || 300,

        init() {
            if (!window.AMPass || !window.AMPass.vaultUnlocked) return;

            this.reset();
            ['click', 'keypress', 'mousemove', 'scroll', 'touchstart'].forEach(event => {
                document.addEventListener(event, () => this.reset(), { passive: true });
            });
        },

        reset() {
            if (this.timer) clearTimeout(this.timer);
            this.timer = setTimeout(() => this.lock(), this.timeout * 1000);
        },

        async lock() {
            if (typeof AMPassCrypto !== 'undefined') {
                AMPassCrypto.lockVault();
            }
            // Notify server
            try {
                const baseUrl = (window.AMPass && window.AMPass.baseUrl) || '';
                const csrfToken = (window.AMPass && window.AMPass.csrfToken) || '';
                await fetch(baseUrl + '/api/auth/lock', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': csrfToken
                    }
                });
            } catch (e) {}
            window.location.href = ((window.AMPass && window.AMPass.baseUrl) || '') + '/unlock';
        }
    };

    // ===== Dropdown Menus =====
    const Dropdowns = {
        init() {
            document.addEventListener('click', (e) => {
                const toggle = e.target.closest('.dropdown-toggle');
                if (toggle) {
                    e.stopPropagation();
                    const dropdown = toggle.closest('.dropdown');
                    const menu = dropdown.querySelector('.dropdown-menu');
                    
                    // Close all other dropdowns
                    document.querySelectorAll('.dropdown-menu.show').forEach(m => {
                        if (m !== menu) m.classList.remove('show');
                    });
                    
                    menu.classList.toggle('show');
                } else {
                    // Close all dropdowns on outside click
                    document.querySelectorAll('.dropdown-menu.show').forEach(m => m.classList.remove('show'));
                }
            });
        }
    };

    // ===== Search =====
    const Search = {
        init() {
            const input = document.getElementById('globalSearch');
            if (!input) return;

            let debounceTimer;
            input.addEventListener('input', () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => this.performSearch(input.value), 300);
            });
        },

        performSearch(query) {
            if (!query.trim()) {
                // Show all items
                document.querySelectorAll('.vault-item').forEach(item => {
                    item.style.display = '';
                });
                return;
            }

            const lowerQuery = query.toLowerCase();
            document.querySelectorAll('.vault-item').forEach(item => {
                const title = item.querySelector('.vault-item-title')?.textContent?.toLowerCase() || '';
                const subtitle = item.querySelector('.vault-item-subtitle')?.textContent?.toLowerCase() || '';
                const matches = title.includes(lowerQuery) || subtitle.includes(lowerQuery);
                item.style.display = matches ? '' : 'none';
            });
        }
    };

    // ===== Quick Add Button =====
    const QuickAdd = {
        init() {
            const btn = document.getElementById('quickAddBtn');
            if (btn && window.AMPass) {
                btn.addEventListener('click', () => {
                    window.location.href = window.AMPass.baseUrl + '/vault/add';
                });
            }
        }
    };

    // ===== API Helper =====
    window.AMPassAPI = {
        async request(endpoint, options = {}) {
            const baseUrl = (window.AMPass && window.AMPass.baseUrl) || '';
            const url = baseUrl + endpoint;
            
            // Ensure we use the latest token on every attempt
            const getHeaders = () => {
                const currentCsrfToken = (window.AMPass && window.AMPass.csrfToken) || '';
                return {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': currentCsrfToken,
                    ...(options.headers || {})
                };
            };

            const config = { ...options };

            let attempt = 0;
            const maxAttempts = 3;

            while (attempt < maxAttempts) {
                const currentCsrfToken = (window.AMPass && window.AMPass.csrfToken) || '';
                config.headers = getHeaders();

                // Inject the latest CSRF token into the JSON body on every retry attempt
                if (options.body && typeof options.body === 'object' && !(options.body instanceof Blob) && !(options.body instanceof FormData)) {
                    const bodyClone = { ...options.body, csrf_token: currentCsrfToken };
                    config.body = JSON.stringify(bodyClone);
                }

                attempt++;

                let response;
                try {
                    response = await fetch(url, config);
                } catch (fetchErr) {
                    if (attempt >= maxAttempts) {
                        throw fetchErr;
                    }
                    continue;
                }

                if (response.ok) {
                    if (options.rawResponse) {
                        return response;
                    }
                    try {
                        return await response.json();
                    } catch (e) {
                        return null;
                    }
                }

                // If we get here, response is not OK (e.g. status 403, 500, etc.)
                let data = null;
                try {
                    const clone = response.clone();
                    data = await clone.json();
                } catch (e) {}

                if (response.status === 403 && data && attempt < maxAttempts) {
                    // Case 1: Vault is locked
                    if (data.error === 'Vault is locked') {
                        if (typeof AMPassCrypto !== 'undefined') {
                            const unlocked = await AMPassCrypto.ensureVaultKeyUnlocked();
                            if (unlocked) {
                                continue;
                            }
                        }
                    }

                    // Case 2: Invalid CSRF token
                    if (data.code === 'CSRF_INVALID' || (data.error && data.error.includes('Invalid security token'))) {
                        try {
                            const csrfResp = await fetch(baseUrl + '/api/auth/csrfToken?t=' + Date.now());
                            const csrfData = await csrfResp.json();
                            if (csrfResp.ok && csrfData.success && csrfData.csrf_token) {
                                if (window.AMPass) {
                                    window.AMPass.csrfToken = csrfData.csrf_token;
                                }
                                continue;
                            }
                        } catch (csrfErr) {
                            console.warn('Failed to refresh CSRF token:', csrfErr);
                        }
                    }
                }

                throw new Error((data && data.error) || 'Request failed');
            }
        },

        get(endpoint) {
            return this.request(endpoint, { method: 'GET' });
        },

        post(endpoint, body) {
            return this.request(endpoint, { method: 'POST', body });
        }
    };

    // ===== Initialize =====
    document.addEventListener('DOMContentLoaded', () => {
        ThemeManager.init();
        Sidebar.init();
        PasswordToggle.init();
        Dropdowns.init();
        Search.init();
        QuickAdd.init();
        LockTimer.init();

        // Restore vault key from session if available
        if (typeof AMPassCrypto !== 'undefined' && window.AMPass) {
            if (window.AMPass.vaultUnlocked) {
                AMPassCrypto.restoreVaultKey().then(restored => {
                    if (restored) {
                        // Decrypt visible vault items
                        decryptVisibleItems();
                    } else {
                        handleLockedVault();
                    }
                });
            } else {
                handleLockedVault();
            }
        }
    });

    function handleLockedVault() {
        const requireUnlockRoutes = ['vault', 'dashboard', 'import', 'vault/add', 'vault/edit', 'vault/view', 'vault/form'];
        const currentRoute = (window.AMPass && window.AMPass.currentRoute) || '';
        const requiresUnlock = requireUnlockRoutes.some(r => currentRoute === r || currentRoute.startsWith(r + '/'));

        if (!requiresUnlock) return;

        let container = document.querySelector('.page-content') || document.querySelector('.form-page');
        if (!container) return;

        triggerUnlockFlow(container);
    }

    async function triggerUnlockFlow(container) {
        const unlocked = await AMPassCrypto.ensureVaultKeyUnlocked();
        if (unlocked) {
            const banner = document.getElementById('vaultLockedBanner');
            if (banner) banner.remove();
            
            if (typeof decryptVisibleItems === 'function') {
                decryptVisibleItems();
            }

            if (window.AMPass && window.AMPass.currentRoute === 'import') {
                window.location.reload();
            }
        } else {
            if (!document.getElementById('vaultLockedBanner')) {
                const banner = document.createElement('div');
                banner.id = 'vaultLockedBanner';
                banner.className = 'alert alert-warning';
                banner.style.display = 'flex';
                banner.style.justifyContent = 'space-between';
                banner.style.alignItems = 'center';
                banner.style.gap = '12px';
                banner.style.marginBottom = '18px';
                banner.innerHTML = `
                    <span>&#9888; <strong>Vault is locked.</strong> Unlock to decrypt and use your vault items.</span>
                    <button class="btn btn-sm btn-primary" id="btnBannerUnlock" style="padding: 6px 12px; font-size: 0.78rem;">Unlock Vault</button>
                `;
                container.insertBefore(banner, container.firstChild);

                document.getElementById('btnBannerUnlock').addEventListener('click', () => {
                    triggerUnlockFlow(container);
                });
            }
        }
    }

    /**
     * Decrypt all visible vault items on the page (lazy decryption using IntersectionObserver)
     */
    async function decryptVisibleItems() {
        const items = document.querySelectorAll('.vault-item[data-encrypted]');
        if (items.length === 0) return;

        if (typeof IntersectionObserver === 'undefined') {
            // Fallback for old/unsupported browsers: decrypt in parallel
            const promises = Array.from(items).map(async (item) => {
                await decryptSingleItem(item);
            });
            await Promise.all(promises);
            return;
        }

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(async (entry) => {
                if (entry.isIntersecting) {
                    const item = entry.target;
                    observer.unobserve(item); // Only decrypt once
                    await decryptSingleItem(item);
                }
            });
        }, {
            rootMargin: '150px 0px', // Decrypt slightly before scrolling into viewport
            threshold: 0.01
        });

        items.forEach(item => observer.observe(item));
    }

    /**
     * Decrypt a single vault item and update its DOM elements
     */
    async function decryptSingleItem(item) {
        try {
            const encrypted = item.getAttribute('data-encrypted');
            const iv = item.getAttribute('data-iv');
            if (!encrypted || !iv) return;

            const decrypted = await AMPassCrypto.decryptVaultItem(encrypted, iv);

            // Update title
            const titleEl = item.querySelector('[data-decrypt="title"]');
            if (titleEl) titleEl.textContent = decrypted.title || 'Untitled';

            // Update username/subtitle
            const usernameEl = item.querySelector('[data-decrypt="username"]');
            if (usernameEl) usernameEl.textContent = decrypted.username || '(no username)';

            // Update website favicon
            const url = decrypted.url || decrypted.website || decrypted.link;
            if (url) {
                const domain = extractDomain(url);
                if (domain) {
                    const iconEl = item.querySelector('.vault-item-icon');
                    if (iconEl) {
                        iconEl.innerHTML = `<img src="https://www.google.com/s2/favicons?sz=64&domain=${domain}" alt="" style="width:20px; height:20px; border-radius:4px; object-fit:contain; display:block;">`;
                        iconEl.style.background = 'transparent';
                    }
                }
            }

        } catch (e) {
            console.warn('Failed to decrypt item:', e.message);
        }
    }

    /**
     * Helper to extract domain name from a URL
     */
    function extractDomain(url) {
        if (!url) return '';
        let host = url;
        try {
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            host = new URL(url).hostname;
        } catch (e) {
            // Keep as is
        }
        if (host.startsWith('www.')) {
            host = host.substring(4);
        }
        return host.toLowerCase().trim();
    }


    // Expose utilities globally
    window.AMPassToast = Toast;
    window.AMPassClipboard = Clipboard;
    window.AMPassConfirm = Confirm;
    window.decryptVisibleItems = decryptVisibleItems;

})();
