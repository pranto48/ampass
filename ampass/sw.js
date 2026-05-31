/**
 * AMPass - Service Worker
 * SECURITY: Never caches decrypted vault data.
 * Only caches static assets (CSS, JS, fonts, icons).
 */

const CACHE_NAME = 'ampass-v1';
const STATIC_ASSETS = [
    '/public/css/app.css',
    '/public/js/app.js',
    '/public/js/crypto.js',
    '/public/assets/favicon.svg',
    '/manifest.webmanifest'
];

// Install - cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(STATIC_ASSETS);
        })
    );
    self.skipWaiting();
});

// Activate - clean old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
            );
        })
    );
    self.clients.claim();
});

// Fetch - network first, fallback to cache for static assets
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // SECURITY: Never cache API responses or HTML pages (may contain sensitive data references)
    if (url.pathname.startsWith('/api/') || 
        event.request.method !== 'GET' ||
        url.pathname.endsWith('.php')) {
        return; // Let the browser handle it normally
    }

    // For static assets, try network first, then cache
    if (url.pathname.startsWith('/public/') || 
        url.pathname === '/manifest.webmanifest' ||
        url.pathname === '/sw.js') {
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
                    return response;
                })
                .catch(() => caches.match(event.request))
        );
        return;
    }

    // For navigation requests when offline, show offline page
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request).catch(() => {
                return new Response(getOfflinePage(), {
                    headers: { 'Content-Type': 'text/html' }
                });
            })
        );
    }
});

function getOfflinePage() {
    return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMPass - Offline</title>
    <style>
        body { font-family: 'Inter', sans-serif; background: #f8fafc; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; text-align: center; padding: 20px; }
        .offline-container { max-width: 400px; }
        .offline-icon { font-size: 4rem; margin-bottom: 16px; }
        h1 { font-size: 1.5rem; margin-bottom: 8px; }
        p { color: #475569; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 12px 24px; background: #6366f1; color: white; border-radius: 8px; text-decoration: none; font-weight: 500; }
    </style>
</head>
<body>
    <div class="offline-container">
        <div class="offline-icon">🔒</div>
        <h1>Vault Locked - Offline</h1>
        <p>You are currently offline. AMPass requires a network connection to securely access your vault.</p>
        <p>Your encrypted data is safe. Connect to the internet and try again.</p>
        <a href="/" class="btn" onclick="window.location.reload()">Retry Connection</a>
    </div>
</body>
</html>`;
}
