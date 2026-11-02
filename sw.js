// VAULT — service worker
// Caches the app shell so it works offline. It never sees vault data
// (that lives encrypted in IndexedDB). Bump CACHE_VERSION on every code change
// so phones download the new version.
const CACHE_VERSION = 'vault-v5.2.0';
const ASSETS = [
  './', './index.html', './app.js', './crypto.js', './words.js', './vendor/argon2.umd.min.js', './style.css', './manifest.webmanifest',
  './icons/icon-192.png', './icons/icon-512.png', './icons/maskable-512.png', './icons/apple-touch-icon.png',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_VERSION).then(c => c.addAll(ASSETS)));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_VERSION).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  e.respondWith(
    caches.match(req, { ignoreSearch: true }).then(hit => {
      if (hit) return hit;
      if (req.mode === 'navigate') return caches.match('./index.html').then(r => r || fetch(req));
      return fetch(req);
    })
  );
});
