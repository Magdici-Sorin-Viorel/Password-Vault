// VAULT — service worker
// Caches the app shell so it works offline. It never sees vault data
// (that lives encrypted in IndexedDB). Bump CACHE_VERSION on every code change
// so phones download the new version.
const CACHE_VERSION = 'vault-v5.5.0';
// The OCR engine (~10 MB) is cached on first use and kept across app updates.
const OCR_CACHE = 'vault-ocr-5.1.1';
const OCR_PATH = '/vendor/tesseract/';
const ASSETS = [
  './', './index.html', './app.js', './crypto.js', './words.js', './ocr.js', './vendor/argon2.umd.min.js', './vendor/tesseract/tesseract.min.js', './style.css', './manifest.webmanifest',
  './icons/icon-192.png', './icons/icon-512.png', './icons/maskable-512.png', './icons/apple-touch-icon.png',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_VERSION).then(c => c.addAll(ASSETS)));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_VERSION && k !== OCR_CACHE).map(k => caches.delete(k))))
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
      if (new URL(req.url).pathname.includes(OCR_PATH)) {
        return fetch(req).then(res => {
          if (res.ok) { const copy = res.clone(); caches.open(OCR_CACHE).then(c => c.put(req, copy)); }
          return res;
        });
      }
      return fetch(req);
    })
  );
});
