const CACHE = 'aegis-shell-v092-secure-share';
const CORE = ['/', '/index.html', '/app.js', '/vault-store.mjs', '/secure-share.mjs', '/src/styles.css', '/manifest.webmanifest', '/public/aegis-icon.svg'];
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll(CORE);
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith('aegis-shell-') && key !== CACHE).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET' || new URL(event.request.url).origin !== self.location.origin) return;
  const url = new URL(event.request.url);
  if (url.pathname === '/index.html' || url.pathname === '/app.js' || url.pathname === '/sw.js') {
    event.respondWith(fetch(event.request, {cache:'no-store'}).then(response => {
      if (response.ok && url.pathname !== '/sw.js') caches.open(CACHE).then(cache => cache.put(event.request, response.clone()));
      return response;
    }).catch(() => caches.match(event.request).then(cached => cached || caches.match('/index.html'))));
    return;
  }
  event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request).then(response => {
    if (response.ok) caches.open(CACHE).then(cache => cache.put(event.request, response.clone()));
    return response;
  }).catch(() => caches.match('/index.html'))));
});
