// Hardened service worker: versioned cache, safe caching, web push handling without PHI in payloads
const CACHE_VERSION = 'v1.0.0';
const RUNTIME_CACHE = `runtime-${CACHE_VERSION}`;
const PRECACHE_URLS = [
  // Precache only static assets safe to cache; never cache API/HTML with PHI
  '/static/css/style.css',
  '/static/js/main.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(RUNTIME_CACHE).then(cache => cache.addAll(PRECACHE_URLS)).catch(()=>{})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== RUNTIME_CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // Never cache API calls or anything under /api, /uploads, or pages that may contain PHI
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/uploads')) {
    return; // network-only
  }
  // Only cache GET requests for static assets
  if (event.request.method === 'GET' && url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then(cached => cached || fetch(event.request).then(resp => {
        const copy = resp.clone();
        caches.open(RUNTIME_CACHE).then(cache => cache.put(event.request, copy));
        return resp;
      }).catch(() => cached))
    );
  }
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (let client of windowClients) {
        if (client.url === url && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});

self.addEventListener('push', function(event) {
  try {
    const data = event.data ? event.data.json() : { title: 'Notification', body: '', url: '/' };
    // Do not include PHI in push payloads. The server should send generic info.
    const title = data.title || 'Notification';
    const options = {
      body: data.body || '',
      data: { url: data.url || '/' },
      icon: '/favicon.ico',
      tag: data.tag || undefined,
      renotify: false
    };
    event.waitUntil(self.registration.showNotification(title, options));
  } catch (e) {
    console.warn('Push event handling failed', e);
  }
});
