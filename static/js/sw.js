// Simple service worker to surface notifications and handle clicks
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
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
  // Push payload handling left minimal - server should send title/body/url as JSON
  try {
    const data = event.data ? event.data.json() : { title: 'Notification', body: '', url: '/' };
    const title = data.title || 'Notification';
    const options = { body: data.body || '', data: { url: data.url || '/' }, icon: '/static/img/favicon.ico' };
    event.waitUntil(self.registration.showNotification(title, options));
  } catch (e) {
    console.warn('Push event handling failed', e);
  }
});
