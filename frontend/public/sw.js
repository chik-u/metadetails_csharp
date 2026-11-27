// MetaGuard PWA OS Share Target Service Worker
// Intercepts OS share-sheet POST requests to /share-mediate and buffers files into transient CacheStorage.

const SHARE_CACHE = 'metaguard-share-buffer-v1';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method === 'POST' && url.pathname === '/share-mediate') {
    event.respondWith((async () => {
      try {
        const formData = await event.request.formData();
        const sharedFiles = formData.getAll('files').filter((f) => f && typeof f.arrayBuffer === 'function');
        const cache = await caches.open(SHARE_CACHE);

        // Clear any stale shared entries
        const oldKeys = await cache.keys();
        await Promise.all(oldKeys.map((k) => cache.delete(k)));

        const manifest = [];
        for (let i = 0; i < sharedFiles.length; i++) {
          const file = sharedFiles[i];
          const key = `/_metaguard_shared/${i}/${encodeURIComponent(file.name)}`;
          await cache.put(key, new Response(file, {
            headers: {
              'Content-Type': file.type || 'application/octet-stream',
              'X-Shared-Name': encodeURIComponent(file.name)
            }
          }));
          manifest.push({ key, name: file.name, type: file.type || 'application/octet-stream' });
        }

        await cache.put('/_metaguard_shared/manifest.json', new Response(JSON.stringify(manifest), {
          headers: { 'Content-Type': 'application/json' }
        }));
      } catch (err) {
        console.error('MetaGuard SW share interception failed:', err);
      }

      return Response.redirect('/share-mediate?shared=1', 303);
    })());
  }
});
