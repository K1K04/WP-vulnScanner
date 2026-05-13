

const APP_VERSION   = 'wpvs-v541';
const STATIC_CACHE  = `${APP_VERSION}-static`;
const RESULT_CACHE  = `${APP_VERSION}-results`;  // Cache de últimos resultados por URL
const OFFLINE_CACHE = `${APP_VERSION}-offline`;
const PRECACHE_ASSETS = [
  '/static/icons.svg',
  '/static/manifest.json',
  '/static/pwa/icon-192.png',
  '/static/pwa/icon-512.png',
];
const HTML_ROUTES = ['/', '/dashboard', '/compare', '/vulns-db', '/schedules', '/settings'];
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE_ASSETS).catch((e) => {
        console.warn('[SW] Pre-cache partial failure:', e);
      }))
      .then(() => self.skipWaiting())
  );
});
self.addEventListener('activate', (event) => {
  const VALID = [STATIC_CACHE, RESULT_CACHE, OFFLINE_CACHE];
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => !VALID.includes(k)).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (url.pathname.includes('/stream')) return;
  if (req.method !== 'GET') return;
  if (
    url.pathname.startsWith('/static/') ||
    url.hostname === 'fonts.googleapis.com' ||
    url.hostname === 'fonts.gstatic.com' ||
    url.hostname === 'cdnjs.cloudflare.com'
  ) {
    event.respondWith(cacheFirst(req, STATIC_CACHE));
    return;
  }
  if (url.pathname === '/api/pwa/last-result') {
    event.respondWith(networkFirstWithCache(req, RESULT_CACHE));
    return;
  }
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/scan/')) {
    event.respondWith(
      fetch(req).catch(() => new Response(
        JSON.stringify({ error: 'Sin conexión — reintenta cuando estés en línea.', offline: true }),
        { status: 503, headers: { 'Content-Type': 'application/json' } }
      ))
    );
    return;
  }
  if (
    req.headers.get('accept')?.includes('text/html') ||
    HTML_ROUTES.includes(url.pathname)
  ) {
    event.respondWith(networkFirstHtml(req));
    return;
  }
  event.respondWith(networkFirstWithCache(req, STATIC_CACHE));
});


async function cacheFirst(req, cacheName) {
  const cache  = await caches.open(cacheName);
  const cached = await cache.match(req);
  if (cached) return cached;
  try {
    const fresh = await fetch(req);
    if (fresh.ok) cache.put(req, fresh.clone());
    return fresh;
  } catch(e) {
    return new Response('Offline', { status: 503 });
  }
}


async function networkFirstWithCache(req, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const fresh = await fetch(req);
    if (fresh.ok) cache.put(req, fresh.clone());
    return fresh;
  } catch(e) {
    const cached = await cache.match(req);
    return cached || new Response(
      JSON.stringify({ error: 'Sin conexión', offline: true }),
      { status: 503, headers: { 'Content-Type': 'application/json' } }
    );
  }
}


async function networkFirstHtml(req) {
  const cache = await caches.open(OFFLINE_CACHE);
  try {
    const fresh = await fetch(req);
    if (fresh.ok) cache.put(req, fresh.clone());
    return fresh;
  } catch(e) {
    const cached = await cache.match(req);
    if (cached) return cached;
    return new Response(offlineShell(), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }
}

function offlineShell() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sin conexión — WP VulnScanner</title>
  <style>
    body{background:#08090E;color:#DCE1F0;font-family:'JetBrains Mono',monospace;
         display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
    .box{text-align:center;max-width:400px;padding:40px 24px;}
    .icon{font-size:48px;margin-bottom:16px;opacity:.6;}
    h1{font-family:'Barlow Condensed',sans-serif;font-size:24px;font-weight:800;
       color:#2B7FFF;margin-bottom:8px;}
    p{font-size:12px;color:#8890B0;line-height:1.6;}
    a{color:#2B7FFF;text-decoration:none;border:1px solid rgba(43,127,255,.4);
      padding:8px 20px;border-radius:4px;display:inline-block;margin-top:20px;
      font-family:'Barlow Condensed',sans-serif;font-size:12px;font-weight:700;
      letter-spacing:.5px;text-transform:uppercase;}
  </style></head>
  <body><div class="box">
    <div class="icon">📡</div>
    <h1>Sin conexión</h1>
    <p>No hay conexión a internet. Cuando vuelvas a conectarte, la app se actualizará automáticamente.</p>
    <a href="/" onclick="location.reload()">Reintentar conexión</a>
  </div></body></html>`;
}
self.addEventListener('push', (event) => {
  if (!event.data) return;

  let data;
  try { data = event.data.json(); }
  catch(e) { data = { title: 'WP VulnScanner', body: event.data.text() }; }

  const title   = data.title || 'WP VulnScanner';
  const options = {
    body:    data.body    || 'Escaneo completado',
    icon:    '/static/pwa/icon-192.png',
    badge:   '/static/pwa/icon-192.png',
    tag:     data.tag     || 'scan-complete',
    data:    { url: data.url || '/dashboard' },
    actions: [
      { action: 'view',    title: 'Ver resultado' },
      { action: 'dismiss', title: 'Cerrar' },
    ],
    requireInteraction: false,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  if (event.action === 'dismiss') return;

  const targetUrl = event.notification.data?.url || '/dashboard';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((windowClients) => {
        const existing = windowClients.find((c) => c.url.includes(targetUrl));
        if (existing) return existing.focus();
        return clients.openWindow(targetUrl);
      })
  );
});
self.addEventListener('sync', (event) => {
  if (event.tag === 'push-subscribe') {
    event.waitUntil(
      self.clients.matchAll().then((clients) => {
        clients.forEach((c) => c.postMessage({ type: 'SW_SYNC', tag: 'push-subscribe' }));
      })
    );
  }
});
self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data?.type === 'CACHE_RESULT' && event.data.url && event.data.data) {
    caches.open(RESULT_CACHE).then((cache) => {
      const resp = new Response(JSON.stringify(event.data.data), {
        headers: { 'Content-Type': 'application/json' },
      });
      cache.put(
        `/api/pwa/last-result?url=${encodeURIComponent(event.data.url)}`,
        resp
      );
    });
  }
});
