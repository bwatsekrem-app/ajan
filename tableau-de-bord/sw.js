// Service worker du tableau de bord : garde une copie de la page pour l'ouvrir sans Internet.
// Réseau d'abord (toujours la dernière version quand Internet est là), copie locale sinon.
const CACHE = 'tablo-v1';
const PAGE = new URL('./', self.registration.scope).href;

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.add(new Request(PAGE, { cache: 'reload' }))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith('tablo-') && k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return; // Supabase, etc. : jamais touchés
  if (req.mode !== 'navigate') return;
  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 8000);
      const r = await fetch(req, { signal: ctrl.signal }); clearTimeout(t);
      if (r.ok) cache.put(PAGE, r.clone());
      return r;
    } catch {
      return (await cache.match(PAGE)) || (await cache.match(req)) || new Response('Hors ligne — page non disponible.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }
  })());
});
