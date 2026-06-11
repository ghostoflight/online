const CACHE = 'online-v1';
const ASSETS = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => {
      // استخدام حلقة تكرار لمحاولة تخزين كل ملف بشكل منفصل
      return Promise.all(
        ASSETS.map(url => {
          return cache.add(url).catch(err => {
            console.error(`فشل تخزين: ${url}`, err);
          });
        })
      );
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', e => {
  // 1. استثناء طلبات السيرفر من الكاش تماماً لكي لا يظهر خطأ 404
  if (e.request.url.includes('/api/')) {
    return; // هذا السطر يخبر المتصفح أن يترك الطلب ليمر عبر الإنترنت مباشرة
  }

  // 2. باقي الملفات (HTML, CSS) نبحث عنها في الكاش كالمعتاد
  e.respondWith(
    caches.match(e.request).then(response => {
      return response || fetch(e.request);
    })
  );
});
