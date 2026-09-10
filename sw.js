const CACHE = "tenkord-v11";
const ASSETS = [
  "./",
  "./index.html",
  "./tenkord-v11.css",
  "./tenkord-v11.js",
  "./manifest.json",
  "./icon-192.png",
  "./icon-512.png"
];

self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  const networkFirst = e.request.mode === "navigate" ||
    url.pathname.endsWith(".js") ||
    url.pathname.endsWith(".css") ||
    url.pathname.endsWith(".html");
  if (networkFirst) {
    e.respondWith(
      fetch(e.request).then(nr => {
        if (nr && nr.status === 200) {
          const c = nr.clone();
          caches.open(CACHE).then(cache => cache.put(e.request, c));
        }
        return nr;
      }).catch(() => caches.match(e.request).then(r => r || caches.match("./index.html")))
    );
  } else {
    e.respondWith(
      caches.match(e.request).then(r => r || fetch(e.request).then(nr => {
        if (nr && nr.status === 200) {
          const c = nr.clone();
          caches.open(CACHE).then(cache => cache.put(e.request, c));
        }
        return nr;
      }))
    );
  }
});
