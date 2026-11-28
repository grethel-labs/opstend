// OpsTend service worker: installable app shell and a read-only offline view.
// State-changing requests always go to the network; nothing is queued offline.
const VERSION = "opstend-v1";
const SHELL = ["/", "/manifest.webmanifest", "/brand/opstend.svg", "/icons/icon-192.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname === "/api/stream") return;
  if (url.pathname.startsWith("/assets/")) {
    event.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((res) => {
      const copy = res.clone();
      caches.open(VERSION).then((c) => c.put(req, copy));
      return res;
    })));
    return;
  }
  // Network first; the last good answer serves as offline fallback.
  event.respondWith(fetch(req).then((res) => {
    if (res.ok && (url.pathname.startsWith("/api/") || req.mode === "navigate")) {
      const copy = res.clone();
      caches.open(VERSION).then((c) => c.put(req.mode === "navigate" ? "/" : req, copy));
    }
    return res;
  }).catch(() => caches.match(req.mode === "navigate" ? "/" : req).then((hit) => {
    if (hit) {
      const headers = new Headers(hit.headers);
      headers.set("x-opstend-offline", "1");
      return hit.blob().then((b) => new Response(b, { status: hit.status, headers }));
    }
    return new Response(JSON.stringify({ detail: "offline" }), {
      status: 503, headers: { "content-type": "application/json", "x-opstend-offline": "1" },
    });
  })));
});

self.addEventListener("push", (event) => {
  const data = event.data ? event.data.json() : { title: "OpsTend", body: "" };
  event.waitUntil(self.registration.showNotification(data.title, {
    body: data.body, icon: "/icons/icon-192.png", badge: "/icons/icon-192.png",
    data: { url: data.url || "/" },
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(self.clients.openWindow(event.notification.data.url));
});
