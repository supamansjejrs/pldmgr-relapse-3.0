/* Relapse pldmgr - service worker.
 *
 * Keeps the whole site inside the PS5 webkit cache so the exploit page opens
 * and runs even when the network is gone (the console-side twin of the
 * localStorage payload cache in src/payload_cache.js).
 *
 * Strategy:
 *   - page (index.html) and offsets: network-first, cache fallback -> new
 *     deploys and offset updates always win when the network is available.
 *   - everything else (site JS, embedded payloads, binaries): cache-first ->
 *     instant loads straight from the webkit cache.
 *
 * Releasing an update: bump VERSION below (any byte change to sw.js makes the
 * browser reinstall it and refresh the cache).
 */
const VERSION = "relapse-pldmgr-v8.0";
const CORE = [
  "./",
  "./index.html",
  "./src/payload_cache.js",
  "./src/payload_catalog.js",
  "./src/payload_data.js",
  "./src/firmware.js",
  "./src/main.js",
  "./src/inject.js",
  "./src/rop.js",
  "./src/site.js",
  "./src/ui.js",
  "./src/webkit.js",
  "./src/kexp.js",
  "./src/relapse_exploit.js",
  "./src/utils/int64.js",
  "./src/utils/mem.js",
  "./src/utils/rop_slave.js",
  "./src/utils/syscalls.js",
  "./payloads/elfldr-ps5-1360.elf",
  "./payloads/kexp_2026_05_25.bin",
  "./offsets/13.60.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    await Promise.allSettled(CORE.map((url) => cache.add(url)));
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n !== VERSION).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return; // 127.0.0.1:9021 delivery etc.

  const keepFresh = url.pathname.endsWith("/") ||
    url.pathname.endsWith("index.html") ||
    (url.pathname.includes("/offsets/") && url.pathname.endsWith(".js"));

  event.respondWith((async () => {
    const cache = await caches.open(VERSION);
    if (!keepFresh) {
      const hit = await cache.match(request, { ignoreSearch: true });
      if (hit) return hit;
    }
    try {
      const fresh = await fetch(request);
      if (fresh && fresh.status === 200) cache.put(request, fresh.clone());
      return fresh;
    } catch (e) {
      const hit = await cache.match(request, { ignoreSearch: true });
      if (hit) return hit;
      throw e;
    }
  })());
});
