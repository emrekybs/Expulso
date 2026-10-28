// Minimal service worker: makes the panel installable. Requests go straight to the network,
// so scan results are never served from a stale cache.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});
