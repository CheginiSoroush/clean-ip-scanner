/**
 * Clean IP Scanner — offline shell service worker.
 *
 * Strategy:
 *  - Navigations: network-first with cached-shell fallback (works offline)
 *  - Static assets (/_next/static, icons, fonts): stale-while-revalidate
 *
 * Registered only in production (see src/components/pwa-register.tsx) so the
 * dev server + HMR never get served stale cache.
 */

const CACHE = 'cis-shell-v1'
const CORE = ['/', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png', '/favicon-32.png']

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => Promise.allSettled(CORE.map((url) => cache.add(url))))
      .then(() => self.skipWaiting()),
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

self.addEventListener('fetch', (event) => {
  const req = event.request
  if (req.method !== 'GET') return

  let url
  try {
    url = new URL(req.url)
  } catch {
    return
  }
  if (url.origin !== location.origin) return

  // page navigations: network-first → cached shell
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone()
          caches.open(CACHE).then((cache) => cache.put('/', copy))
          return res
        })
        .catch(() => caches.match('/')),
    )
    return
  }

  // immutable static assets: stale-while-revalidate
  const isStatic =
    url.pathname.startsWith('/_next/static') ||
    /\.(png|jpg|jpeg|svg|ico|woff2?|webmanifest)$/.test(url.pathname)
  if (isStatic) {
    event.respondWith(
      caches.match(req).then((hit) => {
        const fresh = fetch(req)
          .then((res) => {
            const copy = res.clone()
            caches.open(CACHE).then((cache) => cache.put(req, copy))
            return res
          })
          .catch(() => hit)
        return hit || fresh
      }),
    )
  }
})
