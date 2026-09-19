/* global self */

const DEFAULT_NOTIFICATION = Object.freeze({
  title: 'OpenBao approval pending',
  body: 'A new control-group request needs review.',
  url: '/',
})

function safeText(value, fallback, maximumLength) {
  if (typeof value !== 'string') return fallback
  const trimmed = value.trim()
  if (trimmed === '' || trimmed.length > maximumLength) return fallback
  return trimmed
}

function sameOriginURL(value) {
  try {
    const target = new URL(typeof value === 'string' ? value : '/', self.location.origin)
    if (target.origin !== self.location.origin || target.username !== '' || target.password !== '') {
      return new URL('/', self.location.origin)
    }
    return target
  } catch {
    return new URL('/', self.location.origin)
  }
}

function notificationPayload(event) {
  let envelope = {}
  try {
    const parsed = event.data?.json()
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) envelope = parsed
  } catch {
    // A malformed or absent payload still produces a generic notification.
  }

  const target = sameOriginURL(envelope.url)
  return {
    title: safeText(envelope.title, DEFAULT_NOTIFICATION.title, 120),
    body: safeText(envelope.body, DEFAULT_NOTIFICATION.body, 240),
    url: `${target.pathname}${target.search}${target.hash}`,
  }
}

self.addEventListener('push', (event) => {
  const payload = notificationPayload(event)
  event.waitUntil(self.registration.showNotification(payload.title, {
    body: payload.body,
    icon: '/pwa-192x192.png',
    badge: '/pwa-192x192.png',
    tag: 'openbao-authorizer-request',
    renotify: true,
    data: { url: payload.url },
  }))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  event.waitUntil((async () => {
    const target = sameOriginURL(event.notification.data?.url)
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    for (const client of windows) {
      try {
        if ('navigate' in client) await client.navigate(target.href)
        if ('focus' in client) return client.focus()
      } catch {
        // Try another controlled window, then fall back to opening the app.
      }
    }
    return self.clients.openWindow(target.href)
  })())
})
