import { describe, expect, it } from 'vitest'
import { apiNetworkOnlyUrlPattern, navigateFallbackDenylist, workboxActivation } from '../pwa'

describe('service worker routing', () => {
	it('activates updates immediately and takes control of open clients', () => {
		expect(workboxActivation).toEqual({ skipWaiting: true, clientsClaim: true })
	})

  it('keeps same-origin API requests network-only using the Workbox URL callback', () => {
    expect(apiNetworkOnlyUrlPattern({
      sameOrigin: true,
      url: new URL('https://control.example/api/v1/request-groups'),
    })).toBe(true)
    expect(apiNetworkOnlyUrlPattern({
      sameOrigin: false,
      url: new URL('https://api.example/api/v1/request-groups'),
    })).toBe(false)
    expect(apiNetworkOnlyUrlPattern({
      sameOrigin: true,
      url: new URL('https://control.example/requests'),
    })).toBe(false)
  })

  it.each(['/api', '/api/v1/session', '/healthz', '/healthz/ready'])(
    'denies navigation fallback for %s',
    (pathname) => {
      expect(navigateFallbackDenylist.some((pattern) => pattern.test(pathname))).toBe(true)
    },
  )

  it.each(['/apiary', '/healthzone', '/requests'])(
    'allows navigation fallback outside backend routes for %s',
    (pathname) => {
      expect(navigateFallbackDenylist.some((pattern) => pattern.test(pathname))).toBe(false)
    },
  )
})
