export interface WorkboxRouteMatchOptions {
  sameOrigin: boolean
  url: URL
}

export function apiNetworkOnlyUrlPattern({ sameOrigin, url }: WorkboxRouteMatchOptions) {
  return sameOrigin && (url.pathname === '/api/v1' || url.pathname.startsWith('/api/v1/'))
}

export const navigateFallbackDenylist = [
  /^\/api(?:\/|$)/,
  /^\/healthz(?:\/|$)/,
]
