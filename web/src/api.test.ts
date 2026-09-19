import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

describe('push subscription API', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('deletes one device endpoint with JSON and CSRF protection', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    await api.unsubscribeFromPush('https://push.example/device', 'csrf-token')

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/push/subscriptions', expect.objectContaining({
      method: 'DELETE',
      cache: 'no-store',
      body: JSON.stringify({ endpoint: 'https://push.example/device' }),
    }))
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('X-CSRF-Token')).toBe('csrf-token')
  })
})
