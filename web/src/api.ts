import type { RequestGroup, Session } from './types'

export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body !== undefined) headers.set('Content-Type', 'application/json')

  const response = await fetch(path, {
    ...init,
    headers,
    cache: 'no-store',
    credentials: 'same-origin',
  })

  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const payload = await response.json() as { message?: string; error?: string }
      message = payload.message ?? payload.error ?? message
    } catch {
      // Keep the status-based message when the server has no JSON body.
    }
    throw new ApiError(message, response.status)
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  getSession: () => apiFetch<Session>('/api/v1/session'),
  createSession: (username: string, password: string) => apiFetch<Session>('/api/v1/session', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  }),
  deleteSession: (csrfToken: string) => apiFetch<void>('/api/v1/session', {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken },
    body: JSON.stringify({}),
  }),
  getRequestGroups: () => apiFetch<RequestGroup[]>('/api/v1/request-groups'),
  approveRequestGroup: (id: string, csrfToken: string) => apiFetch<RequestGroup>(
    `/api/v1/request-groups/${encodeURIComponent(id)}/approve`,
    {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({}),
    },
  ),
  rejectRequestGroup: (id: string, csrfToken: string) => apiFetch<RequestGroup>(
    `/api/v1/request-groups/${encodeURIComponent(id)}/reject`,
    {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({}),
    },
  ),
  getPushPublicKey: () => apiFetch<{ publicKey: string }>('/api/v1/push/public-key'),
  subscribeToPush: (
    subscription: { endpoint: string; keys: { p256dh: string; auth: string } },
    csrfToken: string,
  ) => apiFetch<void>('/api/v1/push/subscriptions', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: JSON.stringify(subscription),
  }),
  unsubscribeFromPush: (endpoint: string, csrfToken: string) => apiFetch<void>('/api/v1/push/subscriptions', {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken },
    body: JSON.stringify({ endpoint }),
  }),
}
