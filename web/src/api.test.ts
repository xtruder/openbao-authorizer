import { Code, ConnectError } from '@connectrpc/connect'
import { describe, expect, it, vi } from 'vitest'
import { createApproverClient, getErrorMessage, isSessionLost } from './api'
import { rpcError } from './test/fakeApprover'

describe('approver client', () => {
  it('calls ApproverService over Connect JSON under /api with same-origin credentials', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(
      JSON.stringify({ identity: { displayName: 'SRE on-call' } }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ))
    vi.stubGlobal('fetch', fetchMock)

    const response = await createApproverClient().getSession({})

    expect(response.identity?.displayName).toBe('SRE on-call')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/openbao.authorizer.v1.ApproverService/GetSession')
    expect(init).toEqual(expect.objectContaining({ method: 'POST', credentials: 'same-origin' }))
    const headers = new Headers(init?.headers)
    expect(headers.get('Content-Type')).toBe('application/json')
  })
})

describe('approver errors', () => {
  it('maps stable reasons to user-facing messages', () => {
    expect(getErrorMessage(rpcError(Code.Unauthenticated, 'SESSION_EXPIRED'), 'fallback')).toBe('Your session has expired. Sign in again.')
    expect(getErrorMessage(rpcError(Code.FailedPrecondition, 'GRANT_NOT_ACTIVE'), 'fallback')).toBe('That grant was already revoked or has expired.')
    expect(getErrorMessage(rpcError(Code.NotFound, 'NOT_FOUND'), 'fallback')).toBe('That request or grant no longer exists.')
    expect(getErrorMessage(rpcError(Code.PermissionDenied, 'SELF_APPROVAL'), 'fallback')).toBe("You can't decide your own request.")
    expect(getErrorMessage(rpcError(Code.PermissionDenied, 'NOT_REQUESTER'), 'fallback')).toBe('That OpenBao identity matches no requester rule.')
  })

  it('keeps the server explanation for invalid input', () => {
    expect(getErrorMessage(rpcError(Code.InvalidArgument, 'INVALID_REQUEST', 'ttl must be positive'), 'fallback')).toBe('ttl must be positive')
  })

  it('hides transport details when the authorizer is unreachable', () => {
    expect(getErrorMessage(new ConnectError('Failed to fetch', Code.Unavailable), 'fallback')).toBe(
      'The authorizer is unreachable. Check your connection and try again.',
    )
  })

  it('falls back for errors without a message', () => {
    expect(getErrorMessage(new ConnectError('', Code.Internal), 'fallback')).toBe('fallback')
    expect(getErrorMessage(null, 'fallback')).toBe('fallback')
  })

  it('treats expired sessions, cross-origin rejections and revoked approvers as signed out', () => {
    expect(isSessionLost(rpcError(Code.Unauthenticated, 'SESSION_EXPIRED'))).toBe(true)
    expect(isSessionLost(rpcError(Code.PermissionDenied, 'CROSS_ORIGIN'))).toBe(true)
    expect(isSessionLost(rpcError(Code.PermissionDenied, 'NOT_APPROVER'))).toBe(true)
    expect(isSessionLost(rpcError(Code.FailedPrecondition, 'ITEM_NOT_PENDING'))).toBe(false)
    expect(isSessionLost(new Error('offline'))).toBe(false)
  })
})
