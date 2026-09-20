import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import App from './App'

const identity = {
  entity_id: 'entity-1',
  display_name: 'SRE on-call',
}

const pendingRequest = {
  id: 'req-7f31',
  approved: false,
  status: 'pending',
  operation: 'update',
  path: 'secret/data/production/payments',
  data: { ttl: '30m', reason: 'Emergency credential rotation' },
  entity: { id: 'entity-2', name: 'Payments deploy' },
  authorizations: ['control-group/platform'],
  firstSeen: '2026-09-17T08:15:00Z',
  lastSeen: '2026-09-17T08:17:00Z',
}

const contextualRequest = {
  ...pendingRequest,
  id: 'github-request',
  operation: 'read',
  path: 'github/token/project-authorizer',
  data: undefined,
  approvalContext: {
    available: true,
    data: {
      org_name: 'example-org',
      repositories: ['example-repo'],
      permissions: { administration: 'write', contents: 'write', workflows: 'write' },
    },
  },
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('OpenBao Authorizer user workflows', () => {
  it('opens a fresh event stream when the current connection cannot recover', async () => {
    class TerminalEventSource {
      static instances: TerminalEventSource[] = []
      onopen: (() => void) | null = null
      onerror: (() => void) | null = null

      constructor() {
        TerminalEventSource.instances.push(this)
      }

      addEventListener() {}
      close() {}
    }

    vi.stubGlobal('EventSource', TerminalEventSource)
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-events' }))
      .mockResolvedValueOnce(jsonResponse([]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Approval requests' })).toBeInTheDocument()
    await waitFor(() => expect(TerminalEventSource.instances).toHaveLength(1))
    const firstSource = TerminalEventSource.instances[0]
    firstSource.onopen?.()
    expect(await screen.findByText('Live')).toBeInTheDocument()

    firstSource.onerror?.()
    expect(await screen.findByText('Reconnecting')).toBeInTheDocument()

    await waitFor(() => expect(TerminalEventSource.instances).toHaveLength(2), { timeout: 2_000 })
    TerminalEventSource.instances[1].onopen?.()
    expect(await screen.findByText('Live')).toBeInTheDocument()
  })

  it('signs in with username and password without persisting credentials in browser storage', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ message: 'unauthenticated' }, 401))
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-login' }))
      .mockResolvedValueOnce(jsonResponse([]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.type(await screen.findByLabelText('Username'), 'bob')
    await user.type(screen.getByLabelText('Password'), 'correct horse')
    await user.click(screen.getByRole('button', { name: 'Sign in securely' }))

    expect(await screen.findByRole('heading', { name: 'Approval requests' })).toBeInTheDocument()
    expect(screen.getByText('SRE on-call')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/session', expect.objectContaining({
      method: 'POST',
      cache: 'no-store',
      body: JSON.stringify({ username: 'bob', password: 'correct horse' }),
    }))
    expect(localStorage).toHaveLength(0)
    expect(sessionStorage).toHaveLength(0)
  })

  it('keeps the operator signed in and offers a retry when logout fails', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-logout' }))
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({ message: 'Logout service unavailable' }, 503))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Approval requests' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Logout service unavailable')
    expect(screen.getByRole('heading', { name: 'Approval requests' })).toBeInTheDocument()

    await user.click(within(alert).getByRole('button', { name: 'Retry sign out' }))

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenNthCalledWith(4, '/api/v1/session', expect.objectContaining({
      method: 'DELETE',
      cache: 'no-store',
    }))
  })

  it('treats an unauthorized logout as an expired signed-out session', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-expired' }))
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({ message: 'Session expired' }, 401))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Approval requests' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
  })

  it('treats a forbidden request list as a lost approver session', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-revoked' }))
      .mockResolvedValueOnce(jsonResponse({ message: 'Approver policy revoked' }, 403))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    expect(screen.queryByText('Approver policy revoked')).not.toBeInTheDocument()
  })

  it('manages focus when opening and closing request details', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-keyboard' }))
      .mockResolvedValueOnce(jsonResponse([pendingRequest]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    const requestRow = await screen.findByRole('button', { name: new RegExp(pendingRequest.path) })
    requestRow.focus()
    await user.keyboard('{Enter}')

    const detailHeading = screen.getByRole('heading', { level: 2, name: pendingRequest.path })
    expect(detailHeading).toHaveFocus()
    expect(requestRow).toHaveAttribute('aria-current', 'true')

    await user.click(screen.getByRole('button', { name: 'Back to requests' }))
    await waitFor(() => expect(requestRow).toHaveFocus())
  })

  it('shows generic approval context before approval', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-policy' }))
      .mockResolvedValueOnce(jsonResponse([contextualRequest]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: new RegExp(contextualRequest.path) }))
    expect(screen.getByRole('heading', { name: 'Approval context' })).toBeInTheDocument()
    expect(screen.getByText(/"org_name": "example-org"/)).toBeInTheDocument()
    expect(screen.getByText(/"example-repo"/)).toBeInTheDocument()
    expect(screen.getByText(/"administration": "write"/)).toBeInTheDocument()
    expect(screen.getByText(/Redacted by the server/)).toBeInTheDocument()
  })

  it('approves the selected request immediately', async () => {
    const user = userEvent.setup()
    const approvedRequest = { ...pendingRequest, approved: true, status: 'approved' }
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-approve' }))
      .mockResolvedValueOnce(jsonResponse([pendingRequest]))
      .mockResolvedValueOnce(jsonResponse(approvedRequest))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByText('secret/data/production/payments')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: new RegExp(pendingRequest.path) }))
    expect(screen.getByText(/Emergency credential rotation/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Approve request' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const [approveUrl, approveInit] = fetchMock.mock.calls[2]
    expect(approveUrl).toBe('/api/v1/requests/req-7f31/approve')
    expect(approveInit).toEqual(expect.objectContaining({ method: 'POST', cache: 'no-store', body: JSON.stringify({}) }))
    expect(new Headers(approveInit?.headers).get('Content-Type')).toBe('application/json')
    expect(new Headers(approveInit?.headers).get('X-CSRF-Token')).toBe('csrf-approve')
    expect((await screen.findAllByText('Approved')).length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { level: 2, name: approvedRequest.path })).toHaveFocus()
  })

  it('rejects and revokes a pending request immediately', async () => {
    const user = userEvent.setup()
    const rejectedRequest = { ...pendingRequest, status: 'rejected' }
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-reject' }))
      .mockResolvedValueOnce(jsonResponse([pendingRequest]))
      .mockResolvedValueOnce(jsonResponse(rejectedRequest))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: new RegExp(pendingRequest.path) }))
    await user.click(screen.getByRole('button', { name: 'Reject request' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const [rejectURL, rejectInit] = fetchMock.mock.calls[2]
    expect(rejectURL).toBe('/api/v1/requests/req-7f31/reject')
    expect(new Headers(rejectInit?.headers).get('X-CSRF-Token')).toBe('csrf-reject')
    expect((await screen.findAllByText('Rejected')).length).toBeGreaterThan(0)
  })
})
