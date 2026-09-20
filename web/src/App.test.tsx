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

  it('manages focus for request details and traps keyboard focus in confirmation', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-keyboard' }))
      .mockResolvedValueOnce(jsonResponse([pendingRequest]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    const reviewButton = await screen.findByRole('button', { name: /review request/i })
    reviewButton.focus()
    await user.keyboard('{Enter}')

    const detailHeading = screen.getByRole('heading', { level: 2, name: pendingRequest.path })
    expect(detailHeading).toHaveFocus()

    await user.click(screen.getByRole('button', { name: 'Back to requests' }))
    await waitFor(() => expect(reviewButton).toHaveFocus())

    await user.click(reviewButton)
    const approveButton = screen.getByRole('button', { name: 'Approve request' })
    const dashboardBackground = screen.getByRole('main').parentElement
    await user.click(approveButton)

    const dialog = screen.getByRole('dialog', { name: 'Confirm approval' })
    const confirmButton = within(dialog).getByRole('button', { name: 'Confirm approval' })
    const cancelButton = within(dialog).getByRole('button', { name: 'Cancel' })
    expect(confirmButton).toHaveFocus()
    expect(dashboardBackground).toHaveAttribute('inert')
    expect(dashboardBackground).toHaveAttribute('aria-hidden', 'true')

    await user.tab()
    expect(cancelButton).toHaveFocus()
    await user.tab({ shift: true })
    expect(confirmButton).toHaveFocus()

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog', { name: 'Confirm approval' })).not.toBeInTheDocument()
    expect(reviewButton).toHaveFocus()
    expect(dashboardBackground).not.toHaveAttribute('inert')
    expect(dashboardBackground).not.toHaveAttribute('aria-hidden')
  })

  it('shows generic approval context before approval', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-policy' }))
      .mockResolvedValueOnce(jsonResponse([contextualRequest]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: /review request/i }))
    expect(screen.getByRole('heading', { name: 'Approval context' })).toBeInTheDocument()
    expect(screen.getByText(/"org_name": "example-org"/)).toBeInTheDocument()
    expect(screen.getByText(/"example-repo"/)).toBeInTheDocument()
    expect(screen.getByText(/"administration": "write"/)).toBeInTheDocument()
    expect(screen.getByText(/Redacted by the server/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Approve request' }))
    const dialog = screen.getByRole('dialog', { name: 'Confirm approval' })
    expect(within(dialog).getByText(/"org_name": "example-org"/)).toBeInTheDocument()
    expect(within(dialog).getByText(/"workflows": "write"/)).toBeInTheDocument()
  })

  it('requires confirmation before approving the selected request', async () => {
    const user = userEvent.setup()
    const approvedRequest = { ...pendingRequest, approved: true }
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-approve' }))
      .mockResolvedValueOnce(jsonResponse([pendingRequest]))
      .mockResolvedValueOnce(jsonResponse(approvedRequest))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByText('secret/data/production/payments')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /review request/i }))
    expect(screen.getByText(/Emergency credential rotation/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Approve request' }))
    const dialog = screen.getByRole('dialog', { name: 'Confirm approval' })
    expect(within(dialog).getByText(/cannot be undone/i)).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)

    await user.click(within(dialog).getByRole('button', { name: 'Confirm approval' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const [approveUrl, approveInit] = fetchMock.mock.calls[2]
    expect(approveUrl).toBe('/api/v1/requests/req-7f31/approve')
    expect(approveInit).toEqual(expect.objectContaining({ method: 'POST', cache: 'no-store', body: JSON.stringify({}) }))
    expect(new Headers(approveInit?.headers).get('Content-Type')).toBe('application/json')
    expect(new Headers(approveInit?.headers).get('X-CSRF-Token')).toBe('csrf-approve')
    expect((await screen.findAllByText('Approved')).length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { level: 2, name: approvedRequest.path })).toHaveFocus()
  })
})
