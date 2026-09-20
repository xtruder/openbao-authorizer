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
  status: 'pending' as const,
  operation: 'update',
  path: 'secret/data/production/payments',
  data: { ttl: '30m' },
  entity: { id: 'entity-2', name: 'Payments deploy' },
  authorizations: ['control-group/platform'],
  firstSeen: '2026-09-17T08:15:00Z',
  lastSeen: '2026-09-17T08:17:00Z',
  position: 1,
  groupId: 'group-7f31',
}

const pendingGroup = {
  id: 'group-7f31',
  reason: 'Emergency credential rotation',
  status: 'pending' as const,
  entity: { id: 'entity-2', name: 'Payments deploy' },
  requests: [pendingRequest],
  createdAt: '2026-09-17T08:15:00Z',
  updatedAt: '2026-09-17T08:17:00Z',
}

const contextualRequest = {
  ...pendingRequest,
  id: 'github-request',
  operation: 'read',
  path: 'github/token/project-authorizer',
  data: undefined,
  position: 2,
  groupId: 'github-group',
  approvalContext: {
    available: true,
    data: {
      org_name: 'example-org',
      repositories: ['example-repo'],
      permissions: { administration: 'write', contents: 'write', workflows: 'write' },
    },
  },
}

const firstContextualRequest = {
  ...pendingRequest,
  id: 'policy-request',
  operation: 'create',
  path: 'sys/policies/acl/project-authorizer',
  data: undefined,
  position: 1,
  groupId: 'github-group',
}

const contextualGroup = {
  ...pendingGroup,
  id: 'github-group',
  reason: 'Provision automation access for the release',
  requests: [contextualRequest, firstContextualRequest],
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('OpenBao Authorizer user workflows', () => {
  it('opens the group linked by a notification', async () => {
    window.history.replaceState({}, '', '/?request=group-7f31')
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-notification' }))
      .mockResolvedValueOnce(jsonResponse([pendingGroup]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    const detailHeading = await screen.findByRole('heading', { level: 2, name: pendingGroup.reason })
    expect(detailHeading).toHaveFocus()
  })

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

    expect(await screen.findByRole('heading', { name: 'Approval groups' })).toBeInTheDocument()
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

    expect(await screen.findByRole('heading', { name: 'Approval groups' })).toBeInTheDocument()
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

    expect(await screen.findByRole('heading', { name: 'Approval groups' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Logout service unavailable')
    expect(screen.getByRole('heading', { name: 'Approval groups' })).toBeInTheDocument()

    await user.click(within(alert).getByRole('button', { name: 'Retry sign out' }))

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenNthCalledWith(4, '/api/v1/session', expect.objectContaining({
      method: 'DELETE',
      cache: 'no-store',
    }))
  })

  it('treats an unauthorized group list as a lost approver session', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-revoked' }))
      .mockResolvedValueOnce(jsonResponse({ message: 'Approver policy revoked' }, 403))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    expect(screen.queryByText('Approver policy revoked')).not.toBeInTheDocument()
  })

  it('manages focus when opening and closing group details', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-keyboard' }))
      .mockResolvedValueOnce(jsonResponse([pendingGroup]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    const groupRow = await screen.findByRole('button', { name: new RegExp(pendingGroup.reason) })
    groupRow.focus()
    await user.keyboard('{Enter}')

    const detailHeading = screen.getByRole('heading', { level: 2, name: pendingGroup.reason })
    expect(detailHeading).toHaveFocus()
    expect(groupRow).toHaveAttribute('aria-current', 'true')

    await user.click(screen.getByRole('button', { name: 'Back to groups' }))
    await waitFor(() => expect(groupRow).toHaveFocus())
  })

  it('shows a shared reason with redacted data and orders all member operations by position', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-policy' }))
      .mockResolvedValueOnce(jsonResponse([contextualGroup]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: new RegExp(contextualGroup.reason) }))
    expect(screen.getByRole('heading', { name: 'Shared reason' })).toBeInTheDocument()
    expect(screen.getAllByText(contextualGroup.reason).length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { name: 'Approval context' })).toBeInTheDocument()
    expect(screen.getByText(/"org_name": "example-org"/)).toBeInTheDocument()
    expect(screen.getAllByText(/Redacted by the server/)).toHaveLength(2)

    const firstMember = screen.getByRole('heading', { level: 3, name: firstContextualRequest.path })
    const secondMember = screen.getByRole('heading', { level: 3, name: contextualRequest.path })
    expect(firstMember.compareDocumentPosition(secondMember) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('records a group authorization without claiming the group is fully approved', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-approve' }))
      .mockResolvedValueOnce(jsonResponse([pendingGroup]))
      .mockResolvedValueOnce(jsonResponse(pendingGroup))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: new RegExp(pendingGroup.reason) }))
    await user.click(screen.getByRole('button', { name: 'Approve group' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const [approveUrl, approveInit] = fetchMock.mock.calls[2]
    expect(approveUrl).toBe('/api/v1/request-groups/group-7f31/approve')
    expect(approveInit).toEqual(expect.objectContaining({ method: 'POST', cache: 'no-store', body: JSON.stringify({}) }))
    expect(new Headers(approveInit?.headers).get('Content-Type')).toBe('application/json')
    expect(new Headers(approveInit?.headers).get('X-CSRF-Token')).toBe('csrf-approve')
    expect(await screen.findByText('Authorization recorded. Required quorum is still pending.')).toBeInTheDocument()
  })

  it('reports a fully approved group from the returned group status', async () => {
    const user = userEvent.setup()
    const approvedGroup = { ...pendingGroup, status: 'approved' as const }
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-approved' }))
      .mockResolvedValueOnce(jsonResponse([pendingGroup]))
      .mockResolvedValueOnce(jsonResponse(approvedGroup))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: new RegExp(pendingGroup.reason) }))
    await user.click(screen.getByRole('button', { name: 'Approve group' }))

    expect(await screen.findByText('Group fully approved.')).toBeInTheDocument()
    expect(screen.getByText('Fully approved')).toBeInTheDocument()
  })

  it('keeps failed groups actionable and displays their failure state', async () => {
    const user = userEvent.setup()
    const failedGroup = { ...pendingGroup, id: 'failed-group', status: 'approval_failed' as const }
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-failed' }))
      .mockResolvedValueOnce(jsonResponse([failedGroup]))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByRole('button', { name: 'Pending 1' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: new RegExp(failedGroup.reason) }))
    expect(screen.getByRole('alert')).toHaveTextContent('last approval attempt failed')
    expect(screen.getByRole('button', { name: 'Approve group' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Reject group' })).toBeEnabled()
  })

  it('rejects and revokes a pending group immediately', async () => {
    const user = userEvent.setup()
    const rejectedGroup = { ...pendingGroup, status: 'rejected' as const }
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ identity, csrfToken: 'csrf-reject' }))
      .mockResolvedValueOnce(jsonResponse([pendingGroup]))
      .mockResolvedValueOnce(jsonResponse(rejectedGroup))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    await user.click(await screen.findByRole('button', { name: new RegExp(pendingGroup.reason) }))
    await user.click(screen.getByRole('button', { name: 'Reject group' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const [rejectURL, rejectInit] = fetchMock.mock.calls[2]
    expect(rejectURL).toBe('/api/v1/request-groups/group-7f31/reject')
    expect(new Headers(rejectInit?.headers).get('X-CSRF-Token')).toBe('csrf-reject')
    expect(await screen.findByText('Group rejected and revoked.')).toBeInTheDocument()
  })
})
