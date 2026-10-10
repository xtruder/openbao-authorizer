import { create, type MessageInitShape } from '@bufbuild/protobuf'
import { timestampFromDate } from '@bufbuild/protobuf/wkt'
import { Code } from '@connectrpc/connect'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { Decision, type DecideItemsRequest, type DeletePushSubscriptionRequest, type RegisterPushSubscriptionRequest, type RevokeGrantRequest } from './gen/openbao/authorizer/v1/approver_pb'
import { GrantRequestSchema, GrantSchema, ItemState } from './gen/openbao/authorizer/v1/types_pb'
import { fakeApprover, rpcError } from './test/fakeApprover'

const at = (value: string) => timestampFromDate(new Date(value))
const hours = (count: number) => ({ seconds: BigInt(count * 3600) })

const requester = { id: 'ses_abc123', title: 'Payments rollout', directory: '/src/payments', entityId: 'entity-2', rule: 'opencode-sessions' }

// Fixtures stay plain init objects so tests can derive variants by spreading;
// spreading a created message would carry its $typeName and skip nested init.
const pendingInit = {
  id: 'req-7f31',
  reason: 'Deploy the payments service to staging',
  createdAt: at('2026-09-17T08:15:00Z'),
  requester,
  items: [
    { id: 'item-a', path: 'kv/data/payments/db', capabilities: ['read'], ttl: hours(8), state: ItemState.PENDING, expiresAt: at('2026-09-18T08:15:00Z') },
    { id: 'item-b', path: 'kv/data/payments/api', capabilities: ['read', 'update'], ttl: hours(8), state: ItemState.PENDING, expiresAt: at('2026-09-18T08:15:00Z') },
    { id: 'item-c', path: 'sys/policies/acl/root', capabilities: ['read'], state: ItemState.REFUSED, reason: 'paths under sys/ are on the hard denylist' },
  ],
} satisfies MessageInitShape<typeof GrantRequestSchema>
const pendingRequest = create(GrantRequestSchema, pendingInit)

const decidedRequest = create(GrantRequestSchema, {
  ...pendingInit,
  id: 'req-old',
  reason: 'Rotate the staging database password',
  items: [
    { id: 'item-old', path: 'kv/data/staging/db', capabilities: ['read'], ttl: hours(1), state: ItemState.APPROVED, decidedBy: 'Bob', expiresAt: at('2026-09-17T09:15:00Z'), grantId: 'grant-1' },
  ],
})

const activeGrant = create(GrantSchema, {
  id: 'grant-1',
  itemId: 'item-old',
  path: 'kv/data/staging/db',
  capabilities: ['read'],
  createdAt: at('2026-09-17T08:15:00Z'),
  expiresAt: at('2026-09-17T09:15:00Z'),
  approvedBy: 'Bob',
  requester,
})

// signedIn starts each test with only the session cookie, as after a reload.
function signedIn(options: Parameters<typeof fakeApprover>[0] = {}) {
  const fake = fakeApprover(options)
  fake.state.cookie = true
  return fake
}

describe('OpenBao Authorizer user workflows', () => {
  it('restores the session from the cookie', async () => {
    const fake = signedIn()

    render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
    expect(screen.getByText('SRE on-call')).toBeInTheDocument()
    expect(fake.callsTo('GetSession')).toHaveLength(1)
    await waitFor(() => expect(fake.callsTo('WatchEvents')).toHaveLength(1))
  })

  it('opens the request linked by a notification', async () => {
    window.history.replaceState({}, '', '/?request=req-7f31')
    const fake = signedIn({ initialSnapshot: { pendingRequests: [pendingRequest] } })

    render(<App client={fake.client} />)

    const heading = await screen.findByRole('heading', { level: 3, name: pendingRequest.reason })
    await waitFor(() => expect(heading).toHaveFocus())
  })

  it('renders each snapshot from the event stream', async () => {
    const fake = signedIn({ initialSnapshot: { pendingRequests: [pendingRequest] } })

    render(<App client={fake.client} />)

    const card = (await screen.findByRole('heading', { name: pendingRequest.reason })).closest('article')
    expect(card).not.toBeNull()
    const scope = within(card as HTMLElement)
    expect(scope.getByText('Payments rollout')).toBeInTheDocument()
    expect(scope.getByText('ses_abc123')).toBeInTheDocument()
    expect(scope.getByText('/src/payments')).toBeInTheDocument()
    expect(scope.getByTitle('Requester rule')).toHaveTextContent('opencode-sessions')
    expect(scope.getByText('kv/data/payments/db')).toBeInTheDocument()
    expect(scope.getByText('paths under sys/ are on the hard denylist')).toBeInTheDocument()
    expect(scope.getByLabelText('TTL for kv/data/payments/db')).toHaveValue('8h')
    expect(scope.queryByRole('button', { name: 'Approve sys/policies/acl/root' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Pending/ })).toHaveTextContent('2')
    expect(screen.getByText('Live')).toBeInTheDocument()

    fake.streams[0].snapshot({ decidedRequests: [decidedRequest], activeGrants: [activeGrant] })

    expect(await screen.findByText('Queue is clear')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /History/ })).toHaveTextContent('1')
    expect(screen.getByRole('button', { name: /Active grants/ })).toHaveTextContent('1')
  })

  it('renders agent-supplied strings as plain text', async () => {
    const markup = '<img src=x onerror="alert(1)">'
    const hostile = create(GrantRequestSchema, {
      ...pendingInit,
      reason: `Need ${markup}`,
      requester: { ...requester, title: `<b>${markup}</b>`, directory: `/tmp/${markup}` },
      items: [{ ...pendingInit.items[0], path: `kv/data/${markup}` }],
    })
    const fake = signedIn({ initialSnapshot: { pendingRequests: [hostile] } })

    const { container } = render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: `Need ${markup}` })).toBeInTheDocument()
    expect(screen.getByText(`<b>${markup}</b>`)).toBeInTheDocument()
    expect(screen.getByText(`/tmp/${markup}`)).toBeInTheDocument()
    expect(screen.getByText(`kv/data/${markup}`)).toBeInTheDocument()
    expect(container.querySelector('img, b')).toBeNull()
  })

  it('marks the stream live on heartbeats and reconnects after a drop', async () => {
    const fake = signedIn({ initialSnapshot: null })

    render(<App client={fake.client} />)

    expect(await screen.findByText('Connecting')).toBeInTheDocument()
    await waitFor(() => expect(fake.streams).toHaveLength(1))
    fake.streams[0].heartbeat()
    expect(await screen.findByText('Live')).toBeInTheDocument()

    fake.streams[0].fail(rpcError(Code.Unavailable, 'OPENBAO_UNAVAILABLE'))
    expect(await screen.findByText('Reconnecting')).toBeInTheDocument()

    await waitFor(() => expect(fake.streams).toHaveLength(2), { timeout: 2_000 })
    fake.streams[1].snapshot({ pendingRequests: [pendingRequest] })
    expect(await screen.findByText('Live')).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: pendingRequest.reason })).toBeInTheDocument()
  })

  it('reports a stream that fails before its first snapshot', async () => {
    const fake = signedIn({ initialSnapshot: null })

    render(<App client={fake.client} />)

    await waitFor(() => expect(fake.streams).toHaveLength(1))
    fake.streams[0].fail(rpcError(Code.Unavailable, 'OPENBAO_UNAVAILABLE'))

    expect(await screen.findByRole('alert')).toHaveTextContent('OpenBao is unavailable. Try again shortly.')
  })

  it('returns to sign in when the stream reports an expired session', async () => {
    const fake = signedIn({ initialSnapshot: null })

    render(<App client={fake.client} />)

    await waitFor(() => expect(fake.streams).toHaveLength(1))
    fake.streams[0].fail(rpcError(Code.Unauthenticated, 'SESSION_EXPIRED'))

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    await new Promise((resolve) => setTimeout(resolve, 1_200))
    expect(fake.streams).toHaveLength(1)
  })

  it('treats a revoked approver policy as a lost session', async () => {
    const fake = signedIn({
      handlers: { watchEvents: () => { throw rpcError(Code.PermissionDenied, 'NOT_APPROVER', 'approver policy revoked') } },
    })

    render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    expect(screen.queryByText('approver policy revoked')).not.toBeInTheDocument()
  })

  it('falls back to sign in when there is no session cookie', async () => {
    const fake = fakeApprover()

    render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
  })

  it('offers a retry instead of sign in when the session check cannot reach the server', async () => {
    const user = userEvent.setup()
    let reachable = false
    const fake = signedIn({
      handlers: {
        getSession: () => {
          if (!reachable) throw rpcError(Code.Unavailable, 'UNREACHABLE', 'network down')
          return { identity: { entityId: 'entity-1', displayName: 'SRE on-call' } }
        },
      },
    })

    render(<App client={fake.client} />)

    expect(await screen.findByRole('alert')).toHaveTextContent('The authorizer is unreachable.')
    expect(screen.queryByRole('heading', { name: 'Operator sign in' })).not.toBeInTheDocument()

    reachable = true
    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
    expect(fake.callsTo('GetSession')).toHaveLength(2)
  })

  it('signs out when the session check reports a lost session', async () => {
    const fake = signedIn({
      handlers: { getSession: () => { throw rpcError(Code.PermissionDenied, 'NOT_APPROVER', 'approver policy revoked') } },
    })

    render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
  })

  describe('stream watchdog', () => {
    afterEach(() => {
      vi.useRealTimers()
      Reflect.deleteProperty(document, 'visibilityState')
    })

    it('reconnects a stream that has gone silent', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true })
      const fake = signedIn({ initialSnapshot: null })

      render(<App client={fake.client} />)

      await waitFor(() => expect(fake.streams).toHaveLength(1))
      await vi.advanceTimersByTimeAsync(50_000)
      fake.streams[0].heartbeat()
      expect(await screen.findByText('Live')).toBeInTheDocument()
      // The heartbeat restarted the countdown.
      await vi.advanceTimersByTimeAsync(50_000)
      expect(fake.streams).toHaveLength(1)

      await vi.advanceTimersByTimeAsync(10_000)
      await waitFor(() => expect(fake.streams).toHaveLength(2))
      expect(fake.streams[0].aborted).toBe(true)
      fake.streams[1].snapshot({ pendingRequests: [pendingRequest] })
      expect(await screen.findByRole('heading', { name: pendingRequest.reason })).toBeInTheDocument()
    })

    it('restarts an idle stream when the page becomes visible again', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true })
      const fake = signedIn()
      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })

      render(<App client={fake.client} />)

      expect(await screen.findByText('Live')).toBeInTheDocument()
      document.dispatchEvent(new Event('visibilitychange'))
      expect(fake.streams).toHaveLength(1)

      await vi.advanceTimersByTimeAsync(35_000)
      document.dispatchEvent(new Event('visibilitychange'))

      await waitFor(() => expect(fake.streams).toHaveLength(2))
      expect(fake.streams[0].aborted).toBe(true)
    })
  })

  it('approves one item with a shortened TTL', async () => {
    const user = userEvent.setup()
    const approved = create(GrantRequestSchema, {
      ...pendingInit,
      items: [
        { ...pendingInit.items[0], state: ItemState.APPROVED, ttl: { seconds: 1800n }, decidedBy: 'SRE on-call', grantId: 'grant-9' },
        ...pendingInit.items.slice(1),
      ],
    })
    const decisions: DecideItemsRequest[] = []
    const fake = signedIn({
      initialSnapshot: { pendingRequests: [pendingRequest] },
      handlers: { decideItems: (request) => { decisions.push(request); return { grantRequest: approved } } },
    })

    render(<App client={fake.client} />)

    const ttl = await screen.findByLabelText('TTL for kv/data/payments/db')
    await user.clear(ttl)
    await user.type(ttl, '30m')
    await user.click(screen.getByRole('button', { name: 'Approve kv/data/payments/db' }))

    expect(await screen.findByText('Granted kv/data/payments/db.')).toBeInTheDocument()
    expect(decisions).toHaveLength(1)
    expect(decisions[0].grantRequestId).toBe('req-7f31')
    expect(decisions[0].decisions).toHaveLength(1)
    expect(decisions[0].decisions[0]).toEqual(expect.objectContaining({ itemId: 'item-a', decision: Decision.APPROVE }))
    expect(decisions[0].decisions[0].ttl?.seconds).toBe(1800n)
    expect(screen.queryByRole('button', { name: 'Approve kv/data/payments/db' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Approve kv/data/payments/api' })).toBeInTheDocument()
  })

  it('approves with the resolved TTL by leaving it unset', async () => {
    const user = userEvent.setup()
    const fake = signedIn({ initialSnapshot: { pendingRequests: [pendingRequest] } })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: 'Approve kv/data/payments/db' }))

    await waitFor(() => expect(fake.requests<DecideItemsRequest>('DecideItems')).toHaveLength(1))
    expect(fake.requests<DecideItemsRequest>('DecideItems')[0].decisions[0].ttl).toBeUndefined()
  })

  it('rejects one item without sending a TTL', async () => {
    const user = userEvent.setup()
    const fake = signedIn({ initialSnapshot: { pendingRequests: [pendingRequest] } })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: 'Reject kv/data/payments/api' }))

    expect(await screen.findByText('Rejected kv/data/payments/api.')).toBeInTheDocument()
    const [request] = fake.requests<DecideItemsRequest>('DecideItems')
    expect(request.decisions[0]).toEqual(expect.objectContaining({ itemId: 'item-b', decision: Decision.REJECT }))
    expect(request.decisions[0].ttl).toBeUndefined()
  })

  it('refuses a TTL it cannot parse without calling the server', async () => {
    const user = userEvent.setup()
    const fake = signedIn({ initialSnapshot: { pendingRequests: [pendingRequest] } })

    render(<App client={fake.client} />)

    const ttl = await screen.findByLabelText('TTL for kv/data/payments/db')
    await user.clear(ttl)
    await user.type(ttl, 'soon')
    await user.click(screen.getByRole('button', { name: 'Approve kv/data/payments/db' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Enter the TTL as a duration such as 30m or 2h')
    expect(fake.callsTo('DecideItems')).toHaveLength(0)
  })

  it('shows decision errors on the request card', async () => {
    const user = userEvent.setup()
    const fake = signedIn({
      initialSnapshot: { pendingRequests: [pendingRequest] },
      handlers: { decideItems: () => { throw rpcError(Code.InvalidArgument, 'INVALID_REQUEST', 'ttl 9h may only shorten the resolved 8h') } },
    })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: 'Approve kv/data/payments/db' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('ttl 9h may only shorten the resolved 8h')
  })

  it('refuses to let an approver decide their own request', async () => {
    const user = userEvent.setup()
    const fake = signedIn({
      initialSnapshot: { pendingRequests: [pendingRequest] },
      handlers: { decideItems: () => { throw rpcError(Code.PermissionDenied, 'SELF_APPROVAL', 'approver filed this request') } },
    })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: 'Approve kv/data/payments/db' }))

    expect(await screen.findByRole('alert')).toHaveTextContent("You can't decide your own request")
    expect(screen.getByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
  })

  it('explains an item that someone else already decided', async () => {
    const user = userEvent.setup()
    const fake = signedIn({
      initialSnapshot: { pendingRequests: [pendingRequest] },
      handlers: { decideItems: () => { throw rpcError(Code.FailedPrecondition, 'ITEM_NOT_PENDING', 'item item-a is not pending') } },
    })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: 'Approve kv/data/payments/db' }))

    expect(await screen.findByText('That item was already decided. Showing the latest state.')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('lists decided requests in history', async () => {
    const user = userEvent.setup()
    const fake = signedIn({ initialSnapshot: { decidedRequests: [decidedRequest] } })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: /History/ }))

    expect(await screen.findByRole('heading', { name: decidedRequest.reason })).toBeInTheDocument()
    expect(screen.getByText('By Bob')).toBeInTheDocument()
    expect(screen.getByText('TTL 1h')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Approve/ })).not.toBeInTheDocument()
  })

  it('revokes an active grant', async () => {
    const user = userEvent.setup()
    const fake = signedIn({ initialSnapshot: { activeGrants: [activeGrant] } })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: /Active grants/ }))
    expect(await screen.findByText('Approved by Bob')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Revoke kv/data/staging/db' }))

    expect(await screen.findByText('Revoked kv/data/staging/db.')).toBeInTheDocument()
    expect(fake.requests<RevokeGrantRequest>('RevokeGrant')[0].grantId).toBe('grant-1')
    expect(await screen.findByText('No active grants')).toBeInTheDocument()
  })

  it('shows revocation errors above the grant list', async () => {
    const user = userEvent.setup()
    const fake = signedIn({
      initialSnapshot: { activeGrants: [activeGrant] },
      handlers: { revokeGrant: () => { throw rpcError(Code.Unavailable, 'OPENBAO_UNAVAILABLE') } },
    })

    render(<App client={fake.client} />)

    await user.click(await screen.findByRole('button', { name: /Active grants/ }))
    await user.click(await screen.findByRole('button', { name: 'Revoke kv/data/staging/db' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('OpenBao is unavailable. Try again shortly.')
    expect(screen.getByRole('button', { name: 'Revoke kv/data/staging/db' })).toBeInTheDocument()
  })

  describe('grantable rules', () => {
    const discovered = Array.from({ length: 7 }, (_, index) => `github/token/repo-${index + 1}`)
    const grantables = [
      { name: 'github', path: 'github/token/+', capabilities: ['read'], maxTtl: hours(1), description: 'Repository-scoped GitHub tokens', paths: discovered },
      { name: 'local-kv', path: 'kv/data/opencode/*', capabilities: ['read', 'update'], maxTtl: hours(8), discoverError: 'permission denied' },
    ]

    async function openCatalog(user: ReturnType<typeof userEvent.setup>) {
      await user.click(await screen.findByRole('button', { name: /Grantable rules/ }))
      return screen.findByRole('list', { name: 'Grantable rules' })
    }

    it('lists each rule with its discovered paths and discovery errors', async () => {
      const user = userEvent.setup()
      const fake = signedIn({ grantables })

      render(<App client={fake.client} />)
      expect(fake.callsTo('ListGrantableRules')).toHaveLength(0)
      const list = await openCatalog(user)

      const github = within(list).getByRole('heading', { name: 'github' }).closest('li')!
      expect(within(github).getByText('github/token/+')).toBeInTheDocument()
      expect(within(github).getByText('Repository-scoped GitHub tokens')).toBeInTheDocument()
      expect(within(github).getByText('Max TTL 1h')).toBeInTheDocument()
      expect(within(github).getByText('read')).toBeInTheDocument()
      expect(within(within(github).getByRole('list', { name: 'Discovered paths for github' })).getAllByRole('listitem')).toHaveLength(5)
      expect(within(github).getByText('2 more paths')).toBeInTheDocument()
      expect(within(github).getByRole('list', { name: 'More discovered paths for github', hidden: true })).toHaveTextContent('github/token/repo-7')

      const kv = within(list).getByRole('heading', { name: 'local-kv' }).closest('li')!
      expect(within(kv).getByText('Max TTL 8h')).toBeInTheDocument()
      expect(within(kv).getByText(/Path discovery failed: permission denied/)).toBeInTheDocument()
      expect(within(kv).queryByText('Discovered paths')).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Grantable rules/ })).toHaveTextContent('2')
    })

    it('shows an empty catalog', async () => {
      const user = userEvent.setup()
      const fake = signedIn()

      render(<App client={fake.client} />)
      await user.click(await screen.findByRole('button', { name: /Grantable rules/ }))

      expect(await screen.findByText('No grantable rules')).toBeInTheDocument()
    })

    it('reloads the catalog on refresh without restarting the stream', async () => {
      const user = userEvent.setup()
      let current = [grantables[1]]
      const fake = signedIn({ handlers: { listGrantableRules: () => ({ grantables: current }) } })

      render(<App client={fake.client} />)
      const list = await openCatalog(user)
      expect(within(list).getByRole('heading', { name: 'local-kv' })).toBeInTheDocument()

      current = grantables
      await user.click(screen.getByRole('button', { name: 'Refresh' }))

      expect(await within(list).findByRole('heading', { name: 'github' })).toBeInTheDocument()
      expect(fake.callsTo('ListGrantableRules')).toHaveLength(2)
      expect(fake.streams).toHaveLength(1)
    })

    it('reports load errors and retries', async () => {
      const user = userEvent.setup()
      let fail = true
      const fake = signedIn({
        handlers: {
          listGrantableRules: () => {
            if (fail) throw rpcError(Code.Unavailable, 'OPENBAO_UNAVAILABLE')
            return { grantables }
          },
        },
      })

      render(<App client={fake.client} />)
      await user.click(await screen.findByRole('button', { name: /Grantable rules/ }))

      expect(await screen.findByRole('alert')).toHaveTextContent('OpenBao is unavailable. Try again shortly.')
      fail = false
      await user.click(screen.getByRole('button', { name: 'Retry' }))

      expect(await screen.findByRole('list', { name: 'Grantable rules' })).toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })
  })

  it('keeps the operator signed in and offers a retry when logout fails', async () => {
    const user = userEvent.setup()
    let attempts = 0
    const fake = signedIn({
      handlers: {
        logout: () => {
          attempts += 1
          if (attempts === 1) throw rpcError(Code.Unavailable, 'OPENBAO_UNAVAILABLE')
          return {}
        },
      },
    })

    render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('OpenBao is unavailable. Try again shortly.')
    expect(fake.streams[0].aborted).toBe(false)

    await user.click(within(alert).getByRole('button', { name: 'Retry sign out' }))

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
    expect(attempts).toBe(2)
    expect(fake.callsTo('Logout')).toHaveLength(2)
    await waitFor(() => expect(fake.streams[0].aborted).toBe(true))
  })

  it('treats an unauthenticated logout as an expired signed-out session', async () => {
    const user = userEvent.setup()
    const fake = signedIn({
      handlers: { logout: () => { throw rpcError(Code.Unauthenticated, 'SESSION_EXPIRED') } },
    })

    render(<App client={fake.client} />)

    expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(await screen.findByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
  })

  describe('push notifications', () => {
    function stubPush(existing: PushSubscription | null = null) {
      const subscription = {
        endpoint: 'https://push.example/device',
        toJSON: () => ({ endpoint: 'https://push.example/device', keys: { p256dh: 'p256-key', auth: 'auth-key' } }),
        unsubscribe: vi.fn(async () => true),
      }
      const pushManager = {
        getSubscription: vi.fn(async () => existing),
        subscribe: vi.fn(async () => subscription),
      }
      vi.stubGlobal('Notification', { requestPermission: vi.fn(async () => 'granted') })
      vi.stubGlobal('PushManager', function PushManager() {})
      Object.defineProperty(navigator, 'serviceWorker', {
        configurable: true,
        value: { ready: Promise.resolve({ pushManager }) },
      })
      return { pushManager, subscription }
    }

    afterEach(() => {
      Reflect.deleteProperty(navigator, 'serviceWorker')
    })

    it('enrolls this device through the push RPCs', async () => {
      const user = userEvent.setup()
      const { pushManager } = stubPush()
      const fake = signedIn()

      render(<App client={fake.client} />)

      await user.click(await screen.findByRole('button', { name: 'Enable notifications' }))

      expect(await screen.findByText('Notifications enabled. Alerts never include request details.')).toBeInTheDocument()
      expect(fake.callsTo('GetPushPublicKey')).toHaveLength(1)
      expect(pushManager.subscribe).toHaveBeenCalledWith(expect.objectContaining({ userVisibleOnly: true }))
      expect(fake.requests<RegisterPushSubscriptionRequest>('RegisterPushSubscription')[0]).toEqual(expect.objectContaining({
        endpoint: 'https://push.example/device',
        p256dh: 'p256-key',
        auth: 'auth-key',
      }))
    })

    it('removes this device through the push RPCs', async () => {
      const user = userEvent.setup()
      const { subscription } = stubPush()
      const fake = signedIn()

      render(<App client={fake.client} />)

      await user.click(await screen.findByRole('button', { name: 'Enable notifications' }))
      await screen.findByText('Notifications enabled. Alerts never include request details.')
      stubPush(subscription as unknown as PushSubscription)
      await user.click(screen.getByRole('button', { name: 'Disable notifications' }))

      expect(await screen.findByText('Notifications disabled for this device.')).toBeInTheDocument()
      expect(fake.requests<DeletePushSubscriptionRequest>('DeletePushSubscription')[0].endpoint).toBe('https://push.example/device')
      expect(subscription.unsubscribe).toHaveBeenCalled()
    })

    it('explains when the server has push disabled', async () => {
      const user = userEvent.setup()
      stubPush()
      const fake = signedIn({ handlers: { getPushPublicKey: () => ({ publicKey: '' }) } })

      render(<App client={fake.client} />)

      await user.click(await screen.findByRole('button', { name: 'Enable notifications' }))

      expect(await screen.findByText('Push notifications are not configured on this server.')).toBeInTheDocument()
      expect(fake.callsTo('RegisterPushSubscription')).toHaveLength(0)
    })
  })
})
