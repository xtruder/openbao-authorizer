import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { timestampDate, type Timestamp } from '@bufbuild/protobuf/wkt'
import { ConnectError } from '@connectrpc/connect'
import { createApproverClient, errorReason, getErrorMessage, isSessionLost, type ApproverClient, type Session } from './api'
import { formatDuration, parseDuration } from './duration'
import { Decision, type DashboardSnapshot, type Identity } from './gen/openbao/authorizer/v1/approver_pb'
import { ItemState, type AgentSession, type Grant, type GrantRequest, type PermissionItem } from './gen/openbao/authorizer/v1/types_pb'
import { pushEnrollmentErrorMessage } from './push'
import {
  BellIcon,
  CheckIcon,
  ChevronIcon,
  ClockIcon,
  CloseIcon,
  InboxIcon,
  KeyIcon,
  LogOutIcon,
  RefreshIcon,
  ShieldIcon,
  UserIcon,
  WifiOffIcon,
} from './components/Icons'
import type { ConnectionState, DashboardTab } from './types'

const defaultClient = createApproverClient()

type AuthState =
  | { status: 'checking' }
  | { status: 'signed-out' }
  | { status: 'unavailable'; message: string }
  | { status: 'signed-in'; session: Session }

function identityName(identity: Identity | undefined) {
  return identity?.displayName.trim() || 'Authenticated operator'
}

function initials(value: string) {
  return value
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'OP'
}

function formatDate(value: Timestamp | undefined) {
  if (!value) return ''
  const date = timestampDate(value)
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date)
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <div className={`${compact ? 'size-9' : 'size-11'} brand-mark`} aria-hidden="true">
        <ShieldIcon className={compact ? 'size-5' : 'size-6'} />
      </div>
      <div className="leading-none">
        <div className={`${compact ? 'text-[15px]' : 'text-lg'} font-semibold tracking-[-0.02em] text-white`}>OpenBao</div>
        <div className="mt-1 text-[10px] font-semibold uppercase tracking-[0.17em] text-zinc-400">Authorizer</div>
      </div>
    </div>
  )
}

function LoadingScreen() {
  return (
    <main className="grid min-h-svh place-items-center bg-ink px-6 text-white">
      <div className="flex flex-col items-center gap-5" role="status" aria-live="polite">
        <Brand />
        <span className="loader" aria-hidden="true" />
        <p className="text-sm text-zinc-400">Checking your secure session…</p>
      </div>
    </main>
  )
}

function SessionUnavailable({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <main className="grid min-h-svh place-items-center bg-ink px-6 text-white">
      <div className="flex max-w-sm flex-col items-center gap-5 text-center">
        <Brand />
        <p role="alert" className="text-sm text-zinc-300">{message}</p>
        <button type="button" onClick={onRetry} className="secondary-button">Retry</button>
      </div>
    </main>
  )
}

function Login({ client, onAuthenticated }: { client: ApproverClient; onAuthenticated: (session: Session) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!username.trim() || !password || submitting) return
    setSubmitting(true)
    setError('')
    try {
      const response = await client.login({ username: username.trim(), password })
      setPassword('')
      onAuthenticated({ identity: response.identity })
    } catch (caught) {
      setError(getErrorMessage(caught, 'Unable to sign in. Check your username and password.'))
    } finally {
      setPassword('')
      setSubmitting(false)
    }
  }

  return (
    <main className="min-h-svh bg-ink text-white lg:grid lg:grid-cols-[minmax(0,1.08fr)_minmax(440px,0.92fr)]">
      <section className="relative hidden min-h-svh overflow-hidden border-r border-white/10 px-12 py-10 lg:flex lg:flex-col xl:px-20 xl:py-14">
        <div className="login-grid absolute inset-0 opacity-30" aria-hidden="true" />
        <div className="login-glow absolute -left-36 top-1/4 size-[38rem] rounded-full" aria-hidden="true" />
        <div className="relative z-10"><Brand /></div>
        <div className="relative z-10 my-auto max-w-2xl pb-10">
          <div className="eyebrow mb-7"><span className="size-1.5 rounded-full bg-brand shadow-[0_0_14px_rgba(245,207,45,.8)]" /> Privileged access workflow</div>
          <h1 className="max-w-xl text-5xl font-semibold leading-[1.04] tracking-[-0.045em] text-white xl:text-6xl">
            Sensitive changes.<br /><span className="text-brand">Human judgment.</span>
          </h1>
          <p className="mt-7 max-w-lg text-lg leading-8 text-zinc-400">
            Review what AI agent sessions ask for, decide each permission on its own, and revoke access at any time.
          </p>
          <div className="mt-12 grid max-w-xl grid-cols-3 gap-3">
            {[
              ['01', 'Authenticate'],
              ['02', 'Review request'],
              ['03', 'Grant access'],
            ].map(([number, label]) => (
              <div key={number} className="border-t border-white/15 pt-4">
                <span className="font-mono text-xs text-brand">{number}</span>
                <p className="mt-2 text-sm font-medium text-zinc-300">{label}</p>
              </div>
            ))}
          </div>
        </div>
        <p className="relative z-10 text-xs text-zinc-600">Your password is exchanged directly for a renewable OpenBao session and is never stored by this app.</p>
      </section>

      <section className="flex min-h-svh items-center justify-center px-5 py-10 sm:px-10 lg:px-12">
        <div className="w-full max-w-[430px]">
          <div className="mb-12 lg:hidden"><Brand /></div>
          <div className="mb-9">
            <div className="mb-6 grid size-12 place-items-center rounded-sm border border-white/10 bg-white/[0.04] text-brand">
              <KeyIcon className="size-6" />
            </div>
            <h2 className="text-3xl font-semibold tracking-[-0.035em] text-white">Operator sign in</h2>
            <p className="mt-3 leading-7 text-zinc-400">Sign in with your OpenBao username and password. Your secure session stays active for background access-request notifications.</p>
          </div>

          <form onSubmit={submit} className="space-y-5">
            <div>
              <label htmlFor="username" className="mb-2.5 block text-sm font-medium text-zinc-200">Username</label>
              <input
                id="username"
                name="username"
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                required
                className="secure-input"
              />
            </div>
            <div>
              <label htmlFor="password" className="mb-2.5 block text-sm font-medium text-zinc-200">Password</label>
              <div className="group relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  required
                  className="secure-input"
                  aria-describedby="password-help"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((visible) => !visible)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded-sm px-2 py-1 text-xs font-semibold text-zinc-400 transition hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              <p id="password-help" className="mt-2.5 flex items-center gap-2 text-xs leading-5 text-zinc-500">
                <ShieldIcon className="size-3.5 shrink-0" /> Sent to OpenBao over the server connection and never retained.
              </p>
            </div>

            {error && <div role="alert" className="error-banner">{error}</div>}

            <button type="submit" disabled={!username.trim() || !password || submitting} className="primary-button w-full">
              {submitting ? <><span className="button-spinner" /> Authenticating…</> : <>Sign in securely <ChevronIcon className="size-4" /></>}
            </button>
          </form>

          <div className="mt-8 border-t border-white/10 pt-6">
            <p className="text-xs leading-5 text-zinc-500">
              The secure HTTP-only session lasts 30 days while the server renews its OpenBao token. Signing out revokes that token and browser access.
            </p>
          </div>
        </div>
      </section>
    </main>
  )
}

function ConnectionBadge({ state }: { state: ConnectionState }) {
  const labels: Record<ConnectionState, string> = {
    connected: 'Live',
    connecting: 'Connecting',
    reconnecting: 'Reconnecting',
    offline: 'Offline',
  }
  return (
    <div className={`connection-badge connection-${state}`} title={`Event stream: ${labels[state]}`}>
      {state === 'offline' ? <WifiOffIcon className="size-3.5" /> : <span className="connection-dot" />}
      <span>{labels[state]}</span>
    </div>
  )
}

// Slugs match the status-* classes in index.css.
const stateStyles: Record<ItemState, { label: string; slug: string }> = {
  [ItemState.UNSPECIFIED]: { label: 'Unknown', slug: 'unspecified' },
  [ItemState.PENDING]: { label: 'Pending', slug: 'pending' },
  [ItemState.ALREADY_GRANTED]: { label: 'Already granted', slug: 'already_granted' },
  [ItemState.APPROVED]: { label: 'Approved', slug: 'approved' },
  [ItemState.REJECTED]: { label: 'Rejected', slug: 'rejected' },
  [ItemState.REFUSED]: { label: 'Refused', slug: 'refused' },
  [ItemState.EXPIRED]: { label: 'Expired', slug: 'expired' },
  [ItemState.REVOKED]: { label: 'Revoked', slug: 'revoked' },
}

function sessionLabel(session: AgentSession) {
  return session.title.trim() || `Session ${session.id}`
}

function SessionDetails({ session }: { session: AgentSession | undefined }) {
  if (!session) return null
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-zinc-500">
      <span className="inline-flex min-w-0 items-center gap-1.5 font-medium text-zinc-800"><UserIcon className="size-3.5 shrink-0" /><span className="truncate">{sessionLabel(session)}</span></span>
      <span className="font-mono text-[11px]" title="Agent session ID">{session.id}</span>
      {session.directory && <span className="min-w-0 truncate font-mono text-[11px]" title={session.directory}>{session.directory}</span>}
    </div>
  )
}

function ItemRow({ item, busy, disabled, onDecide }: {
  item: PermissionItem
  busy: boolean
  disabled: boolean
  onDecide?: (item: PermissionItem, decision: Decision, ttl?: string) => void
}) {
  const resolvedTtl = formatDuration(item.ttl)
  const [ttl, setTtl] = useState(resolvedTtl)
  const pending = item.state === ItemState.PENDING && onDecide
  const style = stateStyles[item.state] ?? stateStyles[ItemState.UNSPECIFIED]

  function approve() {
    const trimmed = ttl.trim()
    // Only send a TTL the approver actually changed; the server rejects longer ones.
    onDecide?.(item, Decision.APPROVE, trimmed && trimmed !== resolvedTtl ? trimmed : undefined)
  }

  return (
    <li className="item-row">
      <div className="min-w-0 flex-1">
        <div className="mb-1.5 flex flex-wrap items-center gap-2">
          <span className={`status-pill status-${style.slug}`}>{style.label}</span>
          {item.capabilities.map((capability) => <span key={capability} className="operation-pill">{capability}</span>)}
        </div>
        <p className="break-all font-mono text-[13px] font-semibold text-zinc-900">{item.path}</p>
        <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
          {item.reason && <span>{item.reason}</span>}
          {!pending && resolvedTtl && item.state !== ItemState.REFUSED && <span>TTL {resolvedTtl}</span>}
          {item.decidedBy && <span>By {item.decidedBy}</span>}
          {item.expiresAt && item.state !== ItemState.PENDING && <span className="inline-flex items-center gap-1"><ClockIcon className="size-3.5" />{item.state === ItemState.REVOKED ? 'Was due to expire' : 'Expires'} {formatDate(item.expiresAt)}</span>}
          {item.expiresAt && item.state === ItemState.PENDING && <span className="inline-flex items-center gap-1"><ClockIcon className="size-3.5" />Undecided after {formatDate(item.expiresAt)}</span>}
        </div>
      </div>
      {pending && (
        <div className="item-actions">
          <label className="ttl-field">
            <span>TTL</span>
            <input
              type="text"
              value={ttl}
              onChange={(event) => setTtl(event.target.value)}
              aria-label={`TTL for ${item.path}`}
              title="Shorten the grant, for example 30m or 2h"
              inputMode="text"
              autoCapitalize="none"
              spellCheck={false}
            />
          </label>
          <button type="button" onClick={() => onDecide?.(item, Decision.REJECT)} disabled={disabled} className="reject-button compact" aria-label={`Reject ${item.path}`}>
            <CloseIcon className="size-4" />Reject
          </button>
          <button type="button" onClick={approve} disabled={disabled} className="approve-button compact" aria-label={`Approve ${item.path}`}>
            {busy ? <span className="button-spinner dark" /> : <CheckIcon className="size-4" />}Approve
          </button>
        </div>
      )}
    </li>
  )
}

function RequestCard({ request, highlighted, busyItemId, error, onDecide }: {
  request: GrantRequest
  highlighted: boolean
  busyItemId: string | null
  error: string
  onDecide?: (request: GrantRequest, item: PermissionItem, decision: Decision, ttl?: string) => void
}) {
  const headingRef = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    if (!highlighted) return
    headingRef.current?.scrollIntoView?.({ block: 'center' })
    headingRef.current?.focus()
  }, [highlighted])

  return (
    <article className={`request-card ${highlighted ? 'highlighted' : ''}`} aria-labelledby={`request-${request.id}`}>
      <header className="request-card-header">
        <SessionDetails session={request.session} />
        <h3 ref={headingRef} id={`request-${request.id}`} tabIndex={-1} className="mt-3 text-[15px] font-medium leading-6 text-zinc-950 whitespace-pre-wrap break-words">{request.reason}</h3>
        <p className="mt-1.5 inline-flex items-center gap-1.5 text-xs text-zinc-400"><ClockIcon className="size-3.5" />Requested {formatDate(request.createdAt)}</p>
      </header>
      {error && <div role="alert" className="mx-4 mt-3 rounded-sm border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700 sm:mx-6">{error}</div>}
      <ul className="divide-y divide-zinc-100" aria-label="Permission items">
        {request.items.map((item) => (
          <ItemRow
            key={`${item.id}-${item.state}`}
            item={item}
            busy={busyItemId === item.id}
            disabled={busyItemId !== null}
            onDecide={onDecide ? (target, decision, ttl) => onDecide(request, target, decision, ttl) : undefined}
          />
        ))}
      </ul>
    </article>
  )
}

function GrantRow({ grant, busy, disabled, onRevoke }: { grant: Grant; busy: boolean; disabled: boolean; onRevoke: (grant: Grant) => void }) {
  return (
    <li className="item-row">
      <div className="min-w-0 flex-1">
        <div className="mb-1.5 flex flex-wrap items-center gap-2">
          {grant.capabilities.map((capability) => <span key={capability} className="operation-pill">{capability}</span>)}
        </div>
        <p className="break-all font-mono text-[13px] font-semibold text-zinc-900">{grant.path}</p>
        <div className="mt-2"><SessionDetails session={grant.session} /></div>
        <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
          <span className="inline-flex items-center gap-1"><ClockIcon className="size-3.5" />Expires {formatDate(grant.expiresAt)}</span>
          {grant.approvedBy && <span>Approved by {grant.approvedBy}</span>}
        </div>
      </div>
      <div className="item-actions">
        <button type="button" onClick={() => onRevoke(grant)} disabled={disabled} className="reject-button compact" aria-label={`Revoke ${grant.path}`}>
          {busy ? <span className="button-spinner dark" /> : <CloseIcon className="size-4" />}Revoke
        </button>
      </div>
    </li>
  )
}

function EmptyState({ tab }: { tab: DashboardTab }) {
  const content = {
    pending: ['Queue is clear', 'New access requests from agent sessions will appear here as they arrive.'],
    history: ['No decided requests', 'Requests leave the queue once every item is decided, refused or expired.'],
    grants: ['No active grants', 'Approved permissions appear here until they expire or you revoke them.'],
  }[tab]
  return (
    <div className="grid min-h-[390px] place-items-center px-6 py-16 text-center">
      <div>
        <div className="mx-auto grid size-14 place-items-center rounded-full border border-zinc-200 bg-zinc-50 text-zinc-400">
          {tab === 'pending' ? <InboxIcon className="size-6" /> : tab === 'history' ? <ClockIcon className="size-6" /> : <KeyIcon className="size-6" />}
        </div>
        <h3 className="mt-5 text-base font-semibold text-zinc-900">{content[0]}</h3>
        <p className="mx-auto mt-2 max-w-xs text-sm leading-6 text-zinc-500">{content[1]}</p>
      </div>
    </div>
  )
}

function urlBase64ToUint8Array(value: string) {
  const padding = '='.repeat((4 - value.length % 4) % 4)
  const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/')
  const raw = window.atob(base64)
  return Uint8Array.from(raw, (character) => character.charCodeAt(0))
}

const RECONNECT_BASE_DELAY_MS = 1_000
const RECONNECT_MAX_DELAY_MS = 30_000
// The server heartbeats every 25s, so a silent stream is a dead one that the
// browser has not noticed, e.g. behind a proxy that dropped it.
const STREAM_IDLE_TIMEOUT_MS = 60_000
// Timers are throttled in background tabs, so a page coming back is checked
// against a single missed heartbeat instead.
const STREAM_STALE_MS = 30_000

// Outside the effect because oxlint's effect-dependency check stops at for-await loops.
async function forEachEvent<T>(events: AsyncIterable<T>, onEvent: (event: T) => void) {
  for await (const event of events) onEvent(event)
}

function Dashboard({ client, session, onSignedOut }: { client: ApproverClient; session: Session; onSignedOut: () => void }) {
  const [pending, setPending] = useState<GrantRequest[]>([])
  const [history, setHistory] = useState<GrantRequest[]>([])
  const [grants, setGrants] = useState<Grant[]>([])
  const [tab, setTab] = useState<DashboardTab>('pending')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [connection, setConnection] = useState<ConnectionState>(navigator.onLine ? 'connecting' : 'offline')
  const [busyItemId, setBusyItemId] = useState<string | null>(null)
  const [busyGrantId, setBusyGrantId] = useState<string | null>(null)
  const [cardErrors, setCardErrors] = useState<Record<string, string>>({})
  const [grantError, setGrantError] = useState('')
  const [highlightedId, setHighlightedId] = useState<string | null>(null)
  const [signingOut, setSigningOut] = useState(false)
  const [signOutError, setSignOutError] = useState('')
  const [notificationStatus, setNotificationStatus] = useState<'idle' | 'enabling' | 'enabled' | 'disabling' | 'unsupported'>(() => {
    if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) return 'unsupported'
    return 'idle'
  })
  const [notice, setNotice] = useState('')
  const linkedRequestId = useRef(new URLSearchParams(window.location.search).get('request'))
  // Set by the stream effect. A fresh stream starts with a full snapshot, so restarting doubles as a refresh.
  const stream = useRef({ restart: () => {}, stop: () => {} })

  function restartStream(background = false) {
    if (background && navigator.onLine) setRefreshing(true)
    stream.current.restart()
  }

  useEffect(() => {
    let controller: AbortController | null = null
    let retryTimeout: number | null = null
    let watchdog: number | null = null
    let lastMessageAt = Date.now()
    let failures = 0
    let receivedSnapshot = false
    let disposed = false

    function stop() {
      if (retryTimeout !== null) {
        window.clearTimeout(retryTimeout)
        retryTimeout = null
      }
      clearWatchdog()
      controller?.abort()
      controller = null
    }

    function clearWatchdog() {
      if (watchdog !== null) {
        window.clearTimeout(watchdog)
        watchdog = null
      }
    }

    function armWatchdog() {
      lastMessageAt = Date.now()
      clearWatchdog()
      watchdog = window.setTimeout(() => void connect(true), STREAM_IDLE_TIMEOUT_MS)
    }

    function applySnapshot(snapshot: DashboardSnapshot) {
      receivedSnapshot = true
      setPending(snapshot.pendingRequests)
      setHistory(snapshot.decidedRequests)
      setGrants(snapshot.activeGrants)
      setError('')
      setLoading(false)
      setRefreshing(false)
    }

    async function connect(reconnecting: boolean) {
      if (disposed || !navigator.onLine) return
      stop()
      const current = new AbortController()
      controller = current
      setConnection(reconnecting ? 'reconnecting' : 'connecting')
      armWatchdog()
      try {
        await forEachEvent(client.watchEvents({}, { signal: current.signal }), (response) => {
          // Heartbeats only prove the stream is healthy.
          armWatchdog()
          failures = 0
          setConnection('connected')
          if (response.event.case === 'snapshot') applySnapshot(response.event.value)
        })
      } catch (caught) {
        if (current.signal.aborted) return
        if (isSessionLost(caught)) {
          disposed = true
          stop()
          onSignedOut()
          return
        }
        if (!receivedSnapshot) setError(getErrorMessage(caught, 'Unable to load access requests.'))
      }
      if (disposed || current.signal.aborted) return
      // A stream that ends cleanly is a drop too; the next snapshot is the truth.
      clearWatchdog()
      controller = null
      setRefreshing(false)
      setConnection(navigator.onLine ? 'reconnecting' : 'offline')
      if (!navigator.onLine) return
      const delay = Math.min(RECONNECT_BASE_DELAY_MS * 2 ** failures, RECONNECT_MAX_DELAY_MS)
      failures += 1
      retryTimeout = window.setTimeout(() => void connect(true), delay)
    }

    function onOnline() {
      failures = 0
      void connect(true)
    }
    function onOffline() {
      setConnection('offline')
      stop()
    }
    function onVisibilityChange() {
      if (document.visibilityState === 'visible' && Date.now() - lastMessageAt >= STREAM_STALE_MS) void connect(true)
    }

    stream.current = {
      restart: () => {
        failures = 0
        receivedSnapshot = false
        void connect(true)
      },
      stop: () => {
        disposed = true
        stop()
      },
    }
    void connect(false)
    window.addEventListener('online', onOnline)
    window.addEventListener('offline', onOffline)
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => {
      disposed = true
      stop()
      window.removeEventListener('online', onOnline)
      window.removeEventListener('offline', onOffline)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [client, onSignedOut])

  useEffect(() => {
    if (!notice) return
    const timeout = window.setTimeout(() => setNotice(''), 4500)
    return () => window.clearTimeout(timeout)
  }, [notice])

  useEffect(() => {
    if (loading || !linkedRequestId.current) return
    const id = linkedRequestId.current
    const inPending = pending.some((request) => request.id === id)
    const inHistory = history.some((request) => request.id === id)
    if (!inPending && !inHistory) return
    setTab(inPending ? 'pending' : 'history')
    setHighlightedId(id)
    linkedRequestId.current = null
  }, [loading, pending, history])

  const operatorName = identityName(session.identity)
  const pendingItemCount = useMemo(() => pending.reduce((count, request) => count + request.items.filter((item) => item.state === ItemState.PENDING).length, 0), [pending])

  async function decide(request: GrantRequest, item: PermissionItem, decision: Decision, ttlText?: string) {
    if (busyItemId) return
    const ttl = ttlText ? parseDuration(ttlText) : undefined
    if (ttlText && !ttl) {
      setCardErrors((current) => ({ ...current, [request.id]: `Enter the TTL as a duration such as 30m or 2h, not "${ttlText}".` }))
      return
    }
    setBusyItemId(item.id)
    setCardErrors((current) => ({ ...current, [request.id]: '' }))
    try {
      const { grantRequest: updated } = await client.decideItems({
        grantRequestId: request.id,
        decisions: [{ itemId: item.id, decision, ttl }],
      })
      // The next snapshot also covers joined items in other requests and new grants.
      if (updated) setPending((current) => current.map((candidate) => candidate.id === updated.id ? updated : candidate))
      setNotice(decision === Decision.APPROVE ? `Granted ${item.path}.` : `Rejected ${item.path}.`)
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      if (errorReason(caught) === 'ITEM_NOT_PENDING') {
        setNotice(getErrorMessage(caught, 'That item was already decided.'))
        return
      }
      setCardErrors((current) => ({ ...current, [request.id]: getErrorMessage(caught, 'Decision failed. Try again.') }))
    } finally {
      setBusyItemId(null)
    }
  }

  async function revoke(grant: Grant) {
    if (busyGrantId) return
    setBusyGrantId(grant.id)
    setGrantError('')
    try {
      await client.revokeGrant({ grantId: grant.id })
      setGrants((current) => current.filter((candidate) => candidate.id !== grant.id))
      setNotice(`Revoked ${grant.path}.`)
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      if (errorReason(caught) === 'GRANT_NOT_ACTIVE') {
        setGrants((current) => current.filter((candidate) => candidate.id !== grant.id))
        setNotice(getErrorMessage(caught, 'That grant is no longer active.'))
        return
      }
      setGrantError(getErrorMessage(caught, 'Revocation failed. Try again.'))
    } finally {
      setBusyGrantId(null)
    }
  }

  async function signOut() {
    if (signingOut) return
    setSigningOut(true)
    setSignOutError('')
    try {
      await client.logout({})
      stream.current.stop()
      onSignedOut()
    } catch (caught) {
      if (isSessionLost(caught)) {
        stream.current.stop()
        onSignedOut()
        return
      }
      setSignOutError(getErrorMessage(caught, 'Unable to sign out. Try again.'))
    } finally {
      setSigningOut(false)
    }
  }

  async function enableNotifications() {
    if (notificationStatus === 'unsupported' || notificationStatus === 'enabling') return
    setNotificationStatus('enabling')
    try {
      const permission = await Notification.requestPermission()
      if (permission !== 'granted') throw new Error('Notification permission was not granted.')
      const [{ publicKey }, registration] = await Promise.all([
        client.getPushPublicKey({}),
        navigator.serviceWorker.ready,
      ])
      if (!publicKey) throw new Error('Push notifications are not configured on this server.')
      let subscription = await registration.pushManager.getSubscription()
      if (!subscription) {
        subscription = await registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        })
      }
      const serialized = subscription.toJSON()
      if (!serialized.endpoint || !serialized.keys?.p256dh || !serialized.keys.auth) {
        throw new Error('The browser returned an incomplete push subscription.')
      }
      await client.registerPushSubscription({
        endpoint: serialized.endpoint,
        p256dh: serialized.keys.p256dh,
        auth: serialized.keys.auth,
      })
      setNotificationStatus('enabled')
      setNotice('Notifications enabled. Alerts never include request details.')
    } catch (caught) {
      setNotificationStatus('idle')
      setNotice(caught instanceof ConnectError
        ? getErrorMessage(caught, 'Unable to enable notifications.')
        : pushEnrollmentErrorMessage(caught, navigator.userAgent))
    }
  }

  async function disableNotifications() {
    if (notificationStatus !== 'enabled') return
    setNotificationStatus('disabling')
    try {
      const registration = await navigator.serviceWorker.ready
      const subscription = await registration.pushManager.getSubscription()
      if (subscription) {
        await client.deletePushSubscription({ endpoint: subscription.endpoint })
        await subscription.unsubscribe()
      }
      setNotificationStatus('idle')
      setNotice('Notifications disabled for this device.')
    } catch (caught) {
      setNotificationStatus('enabled')
      setNotice(getErrorMessage(caught, 'Unable to disable notifications.'))
    }
  }

  const tabs: { id: DashboardTab; label: string; count: number }[] = [
    { id: 'pending', label: 'Pending', count: pendingItemCount },
    { id: 'history', label: 'History', count: history.length },
    { id: 'grants', label: 'Active grants', count: grants.length },
  ]
  const visibleCount = tab === 'pending' ? pending.length : tab === 'history' ? history.length : grants.length

  return (
    <>
      <div className="min-h-svh bg-canvas text-zinc-900">
      <header className="sticky top-0 z-30 border-b border-white/10 bg-ink text-white shadow-[0_1px_0_rgba(0,0,0,.2)]">
        <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-3 px-4 sm:px-6 lg:px-8">
          <Brand compact />
          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            <ConnectionBadge state={connection} />
            <button
              type="button"
              onClick={() => void (notificationStatus === 'enabled' ? disableNotifications() : enableNotifications())}
              disabled={notificationStatus === 'unsupported' || notificationStatus === 'enabling' || notificationStatus === 'disabling'}
              className="header-action"
              title={notificationStatus === 'unsupported' ? 'Push notifications are not supported by this browser' : notificationStatus === 'enabled' ? 'Disable notifications for this device' : 'Enable generic request notifications'}
            >
              <BellIcon className="size-4" />
              <span className="hidden md:inline">{notificationStatus === 'enabled' ? 'Disable notifications' : notificationStatus === 'enabling' ? 'Enabling…' : notificationStatus === 'disabling' ? 'Disabling…' : notificationStatus === 'unsupported' ? 'Unavailable' : 'Enable notifications'}</span>
            </button>
            <div className="hidden h-6 w-px bg-white/10 sm:block" />
            <div className="hidden items-center gap-2.5 sm:flex">
              <div className="grid size-8 place-items-center rounded-full bg-brand text-[10px] font-bold text-zinc-950">{initials(operatorName)}</div>
              <span className="max-w-36 truncate text-xs font-medium text-zinc-300">{operatorName}</span>
            </div>
            <button type="button" onClick={signOut} disabled={signingOut} className="icon-button-dark" aria-label="Sign out" title="Sign out">
              <LogOutIcon className="size-4" />
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1100px] px-4 py-7 sm:px-6 sm:py-9 lg:px-8">
        <div className="mb-7 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="eyebrow text-zinc-500"><span className="size-1.5 rounded-full bg-brand-dark" />Agent session grants</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-zinc-950 sm:text-4xl">Access requests</h1>
            <p className="mt-2 text-sm leading-6 text-zinc-500">Decide each permission an agent session asks for. Approved grants expire on their own.</p>
          </div>
          <button type="button" onClick={() => restartStream(true)} disabled={refreshing} className="secondary-button self-start sm:self-auto">
            <RefreshIcon className={`size-4 ${refreshing ? 'animate-spin' : ''}`} />Refresh
          </button>
        </div>

        {error && (
          <div role="alert" className="mb-5 flex items-center justify-between gap-4 rounded-sm border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <span>{error}</span><button type="button" onClick={() => restartStream()} className="font-semibold underline underline-offset-2">Retry</button>
          </div>
        )}

        {signOutError && (
          <div role="alert" className="mb-5 flex items-center justify-between gap-4 rounded-sm border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <span>{signOutError}</span><button type="button" onClick={() => void signOut()} className="font-semibold underline underline-offset-2">Retry sign out</button>
          </div>
        )}

        <section className="dashboard-shell" aria-label="Access requests">
          <div className="list-toolbar">
            <div className="filter-tabs" role="group" aria-label="Views">
              {tabs.map((entry) => (
                <button key={entry.id} type="button" aria-pressed={tab === entry.id} onClick={() => setTab(entry.id)} className={tab === entry.id ? 'active' : ''}>
                  {entry.label} <span>{entry.count}</span>
                </button>
              ))}
            </div>
            <p className="hidden text-xs text-zinc-400 sm:block">{visibleCount} {tab === 'grants' ? (visibleCount === 1 ? 'grant' : 'grants') : (visibleCount === 1 ? 'request' : 'requests')}</p>
          </div>

          {grantError && tab === 'grants' && <div role="alert" className="mx-4 mt-3 rounded-sm border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700 sm:mx-6">{grantError}</div>}

          {loading ? (
            <div className="space-y-px" aria-label="Loading requests" role="status">
              {[0, 1, 2].map((item) => <div className="request-skeleton" key={item}><div className="size-10 animate-pulse rounded-sm bg-zinc-100" /><div className="flex-1 space-y-3"><div className="h-3 w-24 animate-pulse rounded bg-zinc-100" /><div className="h-3 w-2/3 animate-pulse rounded bg-zinc-100" /><div className="h-2.5 w-1/2 animate-pulse rounded bg-zinc-100" /></div></div>)}
            </div>
          ) : visibleCount === 0 ? <EmptyState tab={tab} /> : tab === 'grants' ? (
            <ul className="divide-y divide-zinc-100" aria-label="Active grants">
              {grants.map((grant) => <GrantRow key={grant.id} grant={grant} busy={busyGrantId === grant.id} disabled={busyGrantId !== null} onRevoke={(target) => void revoke(target)} />)}
            </ul>
          ) : (
            <div className="request-card-list">
              {(tab === 'pending' ? pending : history).map((request) => (
                <RequestCard
                  key={request.id}
                  request={request}
                  highlighted={request.id === highlightedId}
                  busyItemId={busyItemId}
                  error={cardErrors[request.id] ?? ''}
                  onDecide={tab === 'pending' ? (target, item, decision, ttl) => void decide(target, item, decision, ttl) : undefined}
                />
              ))}
            </div>
          )}
        </section>
      </main>

        {notice && <div className="toast" role="status" aria-live="polite"><CheckIcon className="size-4 shrink-0 text-brand-dark" />{notice}</div>}
      </div>
    </>
  )
}

export default function App({ client = defaultClient }: { client?: ApproverClient }) {
  const [auth, setAuth] = useState<AuthState>({ status: 'checking' })

  const restoreSession = useCallback((isActive: () => boolean) => {
    // Without a session cookie this fails and falls through to sign in.
    client.getSession({})
      .then((response) => {
        if (!isActive()) return
        setAuth({ status: 'signed-in', session: { identity: response.identity } })
      })
      .catch((caught: unknown) => {
        if (!isActive()) return
        // An unreachable server says nothing about the cookie, which may still
        // hold a valid session; signing in again would orphan it.
        if (!isSessionLost(caught)) {
          setAuth({ status: 'unavailable', message: getErrorMessage(caught, 'Unable to check your session.') })
          return
        }
        setAuth({ status: 'signed-out' })
      })
  }, [client])

  useEffect(() => {
    let active = true
    restoreSession(() => active)
    return () => { active = false }
  }, [restoreSession])

  const retryRestore = useCallback(() => {
    setAuth({ status: 'checking' })
    restoreSession(() => true)
  }, [restoreSession])

  const signedIn = useCallback((session: Session) => setAuth({ status: 'signed-in', session }), [])
  const signedOut = useCallback(() => setAuth({ status: 'signed-out' }), [])

  if (auth.status === 'checking') return <LoadingScreen />
  if (auth.status === 'unavailable') return <SessionUnavailable message={auth.message} onRetry={retryRestore} />
  if (auth.status === 'signed-out') return <Login client={client} onAuthenticated={signedIn} />
  return <Dashboard client={client} session={auth.session} onSignedOut={signedOut} />
}
