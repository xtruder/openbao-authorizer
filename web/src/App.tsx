import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { api, ApiError } from './api'
import { pushEnrollmentErrorMessage } from './push'
import {
  ArrowLeftIcon,
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
import type { ApprovalContext, ApprovalRequest, ConnectionState, GroupFilter, GroupStatus, Identity, RequestGroup, Session } from './types'

function isSessionLost(error: unknown) {
  return error instanceof ApiError && (error.status === 401 || error.status === 403)
}

type AuthState =
  | { status: 'checking' }
  | { status: 'signed-out' }
  | { status: 'signed-in'; session: Session }

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback
}

function identityName(identity: Identity) {
  const candidate = identity.name ?? identity.displayName ?? identity.display_name ?? identity.alias
  return typeof candidate === 'string' && candidate.trim() ? candidate : 'Authenticated operator'
}

function initials(value: string) {
  return value
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'OP'
}

function formatDate(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.valueOf())) return value
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date)
}

function formatOperation(operation: string) {
  return operation ? operation.charAt(0).toUpperCase() + operation.slice(1).toLowerCase() : 'Unknown'
}

function authorizationLabel(value: unknown) {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const candidate = record.name ?? record.entity_name ?? record.path ?? record.id ?? record.entity_id
    if (typeof candidate === 'string') return candidate
  }
  return JSON.stringify(value)
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

function Login({ onAuthenticated }: { onAuthenticated: (session: Session) => void }) {
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
      const session = await api.createSession(username.trim(), password)
      setPassword('')
      onAuthenticated(session)
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
            Review control group requests, inspect the full context, and authorize critical operations from one secure workspace.
          </p>
          <div className="mt-12 grid max-w-xl grid-cols-3 gap-3">
            {[
              ['01', 'Authenticate'],
              ['02', 'Review context'],
              ['03', 'Authorize'],
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
            <p className="mt-3 leading-7 text-zinc-400">Sign in with your OpenBao username and password. Your secure session stays active for background approval notifications.</p>
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

const statusLabels = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  expired: 'Expired',
  approval_failed: 'Approval failed',
  rejection_failed: 'Rejection failed',
} as const

const statusIconClasses: Record<GroupStatus, string> = {
  pending: 'border-amber-200 bg-amber-50 text-amber-700',
  approved: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  rejected: 'border-red-200 bg-red-50 text-red-700',
  expired: 'border-zinc-200 bg-zinc-50 text-zinc-500',
  approval_failed: 'border-red-200 bg-red-50 text-red-700',
  rejection_failed: 'border-red-200 bg-red-50 text-red-700',
}

function isActionable(status: GroupStatus) {
  return status === 'pending' || status === 'approval_failed' || status === 'rejection_failed'
}

function matchesFilter(group: RequestGroup, filter: GroupFilter) {
  return filter === 'pending' ? isActionable(group.status) : group.status === filter
}

function GroupRow({ group, selected, onSelect }: { group: RequestGroup; selected: boolean; onSelect: (trigger: HTMLButtonElement) => void }) {
  const orderedRequests = [...group.requests].sort((left, right) => left.position - right.position)
  const firstRequest = orderedRequests[0]
  const label = group.reason?.trim() || (group.requests.length === 1 ? firstRequest?.path : `${group.requests.length} related operations`)
  return (
    <button data-review-trigger type="button" onClick={(event) => onSelect(event.currentTarget)} className={`group-row ${selected ? 'selected' : ''}`} aria-label={`Open request group ${label}`} aria-current={selected ? 'true' : undefined}>
      <div className="flex min-w-0 flex-1 gap-3.5 sm:gap-5">
        <div className={`mt-0.5 grid size-10 shrink-0 place-items-center rounded-sm border ${statusIconClasses[group.status]}`}>
          {group.status === 'approved' ? <CheckIcon className="size-5" /> : group.status === 'rejected' || group.status.endsWith('_failed') ? <CloseIcon className="size-5" /> : <ClockIcon className="size-5" />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className={`status-pill status-${group.status}`}>{statusLabels[group.status]}</span>
            <span className="operation-pill">{group.requests.length === 1 ? formatOperation(firstRequest?.operation ?? '') : `${group.requests.length} operations`}</span>
          </div>
          <h3 className="truncate text-[13px] font-semibold text-zinc-900 sm:text-sm" title={label}>{label}</h3>
          {group.reason?.trim() && firstRequest && <p className="mt-1.5 truncate font-mono text-xs text-zinc-500">{firstRequest.path}</p>}
          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-zinc-500">
            <span className="inline-flex items-center gap-1.5"><UserIcon className="size-3.5" />{group.entity.name || group.entity.id}</span>
            <span className="inline-flex items-center gap-1.5"><ClockIcon className="size-3.5" />Updated {formatDate(group.updatedAt)}</span>
          </div>
        </div>
      </div>
    </button>
  )
}

function EmptyState({ filter }: { filter: GroupFilter }) {
  const content = {
    pending: ['Queue is clear', 'New control group requests will appear here as they arrive.'],
    approved: ['No approved groups', 'Groups you fully approve will be collected here.'],
    rejected: ['No rejected groups', 'Groups you reject will be collected here.'],
    expired: ['No expired groups', 'Groups that expire before a decision will be collected here.'],
  }[filter]
  return (
    <div className="grid min-h-[390px] place-items-center px-6 py-16 text-center">
      <div>
        <div className="mx-auto grid size-14 place-items-center rounded-full border border-zinc-200 bg-zinc-50 text-zinc-400">
          {filter === 'pending' ? <InboxIcon className="size-6" /> : filter === 'approved' ? <CheckIcon className="size-6" /> : filter === 'rejected' ? <CloseIcon className="size-6" /> : <ClockIcon className="size-6" />}
        </div>
        <h3 className="mt-5 text-base font-semibold text-zinc-900">{content[0]}</h3>
        <p className="mx-auto mt-2 max-w-xs text-sm leading-6 text-zinc-500">{content[1]}</p>
      </div>
    </div>
  )
}

function ApprovalContextView({ context }: { context: ApprovalContext }) {
  if (!context.available) {
    return (
      <div role="alert" className="rounded-sm border border-red-200 bg-red-50 px-3 py-3 text-sm text-red-700">
        Approval context could not be loaded. Do not approve this request.
      </div>
    )
  }
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="detail-label">Approval context</h3>
        <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-400">Read from OpenBao</span>
      </div>
      <pre className="json-block"><code>{JSON.stringify(context.data, null, 2)}</code></pre>
    </div>
  )
}

function RequestMember({ request, index, count }: { request: ApprovalRequest; index: number; count: number }) {
  return (
    <article className="request-member" aria-labelledby={`request-${request.id}-title`}>
      <div className="request-member-header">
        <div className="min-w-0">
          <p className="detail-label">{count === 1 ? 'Operation' : `Operation ${index + 1} of ${count}`}</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className={`status-pill status-${request.status}`}>{statusLabels[request.status]}</span>
            <span className="operation-pill">{formatOperation(request.operation)}</span>
          </div>
          <h3 id={`request-${request.id}-title`} className="mt-3 break-all font-mono text-sm font-semibold leading-6 text-zinc-950">{request.path}</h3>
        </div>
        {count > 1 && <span className="member-position" aria-label={`Position ${request.position}`}>{request.position}</span>}
      </div>

      {request.approvalContext && (
        <div className="request-member-section">
          <ApprovalContextView context={request.approvalContext} />
        </div>
      )}

      <div className="request-member-section">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h4 className="detail-label">Request payload</h4>
          <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-400">JSON</span>
        </div>
        {request.data === undefined ? (
          <p className="rounded-sm border border-zinc-200 bg-zinc-50 px-3 py-3 text-sm text-zinc-500">Redacted by the server. Enable request payload exposure only when the submitted fields are safe to display.</p>
        ) : (
          <pre className="json-block"><code>{JSON.stringify(request.data, null, 2) ?? 'null'}</code></pre>
        )}
      </div>

      <div className="request-member-section grid gap-4 sm:grid-cols-2">
        <div>
          <h4 className="detail-label">Required authorizations</h4>
          <div className="mt-3 flex flex-wrap gap-2">
            {request.authorizations.length ? request.authorizations.map((authorization, authorizationIndex) => (
              <span key={`${authorizationLabel(authorization)}-${authorizationIndex}`} className="authorization-chip"><ShieldIcon className="size-3.5" />{authorizationLabel(authorization)}</span>
            )) : <span className="text-sm text-zinc-500">No authorization metadata provided.</span>}
          </div>
        </div>
        <div>
          <h4 className="detail-label">Request activity</h4>
          <dl className="mt-2 space-y-1.5 text-xs">
            <div className="flex justify-between gap-3"><dt className="text-zinc-500">First seen</dt><dd className="font-medium text-zinc-700">{formatDate(request.firstSeen)}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-zinc-500">Last seen</dt><dd className="font-medium text-zinc-700">{formatDate(request.lastSeen)}</dd></div>
          </dl>
        </div>
      </div>

      <div className="request-member-section">
        <h4 className="detail-label">Request ID</h4>
        <p className="mt-2 break-all font-mono text-xs text-zinc-600">{request.id}</p>
      </div>
    </article>
  )
}

function GroupDetail({ group, onBack, onApprove, onReject, submitting, actionError }: {
  group: RequestGroup
  onBack: () => void
  onApprove: () => void
  onReject: () => void
  submitting: boolean
  actionError: string
}) {
  const headingRef = useRef<HTMLHeadingElement>(null)
  const orderedRequests = useMemo(() => [...group.requests].sort((left, right) => left.position - right.position), [group.requests])
  const title = group.reason?.trim() || (group.requests.length === 1 ? orderedRequests[0]?.path : `${group.requests.length} related operations`)

  useEffect(() => {
    headingRef.current?.focus()
  }, [])

  return (
    <section className="detail-panel" aria-labelledby="group-detail-title">
      <div className="detail-header">
        <button type="button" onClick={onBack} className="icon-button lg:hidden" aria-label="Back to groups"><ArrowLeftIcon className="size-5" /></button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`status-pill status-${group.status}`}>{group.status === 'pending' ? 'Pending review' : statusLabels[group.status]}</span>
            <span className="operation-pill">{group.requests.length === 1 ? '1 operation' : `${group.requests.length} operations`}</span>
          </div>
          <h2 ref={headingRef} id="group-detail-title" tabIndex={-1} className="mt-3 break-words text-base font-semibold leading-6 text-zinc-950">{title}</h2>
        </div>
        <button type="button" onClick={onBack} className="icon-button hidden lg:grid" aria-label="Close group details"><CloseIcon className="size-4" /></button>
      </div>

      <div className="detail-scroll">
        <div className="detail-section grid gap-4 sm:grid-cols-2">
          <div>
            <p className="detail-label">Requested by</p>
            <div className="mt-2 flex items-center gap-2.5">
              <div className="grid size-8 place-items-center rounded-full bg-zinc-900 text-[10px] font-semibold text-white">{initials(group.entity.name || group.entity.id)}</div>
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-zinc-900">{group.entity.name || 'Unknown entity'}</p>
                <p className="truncate font-mono text-[11px] text-zinc-500">{group.entity.id}</p>
              </div>
            </div>
          </div>
          <div>
            <p className="detail-label">Activity</p>
            <dl className="mt-2 space-y-1.5 text-xs">
              <div className="flex justify-between gap-3"><dt className="text-zinc-500">Created</dt><dd className="font-medium text-zinc-700">{formatDate(group.createdAt)}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-zinc-500">Updated</dt><dd className="font-medium text-zinc-700">{formatDate(group.updatedAt)}</dd></div>
            </dl>
          </div>
        </div>

        <div className="detail-section">
          <h3 className="detail-label">Shared reason</h3>
          <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-zinc-800">{group.reason?.trim() || 'No reason provided.'}</p>
        </div>

        {group.status === 'approval_failed' && (
          <div role="alert" className="group-failure">The last approval attempt failed. Review the group and try again, or reject it.</div>
        )}
        {group.status === 'rejection_failed' && (
          <div role="alert" className="group-failure">The last rejection attempt failed. Review the group and try again, or approve it.</div>
        )}

        <div className="detail-section bg-zinc-50/60">
          <h3 className="detail-label">Operations</h3>
          <div className="mt-3 space-y-3">
            {orderedRequests.map((request, index) => <RequestMember key={request.id} request={request} index={index} count={orderedRequests.length} />)}
          </div>
        </div>

        <div className="detail-section border-b-0">
          <h3 className="detail-label">Group ID</h3>
          <p className="mt-2 break-all font-mono text-xs text-zinc-600">{group.id}</p>
        </div>
      </div>

      <div className="detail-footer">
        {actionError && <div role="alert" className="mb-3 rounded-sm border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700">{actionError}</div>}
        {!isActionable(group.status) ? (
          <div className={`flex w-full items-center justify-center gap-2 rounded-sm border px-4 py-3 text-sm font-semibold status-${group.status}`}>{group.status === 'approved' ? <CheckIcon className="size-4" /> : group.status === 'rejected' ? <CloseIcon className="size-4" /> : <ClockIcon className="size-4" />}{group.status === 'approved' ? 'Fully approved' : statusLabels[group.status]}</div>
        ) : (
          <div className="grid w-full grid-cols-2 gap-2">
            <button type="button" onClick={onReject} disabled={submitting} className="reject-button"><CloseIcon className="size-4" />Reject group</button>
            <button type="button" onClick={onApprove} disabled={submitting} className="approve-button"><ShieldIcon className="size-4" />Approve group</button>
          </div>
        )}
      </div>
    </section>
  )
}

function urlBase64ToUint8Array(value: string) {
  const padding = '='.repeat((4 - value.length % 4) % 4)
  const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/')
  const raw = window.atob(base64)
  return Uint8Array.from(raw, (character) => character.charCodeAt(0))
}

function Dashboard({ session, onSignedOut }: { session: Session; onSignedOut: () => void }) {
  const [groups, setGroups] = useState<RequestGroup[]>([])
  const [filter, setFilter] = useState<GroupFilter>('pending')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null)
  const hadSelectedDetailRef = useRef(false)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [connection, setConnection] = useState<ConnectionState>(navigator.onLine ? 'connecting' : 'offline')
  const [approving, setApproving] = useState(false)
  const [rejecting, setRejecting] = useState(false)
  const [approvalError, setApprovalError] = useState('')
  const [rejectionError, setRejectionError] = useState('')
  const [signingOut, setSigningOut] = useState(false)
  const [signOutError, setSignOutError] = useState('')
  const [notificationStatus, setNotificationStatus] = useState<'idle' | 'enabling' | 'enabled' | 'disabling' | 'unsupported'>(() => {
    if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) return 'unsupported'
    return Notification.permission === 'granted' ? 'idle' : 'idle'
  })
  const [notice, setNotice] = useState('')
  const linkedGroupId = useRef(new URLSearchParams(window.location.search).get('request'))

  const loadGroups = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    setError('')
    try {
      const next = await api.getRequestGroups()
      setGroups(next)
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      setError(getErrorMessage(caught, 'Unable to load approval groups.'))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [onSignedOut])

  useEffect(() => {
      const timeout = window.setTimeout(() => void loadGroups(), 0)
      return () => window.clearTimeout(timeout)
  }, [loadGroups])

  useEffect(() => {
    let source: EventSource | null = null
    let retryTimeout: number | null = null
    let disposed = false

    function connect(reconnecting = false) {
      if (disposed || !navigator.onLine) return
      if (retryTimeout !== null) {
        window.clearTimeout(retryTimeout)
        retryTimeout = null
      }
      source?.close()
      setConnection(reconnecting ? 'reconnecting' : 'connecting')
      const nextSource = new EventSource('/api/v1/events')
      source = nextSource
      nextSource.onopen = () => setConnection('connected')
      nextSource.onerror = () => {
        if (source !== nextSource) return
        nextSource.close()
        setConnection(navigator.onLine ? 'reconnecting' : 'offline')
        if (navigator.onLine) {
          retryTimeout = window.setTimeout(() => connect(true), 1_000)
        }
      }

      const handleUpdate = (event: MessageEvent<string>) => {
        void event
        void loadGroups(true)
      }
      nextSource.addEventListener('new-request', handleUpdate)
      nextSource.addEventListener('status', handleUpdate)
    }

    function onOnline() {
      connect(true)
    }
    function onOffline() {
      setConnection('offline')
      source?.close()
      if (retryTimeout !== null) {
        window.clearTimeout(retryTimeout)
        retryTimeout = null
      }
    }

    connect()
    window.addEventListener('online', onOnline)
    window.addEventListener('offline', onOffline)
    return () => {
      disposed = true
      source?.close()
      if (retryTimeout !== null) window.clearTimeout(retryTimeout)
      window.removeEventListener('online', onOnline)
      window.removeEventListener('offline', onOffline)
    }
  }, [loadGroups])

  useEffect(() => {
    if (!notice) return
    const timeout = window.setTimeout(() => setNotice(''), 4500)
    return () => window.clearTimeout(timeout)
  }, [notice])

  const counts = Object.fromEntries((['pending', 'approved', 'rejected', 'expired'] as GroupFilter[]).map((status) => [status, groups.filter((group) => matchesFilter(group, status)).length])) as Record<GroupFilter, number>
  const visibleGroups = useMemo(() => groups.filter((group) => matchesFilter(group, filter)), [filter, groups])
  const selected = groups.find((group) => group.id === selectedId) ?? null
  const operatorName = identityName(session.identity)

  useEffect(() => {
    if (loading || !linkedGroupId.current) return
    const linkedGroup = groups.find((group) => group.id === linkedGroupId.current)
    if (!linkedGroup) return
    setFilter(isActionable(linkedGroup.status) ? 'pending' : linkedGroup.status)
    setSelectedId(linkedGroup.id)
    linkedGroupId.current = null
  }, [groups, loading])

  useEffect(() => {
    if (selectedId) {
      hadSelectedDetailRef.current = true
      return
    }
    if (hadSelectedDetailRef.current) {
      hadSelectedDetailRef.current = false
      const trigger = detailTriggerRef.current
      if (trigger && trigger.isConnected) {
        trigger.focus()
      } else {
        document.querySelector<HTMLElement>('[data-review-trigger]')?.focus()
      }
    }
  }, [selectedId])

  async function approve(targetGroup: RequestGroup) {
    if (approving || rejecting) return
    setApproving(true)
    setApprovalError('')
    try {
      const refreshed = await api.approveRequestGroup(targetGroup.id, session.csrfToken)
      setGroups((current) => current.map((group) => group.id === refreshed.id ? refreshed : group))
      // The action button is replaced by status, so focus cannot return to it.
      setSelectedId(refreshed.id)
      setNotice(refreshed.status === 'approved'
        ? 'Group fully approved.'
        : refreshed.status === 'pending'
          ? 'Authorization recorded. Required quorum is still pending.'
          : refreshed.status === 'approval_failed'
            ? 'Group approval failed. Review the failure state and try again.'
            : `Group status changed to ${statusLabels[refreshed.status].toLowerCase()}.`)
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      if (caught instanceof ApiError && caught.status === 409) {
        await loadGroups(true)
        setNotice(caught.message)
        return
      }
      setApprovalError(getErrorMessage(caught, 'Approval failed. Try again.'))
    } finally {
      setApproving(false)
    }
  }

  async function reject(targetGroup: RequestGroup) {
    if (approving || rejecting) return
    setRejecting(true)
    setRejectionError('')
    try {
      const refreshed = await api.rejectRequestGroup(targetGroup.id, session.csrfToken)
      setGroups((current) => current.map((group) => group.id === refreshed.id ? refreshed : group))
      setSelectedId(refreshed.id)
      setNotice(refreshed.status === 'rejected'
        ? 'Group rejected and revoked.'
        : refreshed.status === 'rejection_failed'
          ? 'Group rejection failed. Review the failure state and try again.'
          : `Group status changed to ${statusLabels[refreshed.status].toLowerCase()}.`)
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      if (caught instanceof ApiError && caught.status === 409) {
        await loadGroups(true)
        setNotice(caught.message)
        return
      }
      setRejectionError(getErrorMessage(caught, 'Rejection failed. Try again.'))
    } finally {
      setRejecting(false)
    }
  }

  async function signOut() {
    if (signingOut) return
    setSigningOut(true)
    setSignOutError('')
    try {
      await api.deleteSession(session.csrfToken)
      onSignedOut()
    } catch (caught) {
      if (isSessionLost(caught)) {
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
        api.getPushPublicKey(),
        navigator.serviceWorker.ready,
      ])
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
      await api.subscribeToPush({
        endpoint: serialized.endpoint,
        keys: { p256dh: serialized.keys.p256dh, auth: serialized.keys.auth },
      }, session.csrfToken)
      setNotificationStatus('enabled')
      setNotice('Notifications enabled. Alerts never include request details.')
    } catch (caught) {
      setNotificationStatus('idle')
      setNotice(pushEnrollmentErrorMessage(caught, navigator.userAgent))
    }
  }

  async function disableNotifications() {
    if (notificationStatus !== 'enabled') return
    setNotificationStatus('disabling')
    try {
      const registration = await navigator.serviceWorker.ready
      const subscription = await registration.pushManager.getSubscription()
      if (subscription) {
        await api.unsubscribeFromPush(subscription.endpoint, session.csrfToken)
        await subscription.unsubscribe()
      }
      setNotificationStatus('idle')
      setNotice('Notifications disabled for this device.')
    } catch (caught) {
      setNotificationStatus('enabled')
      setNotice(getErrorMessage(caught, 'Unable to disable notifications.'))
    }
  }

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

      <main className="mx-auto max-w-[1600px] px-4 py-7 sm:px-6 sm:py-9 lg:px-8">
        <div className="mb-7 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="eyebrow text-zinc-500"><span className="size-1.5 rounded-full bg-brand-dark" />Control group queue</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-zinc-950 sm:text-4xl">Approval groups</h1>
            <p className="mt-2 text-sm leading-6 text-zinc-500">Review every operation in a group before authorizing privileged access.</p>
          </div>
          <button type="button" onClick={() => void loadGroups(true)} disabled={refreshing} className="secondary-button self-start sm:self-auto">
            <RefreshIcon className={`size-4 ${refreshing ? 'animate-spin' : ''}`} />Refresh
          </button>
        </div>

        {error && (
          <div role="alert" className="mb-5 flex items-center justify-between gap-4 rounded-sm border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <span>{error}</span><button type="button" onClick={() => void loadGroups()} className="font-semibold underline underline-offset-2">Retry</button>
          </div>
        )}

        {signOutError && (
          <div role="alert" className="mb-5 flex items-center justify-between gap-4 rounded-sm border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <span>{signOutError}</span><button type="button" onClick={() => void signOut()} className="font-semibold underline underline-offset-2">Retry sign out</button>
          </div>
        )}

        <div className={`dashboard-shell ${selected ? 'has-detail' : ''}`}>
          <section className={`group-list-panel ${selected ? 'hidden lg:block' : ''}`} aria-label="Approval group queue">
            <div className="list-toolbar">
              <div className="filter-tabs" role="group" aria-label="Filter groups">
                <button type="button" aria-pressed={filter === 'pending'} onClick={() => setFilter('pending')} className={filter === 'pending' ? 'active' : ''}>
                  Pending <span>{counts.pending}</span>
                </button>
                <button type="button" aria-pressed={filter === 'approved'} onClick={() => setFilter('approved')} className={filter === 'approved' ? 'active' : ''}>
                  Approved <span>{counts.approved}</span>
                </button>
                <button type="button" aria-pressed={filter === 'rejected'} onClick={() => setFilter('rejected')} className={filter === 'rejected' ? 'active' : ''}>Rejected <span>{counts.rejected}</span></button>
                <button type="button" aria-pressed={filter === 'expired'} onClick={() => setFilter('expired')} className={filter === 'expired' ? 'active' : ''}>Expired <span>{counts.expired}</span></button>
              </div>
              <p className="hidden text-xs text-zinc-400 sm:block">{visibleGroups.length} {visibleGroups.length === 1 ? 'group' : 'groups'}</p>
            </div>

            {loading ? (
              <div className="space-y-px" aria-label="Loading groups" role="status">
                {[0, 1, 2].map((item) => <div className="group-skeleton" key={item}><div className="size-10 animate-pulse rounded-sm bg-zinc-100" /><div className="flex-1 space-y-3"><div className="h-3 w-24 animate-pulse rounded bg-zinc-100" /><div className="h-3 w-2/3 animate-pulse rounded bg-zinc-100" /><div className="h-2.5 w-1/2 animate-pulse rounded bg-zinc-100" /></div></div>)}
              </div>
            ) : visibleGroups.length ? (
              <div className="divide-y divide-zinc-100">
                {visibleGroups.map((group) => <GroupRow key={group.id} group={group} selected={group.id === selectedId} onSelect={(trigger) => { detailTriggerRef.current = trigger; setSelectedId(group.id) }} />)}
              </div>
            ) : <EmptyState filter={filter} />}
          </section>

          {selected && <GroupDetail key={`${selected.id}-${selected.status}`} group={selected} submitting={approving || rejecting} actionError={approvalError || rejectionError} onBack={() => setSelectedId(null)} onApprove={() => { setApprovalError(''); setRejectionError(''); void approve(selected) }} onReject={() => { setApprovalError(''); setRejectionError(''); void reject(selected) }} />}
          {!selected && (
            <aside className="detail-placeholder hidden lg:grid">
              <div className="max-w-xs text-center">
                <div className="mx-auto grid size-12 place-items-center rounded-full border border-zinc-200 bg-white text-zinc-400"><ShieldIcon className="size-5" /></div>
                <h2 className="mt-4 text-sm font-semibold text-zinc-800">Select a group to review</h2>
                <p className="mt-2 text-xs leading-5 text-zinc-500">Inspect every operation, its context, payload, and required authorizations before taking action.</p>
              </div>
            </aside>
          )}
        </div>
      </main>

        {notice && <div className="toast" role="status" aria-live="polite"><CheckIcon className="size-4 shrink-0 text-brand-dark" />{notice}</div>}
      </div>
    </>
  )
}

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ status: 'checking' })

  useEffect(() => {
    let active = true
    api.getSession()
      .then((session) => { if (active) setAuth({ status: 'signed-in', session }) })
      .catch(() => { if (active) setAuth({ status: 'signed-out' }) })
    return () => { active = false }
  }, [])

  if (auth.status === 'checking') return <LoadingScreen />
  if (auth.status === 'signed-out') return <Login onAuthenticated={(session) => setAuth({ status: 'signed-in', session })} />
  return <Dashboard session={auth.session} onSignedOut={() => setAuth({ status: 'signed-out' })} />
}
