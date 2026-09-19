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
import type { ApprovalRequest, ConnectionState, Identity, RequestFilter, Session } from './types'

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

function isApprovalRequest(value: unknown): value is ApprovalRequest {
  if (!value || typeof value !== 'object') return false
  const request = value as Partial<ApprovalRequest>
  return typeof request.id === 'string' && typeof request.path === 'string' && typeof request.approved === 'boolean'
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

function RequestRow({ request, onReview }: { request: ApprovalRequest; onReview: (trigger: HTMLButtonElement) => void }) {
  return (
    <article className="request-row group">
      <div className="flex min-w-0 flex-1 gap-3.5 sm:gap-5">
        <div className={`mt-0.5 grid size-10 shrink-0 place-items-center rounded-sm border ${request.approved ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-amber-200 bg-amber-50 text-amber-700'}`}>
          {request.approved ? <CheckIcon className="size-5" /> : <ClockIcon className="size-5" />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className={`status-pill ${request.approved ? 'status-approved' : 'status-pending'}`}>{request.approved ? 'Approved' : 'Pending'}</span>
            <span className="operation-pill">{formatOperation(request.operation)}</span>
          </div>
          <h3 className="truncate font-mono text-[13px] font-semibold text-zinc-900 sm:text-sm" title={request.path}>{request.path}</h3>
          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-zinc-500">
            <span className="inline-flex items-center gap-1.5"><UserIcon className="size-3.5" />{request.entity.name || request.entity.id}</span>
            <span className="inline-flex items-center gap-1.5"><ClockIcon className="size-3.5" />Updated {formatDate(request.lastSeen)}</span>
          </div>
        </div>
      </div>
      <button data-review-trigger type="button" onClick={(event) => onReview(event.currentTarget)} className="review-button" aria-label={`Review request for ${request.path}`}>
        <span className="hidden sm:inline">Review request</span><ChevronIcon className="size-4" />
      </button>
    </article>
  )
}

function EmptyState({ filter }: { filter: RequestFilter }) {
  return (
    <div className="grid min-h-[390px] place-items-center px-6 py-16 text-center">
      <div>
        <div className="mx-auto grid size-14 place-items-center rounded-full border border-zinc-200 bg-zinc-50 text-zinc-400">
          {filter === 'pending' ? <InboxIcon className="size-6" /> : <CheckIcon className="size-6" />}
        </div>
        <h3 className="mt-5 text-base font-semibold text-zinc-900">{filter === 'pending' ? 'Queue is clear' : 'No approved requests'}</h3>
        <p className="mx-auto mt-2 max-w-xs text-sm leading-6 text-zinc-500">
          {filter === 'pending' ? 'New control group requests will appear here as they arrive.' : 'Requests you approve will be collected here.'}
        </p>
      </div>
    </div>
  )
}

function RequestDetail({ request, onBack, onApprove, approving }: {
  request: ApprovalRequest
  onBack: () => void
  onApprove: () => void
  approving: boolean
}) {
  const headingRef = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    headingRef.current?.focus()
  }, [])

  return (
    <section className="detail-panel" aria-labelledby="request-detail-title">
      <div className="detail-header">
        <button type="button" onClick={onBack} className="icon-button lg:hidden" aria-label="Back to requests"><ArrowLeftIcon className="size-5" /></button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`status-pill ${request.approved ? 'status-approved' : 'status-pending'}`}>{request.approved ? 'Approved' : 'Pending review'}</span>
            <span className="operation-pill">{formatOperation(request.operation)}</span>
          </div>
          <h2 ref={headingRef} id="request-detail-title" tabIndex={-1} className="mt-3 break-all font-mono text-base font-semibold leading-6 text-zinc-950">{request.path}</h2>
        </div>
        <button type="button" onClick={onBack} className="icon-button hidden lg:grid" aria-label="Close request details"><CloseIcon className="size-4" /></button>
      </div>

      <div className="detail-scroll">
        <div className="detail-section grid gap-4 sm:grid-cols-2">
          <div>
            <p className="detail-label">Requested by</p>
            <div className="mt-2 flex items-center gap-2.5">
              <div className="grid size-8 place-items-center rounded-full bg-zinc-900 text-[10px] font-semibold text-white">{initials(request.entity.name || request.entity.id)}</div>
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-zinc-900">{request.entity.name || 'Unknown entity'}</p>
                <p className="truncate font-mono text-[11px] text-zinc-500">{request.entity.id}</p>
              </div>
            </div>
          </div>
          <div>
            <p className="detail-label">Activity</p>
            <dl className="mt-2 space-y-1.5 text-xs">
              <div className="flex justify-between gap-3"><dt className="text-zinc-500">First seen</dt><dd className="font-medium text-zinc-700">{formatDate(request.firstSeen)}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-zinc-500">Last seen</dt><dd className="font-medium text-zinc-700">{formatDate(request.lastSeen)}</dd></div>
            </dl>
          </div>
        </div>

        <div className="detail-section">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="detail-label">Request payload</h3>
            <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-400">JSON</span>
          </div>
          {request.data === undefined ? (
            <p className="rounded-sm border border-zinc-200 bg-zinc-50 px-3 py-3 text-sm text-zinc-500">Redacted by the server. Enable path-specific payload exposure only when the submitted fields are safe to display.</p>
          ) : (
            <pre className="json-block"><code>{JSON.stringify(request.data, null, 2) ?? 'null'}</code></pre>
          )}
        </div>

        <div className="detail-section">
          <h3 className="detail-label">Required authorizations</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {request.authorizations.length ? request.authorizations.map((authorization, index) => (
              <span key={`${authorizationLabel(authorization)}-${index}`} className="authorization-chip"><ShieldIcon className="size-3.5" />{authorizationLabel(authorization)}</span>
            )) : <span className="text-sm text-zinc-500">No authorization metadata provided.</span>}
          </div>
        </div>

        <div className="detail-section border-b-0">
          <h3 className="detail-label">Request ID</h3>
          <p className="mt-2 break-all font-mono text-xs text-zinc-600">{request.id}</p>
        </div>
      </div>

      <div className="detail-footer">
        {request.approved ? (
          <div className="flex w-full items-center justify-center gap-2 rounded-sm border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-semibold text-emerald-700"><CheckIcon className="size-4" />Approved</div>
        ) : (
          <button type="button" onClick={onApprove} disabled={approving} className="approve-button w-full">
            <ShieldIcon className="size-4" />Approve request
          </button>
        )}
      </div>
    </section>
  )
}

function ConfirmationDialog({ request, submitting, error, onCancel, onConfirm }: {
  request: ApprovalRequest
  submitting: boolean
  error: string
  onCancel: () => void
  onConfirm: () => void
}) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const confirmRef = useRef<HTMLButtonElement>(null)
  const onCancelRef = useRef(onCancel)
  const submittingRef = useRef(submitting)

  useEffect(() => {
    onCancelRef.current = onCancel
    submittingRef.current = submitting
  }, [onCancel, submitting])

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null
    confirmRef.current?.focus()

    function onKeyDown(event: KeyboardEvent) {
      const dialog = dialogRef.current
      if (!dialog) return

      if (event.key === 'Escape' && !submittingRef.current) {
        event.preventDefault()
        onCancelRef.current()
        return
      }
      if (event.key !== 'Tab') return

      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ))
      if (!focusable.length) {
        event.preventDefault()
        dialog.focus()
        return
      }

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      const rowTrigger = document.querySelector<HTMLElement>('[data-review-trigger]')
      if (rowTrigger?.isConnected) rowTrigger.focus()
      else if (previouslyFocused?.isConnected) previouslyFocused.focus()
    }
  }, [])

  return (
    <dialog
      ref={dialogRef}
      open
      aria-modal="true"
      aria-labelledby="confirmation-title"
      aria-describedby="confirmation-description"
      className="dialog-backdrop"
    >
      <div className="dialog-card">
        <div className="grid size-11 place-items-center rounded-full bg-brand-soft text-zinc-900"><ShieldIcon className="size-5" /></div>
        <h2 id="confirmation-title" className="mt-5 text-xl font-semibold tracking-[-0.02em] text-zinc-950">Confirm approval</h2>
        <p id="confirmation-description" className="mt-2 text-sm leading-6 text-zinc-600">This authorizes the operation below. This action cannot be undone.</p>
        <div className="mt-5 rounded-sm border border-zinc-200 bg-zinc-50 p-3.5">
          <p className="font-mono text-xs font-semibold text-zinc-900 break-all">{request.path}</p>
          <p className="mt-1.5 text-xs text-zinc-500">{formatOperation(request.operation)} requested by {request.entity.name || request.entity.id}</p>
        </div>
        {error && <div role="alert" className="mt-4 rounded-sm border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700">{error}</div>}
        <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <button type="button" onClick={onCancel} disabled={submitting} className="secondary-button">Cancel</button>
          <button ref={confirmRef} type="button" onClick={onConfirm} disabled={submitting} className="approve-button">
            {submitting ? <><span className="button-spinner dark" />Approving…</> : <><CheckIcon className="size-4" />Confirm approval</>}
          </button>
        </div>
      </div>
    </dialog>
  )
}

function urlBase64ToUint8Array(value: string) {
  const padding = '='.repeat((4 - value.length % 4) % 4)
  const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/')
  const raw = window.atob(base64)
  return Uint8Array.from(raw, (character) => character.charCodeAt(0))
}

function Dashboard({ session, onSignedOut }: { session: Session; onSignedOut: () => void }) {
  const [requests, setRequests] = useState<ApprovalRequest[]>([])
  const [filter, setFilter] = useState<RequestFilter>('pending')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null)
  const hadSelectedDetailRef = useRef(false)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [connection, setConnection] = useState<ConnectionState>(navigator.onLine ? 'connecting' : 'offline')
  const [confirming, setConfirming] = useState<ApprovalRequest | null>(null)
  const [approving, setApproving] = useState(false)
  const [approvalError, setApprovalError] = useState('')
  const [signingOut, setSigningOut] = useState(false)
  const [signOutError, setSignOutError] = useState('')
  const [notificationStatus, setNotificationStatus] = useState<'idle' | 'enabling' | 'enabled' | 'disabling' | 'unsupported'>(() => {
    if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) return 'unsupported'
    return Notification.permission === 'granted' ? 'idle' : 'idle'
  })
  const [notice, setNotice] = useState('')

  const loadRequests = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    setError('')
    try {
      const next = await api.getRequests()
      setRequests(next)
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      setError(getErrorMessage(caught, 'Unable to load approval requests.'))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [onSignedOut])

  useEffect(() => {
    const timeout = window.setTimeout(() => void loadRequests(), 0)
    return () => window.clearTimeout(timeout)
  }, [loadRequests])

  useEffect(() => {
    let source: EventSource | null = null
    let disposed = false

    function connect() {
      if (disposed || !navigator.onLine) return
      setConnection((current) => current === 'connected' ? 'reconnecting' : 'connecting')
      source = new EventSource('/api/v1/events')
      source.onopen = () => setConnection('connected')
      source.onerror = () => setConnection(navigator.onLine ? 'reconnecting' : 'offline')

      const handleUpdate = (event: MessageEvent<string>) => {
        try {
          const payload: unknown = JSON.parse(event.data)
          if (isApprovalRequest(payload)) {
            setRequests((current) => {
              const exists = current.some((request) => request.id === payload.id)
              return exists ? current.map((request) => request.id === payload.id ? payload : request) : [payload, ...current]
            })
            return
          }
        } catch {
          // Refetch if the event only contains an ID or an unexpected payload.
        }
        void loadRequests(true)
      }
      source.addEventListener('new-request', handleUpdate)
      source.addEventListener('status', handleUpdate)
    }

    function onOnline() {
      source?.close()
      connect()
    }
    function onOffline() {
      setConnection('offline')
      source?.close()
    }

    connect()
    window.addEventListener('online', onOnline)
    window.addEventListener('offline', onOffline)
    return () => {
      disposed = true
      source?.close()
      window.removeEventListener('online', onOnline)
      window.removeEventListener('offline', onOffline)
    }
  }, [loadRequests])

  useEffect(() => {
    if (!notice) return
    const timeout = window.setTimeout(() => setNotice(''), 4500)
    return () => window.clearTimeout(timeout)
  }, [notice])

  const pendingCount = requests.filter((request) => !request.approved).length
  const approvedCount = requests.filter((request) => request.approved).length
  const visibleRequests = useMemo(
    () => requests.filter((request) => filter === 'approved' ? request.approved : !request.approved),
    [filter, requests],
  )
  const selected = requests.find((request) => request.id === selectedId) ?? null
  const operatorName = identityName(session.identity)

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

  async function approve() {
    const confirmed = confirming
    if (!confirmed || approving) return
    setApproving(true)
    setApprovalError('')
    try {
      const refreshed = await api.approveRequest(confirmed.id, session.csrfToken)
      setRequests((current) => current.map((request) => request.id === refreshed.id ? refreshed : request))
      // Keep the saved row trigger; the Approve button inside the detail view
      // is about to be replaced by the Approved status, so it cannot be
      // relied on for focus restoration.
      setSelectedId(refreshed.id)
      setConfirming(null)
      setNotice('Request approved successfully.')
    } catch (caught) {
      if (isSessionLost(caught)) {
        onSignedOut()
        return
      }
      setApprovalError(getErrorMessage(caught, 'Approval failed. Try again.'))
    } finally {
      setApproving(false)
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
      <div
        className="min-h-svh bg-canvas text-zinc-900"
        inert={confirming !== null}
        aria-hidden={confirming ? 'true' : undefined}
      >
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
            <h1 className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-zinc-950 sm:text-4xl">Approval requests</h1>
            <p className="mt-2 text-sm leading-6 text-zinc-500">Review the context before authorizing privileged operations.</p>
          </div>
          <button type="button" onClick={() => void loadRequests(true)} disabled={refreshing} className="secondary-button self-start sm:self-auto">
            <RefreshIcon className={`size-4 ${refreshing ? 'animate-spin' : ''}`} />Refresh
          </button>
        </div>

        {error && (
          <div role="alert" className="mb-5 flex items-center justify-between gap-4 rounded-sm border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <span>{error}</span><button type="button" onClick={() => void loadRequests()} className="font-semibold underline underline-offset-2">Retry</button>
          </div>
        )}

        {signOutError && (
          <div role="alert" className="mb-5 flex items-center justify-between gap-4 rounded-sm border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <span>{signOutError}</span><button type="button" onClick={() => void signOut()} className="font-semibold underline underline-offset-2">Retry sign out</button>
          </div>
        )}

        <div className={`dashboard-shell ${selected ? 'has-detail' : ''}`}>
          <section className={`request-list-panel ${selected ? 'hidden lg:block' : ''}`} aria-label="Approval request queue">
            <div className="list-toolbar">
              <div className="filter-tabs" role="group" aria-label="Filter requests">
                <button type="button" aria-pressed={filter === 'pending'} onClick={() => setFilter('pending')} className={filter === 'pending' ? 'active' : ''}>
                  Pending <span>{pendingCount}</span>
                </button>
                <button type="button" aria-pressed={filter === 'approved'} onClick={() => setFilter('approved')} className={filter === 'approved' ? 'active' : ''}>
                  Approved <span>{approvedCount}</span>
                </button>
              </div>
              <p className="hidden text-xs text-zinc-400 sm:block">{visibleRequests.length} {visibleRequests.length === 1 ? 'request' : 'requests'}</p>
            </div>

            {loading ? (
              <div className="space-y-px" aria-label="Loading requests" role="status">
                {[0, 1, 2].map((item) => <div className="request-skeleton" key={item}><div className="size-10 animate-pulse rounded-sm bg-zinc-100" /><div className="flex-1 space-y-3"><div className="h-3 w-24 animate-pulse rounded bg-zinc-100" /><div className="h-3 w-2/3 animate-pulse rounded bg-zinc-100" /><div className="h-2.5 w-1/2 animate-pulse rounded bg-zinc-100" /></div></div>)}
              </div>
            ) : visibleRequests.length ? (
              <div className="divide-y divide-zinc-100">
                {visibleRequests.map((request) => <RequestRow key={request.id} request={request} onReview={(trigger) => { detailTriggerRef.current = trigger; setSelectedId(request.id) }} />)}
              </div>
            ) : <EmptyState filter={filter} />}
          </section>

          {selected && <RequestDetail key={`${selected.id}-${selected.approved}`} request={selected} approving={approving} onBack={() => setSelectedId(null)} onApprove={() => { setApprovalError(''); setConfirming(selected) }} />}
          {!selected && (
            <aside className="detail-placeholder hidden lg:grid">
              <div className="max-w-xs text-center">
                <div className="mx-auto grid size-12 place-items-center rounded-full border border-zinc-200 bg-white text-zinc-400"><ShieldIcon className="size-5" /></div>
                <h2 className="mt-4 text-sm font-semibold text-zinc-800">Select a request to review</h2>
                <p className="mt-2 text-xs leading-5 text-zinc-500">Inspect the operation, identity, payload, and required authorizations before taking action.</p>
              </div>
            </aside>
          )}
        </div>
      </main>

        {notice && <div className="toast" role="status" aria-live="polite"><CheckIcon className="size-4 shrink-0 text-brand-dark" />{notice}</div>}
      </div>
      {confirming && <ConfirmationDialog request={confirming} submitting={approving} error={approvalError} onCancel={() => setConfirming(null)} onConfirm={() => void approve()} />}
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
