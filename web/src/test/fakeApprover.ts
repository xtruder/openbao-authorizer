import { create, type MessageInitShape } from '@bufbuild/protobuf'
import { Code, ConnectError, createRouterTransport, type Interceptor, type ServiceImpl } from '@connectrpc/connect'
import { createApproverClient } from '../api'
import {
  ApproverService,
  DashboardSnapshotSchema,
  WatchEventsResponseSchema,
  type WatchEventsResponse,
} from '../gen/openbao/authorizer/v1/approver_pb'
import { ErrorDetailSchema } from '../gen/openbao/authorizer/v1/types_pb'

export function rpcError(code: Code, reason: string, message = reason) {
  return new ConnectError(message, code, undefined, [{ desc: ErrorDetailSchema, value: { reason } }])
}

// EventStream is one open WatchEvents call that a test feeds by hand.
export class EventStream {
  private queue: (WatchEventsResponse | Error | null)[] = []
  private wake: (() => void) | null = null
  aborted = false

  constructor(signal: AbortSignal) {
    signal.addEventListener('abort', () => {
      this.aborted = true
      this.push(null)
    })
  }

  private push(value: WatchEventsResponse | Error | null) {
    this.queue.push(value)
    this.wake?.()
  }

  snapshot(snapshot: MessageInitShape<typeof DashboardSnapshotSchema>) {
    this.push(create(WatchEventsResponseSchema, { event: { case: 'snapshot', value: create(DashboardSnapshotSchema, snapshot) } }))
  }

  heartbeat() {
    this.push(create(WatchEventsResponseSchema, { event: { case: 'heartbeat', value: {} } }))
  }

  fail(error: Error) {
    this.push(error)
  }

  end() {
    this.push(null)
  }

  async *events() {
    for (;;) {
      while (this.queue.length === 0) await new Promise<void>((resolve) => { this.wake = resolve })
      this.wake = null
      const next = this.queue.shift()
      if (next === null || next === undefined) return
      if (next instanceof Error) throw next
      yield next
    }
  }
}

interface FakeOptions {
  // Snapshot sent as soon as a stream opens; null leaves new streams silent.
  initialSnapshot?: MessageInitShape<typeof DashboardSnapshotSchema> | null
  handlers?: Partial<ServiceImpl<typeof ApproverService>>
}

// fakeApprover serves ApproverService in memory and, like the server, requires
// the session cookie on every RPC except Login.
export function fakeApprover(options: FakeOptions = {}) {
  const state = { cookie: false }
  const calls: string[] = []
  const streams: EventStream[] = []
  const requests = new Map<string, unknown[]>()
  const initialSnapshot = options.initialSnapshot === undefined ? {} : options.initialSnapshot

  const record: Interceptor = (next) => async (request) => {
    calls.push(request.method.name)
    return next(request)
  }
  const requireCookie: Interceptor = (next) => async (request) => {
    if (request.method.name !== 'Login' && !state.cookie) throw rpcError(Code.Unauthenticated, 'SESSION_EXPIRED', 'session expired')
    return next(request)
  }

  function remember(method: string, request: unknown) {
    requests.set(method, [...(requests.get(method) ?? []), request])
  }

  const defaults: ServiceImpl<typeof ApproverService> = {
    login: (request) => {
      remember('Login', request)
      state.cookie = true
      return { identity: { entityId: 'entity-1', displayName: 'SRE on-call' } }
    },
    getSession: () => ({ identity: { entityId: 'entity-1', displayName: 'SRE on-call' } }),
    logout: () => {
      state.cookie = false
      return {}
    },
    listGrantRequests: () => ({}),
    decideItems: (request) => {
      remember('DecideItems', request)
      return {}
    },
    listGrants: () => ({}),
    revokeGrant: (request) => {
      remember('RevokeGrant', request)
      return {}
    },
    async *watchEvents(_request, context) {
      const stream = new EventStream(context.signal)
      streams.push(stream)
      if (initialSnapshot) stream.snapshot(initialSnapshot)
      yield* stream.events()
    },
    getPushPublicKey: () => ({ publicKey: 'BEl6' }),
    registerPushSubscription: (request) => {
      remember('RegisterPushSubscription', request)
      return {}
    },
    deletePushSubscription: (request) => {
      remember('DeletePushSubscription', request)
      return {}
    },
  }

  const transport = createRouterTransport(({ service }) => {
    service(ApproverService, { ...defaults, ...options.handlers })
  }, {
    transport: { interceptors: [record] },
    router: { interceptors: [requireCookie] },
  })

  return {
    client: createApproverClient(transport),
    state,
    calls,
    streams,
    requests: <T>(method: string) => (requests.get(method) ?? []) as T[],
    callsTo: (method: string) => calls.filter((call) => call === method),
  }
}
