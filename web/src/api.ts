import { Code, ConnectError, createClient, type Client, type Transport } from '@connectrpc/connect'
import { createConnectTransport } from '@connectrpc/connect-web'
import { ApproverService, type Identity } from './gen/openbao/authorizer/v1/approver_pb'
import { ErrorDetailSchema } from './gen/openbao/authorizer/v1/types_pb'

export type ApproverClient = Client<typeof ApproverService>

export interface Session {
  identity?: Identity
}

export function createApproverClient(transport: Transport = createConnectTransport({
  baseUrl: '/api',
  useBinaryFormat: false,
  fetch: (input, init) => fetch(input, { ...init, credentials: 'same-origin' }),
})): ApproverClient {
  return createClient(ApproverService, transport)
}

export function errorReason(error: unknown) {
  if (!(error instanceof ConnectError)) return undefined
  return error.findDetails(ErrorDetailSchema)[0]?.reason
}

// A cross-origin rejection or a revoked approver policy can only be fixed by signing in again.
export function isSessionLost(error: unknown) {
  if (!(error instanceof ConnectError)) return false
  if (error.code === Code.Unauthenticated) return true
  const reason = errorReason(error)
  return error.code === Code.PermissionDenied && (reason === 'NOT_APPROVER' || reason === 'CROSS_ORIGIN')
}

const reasonMessages: Record<string, string> = {
  SESSION_EXPIRED: 'Your session has expired. Sign in again.',
  NOT_APPROVER: 'Your OpenBao identity is not allowed to approve requests.',
  NOT_FOUND: 'That request or grant no longer exists.',
  ITEM_NOT_PENDING: 'That item was already decided. Showing the latest state.',
  GRANT_NOT_ACTIVE: 'That grant was already revoked or has expired.',
  OPENBAO_UNAVAILABLE: 'OpenBao is unavailable. Try again shortly.',
  NOT_REQUESTER: 'That OpenBao identity matches no requester rule.',
  SELF_APPROVAL: "You can't decide your own request.",
}

export function getErrorMessage(error: unknown, fallback: string) {
  if (!(error instanceof ConnectError)) return error instanceof Error && error.message ? error.message : fallback
  const reason = errorReason(error)
  if (reason && reasonMessages[reason]) return reasonMessages[reason]
  // INVALID_REQUEST and unclassified errors carry the server's explanation.
  if (error.code === Code.Unavailable) return 'The authorizer is unreachable. Check your connection and try again.'
  return error.rawMessage || fallback
}
