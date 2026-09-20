export interface Identity {
  id?: string
  entity_id?: string
  name?: string
  displayName?: string
  display_name?: string
  alias?: string
  [key: string]: unknown
}

export interface Session {
  identity: Identity
  csrfToken: string
}

export interface ApprovalContext {
  available: boolean
  data?: unknown
}

export interface ApprovalRequest {
  id: string
  approved: boolean
  status: RequestStatus
  operation: string
  path: string
  data?: unknown
  approvalContext?: ApprovalContext
  entity: {
    id: string
    name: string
  }
  authorizations: unknown[]
  firstSeen: string
  lastSeen: string
}

export type RequestStatus = 'pending' | 'approved' | 'rejected' | 'expired'
export type RequestFilter = RequestStatus
export type ConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'offline'
