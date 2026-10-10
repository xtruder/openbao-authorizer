import { OpenBaoError, OpenBaoHttp, type AuthResponse } from "./openbao.ts"
import type { OpenBaoOptions } from "./options.ts"

/** Token `meta` set at mint time; the authorizer shows it to Approvers. */
export interface SessionMeta {
  /** Root Agent Session ID. */
  session_id: string
  title?: string
  directory?: string
}

/** A minted Session Token. Times are epoch milliseconds. */
export interface SessionToken {
  rootSessionID: string
  entityAlias: string
  token: string
  accessor: string
  entityID?: string
  policies: string[]
  /** Lease (the token period for periodic tokens) in seconds, as of the last mint or renewal. */
  ttl: number
  renewable: boolean
  issuedAt: number
  expiresAt?: number
}

interface MinterToken {
  token: string
  refreshAt?: number
}

export interface MinterDeps {
  now?: () => number
  http?: OpenBaoHttp
}

/**
 * Mints, renews and revokes Session Tokens. Logs in with the minter AppRole
 * on demand and reuses the minter token until it is close to expiry.
 */
export class SessionTokenMinter {
  private readonly http: OpenBaoHttp
  private readonly now: () => number
  private minter?: MinterToken
  private login?: Promise<MinterToken>

  constructor(
    private readonly options: OpenBaoOptions,
    deps: MinterDeps = {},
  ) {
    this.http = deps.http ?? new OpenBaoHttp(options)
    this.now = deps.now ?? Date.now
  }

  async mint(meta: SessionMeta): Promise<SessionToken> {
    const entityAlias = `${this.options.aliasPrefix}${meta.session_id}`
    const body = {
      entity_alias: entityAlias,
      meta: compact({ session_id: meta.session_id, title: meta.title, directory: meta.directory }),
    }
    const path = `auth/token/create/${this.options.tokenRole}`
    let res: { auth?: AuthResponse } | undefined
    try {
      res = await this.http.request("POST", path, { token: await this.minterToken(), body })
    } catch (err) {
      // The cached minter token may have been revoked or expired early; log in again once.
      if (!(err instanceof OpenBaoError) || err.status !== 403) throw err
      this.minter = undefined
      res = await this.http.request("POST", path, { token: await this.minterToken(), body })
    }
    const auth = requireAuth(res, "POST", path)
    const issuedAt = this.now()
    return {
      rootSessionID: meta.session_id,
      entityAlias,
      token: auth.client_token,
      accessor: auth.accessor,
      entityID: auth.entity_id || undefined,
      policies: auth.policies ?? auth.token_policies ?? [],
      ttl: auth.lease_duration,
      renewable: auth.renewable,
      issuedAt,
      expiresAt: auth.lease_duration > 0 ? issuedAt + auth.lease_duration * 1000 : undefined,
    }
  }

  /** Renews a Session Token with its own token (`default` policy allows renew-self). */
  async renew(current: SessionToken): Promise<SessionToken> {
    const path = "auth/token/renew-self"
    const auth = requireAuth(await this.http.request("POST", path, { token: current.token, body: {} }), "POST", path)
    const issuedAt = this.now()
    return {
      ...current,
      ttl: auth.lease_duration,
      renewable: auth.renewable,
      issuedAt,
      expiresAt: auth.lease_duration > 0 ? issuedAt + auth.lease_duration * 1000 : undefined,
    }
  }

  async revoke(current: SessionToken): Promise<void> {
    await this.http.request("POST", "auth/token/revoke-self", { token: current.token })
  }

  private async minterToken(): Promise<string> {
    const cached = this.minter
    if (cached && (cached.refreshAt === undefined || this.now() < cached.refreshAt)) return cached.token
    this.login ??= this.approleLogin().finally(() => (this.login = undefined))
    this.minter = await this.login
    return this.minter.token
  }

  private async approleLogin(): Promise<MinterToken> {
    const [roleID, secretID] = await Promise.all([
      readSecretFile(this.options.roleIdFile, "roleIdFile"),
      readSecretFile(this.options.secretIdFile, "secretIdFile"),
    ])
    const path = `auth/${this.options.approleMount}/login`
    const res = await this.http.request<{ auth?: AuthResponse }>("POST", path, {
      body: { role_id: roleID, secret_id: secretID },
    })
    const auth = requireAuth(res, "POST", path)
    const ttl = auth.lease_duration
    // Refresh with a fifth of the TTL (at least 5s) left, so a create call never races expiry.
    const margin = Math.max(5, ttl / 5)
    return { token: auth.client_token, refreshAt: ttl > 0 ? this.now() + Math.max(0, ttl - margin) * 1000 : undefined }
  }
}

/** Mints one Session Token for the root session in `meta`. */
export function mintSessionToken(options: OpenBaoOptions, meta: SessionMeta, deps?: MinterDeps): Promise<SessionToken> {
  return new SessionTokenMinter(options, deps).mint(meta)
}

/** True once a token is past half its lease, the point at which it should be renewed. */
export function needsRenewal(token: SessionToken, now: number): boolean {
  if (token.ttl <= 0) return false
  return now >= token.issuedAt + (token.ttl * 1000) / 2
}

export function isExpired(token: SessionToken, now: number): boolean {
  return token.expiresAt !== undefined && now >= token.expiresAt
}

async function readSecretFile(file: string, option: string): Promise<string> {
  let value: string
  try {
    value = (await Bun.file(file).text()).trim()
  } catch (err) {
    // Only the path and errno text; the file content never reaches the error.
    const code = (err as { code?: string }).code
    throw new Error(`cannot read ${option} ${file}${code ? `: ${code}` : ""}`)
  }
  if (!value) throw new Error(`${option} ${file} is empty`)
  return value
}

function requireAuth(res: { auth?: AuthResponse } | undefined, method: string, path: string): AuthResponse {
  if (!res?.auth?.client_token) throw new OpenBaoError(method, path, 200, ["response has no auth.client_token"])
  return res.auth
}

function compact(record: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(Object.entries(record).filter((e): e is [string, string] => !!e[1]))
}
