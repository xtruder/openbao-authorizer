import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import type { OpenBaoOptions } from "../src/options.ts"

export interface RecordedCall {
  method: string
  path: string
  token?: string
  namespace?: string
  body: any
}

interface TokenState {
  kind: "minter" | "session"
  revoked: boolean
  alias?: string
  meta?: Record<string, string>
}

export const ROLE_ID = "role-id-123"
export const SECRET_ID = "secret-id-super-secret"

/** In-process stand-in for the OpenBao endpoints the plugin uses. */
export class FakeOpenBao {
  readonly calls: RecordedCall[] = []
  readonly tokens = new Map<string, TokenState>()
  minterTTL = 300
  sessionPeriod = 86400
  /** Status to answer the next call to a path with, once. */
  readonly failNext = new Map<string, number>()
  /** Temp dirs from fakeOptions, removed by stop(). */
  readonly dirs: string[] = []
  private seq = 0
  private server: ReturnType<typeof Bun.serve>

  constructor() {
    this.server = Bun.serve({ port: 0, fetch: (req) => this.handle(req) })
  }

  get address(): string {
    return `http://127.0.0.1:${this.server.port}`
  }

  stop(): void {
    this.server.stop(true)
    for (const dir of this.dirs) rmSync(dir, { recursive: true, force: true })
  }

  callsTo(suffix: string): RecordedCall[] {
    return this.calls.filter((c) => c.path.endsWith(suffix))
  }

  sessionTokens(): Array<[string, TokenState]> {
    return [...this.tokens].filter(([, t]) => t.kind === "session")
  }

  private async handle(req: Request): Promise<Response> {
    const url = new URL(req.url)
    const apiPath = url.pathname.replace(/^\/v1\//, "")
    const text = await req.text()
    const call: RecordedCall = {
      method: req.method,
      path: apiPath,
      token: req.headers.get("x-vault-token") ?? undefined,
      namespace: req.headers.get("x-vault-namespace") ?? undefined,
      body: text ? JSON.parse(text) : undefined,
    }
    this.calls.push(call)

    const fail = this.failNext.get(apiPath)
    if (fail) {
      this.failNext.delete(apiPath)
      return errors(fail, "injected failure")
    }

    const caller = call.token ? this.tokens.get(call.token) : undefined
    const live = caller && !caller.revoked

    if (req.method === "POST" && /^auth\/[^/]+\/login$/.test(apiPath)) {
      if (call.body?.role_id !== ROLE_ID || call.body?.secret_id !== SECRET_ID) return errors(400, "invalid role or secret ID")
      const token = `minter-${++this.seq}`
      this.tokens.set(token, { kind: "minter", revoked: false })
      return auth({ client_token: token, accessor: `acc-${token}`, policies: ["opencode-minter"], lease_duration: this.minterTTL, renewable: true })
    }
    if (req.method === "POST" && apiPath.startsWith("auth/token/create/")) {
      if (!live || caller.kind !== "minter") return errors(403, "permission denied")
      if (!call.body?.entity_alias) return errors(400, "entity_alias required")
      const token = `s.session-${++this.seq}`
      this.tokens.set(token, { kind: "session", revoked: false, alias: call.body.entity_alias, meta: call.body.meta })
      return auth({
        client_token: token,
        accessor: `acc-${token}`,
        policies: ["default", "opencode-session"],
        metadata: call.body.meta,
        lease_duration: this.sessionPeriod,
        renewable: true,
        entity_id: `entity-${call.body.entity_alias}`,
      })
    }
    if (req.method === "POST" && apiPath === "auth/token/renew-self") {
      if (!live) return errors(403, "permission denied")
      return auth({ client_token: call.token, accessor: `acc-${call.token}`, lease_duration: this.sessionPeriod, renewable: true })
    }
    if (req.method === "POST" && apiPath === "auth/token/revoke-self") {
      if (!live) return errors(403, "permission denied")
      caller.revoked = true
      return new Response(null, { status: 204 })
    }
    return errors(404, "unsupported path")
  }
}

function auth(body: Record<string, unknown>): Response {
  return Response.json({ auth: body })
}

function errors(status: number, ...messages: string[]): Response {
  return Response.json({ errors: messages }, { status })
}

/** Writes AppRole credential files and returns options pointing at the fake server. */
export function fakeOptions(bao: FakeOpenBao, extra: Partial<OpenBaoOptions> = {}): Record<string, unknown> {
  const dir = mkdtempSync(path.join(os.tmpdir(), "opencode-openbao-"))
  bao.dirs.push(dir)
  const roleIdFile = path.join(dir, "role-id")
  const secretIdFile = path.join(dir, "secret-id")
  writeFileSync(roleIdFile, `${ROLE_ID}\n`)
  writeFileSync(secretIdFile, `${SECRET_ID}\n`)
  return {
    address: bao.address,
    authorizerUrl: "https://authorizer.example.com",
    roleIdFile,
    secretIdFile,
    ...extra,
  }
}
