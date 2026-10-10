import type { OpenBaoOptions } from "./options.ts"

/** `auth` block of an OpenBao login or token response. */
export interface AuthResponse {
  client_token: string
  accessor: string
  policies?: string[] | null
  token_policies?: string[] | null
  metadata?: Record<string, string> | null
  lease_duration: number
  renewable: boolean
  entity_id?: string
}

/**
 * A failed OpenBao call. The message holds only the method, the API path, the
 * status and OpenBao's error strings, never request headers or bodies, so it is
 * safe to log.
 */
export class OpenBaoError extends Error {
  override name = "OpenBaoError"
  constructor(
    readonly method: string,
    readonly path: string,
    readonly status: number,
    readonly errors: string[],
  ) {
    super(`OpenBao ${method} ${path}: HTTP ${status}${errors.length ? `: ${errors.join("; ")}` : ""}`)
  }
}

/** Minimal OpenBao HTTP API client on plain fetch. */
export class OpenBaoHttp {
  private ca?: Promise<string>

  constructor(private readonly options: Pick<OpenBaoOptions, "address" | "namespace" | "caCert">) {}

  async request<T = unknown>(
    method: string,
    path: string,
    { token, body }: { token?: string; body?: unknown } = {},
  ): Promise<T | undefined> {
    const headers: Record<string, string> = {}
    if (token) headers["X-Vault-Token"] = token
    if (this.options.namespace) headers["X-Vault-Namespace"] = this.options.namespace
    if (body !== undefined) headers["Content-Type"] = "application/json"

    const init: RequestInit & { tls?: { ca: string } } = {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }
    // Bun-specific fetch option; other runtimes ignore it.
    if (this.options.caCert) init.tls = { ca: await this.caPem() }

    let res: Response
    try {
      res = await fetch(`${this.options.address}/v1/${path}`, init)
    } catch (err) {
      throw new OpenBaoError(method, path, 0, [err instanceof Error ? err.message : String(err)])
    }
    const text = await res.text()
    const json = text ? safeParse(text) : undefined
    if (!res.ok) {
      const errors = Array.isArray(json?.errors) ? json.errors.map(String) : []
      throw new OpenBaoError(method, path, res.status, errors)
    }
    return json as T | undefined
  }

  private caPem(): Promise<string> {
    this.ca ??= Bun.file(this.options.caCert!).text()
    return this.ca
  }
}

function safeParse(text: string): any {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}
