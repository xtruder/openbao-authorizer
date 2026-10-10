import os from "node:os"
import path from "node:path"

/** Plugin options, as given in opencode.json `["@xtruder/opencode-openbao", {...}]`. */
export interface OpenBaoOptions {
  /** OpenBao address, e.g. https://openbao.example.com:8200. */
  address: string
  /** Authorizer base URL, injected as OPENBAO_AUTHORIZER_URL for bao-cred. */
  authorizerUrl?: string
  /** File holding the minter AppRole role_id. */
  roleIdFile: string
  /** File holding the minter AppRole secret_id. */
  secretIdFile: string
  approleMount: string
  /** Token role that mints Session Tokens. */
  tokenRole: string
  /** Session Identity alias prefix; the alias is `<aliasPrefix><rootSessionID>`. */
  aliasPrefix: string
  namespace?: string
  /** PEM file with the CA that signs the OpenBao server certificate. */
  caCert?: string
}

export const DEFAULTS = {
  approleMount: "approle",
  tokenRole: "opencode-session",
  aliasPrefix: "opencode-session-",
} as const

export class OptionsError extends Error {
  override name = "OptionsError"
}

/**
 * Validates raw options and applies defaults. File paths may start with `~/`.
 * `authorizerUrl` is required for the plugin (bao-cred needs it) but not for the mint CLI.
 */
export function resolveOptions(
  raw: Record<string, unknown> | undefined,
  { requireAuthorizerUrl = true }: { requireAuthorizerUrl?: boolean } = {},
): OpenBaoOptions {
  const input = raw ?? {}
  const str = (key: string): string | undefined => {
    const value = input[key]
    if (value === undefined || value === null || value === "") return undefined
    if (typeof value !== "string") throw new OptionsError(`option ${key} must be a string`)
    return value.trim()
  }
  const required = (key: string): string => {
    const value = str(key)
    if (!value) throw new OptionsError(`option ${key} is required`)
    return value
  }

  const address = required("address").replace(/\/+$/, "")
  const authorizerUrl = requireAuthorizerUrl ? required("authorizerUrl") : str("authorizerUrl")
  const caCert = str("caCert")
  return {
    address,
    authorizerUrl: authorizerUrl?.replace(/\/+$/, ""),
    roleIdFile: expandHome(required("roleIdFile")),
    secretIdFile: expandHome(required("secretIdFile")),
    approleMount: trimSlashes(str("approleMount") ?? DEFAULTS.approleMount),
    tokenRole: trimSlashes(str("tokenRole") ?? DEFAULTS.tokenRole),
    aliasPrefix: str("aliasPrefix") ?? DEFAULTS.aliasPrefix,
    namespace: str("namespace"),
    caCert: caCert ? expandHome(caCert) : undefined,
  }
}

/** Names of the variables that carry the Session Token. */
export const TOKEN_VARS = ["BAO_TOKEN", "VAULT_TOKEN"] as const

/** Environment for agent shell commands; the token variables are omitted without a token. */
export function sessionEnv(options: OpenBaoOptions, token?: string): Record<string, string> {
  const env: Record<string, string> = {
    BAO_ADDR: options.address,
    VAULT_ADDR: options.address,
    // bao-cred would otherwise fall back to the human's `bao login` token file
    // when a command gets no Session Token.
    BAO_CRED_NO_TOKEN_FILE: "1",
  }
  if (token) for (const name of TOKEN_VARS) env[name] = token
  if (options.authorizerUrl) env.OPENBAO_AUTHORIZER_URL = options.authorizerUrl
  if (options.namespace) {
    env.BAO_NAMESPACE = options.namespace
    env.VAULT_NAMESPACE = options.namespace
  }
  if (options.caCert) {
    env.BAO_CACERT = options.caCert
    env.VAULT_CACERT = options.caCert
  }
  return env
}

function expandHome(file: string): string {
  return file.startsWith("~/") ? path.join(os.homedir(), file.slice(2)) : file
}

function trimSlashes(value: string): string {
  return value.replace(/^\/+|\/+$/g, "")
}
