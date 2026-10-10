// Browser-side OpenBao logins. The resulting token is returned to the caller
// for a single CreateSession call and never stored; passwords and other login
// credentials go only to OpenBao, never to the authorizer.

export interface OpenBaoTarget {
  address: string
  namespace: string
}

export const OIDC_CALLBACK_PATH = '/oidc/callback'
export const UNREACHABLE_MESSAGE = 'OpenBao is unreachable from this browser or does not allow this origin (CORS)'

// Holds the mount and role only across the OIDC redirect round trip.
const OIDC_PENDING_KEY = 'openbao-authorizer.oidc-login'

// jsdom cannot navigate, so tests replace this.
export const navigation = {
  assign: (url: string) => window.location.assign(url),
}

export class OpenBaoLoginError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'OpenBaoLoginError'
  }
}

interface PendingOidcLogin {
  mount: string
  role: string
}

function mountPath(mount: string) {
  return mount.split('/').filter(Boolean).map(encodeURIComponent).join('/')
}

async function request(target: OpenBaoTarget, method: 'GET' | 'POST', path: string, body?: unknown) {
  const headers: Record<string, string> = { 'X-Vault-Request': 'true' }
  if (target.namespace) headers['X-Vault-Namespace'] = target.namespace
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  let response: Response
  try {
    response = await fetch(`${target.address.replace(/\/+$/, '')}/v1/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    })
  } catch (caught) {
    // Browsers report CORS refusals and network failures alike as a TypeError.
    if (caught instanceof TypeError) throw new OpenBaoLoginError(UNREACHABLE_MESSAGE)
    throw caught
  }

  const payload: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const errors = (payload as { errors?: unknown } | null)?.errors
    const messages = Array.isArray(errors) ? errors.filter((entry): entry is string => typeof entry === 'string' && entry.trim() !== '') : []
    throw new OpenBaoLoginError(messages.length ? messages.join('; ') : `OpenBao rejected the sign in (HTTP ${response.status}).`)
  }
  return payload
}

function clientToken(payload: unknown) {
  const token = (payload as { auth?: { client_token?: unknown } } | null)?.auth?.client_token
  if (typeof token !== 'string' || !token) throw new OpenBaoLoginError('OpenBao did not return a token.')
  return token
}

// Userpass and LDAP share the same login endpoint shape.
export async function loginWithPassword(target: OpenBaoTarget, mount: string, username: string, password: string) {
  return clientToken(await request(target, 'POST', `auth/${mountPath(mount)}/login/${encodeURIComponent(username)}`, { password }))
}

export async function loginWithGitHub(target: OpenBaoTarget, mount: string, token: string) {
  return clientToken(await request(target, 'POST', `auth/${mountPath(mount)}/login`, { token }))
}

export function oidcRedirectUri() {
  return `${window.location.origin}${OIDC_CALLBACK_PATH}`
}

export async function startOidcLogin(target: OpenBaoTarget, mount: string, role: string) {
  const payload = await request(target, 'POST', `auth/${mountPath(mount)}/oidc/auth_url`, { role, redirect_uri: oidcRedirectUri() })
  const authUrl = (payload as { data?: { auth_url?: unknown } } | null)?.data?.auth_url
  // OpenBao answers with an empty auth_url when the redirect URI is not allowed for the role.
  if (typeof authUrl !== 'string' || !authUrl) {
    throw new OpenBaoLoginError(`OpenBao returned no sign-in URL. Check that the OIDC role allows the redirect URI ${oidcRedirectUri()}.`)
  }
  sessionStorage.setItem(OIDC_PENDING_KEY, JSON.stringify({ mount, role } satisfies PendingOidcLogin))
  navigation.assign(authUrl)
}

export function isOidcCallback() {
  return window.location.pathname === OIDC_CALLBACK_PATH
}

export function discardOidcLogin() {
  sessionStorage.removeItem(OIDC_PENDING_KEY)
}

// Exchanges the provider's redirect for an OpenBao token. The pending state is
// removed whatever the outcome, so a failed attempt starts over cleanly.
export async function completeOidcLogin(target: OpenBaoTarget, search: string) {
  const raw = sessionStorage.getItem(OIDC_PENDING_KEY)
  sessionStorage.removeItem(OIDC_PENDING_KEY)
  let pending: PendingOidcLogin | null = null
  try {
    pending = raw ? JSON.parse(raw) as PendingOidcLogin : null
  } catch {
    pending = null
  }
  if (!pending?.mount) throw new OpenBaoLoginError('This sign-in link has expired or was opened in another tab. Sign in again.')

  const params = new URLSearchParams(search)
  const providerError = params.get('error_description') || params.get('error')
  if (providerError) throw new OpenBaoLoginError(providerError)
  const state = params.get('state')
  const code = params.get('code')
  if (!state || !code) throw new OpenBaoLoginError('The identity provider did not return a sign-in code. Sign in again.')

  const query = new URLSearchParams({ state, code })
  const nonce = params.get('nonce')
  if (nonce) query.set('nonce', nonce)
  return clientToken(await request(target, 'GET', `auth/${mountPath(pending.mount)}/oidc/callback?${query}`))
}
