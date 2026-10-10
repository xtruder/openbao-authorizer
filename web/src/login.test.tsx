import { Code } from '@connectrpc/connect'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import App from './App'
import { LoginMethodType, type CreateSessionRequest } from './gen/openbao/authorizer/v1/approver_pb'
import { navigation } from './openbaoLogin'
import { fakeApprover, rpcError } from './test/fakeApprover'

const address = 'https://bao.example:8200'

const allMethods = {
  openbaoAddress: `${address}/`,
  namespace: 'team-a/',
  methods: [
    { type: LoginMethodType.TOKEN, label: 'Token' },
    { type: LoginMethodType.USERPASS, mount: 'userpass', label: 'Userpass' },
    { type: LoginMethodType.LDAP, mount: 'corp/ldap', label: 'Directory' },
    { type: LoginMethodType.GITHUB, mount: 'github', label: 'GitHub' },
    { type: LoginMethodType.OIDC, mount: 'oidc', label: 'Company SSO', oidcRole: 'approvers' },
  ],
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const tokenResponse = (token: string) => json({ auth: { client_token: token } })

function stubOpenBao(...responses: (Response | Error)[]) {
  const fetchMock = vi.fn<typeof fetch>()
  for (const response of responses) {
    if (response instanceof Error) fetchMock.mockRejectedValueOnce(response)
    else fetchMock.mockResolvedValueOnce(response)
  }
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function openBaoCall(fetchMock: ReturnType<typeof stubOpenBao>, index = 0) {
  const [url, init] = fetchMock.mock.calls[index]
  return {
    url: String(url),
    method: init?.method,
    body: typeof init?.body === 'string' ? JSON.parse(init.body) as unknown : undefined,
    headers: new Headers(init?.headers),
    credentials: init?.credentials,
  }
}

function expectNothingStored() {
  expect(localStorage).toHaveLength(0)
  expect(sessionStorage).toHaveLength(0)
}

async function chooseMethod(name: string) {
  const user = userEvent.setup()
  await user.click(await screen.findByRole('tab', { name }))
  return user
}

describe('sign in through OpenBao', () => {
  it('offers one tab per configured method', async () => {
    render(<App client={fakeApprover({ loginOptions: allMethods }).client} />)

    const tabs = await screen.findAllByRole('tab')
    expect(tabs.map((tab) => tab.textContent)).toEqual(['Token', 'Userpass', 'Directory', 'GitHub', 'Company SSO'])
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel')).toContainElement(screen.getByLabelText('OpenBao token'))
  })

  it('moves between methods with the arrow keys', async () => {
    const user = userEvent.setup()
    render(<App client={fakeApprover({ loginOptions: allMethods }).client} />)

    await user.click(await screen.findByRole('tab', { name: 'Token' }))
    await user.keyboard('{ArrowRight}')

    expect(screen.getByRole('tab', { name: 'Userpass' })).toHaveFocus()
    expect(screen.getByRole('tab', { name: 'Userpass' })).toHaveAttribute('aria-selected', 'true')
    await user.keyboard('{ArrowLeft}{ArrowLeft}')
    expect(screen.getByRole('tab', { name: 'Company SSO' })).toHaveFocus()
  })

  it('exchanges a pasted token without calling OpenBao', async () => {
    const fetchMock = stubOpenBao()
    const fake = fakeApprover({ loginOptions: allMethods })
    render(<App client={fake.client} />)

    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('OpenBao token'), ' s.pasted ')
    await user.click(screen.getByRole('button', { name: 'Sign in with token' }))

    expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
    expect(fake.requests<CreateSessionRequest>('CreateSession')[0]).toEqual(expect.objectContaining({ openbaoToken: 's.pasted', keepToken: true }))
    expect(fetchMock).not.toHaveBeenCalled()
    expectNothingStored()
  })

  it('logs in with userpass directly against OpenBao', async () => {
    const fetchMock = stubOpenBao(tokenResponse('s.userpass'))
    const fake = fakeApprover({ loginOptions: allMethods })
    render(<App client={fake.client} />)

    const user = await chooseMethod('Userpass')
    await user.type(screen.getByLabelText('Username'), 'bob smith')
    await user.type(screen.getByLabelText('Password'), 'correct horse')
    await user.click(screen.getByRole('button', { name: 'Sign in securely' }))

    expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
    const call = openBaoCall(fetchMock)
    expect(call.url).toBe(`${address}/v1/auth/userpass/login/bob%20smith`)
    expect(call.method).toBe('POST')
    expect(call.body).toEqual({ password: 'correct horse' })
    expect(call.headers.get('X-Vault-Request')).toBe('true')
    expect(call.headers.get('X-Vault-Namespace')).toBe('team-a/')
    expect(call.headers.get('Content-Type')).toBe('application/json')
    expect(call.credentials).toBe('omit')
    // Only the OpenBao token reaches the authorizer, never the password.
    const [request] = fake.requests<CreateSessionRequest>('CreateSession')
    expect(request.openbaoToken).toBe('s.userpass')
    // Tokens from an OpenBao login exist only for this exchange, so the server revokes them.
    expect(request.keepToken).toBe(false)
    expect(JSON.stringify(request)).not.toContain('correct horse')
    expectNothingStored()
  })

  it('logs in with LDAP on a nested mount', async () => {
    const fetchMock = stubOpenBao(tokenResponse('s.ldap'))
    const fake = fakeApprover({ loginOptions: allMethods })
    render(<App client={fake.client} />)

    const user = await chooseMethod('Directory')
    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.type(screen.getByLabelText('Password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: 'Sign in securely' }))

    await waitFor(() => expect(fake.requests<CreateSessionRequest>('CreateSession')).toHaveLength(1))
    const call = openBaoCall(fetchMock)
    expect(call.url).toBe(`${address}/v1/auth/corp/ldap/login/alice`)
    expect(call.body).toEqual({ password: 'hunter2' })
    expect(fake.requests<CreateSessionRequest>('CreateSession')[0].openbaoToken).toBe('s.ldap')
  })

  it('logs in with a GitHub personal access token', async () => {
    const fetchMock = stubOpenBao(tokenResponse('s.github'))
    const fake = fakeApprover({ loginOptions: { ...allMethods, namespace: '' } })
    render(<App client={fake.client} />)

    const user = await chooseMethod('GitHub')
    await user.type(screen.getByLabelText('GitHub personal access token'), 'ghp_secret')
    await user.click(screen.getByRole('button', { name: 'Sign in with GitHub' }))

    await waitFor(() => expect(fake.requests<CreateSessionRequest>('CreateSession')).toHaveLength(1))
    const call = openBaoCall(fetchMock)
    expect(call.url).toBe(`${address}/v1/auth/github/login`)
    expect(call.method).toBe('POST')
    expect(call.body).toEqual({ token: 'ghp_secret' })
    expect(call.headers.has('X-Vault-Namespace')).toBe(false)
    expect(call.headers.get('X-Vault-Request')).toBe('true')
    expect(fake.requests<CreateSessionRequest>('CreateSession')[0].openbaoToken).toBe('s.github')
    expectNothingStored()
  })

  it('shows the errors OpenBao returns as text', async () => {
    stubOpenBao(json({ errors: ['invalid username or password'] }, 400))
    const fake = fakeApprover({ loginOptions: allMethods })
    render(<App client={fake.client} />)

    const user = await chooseMethod('Userpass')
    await user.type(screen.getByLabelText('Username'), 'bob')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Sign in securely' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('invalid username or password')
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(fake.callsTo('CreateSession')).toHaveLength(0)
  })

  it('explains a CORS or network failure', async () => {
    stubOpenBao(new TypeError('Failed to fetch'))
    const fake = fakeApprover({ loginOptions: allMethods })
    render(<App client={fake.client} />)

    const user = await chooseMethod('GitHub')
    await user.type(screen.getByLabelText('GitHub personal access token'), 'ghp_secret')
    await user.click(screen.getByRole('button', { name: 'Sign in with GitHub' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('OpenBao is unreachable from this browser or does not allow this origin (CORS)')
    expect(fake.callsTo('CreateSession')).toHaveLength(0)
  })

  it('shows why the authorizer refused the token', async () => {
    const fake = fakeApprover({
      loginOptions: allMethods,
      handlers: { createSession: () => { throw rpcError(Code.PermissionDenied, 'NOT_APPROVER', 'missing approver policy') } },
    })
    render(<App client={fake.client} />)

    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('OpenBao token'), 's.weak')
    await user.click(screen.getByRole('button', { name: 'Sign in with token' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Your OpenBao identity is not allowed to approve requests.')
    expect(screen.getByRole('heading', { name: 'Operator sign in' })).toBeInTheDocument()
  })

  it('offers a retry when sign-in options cannot load', async () => {
    let attempts = 0
    const fake = fakeApprover({
      handlers: {
        getLoginOptions: () => {
          attempts += 1
          if (attempts === 1) throw rpcError(Code.Unavailable, 'UNREACHABLE')
          return allMethods
        },
      },
    })
    render(<App client={fake.client} />)

    const user = userEvent.setup()
    expect(await screen.findByRole('alert')).toHaveTextContent('The authorizer is unreachable.')
    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByRole('tab', { name: 'Token' })).toBeInTheDocument()
  })

  describe('OIDC', () => {
    it('redirects to the identity provider and remembers only the mount and role', async () => {
      const assign = vi.spyOn(navigation, 'assign').mockImplementation(() => {})
      const fetchMock = stubOpenBao(json({ data: { auth_url: 'https://idp.example/authorize?state=abc' } }))
      render(<App client={fakeApprover({ loginOptions: allMethods }).client} />)

      const user = await chooseMethod('Company SSO')
      await user.click(screen.getByRole('button', { name: 'Continue with Company SSO' }))

      await waitFor(() => expect(assign).toHaveBeenCalledWith('https://idp.example/authorize?state=abc'))
      const call = openBaoCall(fetchMock)
      expect(call.url).toBe(`${address}/v1/auth/oidc/oidc/auth_url`)
      expect(call.method).toBe('POST')
      expect(call.body).toEqual({ role: 'approvers', redirect_uri: `${window.location.origin}/oidc/callback` })
      expect(call.headers.get('X-Vault-Namespace')).toBe('team-a/')
      expect(localStorage).toHaveLength(0)
      expect(sessionStorage).toHaveLength(1)
      expect(Object.values({ ...sessionStorage }).join()).not.toMatch(/s\.|token/i)
    })

    it('explains an empty auth URL from a misconfigured role', async () => {
      const assign = vi.spyOn(navigation, 'assign').mockImplementation(() => {})
      stubOpenBao(json({ data: { auth_url: '' } }))
      render(<App client={fakeApprover({ loginOptions: allMethods }).client} />)

      const user = await chooseMethod('Company SSO')
      await user.click(screen.getByRole('button', { name: 'Continue with Company SSO' }))

      expect(await screen.findByRole('alert')).toHaveTextContent('allows the redirect URI')
      expect(assign).not.toHaveBeenCalled()
      expectNothingStored()
    })

    it('completes the callback, creates a session and cleans up', async () => {
      const assign = vi.spyOn(navigation, 'assign').mockImplementation(() => {})
      stubOpenBao(json({ data: { auth_url: 'https://idp.example/authorize' } }))
      const first = render(<App client={fakeApprover({ loginOptions: allMethods }).client} />)
      const user = await chooseMethod('Company SSO')
      await user.click(screen.getByRole('button', { name: 'Continue with Company SSO' }))
      await waitFor(() => expect(assign).toHaveBeenCalled())
      first.unmount()

      // The provider sends the browser back to a fresh page load.
      window.history.replaceState({}, '', '/oidc/callback?state=st-1&code=co-2&nonce=no-3')
      const fetchMock = stubOpenBao(tokenResponse('s.oidc'))
      const fake = fakeApprover({ loginOptions: allMethods })
      render(<App client={fake.client} />)

      expect(await screen.findByRole('heading', { name: 'Access requests' })).toBeInTheDocument()
      const call = openBaoCall(fetchMock)
      expect(call.url).toBe(`${address}/v1/auth/oidc/oidc/callback?state=st-1&code=co-2&nonce=no-3`)
      expect(call.method).toBe('GET')
      expect(call.body).toBeUndefined()
      expect(call.headers.get('X-Vault-Namespace')).toBe('team-a/')
      expect(fake.requests<CreateSessionRequest>('CreateSession')[0].openbaoToken).toBe('s.oidc')
      expect(window.location.pathname).toBe('/')
      expect(window.location.search).toBe('')
      expectNothingStored()
    })

    it('omits the nonce when the provider sends none', async () => {
      sessionStorage.setItem('openbao-authorizer.oidc-login', JSON.stringify({ mount: 'oidc', role: 'approvers' }))
      window.history.replaceState({}, '', '/oidc/callback?state=st-1&code=co-2')
      const fetchMock = stubOpenBao(tokenResponse('s.oidc'))
      const fake = fakeApprover({ loginOptions: allMethods })
      render(<App client={fake.client} />)

      await waitFor(() => expect(fake.callsTo('CreateSession')).toHaveLength(1))
      expect(openBaoCall(fetchMock).url).toBe(`${address}/v1/auth/oidc/oidc/callback?state=st-1&code=co-2`)
    })

    it('shows OpenBao callback errors and returns to the sign-in form', async () => {
      sessionStorage.setItem('openbao-authorizer.oidc-login', JSON.stringify({ mount: 'oidc', role: 'approvers' }))
      window.history.replaceState({}, '', '/oidc/callback?state=st-1&code=co-2')
      stubOpenBao(json({ errors: ['expired or missing OAuth state'] }, 400))
      const fake = fakeApprover({ loginOptions: allMethods })
      render(<App client={fake.client} />)

      expect(await screen.findByRole('alert')).toHaveTextContent('expired or missing OAuth state')
      expect(await screen.findByRole('tab', { name: 'Token' })).toBeInTheDocument()
      expect(fake.callsTo('CreateSession')).toHaveLength(0)
      expect(window.location.pathname).toBe('/')
      expectNothingStored()
    })

    it('refuses a callback it did not start', async () => {
      window.history.replaceState({}, '', '/oidc/callback?state=st-1&code=co-2')
      const fetchMock = stubOpenBao()
      render(<App client={fakeApprover({ loginOptions: allMethods }).client} />)

      expect(await screen.findByRole('alert')).toHaveTextContent('Sign in again.')
      expect(fetchMock).not.toHaveBeenCalled()
    })
  })
})
