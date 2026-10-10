# Approvers sign in to OpenBao; their app sessions are app-owned and need no CSRF token

An Approver signs in to OpenBao directly from the PWA with any auth method the operator lists (token, userpass, LDAP, GitHub or OIDC). The PWA hands the resulting token to the authorizer's `CreateSession` once; it keeps the token only in memory until then. The authorizer runs `lookup-self`, checks the identity's approver policy, then revokes the OpenBao token straight away, so the authorizer never sees passwords or other login credentials. What it keeps is its own session (ID, entity, display name, expiry), referenced by an `HttpOnly`, `SameSite=Strict` cookie. The authorizer's own token performs every OpenBao write, so the human token has nothing left to do after sign-in. Approver RPCs need that cookie and a same-origin request, and no CSRF token.

## Considered options

- **Sign in through the authorizer with userpass.** The authorizer exchanged a username and password with OpenBao. Only one auth method was possible, and credentials passed through the authorizer, where a bug or log line could expose them.
- **Keep the human OpenBao token for the session's lifetime.** Removing someone's approver policy would take effect on their next request. But the authorizer would have to encrypt the token at rest, renew it, revoke it and call OpenBao on every request, and its database would hold live human credentials.
- **A CSRF token on top of the cookie.** It is redundant here, and it forced a special case for restoring the session after a reload. Three protections already stop cross-site calls:
  - a `SameSite=Strict` cookie is never sent cross-site;
  - Connect's content types force a CORS preflight, which the server never grants;
  - the origin check rejects sibling sites.
- **A bearer token for approvers.** Keeping the OpenBao token, or an app token, in the browser would raise no CSRF question, but page JavaScript could read it for the session's lifetime, which makes XSS worse.

## Consequences

- **OpenBao must allow the PWA origin.** Operators configure `sys/config/cors` for the public origin, and OIDC roles must allow `<origin>/oidc/callback` as a redirect URI. The PWA's Content-Security-Policy allows connections to the configured OpenBao address.
- **Tokens obtained by OpenBao login in the PWA are revoked after the check,** even when sign-in is refused, so no live credential outlives the exchange. **Pasted tokens are checked and left valid,** because they may be the user's working token, for example from `bao login`. The authorizer stores neither kind.
- **Removing an approver policy takes effect at the next sign-in.** That can be up to `server.session_ttl` later (default 7 days), so the TTL is the knob that trades convenience against how fast revocation bites.
- **The authorizer's database holds no OpenBao tokens.** Session rows store only an HMAC of the session ID.
- **Push subscriptions live as long as the session that registered them.** They are deleted on logout.
