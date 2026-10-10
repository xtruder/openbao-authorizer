# Approver sessions are app-owned and need no CSRF token

An Approver signs in with OpenBao userpass. The authorizer checks the identity's approver policy, then revokes the OpenBao token straight away. What it keeps is its own session (ID, entity, display name, expiry), referenced by an `HttpOnly`, `SameSite=Strict` cookie. The authorizer's own token performs every OpenBao write, so the human token has nothing left to do after login. Approver RPCs need that cookie and a same-origin request, and no CSRF token.

## Considered options

- **Keep the human OpenBao token for the session's lifetime.** Removing someone's approver policy would take effect on their next request. But the authorizer would have to encrypt the token at rest, renew it, revoke it and call OpenBao on every request, and its database would hold live human credentials.
- **A CSRF token on top of the cookie.** It is redundant here, and it forced a special case for restoring the session after a reload. Three protections already stop cross-site calls:
  - a `SameSite=Strict` cookie is never sent cross-site;
  - Connect's content types force a CORS preflight, which the server never grants;
  - the origin check rejects sibling sites.
- **A bearer token for approvers.** No CSRF question would arise, but page JavaScript could read the token, which makes XSS worse.

## Consequences

- **Removing an approver policy takes effect at the next login.** That can be up to `server.session_ttl` later (default 7 days), so the TTL is the knob that trades convenience against how fast revocation bites.
- **The authorizer's database holds no OpenBao tokens.** Session rows store only an HMAC of the session ID.
- **Push subscriptions live as long as the session that registered them.** They are deleted on logout.
