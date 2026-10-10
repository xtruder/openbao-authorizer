# Plan: ConnectRPC API

This is the shared contract for the subagents doing the REST-to-ConnectRPC migration. It is temporary: once the work lands, the protos, code, README and [ADR-0002](../adr/0002-connectrpc-api.md) are authoritative. Vocabulary is in [`CONTEXT.md`](../../CONTEXT.md).

The contract is `proto/openbao/authorizer/v1/*.proto`. Generated code is committed: Go in `gen/go/...` (package `authorizerv1`, handlers in `authorizerv1connect`) and TypeScript in `web/src/gen/...`. Run `make generate` after any proto change. **Don't change the protos without saying so in your report.**

## Transport

- **Base URL:** services are mounted under the `/api` prefix on the existing HTTP listener, so URLs look like `/api/openbao.authorizer.v1.AgentService/CreateGrantRequest`.
  - Clients use base URL `<origin>/api`.
  - `OPENBAO_AUTHORIZER_URL` and `-authorizer` stay the bare origin; bao-cred appends `/api`.
  - The service worker's network-only rule for `/api/` and Vite's `/api` dev proxy keep working.
- **Protocols:** the server accepts Connect, gRPC and gRPC-Web, which is connect-go's default.
  - The PWA uses `@connectrpc/connect-web` with Connect JSON.
  - bao-cred uses the connect-go client with the Connect protocol and binary format.
- **Removed:** all `/api/v1/*` REST endpoints and the SSE endpoint. Static assets and `GET /healthz` stay.
- **Stream timeouts:** streams must outlive the server's 30s `WriteTimeout`. Extend write deadlines per streaming call (`http.ResponseController`), as the SSE code does now. `ReadHeaderTimeout` is unchanged.

## Authentication

- **Agent RPCs:** take `Authorization: Bearer <Session Token>`. One OpenBao call: `lookup-self` with that token. Accept it only if its `role` equals the configured `openbao.session_token_role` (default `opencode-session`) and it has an `entity_id`. The session ID shown to Approvers comes from token `meta.session_id`, falling back to the entity ID; title and directory also come from `meta`. No entity read and no alias check. Only the minter can create tokens with that role, which is the same trust the alias check relied on. Grants stay keyed by entity ID.
- **Approver RPCs:** every RPC requires a same-origin request (the existing Origin / `Sec-Fetch-Site` checks). Every RPC except `Login` also requires a live session cookie.
  - **No CSRF token.** The cookie is `HttpOnly` and `SameSite=Strict`, Connect's content types force a CORS preflight the server never grants, and the origin check rejects sibling sites.
  - **No stored OpenBao token.** `Login` performs the userpass login, checks the entity and the approver policy, then **revokes the OpenBao token at once**. The session holds only `{id, entity_id, display_name, expires_at}`.
  - Session lifetime is `server.session_ttl`, default `168h`. Removing someone's approver policy in OpenBao takes effect at their next login. This trade-off is accepted and documented.
  - There is no per-request OpenBao lookup, no renewal loop, and no token encryption.
  - `Logout` deletes the session and its push subscriptions, and clears the cookie.
  - Re-login replaces the session the incoming cookie names.
- **Request bodies:** keep today's size limits.

## Errors

Use Connect codes, and attach an `openbao.authorizer.v1.ErrorDetail` with a stable `reason`:

| Code | `reason` | When |
|---|---|---|
| `unauthenticated` | `INVALID_TOKEN` | OpenBao rejects the bearer token |
| `unauthenticated` | `SESSION_EXPIRED` | missing or expired approver session |
| `permission_denied` | `NOT_SESSION_IDENTITY` | agent token not from the session token role, or without an entity |
| `permission_denied` | `NOT_APPROVER` | identity lacks the approver policy |
| `permission_denied` | `CROSS_ORIGIN` | same-origin check failed |
| `invalid_argument` | `INVALID_REQUEST` | bad input |
| `not_found` | `NOT_FOUND` | unknown, or another session's, request or grant |
| `failed_precondition` | `ITEM_NOT_PENDING` | `ids` lists the items |
| `failed_precondition` | `GRANT_NOT_ACTIVE` | grant already revoked or expired |
| `unavailable` | `OPENBAO_UNAVAILABLE` | agent RPCs get a generic message, never OpenBao's text |

Per-item refusals are item state plus `reason`, not errors.

## Streams

Both streams follow "snapshot first, then changes":

- **`WatchGrantRequest`:** on connect, send the full `GrantRequest`; send it again after every change; send a `Heartbeat` every 25s. Once no item is pending, send the final state and end the stream normally.
- **`WatchEvents`:** on connect, send a `DashboardSnapshot` with pending requests, decided requests (the existing 200 cap) and active grants. Send a new snapshot after every change, including the grant-expiry announcements, and heartbeats every 25s. When the approver session ends or is revoked, end with `unauthenticated` / `SESSION_EXPIRED`.
- **Reconnects:** clients reconnect after a drop and treat the next snapshot as the truth. There are no cursors.

## Unchanged

Grant semantics and validation, OpenBao writes, storage, push delivery, config and bao-cred's CLI surface. bao-cred keeps its stdout JSON shapes and exit codes 0/1/2/3/4:
- states printed in lowercase snake_case, e.g. `approved`, `already_granted`;
- `ttl` as a Go duration string;
- timestamps in RFC 3339.

## Tasks

1. **Server:** `internal/httpapi` and `cmd/openbao-authorizer`. Write the handlers, interceptors, streams and error mapping; remove REST and SSE; update Go tests and the README API section.
2. **bao-cred:** `cmd/bao-cred` becomes a generated-client wrapper. `request` waits through `WatchGrantRequest`, reconnecting with backoff until the timeout. `-no-wait` only creates. `-wait ID` watches. Keep the https-or-loopback rule and the redirect-downgrade guard.
3. **PWA:** `web/src`. Use the generated client and the `WatchEvents` stream instead of SSE and REST, and generated types instead of `types.ts` where practical. Push enrollment goes through RPCs. Use `createRouterTransport` in the tests.
4. **E2E** (after 1–3): drive the approver side through the generated Go client.
