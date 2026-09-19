# OpenBao Authorizer

A self-hosted approval inbox for [OpenBao control groups](https://openbao.org/community/rfcs/control-groups/). It discovers pending control-group wrapping accessors, streams them to an installable React PWA, sends generic Web Push notifications, and records approvals with the logged-in human's OpenBao identity.

> **OpenBao compatibility:** control groups are not present in OpenBao 2.6.2. The real-process test is pinned to the official `v2.7.0-beta20260909` prerelease, where the feature first appears. Do not infer production stability from this prerelease test; qualify a stable release before production use.

## Security model

Two OpenBao credentials have deliberately different roles:

- **Scanner token:** lists service-token accessors and calls `sys/control-group/request`. It cannot approve, unwrap, revoke, renew, or read secrets.
- **Human token:** obtained by exchanging username/password with OpenBao's `userpass` auth method, encrypted in the server-side SQLite session store, renewed while the 30-day app session is active, and used for `sys/control-group/authorize`. The password is discarded immediately. Login and every authenticated request require the configured `APPROVER_POLICY`; OpenBao—not this app—then decides whether that identity satisfies each request's control-group factor and prevents disallowed self-approval.

The browser receives neither OpenBao token nor password after login. Its opaque 30-day session is an `HttpOnly`, `SameSite=Strict`, secure cookie; encrypted server-side sessions survive application restarts. Mutations require a session-bound CSRF token, JSON content type, and same-origin checks. Signing out revokes the human token. Wrapping tokens remain with requesters; the app never stores or unwraps them.

Accessors, deferred request payloads, and push subscriptions are AES-256-GCM encrypted before SQLite persistence; the database is created with mode `0600`. Payloads are omitted from API responses unless `EXPOSE_REQUEST_DATA=true` is explicitly configured. Logs, SSE messages, push payloads, URLs, and browser storage do not contain accessors or tokens. Push notifications contain only a generic “approval pending” message, are sent only for an active eligible approver session, expire with that session, and are restricted to configured public push-service host suffixes.

## Architecture

```text
OpenBao ── LIST accessors / inspect ──> Go scanner ──> encrypted SQLite
   ^                                         │              │
   │ human authorize                         ├── SSE ────────┤
   │                                         └── Web Push    │
Browser PWA ── HttpOnly session + CSRF ──> Go HTTP API ─────┘
```

The production Vite build is embedded in the Go binary and served by default. The service worker precaches only static application assets; `/api/` is network-only.

## Prerequisites

- Go 1.26 or newer
- Node.js and npm
- OpenBao with control-group support (`v2.7.0-beta20260909` is the currently tested version)
- HTTPS for production PWA installation, secure cookies, and Web Push

## Build and test

```sh
make test       # Go race tests + React workflow tests
make lint       # go vet, golangci-lint, Oxlint
make build      # web/dist and bin/openbao-authorizer
make e2e        # tagged Go test: real OpenBao + real Go app + API approval flow
```

The E2E Go test downloads and caches the official Linux release, verifies the repository-pinned per-architecture SHA-256 and exact archive layout, allocates kernel-assigned loopback ports, and cleans up both process groups. See [`e2e/openbao/README.md`](e2e/openbao/README.md).

## OpenBao policies

Install [`config/scanner-policy.hcl`](config/scanner-policy.hcl) on a dedicated orphan machine token created **without the default policy**. Assign [`config/approver-policy.hcl`](config/approver-policy.hcl) to the human identity group that appears in your protected path's `control_group` factor.

For example, after writing the scanner policy:

```sh
bao token create -orphan \
  -policy=openbao-authorizer-scanner \
  -no-default-policy \
  -renewable=false
```

The scanner policy uses path-scoped `sudo`; it is not a root token. Listing `auth/token/accessors` still exposes every service-token accessor and must be tightly controlled. The `-no-default-policy` flag is required: without it, OpenBao attaches capabilities such as token self-renewal that are outside the documented scanner role.

Each protected factor must explicitly set `approvals >= 1` and should leave self-authorization disabled:

```hcl
path "pki/issue/*" {
  capabilities = ["update"]

  control_group = {
    ttl               = "30m"
    self_auth_allowed = false

    factor "pki-approvers" {
      controlled_capabilities = ["update"]
      identity {
        group_names = ["pki-approvers"]
        approvals   = 1
      }
    }
  }
}
```

## Run

Build first:

```sh
make build
```

Create an application encryption key and place the scanner token in a mode-`0400` file:

```sh
export APP_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export OPENBAO_SCANNER_TOKEN_FILE=/run/secrets/openbao-scanner-token
export OPENBAO_ADDRESS=https://openbao.example.com
export OPENBAO_CA_FILE=/etc/ssl/certs/organization-openbao-ca.pem
export APPROVER_POLICY=openbao-authorizer-approver
export PUBLIC_ORIGIN=https://approvals.example.com
./bin/openbao-authorizer
```

The default listener is `127.0.0.1:8080`; terminate TLS at a trusted reverse proxy. Do not set `INSECURE_COOKIES=true` outside loopback development or the E2E harness.

### Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `APP_ENCRYPTION_KEY` | required | Base64-encoded 32-byte AES key; loss makes stored accessors unreadable |
| `OPENBAO_SCANNER_TOKEN_FILE` | required* | Preferred file containing the scanner token |
| `OPENBAO_SCANNER_TOKEN` | required* | Direct token fallback for local development |
| `OPENBAO_ADDRESS` | `http://127.0.0.1:8200` | OpenBao API origin |
| `OPENBAO_CA_FILE` | system trust | Additional PEM CA for OpenBao TLS |
| `OPENBAO_NAMESPACE` | empty | Fixed server-side OpenBao namespace |
| `APPROVER_POLICY` | required | Policy every interactive user must retain; normally the installed approver policy |
| `EXPOSE_REQUEST_DATA` | `false` | Return encrypted deferred payloads to approvers; enable only after reviewing path data sensitivity |
| `LISTEN_ADDRESS` | `127.0.0.1:8080` | HTTP listener |
| `PUBLIC_ORIGIN` | required in secure mode | Exact public origin used for CSRF origin checks |
| `INSECURE_COOKIES` | `false` | Local HTTP development only |
| `DATABASE_PATH` | `openbao-authorizer.db` | SQLite state path |
| `STATIC_DIRECTORY` | unset (embedded) | Explicit filesystem frontend override for development |
| `SCAN_INTERVAL` | `15s` | Accessor polling period, minimum `1s` |
| `SCAN_CONCURRENCY` | `8` | Concurrent accessor probes, range 1–64 |
| `VAPID_PUBLIC_KEY` | unset | Web Push public key |
| `VAPID_PRIVATE_KEY` | unset | Web Push private key |
| `VAPID_SUBJECT` | unset | VAPID contact URI, such as `mailto:ops@example.com` |
| `PUSH_ALLOWED_HOST_SUFFIXES` | required with VAPID | Comma-separated push-service DNS suffix allowlist; every resolution must remain public |

`*` Configure exactly one scanner-token source. VAPID variables are optional, but all three must be supplied together to enable push.

### Android Firefox/Fennec Web Push

Fennec-based Android browsers may expose the Notification, Service Worker, and
Push APIs even when their underlying push transport has not been configured.
Granting notification permission alone is therefore not sufficient.

For Fennec F-Droid:

1. Use Fennec `149.0.1` or later. Version `149.0.0` had a known UnifiedPush
   setup regression.
2. Install and configure a UnifiedPush distributor, such as Sunup or ntfy.
3. Enable **Use UnifiedPush** in Fennec settings and restart Fennec when
   prompted.
4. In Android's Fennec notification settings, enable both **Site
   notifications** and **UnifiedPush** channels.
5. Return to this PWA and enable notifications.

`DOMException: Error retrieving push subscription` means Fennec could not
obtain a subscription from its configured distributor; the request has not yet
reached this application's backend. Verify the distributor is running, exempt
it from battery optimization, and confirm that it lists Fennec as a registered
application.

When the browser does obtain a subscription, its HTTPS endpoint must also pass
the backend's outbound SSRF policy. Add only the actual distributor's endpoint
hostname to `PUSH_ALLOWED_HOST_SUFFIXES`. Common examples are:

```dotenv
# Mozilla AutoPush / Sunup, standard FCM, Apple Web Push
PUSH_ALLOWED_HOST_SUFFIXES=updates.push.services.mozilla.com,fcm.googleapis.com,web.push.apple.com

# If Fennec returns an ntfy.sh endpoint:
PUSH_ALLOWED_HOST_SUFFIXES=updates.push.services.mozilla.com,ntfy.sh
```

A `push endpoint is not allowed` response means subscription creation succeeded
in the browser, but its endpoint hostname was not allowlisted (for example,
Fennec returned `ntfy.sh`). The server deliberately logs only the rejected
hostname and validation reason; it never logs the full endpoint URL or push
keys. After changing the allowlist, restart the server and enroll the device
again. Do not use a broad suffix merely to make enrollment pass: permitted
hosts can receive authenticated outbound Web Push requests from the server.

Successful enrollment creates an encrypted subscription in SQLite. New
control-group requests can then notify the device while the PWA is closed,
provided its persistent approver session remains active. Push messages contain
only a generic pending-approval notice; request details still require opening
the authenticated app.

### Frontend development

Run the Go server on port 8080, then:

```sh
cd web
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://127.0.0.1:8080`.

## API

- `POST /api/v1/session` — exchange an OpenBao username/password and create a persistent opaque session
- `GET /api/v1/session` — restore browser session state
- `DELETE /api/v1/session` — sign out
- `GET /api/v1/requests` — list discovered requests without accessors
- `POST /api/v1/requests/{id}/approve` — approve with the session's human token
- `GET /api/v1/events` — same-origin SSE update hints
- `GET /api/v1/push/public-key`, `POST /api/v1/push/subscriptions`, and `DELETE /api/v1/push/subscriptions` — Web Push enrollment/removal
- `GET /healthz` — process health

## Current deployment boundaries

- Encrypted sessions and subscriptions are durable in SQLite, while SSE fan-out remains process-local; deploy one instance unless you add shared event infrastructure.
- SQLite is suited to one app instance. Back it up together with the external encryption key.
- Discovery cost scales with all active service-token accessors because OpenBao has no pending-control-group list endpoint.
- OpenBao currently provides authorize, review, and unwrap operations, not a durable reject operation.
- Browser push is best-effort. The request list and SSE remain authoritative.
- Deferred request payloads are encrypted at rest and redacted from the API by default. If `EXPOSE_REQUEST_DATA=true`, every app approver can view them; use that only where submitted fields are safe to disclose.
