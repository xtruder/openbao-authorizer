# OpenBao Authorizer

A self-hosted approval inbox for [OpenBao control groups](https://openbao.org/community/rfcs/control-groups/). It discovers pending control-group wrapping accessors, streams them to an installable React PWA, sends generic Web Push notifications, and records approvals with the logged-in human's OpenBao identity.

> **OpenBao compatibility:** control groups are not present in OpenBao 2.6.2. The real-process test is pinned to the official `v2.7.0-beta20260909` prerelease, where the feature first appears. Do not infer production stability from this prerelease test; qualify a stable release before production use.

## Security model

Two OpenBao credentials have deliberately different roles:

- **Scanner token:** lists service-token accessors, calls `sys/control-group/request`, and may read explicitly configured non-secret approval metadata. It cannot approve, unwrap, revoke, or renew. Context-reader policies must expose only data safe for every approver to inspect.
- **Human token:** obtained by exchanging username/password with OpenBao's `userpass` auth method, encrypted in the server-side SQLite session store, renewed while the 30-day app session is active, and used for `sys/control-group/authorize`. The password is discarded immediately. Login and every authenticated request require the configured `APPROVER_POLICY`; OpenBao—not this app—then decides whether that identity satisfies each request's control-group factor and prevents disallowed self-approval.

The browser receives neither OpenBao token nor password after login. Its opaque 30-day session is an `HttpOnly`, `SameSite=Strict`, secure cookie; encrypted server-side sessions survive application restarts. Mutations require a session-bound CSRF token, JSON content type, and same-origin checks. Signing out revokes the human token. Wrapping tokens remain with requesters; the app never stores or unwraps them.

Accessors, deferred request payloads, and push subscriptions are AES-256-GCM encrypted before SQLite persistence; the database is created with mode `0600`. Payloads are omitted from API responses unless `requests.expose_data = true` is explicitly configured. Logs, SSE messages, push payloads, URLs, and browser storage do not contain accessors or tokens. Push notifications contain only a generic “approval pending” message, are sent only for an active eligible approver session, expire with that session, and are restricted to configured public push-service host suffixes.

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
make bin/openbao-authorizer
make bin/bao-cred
make e2e        # tagged Go test: real OpenBao + real Go app + API approval flow
```

The E2E setup downloads and caches the official Linux release, verifies the repository-pinned per-architecture SHA-256 and exact archive layout, allocates kernel-assigned loopback ports, and cleans up both process groups. See [`e2e/README.md`](e2e/README.md).

## Container image

The multi-stage [`Dockerfile`](Dockerfile) builds the Vite frontend, embeds it
in the Go binary, and runs as UID/GID `65532` on Alpine with CA certificates.
GitHub Actions publishes multi-architecture images for `linux/amd64` and
`linux/arm64`:

```text
ghcr.io/xtruder/openbao-authorizer:latest
ghcr.io/xtruder/openbao-authorizer:sha-<commit>
```

Version tags publish one archive per supported platform containing both static
`openbao-authorizer` and `bao-cred` binaries, plus a SHA-256 checksum. Linux,
macOS, and Windows are available on amd64 and arm64.

The image expects writable storage plus a mounted HCL configuration and secret
files. OpenBao itself and environment-specific
GitHub App installations, permission sets, passwords, keys, DNS, and Compose
configuration belong in a deployment repository. Generic local-development
examples remain under [`deploy/local`](deploy/local/). The image also contains
`bao-cred` at `/usr/local/bin/bao-cred` for requester workflows that use the
same container image.

## OpenBao policies

Install [`config/scanner-policy.hcl`](config/scanner-policy.hcl) on a dedicated orphan machine token created **without the default policy**. Assign [`config/approver-policy.hcl`](config/approver-policy.hcl) to the human identity group that appears in your protected path's `control_group` factor.

For example, if the HCL configuration includes the GitHub approval-context rule,
install a separate least-privilege metadata-reader policy:

```hcl
path "github/permissionset/*" {
  capabilities = ["read"]
}
```

Then create the scanner token with both policies:

```sh
bao token create -orphan \
  -policy=openbao-authorizer-scanner \
  -policy=openbao-authorizer-github-context \
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
make bin/openbao-authorizer bin/bao-cred
```

Create mode-`0400` files for the application encryption key and scanner token,
then copy and edit [`config/openbao-authorizer.example.hcl`](config/openbao-authorizer.example.hcl):

```sh
openssl rand -base64 32 >/run/secrets/openbao-authorizer-key
chmod 0400 /run/secrets/openbao-authorizer-key /run/secrets/openbao-scanner-token
cp config/openbao-authorizer.example.hcl openbao-authorizer.hcl
./bin/openbao-authorizer -config openbao-authorizer.hcl
```

Terminate TLS at a trusted reverse proxy. Do not set `insecure_cookies = true` outside loopback development or the E2E harness. Relative paths in the HCL file are resolved from the file's directory.

## Credential requester CLI

`bao-cred` reads any OpenBao path and returns its data. When OpenBao applies a
control group, it reports progress on stderr, waits up to 15 minutes for
approval, then consumes the wrapping token. It uses the official OpenBao Go
client and honors standard client variables such as `BAO_ADDR`, `BAO_NAMESPACE`,
and `BAO_CACERT`.

The request token is selected in this order: an explicit `-token-file`,
`BAO_TOKEN`, then
`$OPENBAO_CONTROL_GROUP_CONFIG_DIR/agent-token` (defaulting to
`~/.config/openbao-authorizer/agent-token`). Credentials are delivered through
exactly one output or command action:

For protected paths, the request token's policy must also allow the
parameter-constrained control-group status check used while waiting:

```hcl
path "sys/control-group/request" {
  capabilities        = ["update"]
  required_parameters = ["accessor"]
  allowed_parameters  = { "accessor" = [] }
}
```

```sh
# Complete data object as JSON.
bao-cred database/creds/app

# One scalar, with no trailing newline.
bao-cred -field username database/creds/app

# Custom text from the unwrapped data object.
bao-cred -format template -template '{{ .username }}:{{ .password }}' database/creds/app

# Explicit dotenv mappings written atomically with mode 0600.
bao-cred -format dotenv \
  -map DB_USER=username -map DB_PASSWORD=password \
  -output credentials.env database/creds/app

# Explicit environment mappings available only to the child command.
bao-cred -map GH_TOKEN=token github/token/project-example -- \
  gh repo view example-org/example-repo
```

Formats are `json`, `template`, `dotenv`, and POSIX `shell`. Dot-path selectors
support nested objects, array indexes, and backslash-escaped dots in key names.
Missing fields, duplicate mappings, and mapped arrays or objects fail the whole
operation. Use `-quiet`, `-timeout`, and `-poll-interval` for automation. Shell
output contains credentials by design; source it only in a trusted shell and do
not log it.

### Configuration

The server accepts one HCL file through `-config`; environment variables are not
used for server configuration. The example file documents every required block.
Encryption keys, scanner tokens, and optional VAPID keys are read from files so
secret values do not appear in HCL or the process environment.

An `approval_context` block maps a reviewed request path to a safe, read-only
OpenBao endpoint. Placeholders capture complete path segments and are escaped
before substitution:

```hcl
approval_context "github-token" {
  match_path = "github/token/{name}"
  read_path  = "github/permissionset/{name}"
}
```

The scanner token must have `read` access to every configured `read_path`.
Returned data is displayed opaquely; the authorizer contains no GitHub-specific
schema or path logic. If a configured read fails, the UI warns the operator not
to approve the request.

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
hostname to `web_push.allowed_host_suffixes`. Common examples are:

```hcl
allowed_host_suffixes = ["updates.push.services.mozilla.com", "fcm.googleapis.com", "web.push.apple.com"]

# If Fennec returns an ntfy.sh endpoint:
allowed_host_suffixes = ["updates.push.services.mozilla.com", "ntfy.sh"]
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
- Deferred request payloads are encrypted at rest and redacted from the API by default. If `requests.expose_data = true`, every app approver can view them; use that only where submitted fields are safe to disclose.
