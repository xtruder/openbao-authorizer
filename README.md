# OpenBao Authorizer

Humans approve, item by item, the extra OpenBao permissions that a **Requester**, such as an AI agent working in a project, asks for. Approved permissions apply to the Requester's existing OpenBao token.

A Requester is any OpenBao identity that an operator-defined **Requester Rule** (a token role or an auth mount) lets file requests. The main kinds are a **Named Identity**, a long-lived identity, such as one per project, whose **Named Token** a human mints with `bao-cred init`, and each **Agent Session** working under it: one agent conversation, whose **Session Token** bao-cred mints from the Named Token. A CI job logging in with AppRole can be another kind. The Requester files a **Grant Request**: a reason plus one or more **Permission Items** (path + capabilities). Items outside the operator's **Grantable Rules** are refused at once; the rest wait in an installable React PWA, with Web Push for new items. An **Approver** approves or rejects each item, optionally shortening its TTL and choosing its **Grant Scope**: the one session, the whole project, or every project on the server. An approved item becomes a **Grant**: a path block with its own expiry in the OpenBao policy of its scope. The Requester's unchanged token can read the path immediately, until the Grant expires or is revoked; after expiry the path needs a new approval. See [`CONTEXT.md`](CONTEXT.md) for the vocabulary, and [ADR-0001](docs/adr/0001-identity-scoped-grants.md), [ADR-0005](docs/adr/0005-named-identities.md), [ADR-0006](docs/adr/0006-grant-scopes.md) and [ADR-0007](docs/adr/0007-local-identity-files.md) for the design decisions.

> **OpenBao compatibility:** targets OpenBao **2.7.1** stable. Policy-level `expiration` and entity aliases on token roles are required; OpenBao control groups are not used.

## Security model

Approvers sign in to OpenBao directly from the PWA with any supported auth method, and the PWA exchanges the resulting token for an app-owned session that keeps no OpenBao token ([ADR-0003](docs/adr/0003-approver-sessions.md)). The authorizer never sees passwords or other login credentials.

Three kinds of OpenBao token have deliberately different roles:

- **Authorizer token:** the authorizer's own credential, created without the default policy. It reads identity entities to attach Requester policies, writes and deletes `agent-grant-*` ACL policies, and updates entity `policies`. It can't change other entity fields, other policies' contents, tokens or auth methods. Because it controls Grant policy content and entity policy lists, it can grant privileges and must be protected like an administrative credential. All OpenBao writes use this token.
- **Requester token:** any token matching a `requester` rule and carrying an entity, such as a Named Token minted by `bao-cred` through the `named-identity` token role, with the identity's name as entity alias, or a Session Token minted from it through the `agent-session` role. Besides the baseline policy, both carry only the project and global Grant policies. Requesters present it as `Authorization: Bearer` to the `GrantService`. The authorizer accepts it only when `lookup-self` reports an entity and matches a rule; only humans holding the minter policy can create tokens with the `named-identity` role, and only Named Tokens with the `agent-session` role. It uses the token only for `lookup-self` and `capabilities-self` and never stores it.
- **Approver token:** obtained by the Approver's browser from OpenBao with any enabled auth method (token, userpass, LDAP, GitHub or OIDC) and handed to `CreateSession` once. It only proves that the Approver holds the configured `approver_policy`; when the PWA obtained it by logging in to OpenBao, the authorizer revokes it right after the check, even when it refuses the sign-in. A pasted token is checked and left valid (`keep_token`), because it may be the user's working token. The authorizer never stores either kind.

Grants are enforced by OpenBao, not by the authorizer:

- Each scope has one policy holding one `path` block per active Grant: `agent-grant-<entity id>` for a session-scope Requester, `agent-grant-project-<name>` per project and `agent-grant-global`. Each block carries its own `expiration`, and the policy expires with its last block, so Grants lapse on time even when the authorizer is down.
- Session Grants attach to the Requester's entity, so they reach every token of that identity (including a token minted again by `bao-cred`) and never another Requester's. Project and global Grants reach exactly the tokens minted with that policy name.
- An Approver can't decide a request filed by their own entity (`SELF_APPROVAL`); they can still revoke any Grant.
- The **Hard Denylist** refuses any path with a `sys`, `auth`, `identity` or `cubbyhole` segment in any position (a root-namespace policy on `ns1/sys/...` reaches namespace `ns1`'s `sys/`) and any `sudo` capability, whatever the configuration says. The server refuses to start if a `grantable` rule names such a segment.
- Requested paths must be concrete (no `*` or `+`), so each Grant covers exactly one path.

The threat model guards against agent mistakes, not a malicious local agent: the agent runs as the same OS user as the human who mints Named Tokens, so it could read their `bao login` token, mint a token for any name and use that identity's Grants, and a Named Token may mint Session Tokens carrying another project's Grant policy ([ADR-0005](docs/adr/0005-named-identities.md)).

The browser keeps no OpenBao token after sign-in: the token exists only in memory between OpenBao's response and the `CreateSession` call, and passwords go only to OpenBao. The app session (`server.session_ttl`, default 7 days) is an `HttpOnly`, `SameSite=Strict`, secure cookie; server-side sessions hold only the entity ID, display name and expiry, and survive application restarts. Every approver RPC, including sign-in, reads and the live stream, requires a same-origin request (`Origin` and `Sec-Fetch-Site` checks). There is no CSRF token: the cookie is `SameSite=Strict`, Connect's content types force a CORS preflight the server never grants, and the origin check rejects sibling sites. The authorizer checks the approver policy only at sign-in, so removing it from someone takes effect at their next sign-in, at most `session_ttl` later. Signing out deletes the session and its push subscriptions. The `GrantService` accepts only bearer tokens and ignores cookies, so a browser cannot be tricked into calling it.

Request reasons, Requester display fields (ID, title, directory, rule), and push subscriptions are AES-256-GCM encrypted before SQLite persistence; approver sessions are stored under an HMAC of their ID; the database is created with mode `0600`. Paths and capabilities are stored in plaintext. Logs, stream messages, push payloads, URLs, and browser storage contain no tokens. Push notifications contain only a generic "access requested" message, expire with the approver session that registered them, and are restricted to configured public push-service host suffixes.

## Architecture

Agents learn the workflow from the [`openbao-grants` skill](skills/openbao-grants/SKILL.md) ([Agent skill](#agent-skill)); Named Identities are described in [ADR-0005](docs/adr/0005-named-identities.md) and [ADR-0007](docs/adr/0007-local-identity-files.md).

```text
human ── bao-cred init (bao login token) ──> OpenBao ──token/create/named-identity──> Named Token
                                                                                          │
                                           keyring or file, selected by .git/bao-identity ┘
                                                                     │ token/create/agent-session
                                                                     ▼ (OPENCODE_SESSION_ID / BAO_SESSION_ID)
agent ── bao-cred (Bearer Session Token) ──> GrantService ──lookup-self, capabilities-self
                                               │
                                               ▼
                                     encrypted SQLite ──WatchEvents / Web Push──> Approver PWA ──sign-in──> OpenBao
                                               ▲                                  │
                                               └── CreateSession, per-item approve / reject
                                               │
                      authorizer token: one policy per scope, one path block per Grant (expiration each):
                        agent-grant-<entity id> (attached to the session), agent-grant-project-<name>,
                        agent-grant-global (carried by every Named and Session Token)
agent ── same Session Token ──> OpenBao (bao-cred, bao-cred run -- secretspec / bao CLI)
```

Both clients use one ConnectRPC API defined in `proto/` ([ADR-0002](docs/adr/0002-connectrpc-api.md)), served on the same listener under `/api`. The production Vite build is embedded in the Go binary and served by default. The service worker precaches only static application assets; `/api/` is network-only.

## Prerequisites

- Go 1.26 or newer
- Node.js and npm
- OpenBao 2.7.1 or newer
- HTTPS for production PWA installation, secure cookies, and Web Push

## Build and test

```sh
make test       # Go race tests + React workflow tests
make lint       # go vet, golangci-lint, Oxlint
make bin/openbao-authorizer
make bin/bao-cred
make e2e        # tagged Go test: real OpenBao + authorizer + bao-cred grant flow
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
`openbao-authorizer` and `bao-cred` binaries, plus a SHA-256 checksum. Linux
and macOS are available on amd64 and arm64.

The image expects writable storage plus a mounted HCL configuration and secret
files. OpenBao itself and environment-specific
GitHub App installations, permission sets, passwords, keys, DNS, and Compose
configuration belong in a deployment repository. Generic local-development
examples remain under [`deploy/local`](deploy/local/). The image also contains
`bao-cred` at `/usr/local/bin/bao-cred` for agent workflows that use the same
container image.

## OpenBao setup

| Object | Definition |
|---|---|
| Baseline policy `named-identity` | `update` on `auth/token/create/agent-session`, so Named Tokens can mint Session Tokens; otherwise site-defined. Tokens also carry `default`, which provides `lookup-self`, `renew-self`, `revoke-self` and `capabilities-self`. bao-cred names a role's baseline policy like the role. Example: [`deploy/local/named-identity-policy.hcl`](deploy/local/named-identity-policy.hcl). |
| Token role `named-identity` | `allowed_policies=["named-identity","agent-grant-global"]`, `allowed_policies_glob=["agent-grant-project-*"]`, `orphan=true`, `renewable=true`, `token_period=768h`, `allowed_entity_aliases=["*"]`. OpenBao caps the period at the token mount's max TTL (768h by default) |
| Baseline policy `agent-session` | Empty or site-defined ([`deploy/local/agent-session-policy.hcl`](deploy/local/agent-session-policy.hcl)) |
| Token role `agent-session` | `allowed_policies=["agent-session","agent-grant-global"]`, `allowed_policies_glob=["agent-grant-project-*"]`, `orphan=false`, `renewable=true`, `token_period=24h`, `allowed_entity_aliases=["*"]` |
| Minter policy `named-identity-minter` | `update` on `auth/token/create/named-identity` only ([`deploy/local/named-identity-minter-policy.hcl`](deploy/local/named-identity-minter-policy.hcl)), on a login used only to run `bao-cred init` and `auth`, such as a `dev` userpass user. Never give it to an approver: `bao login` leaves the token in `~/.vault-token`, where agents can read it, and an approver token would let them approve their own requests |
| Authorizer policy | [`config/authorizer-policy.hcl`](config/authorizer-policy.hcl), on a dedicated orphan token created without the default policy |
| Approver policy | [`config/approver-policy.hcl`](config/approver-policy.hcl), on the human approvers' identity group; its name is `openbao.approver_policy` |
| Approver auth methods | Any of token, userpass, LDAP, GitHub or OIDC, listed in `approver_login`. Approver tokens need an entity |
| CORS | `sys/config/cors` allows the PWA origin (see below) |

```sh
bao policy write openbao-authorizer config/authorizer-policy.hcl
bao policy write openbao-authorizer-approver config/approver-policy.hcl
bao policy write named-identity deploy/local/named-identity-policy.hcl
bao policy write named-identity-minter deploy/local/named-identity-minter-policy.hcl
bao policy write agent-session deploy/local/agent-session-policy.hcl

bao write auth/token/roles/named-identity \
  allowed_policies=named-identity,agent-grant-global allowed_policies_glob='agent-grant-project-*' \
  orphan=true renewable=true token_period=768h allowed_entity_aliases='*'
bao write auth/token/roles/agent-session \
  allowed_policies=agent-session,agent-grant-global allowed_policies_glob='agent-grant-project-*' \
  orphan=false renewable=true token_period=24h allowed_entity_aliases='*'

bao token create -orphan -policy=openbao-authorizer -no-default-policy \
  -period=720h -field=token >/run/secrets/openbao-authorizer-token
```

The authorizer policy grants:

```hcl
path "identity/entity/id/*" {
  capabilities = ["read", "update"]
  allowed_parameters = {
    "policies" = []
  }
}

path "sys/policies/acl/agent-grant-*" {
  capabilities = ["create", "read", "update", "delete"]
}
```

For each Grantable Rule with a `discover` path, add a `list` stanza to the
authorizer policy, since the authorizer lists that path with its own token:

```hcl
path "github/permissionsets" {
  capabilities = ["list"]
}
```

OpenBao accepts the trailing-slash form `github/permissionsets/` as well.
Without the stanza the rule still works, and its catalog entry carries a
`discover_error`.

The key-only `allowed_parameters` allows entity updates to change `policies` and nothing else, so `name`, `metadata` and `disabled` are refused. OpenBao can't restrict which policy names go into that list. Value globs such as `["agent-grant-*"]` reject a JSON list and accept a comma-joined string containing any names. Treat this token as a privilege-granting credential: it writes the content of Grant policies and can attach any non-root policy to any entity. Grantable Rules and the Hard Denylist are enforced by the authorizer, not by OpenBao. When it attaches a session policy, the authorizer appends the name and keeps every policy already on the entity.

### CORS and approver sign-in

The PWA calls OpenBao from the browser, so OpenBao must allow the PWA's origin
(`server.public_origin`) and the headers it sends:

```sh
bao write sys/config/cors enabled=true \
  allowed_origins=https://approvals.example.com \
  allowed_headers=X-Vault-Token,X-Vault-Namespace,X-Vault-Request,Content-Type
```

`approver_login.openbao_address` must be reachable from approvers' browsers,
which may differ from `openbao.address`. The PWA's Content-Security-Policy
allows connections to that origin. For OIDC, the role must list
`<public_origin>/oidc/callback` in its `allowed_redirect_uris`. When the PWA
shows "OpenBao is unreachable from this browser or does not allow this origin
(CORS)", check the address and the CORS configuration.

The authorizer renews its own token when it starts and every 72 hours. Create it as a periodic token (`-period=720h`): each renewal extends it by a full period and it has no maximum lifetime, so it never expires while the authorizer runs, and renewals may fail for almost four weeks before it does. The authorizer policy allows `auth/token/renew-self` for this. A token that isn't renewable keeps working until its own expiry, and the authorizer logs every failed renewal.

### Grant lifecycle in OpenBao

- **Approve:** one batch of decisions is all or nothing. The authorizer rewrites the policy of each scope the batch touches once, from that policy's active Grants plus the new approvals, and attaches a session policy's name to the Requester's entity if it isn't there yet. It then stores every decision of the batch in one transaction. If a policy write fails, the policies written before it are restored; if storing fails, every touched policy is rewritten from the stored Grants. A batch with only rejections makes no OpenBao calls.
- **Revoke:** rewrite the Grant's policy without its block, or delete it when no Grant is left, so access ends at once; then record the revocation. A session policy's name stays on the entity: without the policy it grants nothing.
- **Expire:** OpenBao ignores each block after its `expiration` and drops the whole policy after the last one. Expired blocks are left out of the next rewrite.
- **Pending expiry:** all items of a request share one deadline; those no Approver decides within `grants.pending_ttl` become `expired`.

Run a single authorizer process per database. Decisions and policy writes are serialized by an in-process lock, so two instances sharing a database could race on a policy.

## Run

Build first:

```sh
make bin/openbao-authorizer bin/bao-cred
```

Create mode-`0400` files for the application encryption key and authorizer token,
then copy and edit [`config/openbao-authorizer.example.hcl`](config/openbao-authorizer.example.hcl):

```sh
openssl rand -base64 32 >/run/secrets/openbao-authorizer-key
chmod 0400 /run/secrets/openbao-authorizer-key /run/secrets/openbao-authorizer-token
cp config/openbao-authorizer.example.hcl openbao-authorizer.hcl
./bin/openbao-authorizer -config openbao-authorizer.hcl
```

Terminate TLS at a trusted reverse proxy. The proxy must not buffer responses under `/api/`: `WatchEvents` and `WatchGrantRequest` are long-lived streams, and a buffering proxy holds back their snapshots and heartbeats. The server sends `X-Accel-Buffering: no`, which nginx honors; configure other proxies to flush streamed responses immediately and to allow idle reads longer than the 25-second heartbeat. Do not set `insecure_cookies = true` outside loopback development or the E2E harness. Relative paths in the HCL file are resolved from the file's directory.

## Credential requester CLI

`bao-cred` reads and writes OpenBao paths with a **Requester**'s existing OpenBao token,
usually an **Agent Session**'s **Session Token** or a **Named Identity**'s
**Named Token**, and files **Grant Requests** with the authorizer when the
Requester needs more access. `read`, `write`, `ssh`, `request`, `grants`, `revoke`,
`grantable` and `run` work with the Requester's token; `init`, `auth`, `env`, `status` and
`logout` manage tokens; `token-helper` serves the `bao` CLI. Run `bao-cred <command> --help` for details.

| Setting | Source |
|---|---|
| Token | `BAO_TOKEN`, then `VAULT_TOKEN`, then the token of the Named Identity selected by `--identity`, `BAO_IDENTITY` or the identity file of the working directory (see [Named Identities](#named-identities)): its Session Token inside an Agent Session, else its Named Token. Then `~/.vault-token` as written by `bao login` (only the default token helper; skipped when `BAO_NO_TOKEN_FILE` is set). A selected identity without a stored token is an error, never a fall back to `~/.vault-token` |
| Agent session | `BAO_SESSION_ID`, then opencode's `OPENCODE_SESSION_ID`; `BAO_NO_SESSION` turns sessions off. `BAO_SESSION_ROLE` overrides the `agent-session` role |
| OpenBao client | Standard client variables such as `BAO_ADDR`, `BAO_NAMESPACE`, and `BAO_CACERT` |
| Authorizer URL | `--authorizer`, then `BAO_AUTHORIZER_ADDR`; needed only for `request`, `grants`, `grantable`, `ssh config`, and when `read`, `write` or `ssh cert` request access. Give the bare origin; bao-cred calls the `GrantService` RPCs under `/api`. It must be HTTPS unless the host is loopback (`localhost`, `127.0.0.0/8`, `::1`), because the token is sent with every call; redirects to plain HTTP are refused |
| Authorizer TLS | System roots plus any CA from `BAO_CACERT`, `BAO_CACERT_BYTES`, or `BAO_CAPATH`; `BAO_SKIP_VERIFY` is ignored for the authorizer |

A project's `.envrc` can set the addresses, so agents pass no token or address
flags.

### Named Identities

```sh
bao login -method=userpass username=dev   # a login holding only the minter policy
cd ~/src/myproject
bao-cred init                  # creates myproject-k7q2xm in .git/bao-identity, mints its token
cd ~ && bao-cred init          # a personal identity in ~/.bao-identity, for everything else
```

```sh
# .envrc of the project (optional)
export BAO_ADDR=https://openbao.example.com
export BAO_AUTHORIZER_ADDR=https://authorizer.example.com
eval "$(bao-cred env)"         # only for tools that need BAO_TOKEN, such as bao and secretspec
```

`bao-cred init [name]` creates a Named Identity for the current repository,
named after it plus a random suffix (`My_App` becomes `my-app-k7q2xm`), and
mints its Named Token as `auth` does, unless a valid one is already stored.
The suffix keeps the name unique: project Grants belong to the name, so no
other checkout or machine should share it. `[name]` picks a name instead, and
an existing one changes only with `--force`.

The name is written to `bao-identity` in the repository's common git
directory: `.git/bao-identity` in a clone, shared by all linked worktrees,
because each worktree's `.git` file points back to it. Git never commits or
transfers that directory, so a clone can't choose an identity. Outside
repositories, `init` writes `.bao-identity` to the current directory instead,
covering everything below it; `init` in your home directory creates a personal
identity for your own ssh and tools.

bao-cred selects an identity by walking up from the working directory. In a
repository only its `.git/bao-identity` counts: a `.bao-identity` in the
working tree is ignored, because it may have come with the clone. Outside
repositories the nearest `.bao-identity` counts. A repository without an
identity of its own uses the next one above it, such as `~/.bao-identity`.
With an identity selected, bao-cred never falls back to `~/.vault-token`, so
`BAO_NO_TOKEN_FILE` isn't needed. `--identity` and `BAO_IDENTITY` override
the files.

`bao-cred auth [name]` mints a Named Token through the `named-identity` token
role (`--role`) with your `~/.vault-token`, ignoring `BAO_TOKEN`, which may
already hold the Named Token. It sets the entity alias to the name and
`meta.identity`, which Approvers see. Names match `[a-z0-9][a-z0-9-]*`. The new
token replaces the stored one, and the old one is revoked; Grants stay on the
identity, so `auth` is also how to rotate a leaked token. It prints the
token's status as JSON.

Named Tokens are stored in the OS keyring (Secret Service, macOS Keychain or
Windows Credential Manager) under service `bao-cred` and account `<name>`, else
in `$XDG_STATE_HOME/bao-cred/<name>.token` (default `~/.local/state`, mode
`0600`) with a warning. `--store keyring|file` forces one. Each command probes
the keyring once, on first use, and treats it as unavailable when it doesn't
answer within 5 seconds, for example while locked. The non-secret
`$XDG_STATE_HOME/bao-cred/index.json` records which store holds each Named
Token, so a token in a keyring that is now locked fails with a hint to unlock
it or mint a file copy, rather than looking missing, and an old keyring copy
never overrides a newer file.

### Agent Sessions

Inside an agent conversation, detected from `BAO_SESSION_ID` or opencode's
`OPENCODE_SESSION_ID`, bao-cred uses a Session Token instead of the Named
Token. The first command mints it from the Named Token through the
`agent-session` role, with entity alias `<name>.<session id>`, and stores it in
`$XDG_STATE_HOME/bao-cred/sessions/<name>/<session id>.token`. Later commands
reuse it, renewing it once less than half its 24-hour period is left, and
re-mint it for the same entity when it is gone, so the session keeps its
Grants. Session Tokens are children of the Named Token: rotating or revoking
it revokes them. Subagents have session IDs of their own, so each subagent is
a session of its own; files untouched for 48 hours are pruned.

Every Grant has a scope, which the Approver picks:

| Scope | Reaches | Policy |
|---|---|---|
| `session` | This Agent Session only (or a non-project Requester such as CI) | `agent-grant-<entity id>`, on its entity |
| `project` | The project's Named Token and all its sessions | `agent-grant-project-<name>`, carried by those tokens |
| `global` | Every Named and Session Token on the server | `agent-grant-global`, carried by every such token |

Requests from a session default to `session`, those from the Named Token
itself to `project`; `--scope` suggests another. Tokens minted before scopes
existed carry no project or global policy: run `bao-cred auth` to re-mint.

`bao-cred run -- <command>` runs one command with `BAO_TOKEN` and
`VAULT_TOKEN` set to the token bao-cred would use, inside a session its
Session Token, so tools that read only the environment get it without the rest
of the shell. `bao-cred env [name]` renews the token and prints shell exports of
`BAO_TOKEN`, `VAULT_TOKEN` and `BAO_NO_TOKEN_FILE=1`. If renewal fails for any reason but an
invalid token, it warns and exports anyway. Without a valid token it prints
`unset BAO_TOKEN VAULT_TOKEN` and `BAO_NO_TOKEN_FILE=1`, so nothing falls back
to your own token, and exits 1. `bao-cred status [name]` renews the token and
prints its store, entity ID and TTL (inside a session, the Session Token's);
`bao-cred logout [name]` revokes the Named Token, and so its sessions, and
deletes them from every store.

### bao CLI token helper

bao-cred can be the `bao` CLI's token helper, so plain `bao` commands use the
token bao-cred would: in a project with an identity, its Named Token (its
Session Token inside an Agent Session); elsewhere, your `bao login` token, so
no token sits in a config file or `.envrc`.

```sh
bao-cred token-helper --setup
cd ~/src/myproject && bao kv get -mount=kv app/config   # as the project's identity
```

The CLI's `token_helper` must name an existing file, so bao-cred answers to the
name `bao-cred-token-helper` as `bao-cred token-helper`. `--setup` links that
name next to the `bao-cred` you run, as found on `PATH` so a package manager's
upgrades keep it working, and writes `token_helper` to `~/.bao` (or
`$BAO_CONFIG_PATH`). Rerunning changes nothing; a different link or `~/.bao`
is replaced only with `--force`.

- `get` prints the token, renewing, re-minting and minting Session Tokens as
  every bao-cred command does. A selected identity without a token is an
  error, never your login token.
- `store`, called by `bao login`, writes the token to `~/.vault-token`, where
  bao-cred mints Named Tokens from, just like the built-in helper.
- `erase`, called by `bao logout` and `bao token revoke -self`, deletes
  `~/.vault-token`, except in a directory with an identity: the token revoked
  there was the identity's, which bao-cred mints again on next use.

`BAO_TOKEN` and `VAULT_TOKEN` bypass the helper, so inside a project
`BAO_TOKEN=$(cat ~/.vault-token) bao ...` runs a command as yourself.

Named Tokens are periodic: each renewal extends one 32-day period, so a token
in use never expires. bao-cred renews the Named Token whenever it uses it,
and whenever it mints or renews a Session Token. When the stored token is
invalid, for example after 32 days unused, or gone from its store, and this
machine minted that name before (it is in `index.json`), bao-cred mints a new
one with your `~/.vault-token` and carries on; the identity keeps its Grants.
That is safe because the name comes from your own identity file or selection.
Names never minted here, and names removed with `logout`, still need `init`
or `auth`. bao-cred renews the `bao login` token whenever it mints, so a
periodic login also lives on while in use.

### Agent skill

The [`openbao-grants`](skills/openbao-grants/SKILL.md) skill teaches agents to
check their Named Identity, find grantable paths, request Grants and read
credentials without printing them. Install it for every agent the
[skills CLI](https://github.com/vercel-labs/skills) detects, in your user
directory:

```sh
npx skills add xtruder/openbao-authorizer --skill openbao-grants -g
```

Add `-a opencode -a claude-code` (any supported agent) to pick agents, drop
`-g` to install into the current project instead, and run
`npx skills update openbao-grants` to update it.

Long flags take two dashes (`--reason`). The single-dash form of earlier
versions (`-reason`) is a usage error that points to the double-dash flag.

### Reading credentials

```sh
# Complete data object as JSON.
bao-cred read database/creds/app

# One scalar, with no trailing newline.
bao-cred read --field username database/creds/app

# On permission denied, request read access, wait for a decision, and retry once.
bao-cred read --reason "run the app's schema migration" --field password database/creds/app

# Custom text from the data object.
bao-cred read --format template --template '{{ .username }}:{{ .password }}' database/creds/app

# Explicit dotenv mappings written atomically with mode 0600.
bao-cred read --format dotenv \
  --map DB_USER=username --map DB_PASSWORD=password \
  --output credentials.env database/creds/app

# Explicit environment mappings available only to the child command.
bao-cred read --map GH_TOKEN=token github/token/project-example -- \
  gh repo view example-org/example-repo
```

Credentials are delivered through exactly one output or command action. Formats
are `json`, `template`, `dotenv`, and POSIX `shell`. Dot-path selectors support
nested objects, array indexes, and backslash-escaped dots in key names. Missing
fields, duplicate mappings, and mapped arrays or objects fail the whole
operation. Shell output contains credentials by design; source it only in a
trusted shell and do not log it. In command mode the child receives the mapped
variables but not `BAO_TOKEN` or `VAULT_TOKEN`. Everything after `--` goes to
the child unchanged, including arguments that look like bao-cred flags.

Without `--reason`, a permission-denied read fails with a hint to rerun with
`--reason` or to use `bao-cred request`. With `--reason`, bao-cred files a
**Grant Request** for `PATH=read`, waits up to `--timeout` (default 15m), and
retries the read once when the item is approved or already granted.

### Writing to endpoints

`bao-cred write` sends parameters to endpoints that return credentials, such
as `ssh/sign/<role>`, and delivers the response's data object with the same
output and command options as `read`.

```sh
# Have OpenBao sign an SSH public key; request update on denial.
bao-cred write --reason "ssh to jarvis as core" --field signed_key \
  --output ~/.ssh/id_ed25519-cert.pub ssh/sign/jarvis-core public_key=@$HOME/.ssh/id_ed25519.pub

# Request create and update on a KV v2 path that may not exist yet.
bao-cred write --reason "seed the app's webhook secret" --capabilities create,update \
  kv/data/app/webhook data=@webhook.json
```

Data arguments are `key=value` as for `bao write`: `key=@file` reads the value
from a file and `key=-` from stdin. On permission denied, `--reason` files a
Grant Request for the path with `--capabilities` (default `update`; OpenBao
checks `create` instead when the path does not exist yet on endpoints that
distinguish them, such as KV), and retries the write once after approval. A
denied write changed nothing, so the retry is safe. Responses without content
print `{}`.

Grants cover a path, not its parameters, so the endpoint itself must limit
what a write can do. For SSH, define one role per node and user (or per
application) whose `allowed_users`, `default_user`, TTL and extensions are
fixed; a Grant on `ssh/sign/<role>` then means exactly that login.

### SSH credential helper

bao-cred works as a credential helper for ssh: a `Match exec` block in
`~/.ssh/config` runs `bao-cred ssh cert`, which keeps a key and an
OpenBao-signed certificate for the destination's role, and ssh logs in with
them. Plain `ssh`, `scp`, `rsync` and `git` all use it.

```sh
# One block per <host>-<user> role in the catalog, plus aliases; add them
# after your Host blocks.
bao-cred ssh config --alias core-jarvis=jarvis-core >> ~/.ssh/config
ssh core@jarvis            # role jarvis-core
ssh core-jarvis            # the alias, same role
BAO_SSH_REASON="deploy the app" ssh core@jarvis
```

The generated blocks look like this:

```sshconfig
Match originalhost jarvis,jarvis.* user core exec "/usr/local/bin/bao-cred ssh cert --mount ssh --role jarvis-core %r@%n"
  IdentityFile /run/user/1000/bao-cred/ssh/jarvis-core
  CertificateFile /run/user/1000/bao-cred/ssh/jarvis-core-cert.pub
```

`bao-cred ssh cert [user@host]`:

- Derives the role `<host>-<user>` from the first DNS label of the host
  (`core@jarvis.example.ts.net` uses `jarvis-core`), unless `--role` names it.
  A derived role that the catalog doesn't list is refused before any request
  is filed, so a typo never reaches an Approver.
- Reuses the cached pair while the certificate stays valid for at least 5
  more minutes (a fifth of its lifetime for shorter ones), without contacting
  OpenBao; ssh runs the helper on every
  connection to a matching host. Otherwise it generates a new Ed25519 key and
  has OpenBao sign it.
- Keeps keys in `$XDG_RUNTIME_DIR/bao-cred/ssh` (a per-user tmpfs on Linux), or
  in the state directory without it, with mode 0600 and a lock against
  concurrent ssh processes. `--key` picks another path.
- On permission denied, files a Grant Request for `ssh/sign/<role>=update`
  with the reason from `--reason`, `BAO_SSH_REASON`, or else `ssh user@host`,
  and waits for a decision; progress shows on stderr in the ssh session. When
  it fails, ssh skips the block and falls back to its other keys.

ssh passes its environment and working directory to the helper, so it uses the
same token as other bao-cred commands: inside a project or Agent Session, that
identity's token. For your own ssh outside projects, run `bao-cred init` in
your home directory once; the `bao login` token in `~/.vault-token` usually
can't file Grant Requests.

### Requesting Grants

```sh
# What may be requested: every Grantable Rule, with discovered concrete paths.
bao-cred grantable

# Batch several Permission Items under one reason; waits until none is pending.
bao-cred request --reason "deploy app to staging" \
  --item kv/data/app=read --item database/creds/app=read --ttl 2h

# Suggest that every session of the project gets it.
bao-cred request --scope project --reason "CI token for all agents here" --item kv/data/ci=read

# File without waiting, then resume waiting later.
bao-cred request --no-wait --reason "rotate the CI token" --item github/token/project-ci=read
bao-cred request --wait <request-id>

# Active Grants that reach this Requester; "mine" marks those it filed.
bao-cred grants

# End access early: one Grant this Requester filed, or all of them.
bao-cred revoke <grant-id>
bao-cred revoke --all
```

`--item PATH=CAP[,CAP]` is repeatable; capabilities come from `create`, `read`,
`update`, `patch`, `delete`, and `list`. `--ttl` asks for a Grant lifetime for
every item; the authorizer refuses a TTL above the matching **Grantable Rule**'s
`max_ttl`, or above `grants.default_ttl` when the rule sets none. `--scope`
(also on `read --reason`) suggests `session`, `project` or `global` for every
item; the authorizer refuses scopes the token can't use.

While waiting, bao-cred watches the request over a stream that sends its full
state after every decision. If the stream drops or the authorizer is
unavailable, bao-cred reconnects with backoff until `--timeout`; the next
snapshot is the truth, so no decision is missed.

`request` prints `{"id": ..., "items": [...]}` on stdout. Each item has `id`,
`path`, `capabilities`, `ttl` (a Go duration such as `1h0m0s`), `state`
(`pending`, `already_granted`, `approved`, `rejected`, `refused`, `expired`, or
`revoked`), `scope` (requested, or decided once approved), any `reason`, and
`expires_at` (RFC 3339): the pending deadline, or the Grant's expiry once
approved. `grants` prints an array of the active Grants that reach the
Requester, with its session's, its project's and global ones, each with `id`,
`item_id`, `path`, `capabilities`, `scope`, `project` for project Grants,
`mine` (filed by this Requester), `created_at`, and `expires_at`. `revoke`
ends Grants this Requester filed, whatever their scope, and prints their IDs;
Grants filed by other sessions can't be revoked this way, even when they reach
this one. `grantable` prints an array of Grantable Rules, each with
`name`, `path` (the pattern), `capabilities`, `max_ttl` (the effective cap),
and, when set, `description`, `paths` (concrete paths found under the rule's
`discover` path; other paths matching `path` are valid too) and
`discover_error`. Progress goes to stderr; `--quiet` suppresses it.

| Exit status | Meaning |
|---|---|
| `0` | Every Permission Item is approved or already granted, or the read succeeded |
| `1` | Error, including a permission-denied read without `--reason` |
| `2` | Usage error, such as an unknown command or flag |
| `3` | A Permission Item was rejected, refused, expired, or revoked |
| `4` | A Permission Item is still pending at `--timeout`, or after `--no-wait`; resume with `bao-cred request --wait ID` |

Status `4` wins over `3` because the request is not finished. In command mode
and with `run`, bao-cred exits with the child command's status.

### secretspec

[secretspec](https://secretspec.dev) can read Grants too, optionally caching
them in the keyring; see [`examples/secretspec/`](examples/secretspec/README.md).
secretspec ignores `BAO_NO_TOKEN_FILE`, `BAO_IDENTITY` and sessions: run it as
`bao-cred run -- secretspec run -- <command>`, so it gets the session's or the
project's token, or export it with `eval "$(bao-cred env)"`. Pointing an
OpenBao provider alias's `token` credential at the keyring entry with
`{ provider = "keyring", ref = { item = "bao-cred", field = "<name>" } }` gives
it the Named Token, never a Session Token. Otherwise it falls back to your own
`~/.vault-token`.

## Configuration

The server accepts one HCL file through `-config`. String attributes may
explicitly reference process environment variables through expressions such as
`public_origin = "https://authorizer.${env.DOMAIN_NAME}"`; environment variables
do not implicitly override HCL attributes. The
[example file](config/openbao-authorizer.example.hcl) documents every block.
Encryption keys, the authorizer token, and optional VAPID keys are read from
files so secret values do not appear in HCL or the process environment.

```hcl
server {
  listen_address   = "127.0.0.1:8080"
  public_origin    = "https://approvals.example.com"
  insecure_cookies = false
  static_directory = ""     # empty serves the embedded PWA
  session_ttl      = "168h" # default; approver session lifetime
}

openbao {
  address               = "https://openbao.example.com"
  ca_file               = "/etc/ssl/certs/organization-openbao-ca.pem" # optional
  namespace             = ""                                           # optional
  authorizer_token_file = "/run/secrets/openbao-authorizer-token"
  approver_policy       = "openbao-authorizer-approver"
}

approver_login {
  openbao_address = "https://openbao.example.com" # as reachable from approvers' browsers
  namespace       = ""                            # optional; sent as X-Vault-Namespace
  method "token" {}                               # default when no method is listed
  method "userpass" { mount = "userpass"  label = "Username & password" }
  method "ldap"     { mount = "ldap" }
  method "github"   { mount = "github"    label = "GitHub token" }
  method "oidc"     { mount = "oidc"      label = "Single sign-on"  role = "" }
}

requester "named" {
  token_role = "named-identity" # matches lookup-self `role`
}

requester "sessions" {
  token_role = "agent-session"
}

requester "ci" {
  auth_mount = "approle" # matches tokens issued by auth/approle/
}

grants {
  default_ttl = "72h" # default; TTL when a request sets none, and the cap for rules without max_ttl
  pending_ttl = "24h" # default; undecided items expire after this
}

grantable "github-token" {
  path         = "github/token/project-*" # OpenBao ACL pattern: `+` segment, trailing `*`
  capabilities = ["read"]                  # maximum capabilities
  max_ttl      = "8h"                      # optional; caps request and approver TTLs (default: default_ttl)
  description  = "One project's GitHub App token; the name picks org, repos and permissions." # optional
  discover     = "github/permissionsets"   # optional; LIST keys fill the wildcard of `path`
}
```

`approver_login` is required. Each `method` block is a sign-in option on the
PWA, in order; `mount` defaults to the method type and `label` to a generic
name, and `role` applies to OIDC only (empty uses the mount's default role).

`requester` blocks are **Requester Rules**. At least one is required, names
must be unique, and each sets exactly one matcher: `token_role` matches the
token's `role` from `lookup-self`, and `auth_mount` matches the auth mount the
token was issued from (the `path` from `lookup-self`, e.g.
`auth/approle/login`). The first matching rule wins and is shown to Approvers.
Every token of a matched mount qualifies, so don't share that mount with other
machine logins. Tokens without an entity ID, or matching no rule, get
`NOT_REQUESTER`. Approvers see the token's `meta.session`, else
`meta.identity`, as the Requester ID, falling back to the token's display name
and then the entity ID, with `meta.title` and `meta.directory` alongside it
when a token sets them. The Requester's project and allowed scopes come from
the token's own `agent-grant-project-*` and `agent-grant-global` policies, not
its metadata.

`grantable` blocks are **Grantable Rules**. They may be repeated; names must be
unique. Capabilities come from `create`, `read`, `update`, `patch`, `delete`
and `list`. The server refuses to start if a rule grants `sudo`, starts with a
`+` or `*` segment, or has a segment that is `sys`, `auth`, `identity` or
`cubbyhole` (any case) or a glob that could begin one, such as `s*` or
`kv/id*`. A generic `+` or trailing `*` later in the pattern is allowed, but
the concrete paths it expands to are still refused when any of their segments
is on the Hard Denylist. So a KV key literally named `auth` or `sys` can't be
granted.

Requesters and Approvers see every rule in a read-only catalog
(`ListGrantables`, `ListGrantableRules`, `bao-cred grantable`), including its
optional `description`. A rule may also set `discover`, an OpenBao path the
authorizer LISTs with its own token, caching the result for a minute. Each key
replaces the rule's last path segment, so `github/token/project-*` with
`discover = "github/permissionsets"` turns key `project-web` into
`github/token/project-web`. Folder keys (ending in `/`) and results that don't
match the pattern or fail item validation steps 1–2 below are dropped.
`discover` requires exactly one wildcard in the rule's path, in its last
segment (`+`, `*` or `prefix*`); the discover path itself must be concrete and
must not touch the Hard Denylist. The authorizer policy needs `list` on it (see
[OpenBao setup](#openbao-setup)). A failed listing is shown on that rule as
`discover_error` and logged; the rule stays usable. Discovered names are
visible to every Requester, so set `discover` only where that is acceptable.

### Item validation

Every Permission Item passes these steps before an Approver sees it:

1. The path must be concrete (no `*` or `+`, empty or `.`/`..` segments,
   quoting characters, or control or invisible Unicode formatting characters).
   Capabilities must be non-empty and drawn from the list above. The request
   reason may contain newlines and tabs but no other such characters.
2. **Hard Denylist:** paths with a `sys`, `auth`, `identity` or `cubbyhole`
   segment anywhere (any case) and any request for `sudo` are refused,
   whatever the configuration says.
3. The path must match a `grantable` rule whose capabilities include every
   requested one. A rule's cap is its `max_ttl`, or `grants.default_ttl` when
   it sets none. The TTL is `min(requested or default_ttl, cap)`; a requested
   TTL above the cap is refused, not clamped. When several rules match, the
   one with the longest cap applies.
4. `sys/capabilities-self`, called with the Requester's own token, decides
   whether the Requester already has every requested capability; then the item
   is `already_granted`. This does not consider how long an existing Grant
   has left, so an item covered by a Grant that expires in a minute is still
   `already_granted`.
5. Two identical items (same path and capabilities) in one request are
   refused as duplicates.

When an Approver decides, the item is checked again against the current
configuration: an approval of an item that no longer passes steps 1–3 makes it
`refused`, and its TTL is clamped to the rule's current cap.

Refused items get the state `refused` and a human-readable `reason`; the other
items in the request continue.

## Web Push on Android Firefox/Fennec

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

Successful enrollment creates an encrypted subscription in SQLite. Grant
Requests with new pending items can then notify the device while the PWA is
closed, provided its persistent approver session remains active. Push messages
contain only a generic "access requested" notice; reasons, paths and session
details still require opening the authenticated app.

## Approver PWA

- **Sign-in:** one option per `approver_login` method. The PWA signs in to
  OpenBao directly and exchanges the token for an app session.
- **Pending:** one card per Grant Request with the reason, the Requester's
  title, ID, project, session, directory and rule, and every item. Pending
  items have **Approve** and **Reject** buttons, a TTL field that may only
  shorten the resolved TTL, and, when the Requester may use more than one, a
  scope selector preset to the requested scope. Global scope is highlighted.
- **History:** requests with no pending items left, with each item's outcome
  and approver.
- **Active grants:** unexpired, unrevoked Grants across Requesters, each with
  its scope and a **Revoke** button.

## Frontend development

Run the Go server on port 8080, then:

```sh
cd web
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://127.0.0.1:8080`. To sign in from
it, OpenBao's CORS configuration must also allow the dev server's origin.

## API

The API is ConnectRPC, defined in `proto/openbao/authorizer/v1/`; generated
Go and TypeScript clients are committed under `gen/go/` and `web/src/gen/`.
Services are mounted under `/api`, e.g.
`POST /api/openbao.authorizer.v1.GrantService/CreateGrantRequest`, so clients
use `<origin>/api` as their base URL. The server accepts the Connect, gRPC and
gRPC-Web protocols with binary or JSON messages; request messages are limited
to 1 MiB. The proto comments document every RPC and field.

### GrantService

Authenticated with `Authorization: Bearer <OpenBao token>`; no cookies. Only
tokens matching a Requester Rule may call it, and a caller sees only its own
requests and the Grants that reach it.

| RPC | Notes |
|---|---|
| `CreateGrantRequest` | `reason` is required, 1–64 items, each with an optional `ttl` and suggested `scope`. A scope the token can't use is `invalid_argument`. Refused and already-granted items are answered in the item state. |
| `GetGrantRequest` | One of the caller's requests. |
| `WatchGrantRequest` | Sends the request on connect and after every change, plus a heartbeat every 25 seconds. Ends normally after the final state once no item is pending. |
| `ListMyGrants` | The active Grants that reach the caller: its session Grants and those of the project and global scopes its token carries. `mine` marks those it filed. |
| `RevokeMyGrant` | Revokes an active Grant the caller's own identity filed, whatever its scope. Other Requesters' Grants are `not_found`. The PWA history records it as revoked by the Requester. |
| `ListGrantables` | Every Grantable Rule with its effective `max_ttl`, `description`, and discovered `paths` or `discover_error`. The same for every Requester. |

When an OpenBao call made for a Requester fails, the error has a generic message;
details are logged on the server only.

### ApproverService

`GetLoginOptions` returns the OpenBao address, namespace and sign-in methods
from `approver_login`. `CreateSession` takes an OpenBao token the browser just
obtained, checks its entity and the approver policy, revokes it, and sets the
`HttpOnly` cookie for an opaque session; signing in again replaces the session
the cookie names. `Logout` deletes the session and its push subscriptions and
clears the cookie. Every RPC requires a same-origin request (`Origin` and
`Sec-Fetch-Site` checks); every RPC except `GetLoginOptions` and
`CreateSession` also requires the cookie. There is no CSRF token.

| RPC | Notes |
|---|---|
| `GetLoginOptions` | Where and how to sign in to OpenBao; needs no session. |
| `CreateSession`, `GetSession`, `Logout` | Session lifecycle; `CreateSession` and `GetSession` return the Approver's identity. |
| `ListGrantRequests` | Pending, decided (the latest 200) or all requests, with the Requester and per-item decision metadata. |
| `DecideItems` | Approve or reject pending items of one request; a `ttl` may only shorten the resolved TTL, and a `scope` must be one of the Requester's `scopes`. Refused with `SELF_APPROVAL` for the Approver's own requests. Returns the updated request. |
| `ListGrants`, `RevokeGrant` | Active Grants across Requesters; revoke one before its expiry. |
| `ListGrantableRules` | The catalog Requesters get from `ListGrantables`, read-only. |
| `WatchEvents` | Sends a dashboard snapshot (pending requests, decided requests, active Grants) on connect and after every change, including Grant expiry within about 10 seconds, plus a heartbeat every 25 seconds. Ends with `unauthenticated` / `SESSION_EXPIRED` when the session ends. |
| `GetPushPublicKey`, `RegisterPushSubscription`, `DeletePushSubscription` | Web Push enrollment and removal; the key is empty when push is disabled. |

Streams carry full state, not deltas: after a dropped connection, clients
reconnect and treat the next snapshot as the truth.

### Errors

Errors use Connect codes and carry an `openbao.authorizer.v1.ErrorDetail` with
a stable `reason`:

| Code | `reason` | When |
|---|---|---|
| `unauthenticated` | `INVALID_TOKEN` | OpenBao rejects the bearer token or the token given to `CreateSession` |
| `unauthenticated` | `SESSION_EXPIRED` | missing, expired or logged-out approver session |
| `permission_denied` | `NOT_REQUESTER` | bearer token matches no Requester Rule, or has no entity |
| `permission_denied` | `NOT_APPROVER` | identity lacks the approver policy, or the token has no entity |
| `permission_denied` | `SELF_APPROVAL` | an Approver tried to decide their own request |
| `permission_denied` | `CROSS_ORIGIN` | same-origin check failed |
| `invalid_argument` | `INVALID_REQUEST` | bad input |
| `not_found` | `NOT_FOUND` | unknown, or another Requester's, request or grant |
| `failed_precondition` | `ITEM_NOT_PENDING` | an item is no longer pending; `ids` lists it |
| `failed_precondition` | `GRANT_NOT_ACTIVE` | the Grant is already revoked or expired |
| `unavailable` | `OPENBAO_UNAVAILABLE` | an OpenBao call failed; approvers see OpenBao's message, Requesters a generic one |

`GET /healthz` reports process health.

## Current deployment boundaries

- Sessions, requests and subscriptions are durable in SQLite, while stream wake-ups are process-local; deploy one instance unless you add shared event infrastructure.
- SQLite is suited to one app instance. Back it up together with the external encryption key. Losing the database does not revoke Grants in OpenBao; they still expire on their own.
- The Hard Denylist checks the first path segment. With OpenBao namespaces, a rule such as `team/*` in a parent namespace could reach `team/sys/...` of a child namespace named `team`; avoid such rules where child namespaces exist.
- Browser push is best-effort. The request list and `WatchEvents` remain authoritative.
