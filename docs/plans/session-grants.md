# Plan: Session-scoped grants

This is the implementation plan and shared contract for the subagents carrying out the refactor. It isn't durable documentation: once the work lands, the code, README and ADR are authoritative.

Vocabulary: [`CONTEXT.md`](../../CONTEXT.md). Decision: [ADR-0001](../adr/0001-session-scoped-grants.md).
Backward compatibility is **not** required. The existing control-group flow is deleted outright, with no deprecation period.

## Flow

```text
opencode plugin ──AppRole login──> OpenBao ──token/create/opencode-session (entity_alias)──> Session Token
      │ shell.env: BAO_TOKEN, BAO_ADDR, VAULT_*, OPENBAO_AUTHORIZER_URL
      ▼
agent ── bao-cred request / read -reason ──> authorizer (Bearer Session Token)
                                               │ lookup-self, entity check, capabilities-self
                                               ▼
                                        pending items ──SSE/push──> Approver PWA
                                               │ per-item approve(+ttl)/reject
                                               ▼
                  policy agent-grant-<entity-id>, one path block per Grant (expiration each) + attached to Session Identity
agent ── same Session Token ──> OpenBao (bao-cred read, secretspec, bao CLI)
```

## OpenBao setup (shared by deploy/local, e2e, docs)

Target **OpenBao 2.7.1 stable**. Control groups are no longer used.

| Object | Definition |
|---|---|
| Baseline policy `opencode-session` | Empty or site-defined. Session Tokens also carry `default`, which provides lookup-self, renew-self and capabilities-self. |
| Token role `opencode-session` | `allowed_policies=["opencode-session"]`, `orphan=true`, `renewable=true`, `token_period=24h`, `allowed_entity_aliases=["opencode-session-*"]` |
| Minter policy `opencode-minter` | `update` on `auth/token/create/opencode-session` only |
| AppRole role `opencode-minter` | `token_policies=["opencode-minter"]`, short token TTL; role_id/secret_id in files read by the plugin |
| Authorizer policy | `read`/`update` on `identity/entity/id/*` with key-only `allowed_parameters = { "policies" = [] }`, no `delete`; `create/read/update/delete` on `sys/policies/acl/agent-grant-*`. Checked on 2.7.1: a value glob such as `["agent-grant-*"]` rejects JSON lists, even when every element matches, and lets a comma-joined string through. So policy names **can't** be restricted. The key-only form blocks `name`, `metadata` and `disabled` updates. Send `policies` as a JSON list. |
| Approver policy | Unchanged meaning: required to log in to the PWA. The human token now only authenticates the approver; the authorizer token performs all OpenBao writes. |

Each **Agent Session** has one policy, `agent-grant-<entity-id>`, rendered in HCL from its active Grants: one `path` block per Grant with that Grant's capabilities and its own `expiration`. The policy-level `expiration` is the latest block's. Checked on 2.7.1: one policy may repeat a `path` for the same path with different expirations, and each block lapses on its own. JSON policies can't repeat keys, hence HCL.
- **Write order:** write the policy first, then attach its name to the entity if missing (keeping the other names), then store the decisions. A batch of decisions is one policy write and one transaction. Serialize decisions and policy writes for one session.
- **Revoke:** rewrite the policy without the Grant, or delete it when none is left. The name stays attached.
- **Expiry:** OpenBao ignores expired blocks and drops the policy after its last one. Rewrites leave expired Grants out.

## Authorizer

### Configuration (HCL)

```hcl
openbao {
  address               = "https://openbao.example.com"
  ca_file               = "..."
  authorizer_token_file = "/run/secrets/openbao-authorizer-token" # replaces scanner_token_file
  approver_policy       = "openbao-authorizer-approver"
  session_alias_mount   = "token"              # auth mount path holding session aliases
  session_alias_prefix  = "opencode-session-"
}

grants {
  default_ttl = "72h"  # default TTL, and the cap for rules without max_ttl
  pending_ttl = "24h"  # undecided items expire after this
}

grantable "github-token" {
  path         = "github/token/project-*"  # OpenBao ACL pattern: `+` segment, trailing `*`
  capabilities = ["read"]                  # maximum capabilities
  max_ttl      = "8h"                      # optional; caps request and approver TTLs
}
```

- `scanner`, `requests.expose_data`, `approval_context` and `scanner_token_file` are removed.
- Config load fails if a `grantable` rule overlaps the **Hard Denylist**.

### Item validation (before an Approver sees anything)

1. Requested paths must be concrete, with no `*` or `+`. Capabilities must be non-empty and drawn from `create, read, update, patch, delete, list`.
2. **Hard Denylist**: refuse any path with a segment equal to `sys`, `auth`, `identity` or `cubbyhole` (in any case, so namespace-prefixed paths are covered), and any request for `sudo`, regardless of config.
3. The path must match some `grantable` rule, and the capabilities must be a subset of that rule's. The cap is `rule.max_ttl`, or `default_ttl` when the rule has none. TTL resolves as `min(requested or default_ttl, cap)`. A requested TTL above the cap is refused, not clamped. Items are checked against the current rules again when an Approver decides them.
4. Call `sys/capabilities-self` **with the requester's token**. If it already allows every requested capability, the item becomes `already_granted`.
5. A second identical item (same path and capabilities) in the same request is refused as a duplicate.
6. Refused items get a state of `refused` and a human-readable `reason`. The other items in the request continue.

### Requester authentication

Agent endpoints take `Authorization: Bearer <Session Token>`. They don't use cookies or CSRF.
- The authorizer calls `auth/token/lookup-self` with the requester's token, then reads `identity/entity/id/<entity_id>` with its own token.
- **Reject with 403** unless the entity has an alias on `session_alias_mount` whose name starts with `session_alias_prefix`.
- **Display fields:** session ID from the alias suffix; `title` and `directory` from the token `meta`, which the plugin sets at mint time.

### HTTP API

Agent API (Bearer Session Token):

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/agent/grant-requests` | `{reason, items:[{path, capabilities, ttl?}]}`. `reason` is required. Returns `201 {id, items:[Item]}`. |
| `GET` | `/api/v1/agent/grant-requests/{id}?wait=30s` | Long-poll. Returns when any item changes state or the wait elapses. Only the owning session may read it. |
| `GET` | `/api/v1/agent/grants` | Active Grants for the caller's session. |

`Item = {id, path, capabilities, ttl, state, reason?, expires_at?}`, where `state ∈ pending | already_granted | approved | rejected | refused | expired | revoked`.

Approver API (existing cookie session, CSRF and same-origin rules apply):

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/grant-requests?state=pending\|decided` | Requests with their session display fields and items. |
| `POST` | `/api/v1/grant-requests/{id}/decisions` | `{items:[{id, decision: approve\|reject, ttl?}]}`. A `ttl` may only shorten the resolved TTL. Records the approver's identity. |
| `GET` | `/api/v1/grants` | Active Grants across sessions. |
| `DELETE` | `/api/v1/grants/{id}` | Revoke a Grant. |

Session, events (SSE), push and healthz endpoints stay. Push fires when new pending items arrive.

### Storage

New SQLite schema; old data is dropped. Tables cover requests, items, grants and approver decisions. Keep encryption at rest for reasons and display metadata. Session tokens are **never** stored.

### UI (PWA)

- **Pending tab:** one card per Grant Request showing the reason, session title/ID/directory, and items. Each item has approve/reject buttons and a TTL field.
- **History tab:** decided requests.
- **Active grants tab:** lists grants, each with a revoke button.

## bao-cred

- Token comes from `BAO_TOKEN`, then `VAULT_TOKEN`. Authorizer URL comes from `-authorizer`, then `OPENBAO_AUTHORIZER_URL`.
- `login`, `logout`, `-token-file`, the config-dir token, and all control-group/unwrap logic are removed.
- `bao-cred request -reason TEXT -item PATH=CAP[,CAP] [-item ...] [-ttl D] [-timeout 15m] [-no-wait]` files a Grant Request.
  - It waits until no item is pending, then prints item outcomes as JSON.
  - `bao-cred request -wait ID` resumes waiting on an existing request.
  - Exit codes: `0` if all items are approved or already granted; distinct non-zero codes for any rejected/refused/expired item and for still pending at timeout.
- `bao-cred grants` prints the session's active Grants as JSON.
- `bao-cred [flags] <path>` is the existing read (formats, map, exec), with one addition, `-reason TEXT`.
  - On permission denied with `-reason` set, it files a request for `PATH=read`, waits, and retries once.
  - Without `-reason`, it fails with a hint.
- Progress goes to stderr. Secrets never appear in errors.

## opencode plugin and skill: `@xtruder/opencode-openbao`

Location: `integrations/opencode/` (TypeScript, Bun, `@opencode-ai/plugin`).

- **Options** (opencode.json `["@xtruder/opencode-openbao", {...}]`): `address`, `authorizerUrl`, `roleIdFile`, `secretIdFile`, `approleMount="approle"`, `tokenRole="opencode-session"`, `aliasPrefix="opencode-session-"`, `namespace?`, `caCert?`.
- **Root session:** follow `parentID` through the SDK client. Subagents share the root's token and Session Identity.
- **`shell.env`:** lazily mint the root session's token on first use. Resumed sessions emit no `session.created`, so minting can't wait for that event. Inject `BAO_ADDR`, `BAO_TOKEN`, `VAULT_ADDR`, `VAULT_TOKEN`, `OPENBAO_AUTHORIZER_URL`, plus `BAO_NAMESPACE` and `BAO_CACERT` when configured.
- **Minting:** log in with AppRole (cache the minter token until near its expiry), then call `auth/token/create/opencode-session` with `entity_alias=<prefix><rootSessionID>` and `meta={session_id, title, directory}`.
- **Renewal:** renew the Session Token when past half its period. Keep tokens in memory only.
- **`session.deleted`:** revoke that session's token.
- **Skill:** the `config` hook appends the package's `skills/` dir to `cfg.skills.paths`. **Verify** with a test that the skill is discovered; if not, document manual install.
- **Skill `openbao-access`:** teaches the agent that the token is already in env, and covers `bao-cred` read with `-reason`, batch `request` with good reasons, `grants`, secretspec's `openbao://` provider, never echoing secrets, and how to handle refused/rejected/pending outcomes.
- **Mint helper:** export the mint logic as a module, plus a small Bun CLI entry the e2e harness can run.

## Tasks (parallel subagents)

1. **Authorizer.** Remove the scanner, control-group, wrapping, approval_context and reject-revoke code. Add the new config, validation, agent and approver APIs, storage, OpenBao writes and PWA changes. Update `config/`, `deploy/local/` bootstrap and README.
2. **bao-cred.** Implement the CLI surface above against the agent API contract.
3. **Plugin and skill.** Build the `integrations/opencode/` package: Bun unit tests (root-session resolution, env injection, renewal, config hook), the skill, and the mint CLI.
4. **E2E integration** (after 1–3). Bump the harness to OpenBao 2.7.1, bootstrap the objects above, and require `bun` for the plugin mint step.

## E2E acceptance (real OpenBao, authorizer, bao-cred, plugin mint via Bun)

1. Mint session A's token via the plugin module. A baseline read of `kv/data/a` is denied.
2. `bao-cred request` for `kv/data/a=read` and `kv/data/b=read`. A path outside the rules is `refused`, and so is a `sys/...` path.
3. The approver API approves `a` and rejects `b`. bao-cred exits with the partial-result code.
4. Session A's **same token** reads `kv/data/a`; `kv/data/b` is still denied.
5. Re-requesting `kv/data/a` returns `already_granted` without an approver. A request filed with `-no-wait` is approved and resumed with `-wait <id>`.
6. A session B token can't read `kv/data/a`. A subagent of A, resolved to A's root, can.
7. A grant approved with a 5s TTL stops working after expiry. A revoked grant stops working immediately.
8. `bao-cred -reason ... <path>` auto-requests, and the read succeeds after approval.
9. A human (non-session) token gets 403 from the agent API. The authorizer token can't change entity fields other than `policies`.
