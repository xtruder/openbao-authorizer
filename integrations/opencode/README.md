# @xtruder/opencode-openbao

opencode plugin for [openbao-authorizer](../../README.md). It gives every **Agent Session** its own minimal OpenBao **Session Token**, and puts that token into the environment of the agent's shell commands. It also ships the `openbao-access` skill, which teaches the agent to ask an Approver for **Grants** with `bao-cred`.

Terms (Agent Session, Session Token, Session Identity, Grant) are defined in [`CONTEXT.md`](../../CONTEXT.md). The design is in [ADR-0001](../../docs/adr/0001-session-scoped-grants.md).

This is an **opencode V2** plugin (`@opencode/plugin`). It doesn't load in opencode 1.x.

## What it does

- **Lazy minting.** The first time the agent runs the `shell` tool in a session, the plugin logs in with the minter AppRole and calls `auth/token/create/<tokenRole>` with `entity_alias=<aliasPrefix><rootSessionID>` and `meta={session_id, title, directory}`. It caches the AppRole token until it nears expiry. Resumed sessions mint on first use too.
- **One identity per session tree.** A subagent session resolves to its root through `parentID`, so it uses the root's token and Session Identity, and sees the root's Grants.
- **Environment.** Commands run by the `shell` tool get `BAO_ADDR`, `BAO_TOKEN`, `VAULT_ADDR`, `VAULT_TOKEN` and `OPENBAO_AUTHORIZER_URL`. They also get `BAO_NAMESPACE`/`VAULT_NAMESPACE` and `BAO_CACERT`/`VAULT_CACERT` when those are configured.
- **Renewal.** A token past half its period is renewed with `renew-self` before the next shell command. If renewal fails or the token has expired, the plugin mints a new one.
- **Revocation.** Deleting a root session revokes its token. Grants stay on the Session Identity until they expire.
- **Skill.** The plugin registers the bundled `openbao-access` skill through `ctx.skill.transform`.

### How the token reaches the command, and why it fails closed

opencode V2's `shell` `create.before` hook, which can edit a command's environment, doesn't say which session the command belongs to. The plugin therefore works in two steps:

1. The `tool` `execute.before` hook for the `shell` tool knows the session. It resolves the root session, then mints or renews that session's token and caches it in memory.
2. The `shell` `create.before` hook sets the plain variables and defines `BAO_TOKEN` and `VAULT_TOKEN` as getters on the command's env object. After the hooks run, the shell tool adds `OPENCODE_SESSION_ID` to the same object, and opencode reads the object when it spawns the process. At that point each getter returns the cached token for the root of `OPENCODE_SESSION_ID`.

The getter returns `undefined` when `OPENCODE_SESSION_ID` is missing, when the session was never resolved, or when its token is missing or expired. The spawner drops `undefined` variables, so the command gets **no** token. It never gets another session's token, and it never gets a `BAO_TOKEN` inherited from opencode's own environment. One consequence: a shell command that a user starts in a session (`!command`) doesn't go through the `shell` tool, so it gets `BAO_ADDR` but no token. Interactive terminals (PTY) are not touched at all.

If minting fails, the command runs without a token. Tokens live in memory only. The plugin writes errors to the opencode server's stderr, prefixed with `[opencode-openbao]`. These messages hold session IDs and OpenBao error text, never tokens or AppRole secrets.

## OpenBao prerequisites

These objects are described in the main README's [OpenBao setup](../../README.md#openbao-setup), which also covers the authorizer itself. The design of the token injection is recorded in [ADR-0004](../../docs/adr/0004-opencode-session-token-injection.md).

```sh
# Baseline policy for Session Tokens. Site-defined; tokens also carry `default`
# (lookup-self, renew-self, capabilities-self).
bao policy write opencode-session - <<'EOF'
path "auth/token/lookup-self" { capabilities = ["read"] }
EOF

# Token role that mints Session Tokens with a per-session entity alias.
bao write auth/token/roles/opencode-session \
  allowed_policies=opencode-session orphan=true renewable=true \
  token_period=24h allowed_entity_aliases='opencode-session-*'

# Minter: may only create tokens through that role.
bao policy write opencode-minter - <<'EOF'
path "auth/token/create/opencode-session" { capabilities = ["update"] }
EOF

bao auth enable approle   # once per cluster
bao write auth/approle/role/opencode-minter \
  token_policies=opencode-minter token_ttl=10m token_max_ttl=30m

install -d -m 700 ~/.config/opencode-openbao
bao read -field=role_id auth/approle/role/opencode-minter/role-id > ~/.config/opencode-openbao/role-id
bao write -f -field=secret_id auth/approle/role/opencode-minter/secret-id > ~/.config/opencode-openbao/secret-id
chmod 600 ~/.config/opencode-openbao/*
```

Session aliases are created on the token auth mount, so the authorizer's `session_alias_mount` must be `token`, and its `session_alias_prefix` must equal the plugin's `aliasPrefix`.

The agent runs as the same OS user that can read the AppRole files. This setup protects against agent mistakes, not against a malicious agent (see the ADR).

## Install

Add the plugin to `plugins` in `opencode.json` (global `~/.config/opencode/opencode.json`, or per project), using the object form to pass options:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "@xtruder/opencode-openbao",
      "options": {
        "address": "https://openbao.example.com",
        "authorizerUrl": "https://authorizer.example.com",
        "roleIdFile": "~/.config/opencode-openbao/role-id",
        "secretIdFile": "~/.config/opencode-openbao/secret-id"
      }
    }
  ]
}
```

To use a checkout, set `package` to the absolute path of this directory; `make install-opencode` prints the entry. The plugin imports only types at runtime, so it needs no `bun install` to load. opencode loads a plugin directory through its root `index.ts`, which is why the entrypoint sits there and not under `src/`.

You also need `bao-cred` on the agent's `PATH` (`make bin/bao-cred` in the repository root).

### Options

| Option | Default | Meaning |
|---|---|---|
| `address` | required | OpenBao address |
| `authorizerUrl` | required | Authorizer base URL, exported as `OPENBAO_AUTHORIZER_URL` |
| `roleIdFile` | required | File holding the minter AppRole `role_id` (`~/` is expanded) |
| `secretIdFile` | required | File holding the minter AppRole `secret_id`. Both files are reread at each AppRole login |
| `approleMount` | `approle` | AppRole auth mount path |
| `tokenRole` | `opencode-session` | Token role that mints Session Tokens |
| `aliasPrefix` | `opencode-session-` | Entity alias prefix, followed by the root session ID |
| `namespace` | none | OpenBao namespace, sent as `X-Vault-Namespace` and exported as `BAO_NAMESPACE` |
| `caCert` | none | PEM CA file for OpenBao TLS, exported as `BAO_CACERT` |

If the options are invalid, the plugin logs an error and disables itself; opencode keeps running.

### Skill registration

The plugin registers `openbao-access` at startup; `opencode api get '/api/skill?location[directory]=<project>'` lists it with a path inside this package. To use the skill without the plugin, copy `skills/openbao-access/` into `~/.config/opencode/skills/`.

## Mint CLI

`src/mint-cli.ts` mints a Session Token the same way the plugin does and prints it as JSON. The e2e harness and manual tests use it.

```sh
bun src/mint-cli.ts --session-id ses_child --parent ses_root \
  --address http://127.0.0.1:8200 \
  --role-id-file role-id --secret-id-file secret-id
```

```json
{"session_id":"ses_child","root_session_id":"ses_root","entity_alias":"opencode-session-ses_root","token":"s.…","accessor":"…","entity_id":"…","policies":["default","opencode-session"],"ttl":86400,"renewable":true,"expires_at":"2026-10-10T12:00:00.000Z"}
```

`--parent` is repeatable and lists ancestors from the immediate parent up to the root. The token is minted for the last one. Run `--help` for the full list of flags and their environment-variable fallbacks. Exit status is `0` when a token was minted, `1` on an OpenBao or file error, and `2` on a usage error.

The mint logic is also a module: `import { mintSessionToken, resolveOptions } from "@xtruder/opencode-openbao/lib"`.

## Development

```sh
bun install
bun test           # unit tests: fake opencode context and fake OpenBao, real process spawns
bun run typecheck
bun run test:live  # live check against the installed opencode V2 (see below)
```

From the repository root, `make opencode-plugin-test` runs `bun install`, `bun test` and the typecheck.

`test/live/opencode-v2.ts` runs the real `opencode` binary (or `OPENCODE_BIN`) as an isolated service, with its own HOME and XDG directories. It uses a fake OpenBao and a scripted OpenAI-compatible model that calls the `shell` tool. It checks that:
- two sessions in one service get their own, different tokens;
- a user session shell gets no token, even though opencode's own environment has one;
- the skill is registered;
- deleting a session revokes only that session's token.

It needs no credentials or network access beyond localhost.
