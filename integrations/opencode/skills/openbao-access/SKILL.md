---
name: openbao-access
description: Use when a task needs a secret or credential from OpenBao/Vault (API tokens, database passwords, cloud keys, `bao`/`vault` CLI, secretspec `openbao://`), when an OpenBao read fails with permission denied, or when you must ask a human to grant access with bao-cred.
---

# OpenBao access

Every shell command you run already has this session's OpenBao **Session Token** in its environment: `BAO_TOKEN`/`VAULT_TOKEN`, `BAO_ADDR`/`VAULT_ADDR` and `BAO_AUTHORIZER_ADDR`. Don't log in, don't ask the user for a token, and don't export or overwrite these variables. Subagents share the same token and the same grants. If `BAO_TOKEN` is empty or unset, the session has no token (minting failed): tell the user instead of looking for another token.

The token starts with almost no access. You gain access through **Grants**: a human Approver approves each requested path and capability, and the grant then applies to this same token until it expires. You never get a new token.

## Find what you may request

When you don't already know the exact path, start here:

```sh
bao-cred grantable
```

It prints, as JSON, every rule for what may be requested: `path` (an OpenBao pattern: `+` is one segment, a trailing `*` any suffix), `capabilities`, `max_ttl`, `description`, and sometimes `paths`, concrete paths the authorizer found. Prefer a path from `paths` that fits the task. Otherwise build a concrete path that matches `path`, guided by `description`. A `discover_error` only means the list of concrete paths is unavailable; the pattern still applies. Then read it with `bao-cred read --reason ...` or request it with `bao-cred request`. Anything matching no rule is refused.

## Read a credential

Hand the secret straight to the program that needs it, so it never appears in your output:

```sh
bao-cred read --reason "Run the integration tests against the staging DB" \
  --map PGUSER=username --map PGPASSWORD=password database/creds/staging -- make integration-test
```

- `bao-cred read [flags] <path> [-- command ...]` reads `<path>`. With `--reason`, a permission-denied read files a grant request for `PATH=read`, waits for the Approver, then retries once. Without `--reason` it just fails with a hint.
- Output options: `--map ENV=field` (repeatable; with `-- command` it sets the command's environment), `--output FILE` (mode 0600), `--format json|dotenv|shell|template`, `--field NAME` (one value to stdout).
- Flags take two dashes (`--reason`, not `-reason`). Everything after `--` goes to the command unchanged.

## Request several paths at once

When you know up front what the task needs, ask for everything in one request so the human approves it in one pass:

```sh
bao-cred request --reason "Deploy api to staging: read DB creds and push the image" \
  --item database/creds/staging=read \
  --item kv/data/registry/staging=read
```

- `--item PATH=CAP[,CAP]` is repeatable. Capabilities: `create, read, update, patch, delete, list`. Paths are concrete: no `*` or `+`.
- Ask for the least you need: exact paths and only the capabilities you'll use. Add `--ttl 1h` when the task is short.
- It waits until no item is pending (`--timeout`, default 15m) and prints each item's outcome as JSON. Progress goes to stderr. `--no-wait` returns at once; `bao-cred request --wait ID` resumes waiting.

**Write reasons for a human deciding on a phone.** Say what you're doing and why this path is needed: "Rotate the webhook secret for project-foo as the user asked", not "need access" or "task".

## Check what you already have

```sh
bao-cred grants
```

Prints this session's active grants with their expiry as JSON. Check it before requesting, and after an approval if something still fails.

## secretspec

secretspec's `openbao://` provider reads `BAO_ADDR` and `BAO_TOKEN` from the environment, so `secretspec run`/`secretspec get` work without extra auth flags. Its KV v2 secrets live at `<mount>/data/secretspec/<project>/<profile>/<KEY>`. If secretspec fails with permission denied, request those exact paths with `bao-cred request` (`read`), then rerun it.

## Outcomes

Each item ends in one state:

| State | Meaning | What to do |
|---|---|---|
| `approved`, `already_granted` | Access is in effect | Continue |
| `rejected` | The Approver said no | Don't re-request it. Tell the user and continue without it, or ask how to proceed |
| `refused` | Outside what may be requested; `reason` says why | Don't retry the same item. Tell the user; an operator may need to allow it |
| `pending` | Nobody decided before the timeout | Tell the user an approval is waiting; `bao-cred request --wait ID` to keep waiting |
| `expired`, `revoked` | Pending too long, or the grant ran out or was withdrawn | Request again only if still needed, with a reason that says why |

Exit status: `0` every item approved or already granted; `3` some item rejected, refused, expired or revoked; `4` some item still pending (timeout or `--no-wait`); `2` usage error; `1` other error. On `3` or `4`, read the JSON on stdout and act per item. Never loop on re-requests.

## Rules

- Never print, echo, `cat` or paste secret values into the conversation, files you commit, logs or command lines. Use `--map ... -- cmd`, `--output`, or secretspec instead of `--field` when you can.
- Never print `BAO_TOKEN`/`VAULT_TOKEN` or put them in files.
- Paths under `sys/`, `auth/`, `identity/` and `cubbyhole/`, and the `sudo` capability, are always refused. Don't ask for them.
