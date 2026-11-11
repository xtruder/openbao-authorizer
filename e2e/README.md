# Real-process Named Identity grant E2E

The Makefile builds the authorizer and `bao-cred` binaries and prepares the official OpenBao `v2.7.1` Linux release. The tagged Go test receives those binaries and drives the real-process workflow. It mints Named Tokens with `bao-cred auth`, as a developer would.

## Run

From the repository root:

```sh
make e2e
```

The `e2e` build tag is the explicit opt-in for the real-process workflow. Ordinary helper regression tests remain part of the default Go suite:

```sh
go test ./e2e
```

Requirements are Linux on `amd64` or `arm64`, Go 1.26 or newer, `curl`, `sha256sum`, and GNU tar.

Downloads and the extracted `bao` binary are cached beneath ignored `.e2e/openbao/`. Set `OPENBAO_E2E_KEEP_RUNTIME=1` to retain successful-run logs and temporary state. Failed runs retain their runtime directory automatically and print both process logs.

`make e2e` builds the binaries first and passes their paths to the harness. The harness gives the OpenBao and application processes isolated home, temporary, and configuration directories, then writes an isolated HCL application config and secret files. Child environments use explicit allowlists, so workstation credentials, OpenBao/Vault settings, application secrets, GitHub credentials, and CLI authentication state are not inherited. The workflow mounts only OpenBao's built-in engines and asserts that no `github/` plugin mount exists.

## Supply-chain and process checks

The Makefile preparation:

- pins the official archive name and SHA-256 separately for `amd64` and `arm64`;
- requires the matching entry in the release's `checksums.txt` to equal the repository pin;
- hashes the archive itself before use;
- accepts exactly `bao`, `LICENSE`, `README.md`, and `CHANGELOG.md`;
- extracts `bao` from the verified archive.

The Go test:

- lets OpenBao and the application bind `127.0.0.1:0`, then discovers their kernel-assigned ports from `/proc` without a bind-and-release race;
- checks listener ownership before and after every API call; and
- starts each server in its own process group and performs bounded `TERM` followed by `KILL` cleanup, including child processes.
- redacts OpenBao dev-mode bootstrap credentials from failure diagnostics.

## Verified workflow

All credentials, OpenBao state and application state are disposable. The harness installs the repository's real `config/authorizer-policy.hcl`, plus `list` on `kv/metadata/e2e` for the `e2e-kv` rule's `discover` path, an `ssh` mount with a generated CA and an `e2e-node` role for the `e2e-ssh` rule (`ssh/sign/*`, `update`), and `config/approver-policy.hcl`. It also creates the `named-identity` token role with a 768h period and the `agent-session` role with a 24h period, both allowing the project and global Grant policies, the baseline and `named-identity-minter` policies from `deploy/local/`, a `dev` userpass user holding only the minter policy, and two AppRoles: `ci`, and `self-approver`, which also carries the approver policy. The application config has `requester "named"` and `requester "sessions"` (token roles) and `requester "ci"` (`auth_mount = "approle"`) rules. Against the live processes, the test checks the following:

- **Approver sign-in:** OpenBao's `sys/config/cors` allows the application origin, and a CORS preflight from that origin succeeds. `GetLoginOptions` returns the OpenBao address and methods without a session. The test logs in to OpenBao with userpass directly, as the PWA does, and hands the token to `CreateSession`; afterwards the token is revoked.

- **Minting:** the developer's login token goes into the isolated `~/.vault-token`, and `bao-cred auth --store file e2e-project-a` mints a Named Token with a 32-day TTL. The baseline token can't read the KV secrets. Every later bao-cred call selects the identity with `BAO_IDENTITY`, as a project's `.envrc` does.
- **API transport:** the approver side uses the generated ConnectRPC Go client with a cookie session, as the PWA does. bao-cred uses the same API through `GrantService`, waiting on `WatchGrantRequest`.
- **Batch request:**
  - `bao-cred request` files a batch. The approver learns about it from the `WatchEvents` stream, not by polling, and sees the reason, the identity's name as Requester ID, and the matched rule.
  - The approver approves one item and rejects another. A path outside the Grantable Rules and a `sys/` path are refused before anyone sees them.
  - bao-cred exits with the denied code and prints every item's state.
- **Approved access:** the identity's **existing** token reads the approved path, both directly and through `bao-cred read --field`. The rejected path stays denied. A project token's request defaults to project scope: the Grant lands in `agent-grant-project-e2e-project-a`, and nothing is attached to the entity.
- **No duplicates:**
  - Requesting an already-allowed path returns `already_granted` and no approver sees it.
  - A request filed with `--no-wait` is approved, and `bao-cred request --wait <id>` resumes and sees the approval.
- **Identity isolation and rotation:** another Named Identity can't use the Grant. Running `bao-cred auth` again for the first identity revokes its previous token, keeps the entity, and the new token keeps the Grant.
- **Token export:** `bao-cred env` prints the Named Token and `BAO_NO_TOKEN_FILE=1`, and `bao-cred status` reports the identity. An identity with no stored token fails with an `auth` hint instead of using `~/.vault-token`.
- **Agent Sessions:** with `OPENCODE_SESSION_ID` set, `bao-cred status` mints a Session Token from the project token. Its own entity differs from the project's, and its token policies include the project and global Grant policies, so the project's Grant reaches it. A session's `read --reason` defaults to session scope, and the Approver sees the session, project and three allowed scopes; the Grant reaches only that session, not a second session (whose token `bao-cred run` hands to a command) or the project token. A second session's `--scope project` request, widened by the Approver to global, reaches both sessions and the other project's token, which `bao-cred grants` lists as global.
- **Expiry and revoke:**
  - A Grant with a 5s TTL stops working once its block's `expiration` passes, while other blocks of the same Requester policy keep working.
  - Revoking a Grant through the approver API takes effect at once and leaves other Grants intact.
- **Request on denial:** `bao-cred read --reason … <path>` files a request when a read is denied, waits, and prints the secret after approval. Without `--reason` it fails with a hint.
- **Write on denial:** `bao-cred write --reason … ssh/sign/e2e-node public_key=@…` files an `update` request when the write is denied, waits, and after approval writes the signed certificate to `--output`. The certificate is a user certificate for the public key sent, with the role's only principal `core@e2e-node`, the role's key ID format and its 5m TTL.
- **SSH credential helper:** `bao-cred ssh cert --key … node@e2e.example.ts.net` derives the role `e2e-node` (`<host>-<user>`), signs with the same Grant and writes a certificate for `core@e2e-node`; a second run leaves the valid certificate in place.
- **Grant listing:** `bao-cred grants` lists only the identity's active Grants.
- **Catalog:** `bao-cred grantable` shows the `e2e-kv` rule with the concrete paths discovered under `kv/metadata/e2e`, without the folder key. Reading one of them with `--reason` works after approval.
- **Requester Rules:** an approver's userpass token gets `NOT_REQUESTER` from `GrantService`. A `ci` AppRole token matches the `ci` rule, files a request, and reads the path once it is approved; identity A can't.
- **Self-approval:** a `self-approver` AppRole token files a request, then signs in as an Approver; deciding its own request fails with `SELF_APPROVAL`.
- **Authorizer token limits:** the authorizer token can't rename or disable an entity, or write a policy outside `agent-grant-*`.
- **Logout:** `bao-cred logout` revokes the Named Token and with it the Session Tokens it minted, and the next bao-cred call has no token.
- **Project file:** `bao-cred init` in a directory with `.git` writes `.bao-identity` and mints its token. `bao-cred grants` from a subdirectory, with no identity variables and `~/.vault-token` still present, uses the Named Token, and lists the global Grant: the developer's own token would get `NOT_REQUESTER`.
