# Real-process session-grant E2E

The Makefile builds the authorizer and `bao-cred` binaries and prepares the official OpenBao `v2.7.1` Linux release. The tagged Go test receives those binaries and drives the real-process workflow. It mints Session Tokens with the opencode plugin's own mint CLI (`integrations/opencode/src/mint-cli.ts`), run by Bun.

## Run

From the repository root:

```sh
make e2e
```

The `e2e` build tag is the explicit opt-in for the real-process workflow. Ordinary helper regression tests remain part of the default Go suite:

```sh
go test ./e2e
```

Requirements are Linux on `amd64` or `arm64`, Go 1.26 or newer, Bun, `curl`, `sha256sum`, and GNU tar.

Downloads and the extracted `bao` binary are cached beneath ignored `.e2e/openbao/`. Set `OPENBAO_E2E_KEEP_RUNTIME=1` to retain successful-run logs and temporary state. Failed runs retain their runtime directory automatically and print both process logs.

`make e2e` builds the binaries first and passes their paths, plus the `bun` found on `PATH`, to the harness. The harness gives the OpenBao and application processes isolated home, temporary, and configuration directories, then writes an isolated HCL application config and secret files. Child environments use explicit allowlists, so workstation credentials, OpenBao/Vault settings, application secrets, GitHub credentials, and CLI authentication state are not inherited. The workflow mounts only OpenBao's built-in engines and asserts that no `github/` plugin mount exists.

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

All credentials, OpenBao state and application state are disposable. The harness installs the repository's real `config/authorizer-policy.hcl` and `config/approver-policy.hcl`. It also creates the `opencode-session` token role, the baseline policy, and the `opencode-minter` policy and AppRole. Against the live processes, the test checks the following:

- **Minting:** the plugin's mint CLI logs in with AppRole and mints a Session Token for alias `opencode-session-<id>`. The baseline token can't read the KV secrets.
- **API transport:** the approver side uses the generated ConnectRPC Go client with a cookie session, as the PWA does. bao-cred uses the same API through `AgentService`, waiting on `WatchGrantRequest`.
- **Batch request:**
  - `bao-cred request` files a batch. The approver learns about it from the `WatchEvents` stream, not by polling, and sees the reason and the session's ID and title.
  - The approver approves one item and rejects another. A path outside the Grantable Rules and a `sys/` path are refused before anyone sees them.
  - bao-cred exits with the denied code and prints every item's state.
- **Approved access:** the session's **existing** token reads the approved path, both directly and through `bao-cred -field`. The rejected path stays denied. The session's entity carries exactly one `agent-grant-` policy.
- **No duplicates:**
  - Requesting an already-allowed path returns `already_granted` and no approver sees it.
  - A request filed with `-no-wait` is approved, and `bao-cred request -wait <id>` resumes and sees the approval.
- **Session isolation:** another session can't use the Grant. A subagent minted with `--parent` resolves to the root session's identity and can.
- **Expiry and revoke:**
  - A Grant with a 5s TTL stops working once its block's `expiration` passes, while other blocks of the same session policy keep working.
  - Revoking a Grant through the approver API takes effect at once and leaves other Grants intact.
- **Request on denial:** `bao-cred -reason … <path>` files a request when a read is denied, waits, and prints the secret after approval. Without `-reason` it fails with a hint.
- **Grant listing:** `bao-cred grants` lists only the session's active Grants.
- **Agent API access:** a human userpass token gets `permission_denied` from `AgentService`.
- **Authorizer token limits:** the authorizer token can't rename or disable an entity, or write a policy outside `agent-grant-*`.
