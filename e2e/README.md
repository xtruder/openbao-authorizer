# Real-process OpenBao control-group E2E

The Makefile prepares the repository's application binary and the official OpenBao `v2.7.0-beta20260909` Linux release. The tagged Go test receives those prebuilt binaries and drives the real-process workflow.

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

`make e2e` builds the application first and passes its binary path to the harness. The harness gives the OpenBao and application processes isolated home, temporary, and configuration directories, then writes an isolated HCL application config and secret files. Child environments use explicit allowlists, so workstation credentials, OpenBao/Vault settings, application secrets, GitHub credentials, and CLI authentication state are not inherited. The workflow mounts only OpenBao's built-in engines and asserts that no `github/` plugin mount exists.

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

All credentials, OpenBao state, and application state are disposable. The test verifies against the live APIs that:

- userpass aliases bind Alice and Bob to explicit identity entities;
- Alice belongs to `e2e-requesters`, Bob belongs to `e2e-approvers`, and both inherit policy through their identity groups;
- Alice's writes to `kv/data/payroll` are deferred by a factor with `approvals = 1` and `self_auth_allowed = false`;
- the service token has only `e2e-service`, can inspect explicitly supplied accessors and revoke rejected wrapping tokens, but cannot list all accessors;
- the service token receives HTTP 403 from `sys/control-group/authorize`, and the denied call does not change request state;
- unsubmitted requests do not appear in the application;
- Alice submits an ordered two-member group with a shared reason and an idempotency key;
- Bob logs in through `POST /api/v1/session`;
- the application's CSRF-protected approval endpoint authorizes with Bob's human token;
- exactly one human authorization is recorded on each member;
- the secret does not exist before unwrap;
- Alice's wrapping tokens execute the approved deferred writes; and
- the resulting KV value matches the unique per-run marker.

Policy fixtures are in [`policies/`](policies/).

## Version caveat

OpenBao 2.6.2 does **not** contain control groups. They first appear in the official `2.7.0-beta20260909` prerelease, so substituting 2.6.2 cannot exercise this workflow. The test is deliberately pinned to that beta and does not recommend a prerelease for production. Update the version, archive names, both architecture digests, and documentation only with a successful full E2E run.
