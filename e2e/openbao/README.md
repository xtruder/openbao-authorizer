# Real-process OpenBao control-group E2E

The tagged Go test in this directory downloads the official OpenBao `v2.7.0-beta20260909` Linux release and runs it as a real dev-mode process. It also builds and runs the repository's real Go application server. No container or shell harness is involved.

## Run

From the repository root:

```sh
make e2e
# Equivalent:
go test -tags=e2e -count=1 -v ./e2e/openbao
```

The `e2e` build tag is the explicit opt-in for the network download and real-process workflow. Ordinary helper regression tests remain part of the default Go suite:

```sh
go test ./e2e/openbao
```

Requirements are Linux on `amd64` or `arm64` and Go 1.26 or newer. The test uses only Go's standard library for download, checksum validation, archive inspection, HTTP calls, and process management.

Downloads and the extracted `bao` binary are cached beneath ignored `.e2e/openbao/`. Set `OPENBAO_E2E_KEEP_RUNTIME=1` to retain successful-run logs and temporary state. Failed runs retain their runtime directory automatically and print both process logs.

## Supply-chain and process checks

The test:

- pins the official archive name and SHA-256 separately for `amd64` and `arm64`;
- requires the matching entry in the release's `checksums.txt` to equal the repository pin;
- hashes the archive itself before use;
- rejects duplicate, missing, nested, absolute, non-regular, oversized, or unexpected archive entries;
- accepts exactly `bao`, `LICENSE`, `README.md`, and `CHANGELOG.md`;
- verifies the cached executable against the `bao` bytes in the pinned archive and requires an exact `OpenBao v2.7.0-beta20260909` version token;
- lets OpenBao and the application bind `127.0.0.1:0`, then discovers their kernel-assigned ports from `/proc` without a bind-and-release race;
- checks listener ownership before and after every API call; and
- starts each server in its own process group and performs bounded `TERM` followed by `KILL` cleanup, including child processes.

## Verified workflow

All credentials, OpenBao state, and application state are disposable. The test verifies against the live APIs that:

- userpass aliases bind Alice and Bob to explicit identity entities;
- Alice belongs to `e2e-requesters`, Bob belongs to `e2e-approvers`, and both inherit policy through their identity groups;
- Alice's write to `kv/data/payroll` is deferred by a factor with `approvals = 1` and `self_auth_allowed = false`;
- the scanner token has only `e2e-scanner`, can list service-token accessors with `sudo`, and can inspect `sys/control-group/request`;
- the scanner receives HTTP 403 from `sys/control-group/authorize`, and the denied call does not change request state;
- the real application scanner discovers and persists the pending request;
- Bob logs in through `POST /api/v1/session`;
- the application's CSRF-protected approval endpoint authorizes with Bob's human token;
- exactly one human authorization is recorded;
- the secret does not exist before unwrap;
- Alice's single-use wrapping token executes the approved deferred write; and
- the resulting KV value matches the unique per-run marker.

Policy fixtures are in [`policies/`](policies/).

## Version caveat

OpenBao 2.6.2 does **not** contain control groups. They first appear in the official `2.7.0-beta20260909` prerelease, so substituting 2.6.2 cannot exercise this workflow. The test is deliberately pinned to that beta and does not recommend a prerelease for production. Update the version, archive names, both architecture digests, and documentation only with a successful full E2E run.
