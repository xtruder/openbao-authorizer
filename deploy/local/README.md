# Local systemd deployment

This directory contains the simple local deployment installed on this host.
It is intentionally a **development setup**: OpenBao runs with `server -dev`,
in-memory storage, and is reprovisioned whenever its service starts. Do not use
this unit as a production OpenBao deployment.

## Installed layout

- OpenBao API: `http://127.0.0.1:18200`
- Approval app: `http://127.0.0.1:18202`
- Public route: `https://openbao-authorizer.x-truder.dev`
- Binaries/scripts: `~/.local/lib/openbao-authorizer/` and `~/.local/bin/openbao-gh`
- Secret configuration: `~/.config/openbao-authorizer/` (mode `0700`, files `0600`)
- App state: `~/.local/state/openbao-authorizer/app.db`
- User units:
  - `openbao-authorizer-openbao.service`
  - `openbao-authorizer.service`
- Traefik file-provider route:
  `~/.config/traefik/dynamic/openbao-authorizer.yml`

The app binary embeds `web/dist`; the service does not need a frontend directory
or `STATIC_DIRECTORY` at runtime.

## Provisioned local identities

`bootstrap-openbao.sh` creates:

- scanner policy/token for the app;
- `approver` user and the `local-approvers` identity group;
- `requester` user and a protected `kv/data/controlled` path;
- `agent` user restricted to approved `github/token/project-*` permission sets;
- one-approval control-group factors with self-authorization disabled.

Generated login material remains local:

```text
~/.config/openbao-authorizer/approver-password
~/.config/openbao-authorizer/requester-password
~/.config/openbao-authorizer/requester-token
~/.config/openbao-authorizer/agent-token
```

Sign into the PWA as `approver` with the generated approver password. The app
stores only OpenBao's renewable token, encrypted server-side; the password is
not retained. `openbao-gh` reads the agent token directly; do not copy it into
`gh auth login`. Never publish these files.

## Operations

```sh
systemctl --user status openbao-authorizer-openbao.service openbao-authorizer.service
systemctl --user restart openbao-authorizer-openbao.service
journalctl --user -u openbao-authorizer-openbao.service -u openbao-authorizer.service -f
```

Restarting the OpenBao unit also reprovisions it. Because the app is bound to
that unit, systemd restarts the app with the newly generated scanner token.

## Updating the application

From the repository:

```sh
make build
install -m 0755 bin/openbao-authorizer ~/.local/lib/openbao-authorizer/openbao-authorizer
systemctl --user restart openbao-authorizer.service
```

## GitHub App token broker

The local OpenBao service registers
[`openbao-plugin-secrets-github`](https://m7kni.io/openbao-plugin-secrets-github/)
`v0.1.2` from the pinned Linux release binary. Bootstrap verifies SHA-256
`2ac19c2a391b08a38bcbbbc31b36f5b69e65f341a37c34effe7157babb8b64f4`
before registering and mounting it at `github/`.

A PAT cannot mint narrower child PATs. The GitHub App is required because its
installation API can issue one-hour tokens narrowed to a repository and fixed
permissions. Storing and returning the existing PAT would only put an approval
gate around the same long-lived user credential.

### 1. Create and install the GitHub App

The test deployment uses the public-installable GitHub App
`xtruder-openbao-authorizer`, owned by `xtruder`, with homepage
`https://openbao-authorizer.x-truder.dev`. OAuth, device flow, webhooks, event
subscriptions, organization permissions, account permissions, and enterprise
permissions are disabled.

The App has broad repository-management permissions so approval-gated tokens
can be used effectively with `gh`: repository administration, contents,
workflows, Actions, checks, statuses, deployments, issues, pull requests,
discussions, environments, packages, Pages, repository projects, hooks,
repository secrets/variables, Codespaces, and repository security controls.
Metadata and Codespaces metadata are read-only; the remaining selected
repository permissions are read/write. This is intentionally powerful: use
OpenBao permission sets and installation repository selection to constrain each
issued token.

The App is installed on all current and future repositories for both profiles:

- `xtruder`, installation `162977542`;
- `offlinehacker`, installation `162977871`.

From the App settings page, record the numeric **App ID** and generate a private
key. The plugin requires GitHub's PKCS#1 PEM form, whose first line is:

```text
-----BEGIN RSA PRIVATE KEY-----
```

Find the numeric installation ID in the installation settings URL:

```text
https://github.com/settings/installations/INSTALLATION_ID
```

### 2. Seed the test deployment

Install the downloaded key without printing it:

```sh
install -m 0600 /path/to/downloaded-key.pem \
  ~/.config/openbao-authorizer/github-app-private-key.pem
```

Add these non-secret identifiers to
`~/.config/openbao-authorizer/bootstrap.env`:

```sh
GITHUB_APP_ID=4999527
GITHUB_APP_INSTALLATION_ID=162977542
GITHUB_XTRUDER_INSTALLATION_ID=162977542
GITHUB_OFFLINEHACKER_INSTALLATION_ID=162977871
```

Then restart the in-memory development server:

```sh
systemctl --user restart openbao-authorizer-openbao.service
```

Bootstrap writes the App configuration into the `github/` secrets engine. For
this **test deployment**, the PEM remains on disk so the in-memory dev server
can be reseeded after every restart. A production OpenBao deployment should use
durable encrypted storage and remove the bootstrap copy after seeding.

Verify without exposing the private key:

```sh
BAO_ADDR=http://127.0.0.1:18200 \
BAO_TOKEN="$(sed -n 's/^BAO_TOKEN=//p' ~/.config/openbao-authorizer/bootstrap.env)" \
  ~/.local/lib/openbao-authorizer/bao read github/config
```

`prv_key` must be redacted by the plugin.

### 3. Use profile-wide or repository-specific permission sets

Bootstrap creates two broad, profile-wide sets:

- `github/token/project-xtruder` — all repositories in the `xtruder` installation;
- `github/token/project-offlinehacker` — all repositories in the
  `offlinehacker` installation.

For a narrower token, the admin helper fixes a permission set to one repository:

```sh
~/.local/lib/openbao-authorizer/configure-github-project.sh \
  authorizer xtruder/openbao-authorizer
```

This creates `github/token/project-authorizer`. Agents can read only paths
matching `github/token/project-*`; they cannot access `github/config`, the bare
unrestricted `github/token` endpoint, or permission-set administration.

### 4. Run `gh` through approval

The agent helper reads the local agent OpenBao token, requests the fixed project
permission set, waits for a control-group approval, unwraps the GitHub token
only in memory, and exports it only to the child `gh` process:

```sh
openbao-gh xtruder -- gh repo list xtruder --limit 200
openbao-gh offlinehacker -- gh repo list offlinehacker --limit 200
openbao-gh xtruder -- gh pr list --repo xtruder/openbao-authorizer
```

Approve the pending request at:

```text
https://openbao-authorizer.x-truder.dev
```

Sign in there as `approver` with the current value of
`~/.config/openbao-authorizer/approver-password`. The helper waits up to 15
minutes. On approval, the response-wrapping token is consumed once and the
GitHub installation token expires at GitHub after about one hour. Neither token
is written to disk by `openbao-gh`.

## Web Push

The bootstrap environment contains a local VAPID key pair and restricts push
endpoints to these public service suffixes:

- `fcm.googleapis.com`
- `updates.push.services.mozilla.com`
- `web.push.apple.com`

The PWA service worker displays generic notifications only. Enabling or
disabling notifications is performed from the installed HTTPS PWA.
