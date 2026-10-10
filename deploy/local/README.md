# Local systemd deployment

This directory contains the simple local deployment installed on this host.
It is intentionally a **development setup**: OpenBao runs with `server -dev`,
in-memory storage, and is reprovisioned whenever its service starts. Do not use
this unit as a production OpenBao deployment.

## Installed layout

- OpenBao API: `http://127.0.0.1:18200`
- Approval app: `http://127.0.0.1:18202`
- Public route: `https://authorizer.example.com`
- Binaries/scripts: `~/.local/lib/openbao-authorizer/` and `~/.local/bin/bao-cred`
- Secret configuration: `~/.config/openbao-authorizer/` (mode `0700`, files `0600`)
- App state: `~/.local/state/openbao-authorizer/app.db`
- User units:
  - `openbao-authorizer-openbao.service`
  - `openbao-authorizer.service`
- Traefik file-provider route:
  `~/.config/traefik/dynamic/openbao-authorizer.yml`

The app binary embeds `web/dist`; `app.hcl` leaves `server.static_directory`
empty so the service does not need a frontend directory at runtime.

## Provisioned local objects

`bootstrap-openbao.sh` creates:

- the `openbao-authorizer` policy ([`config/authorizer-policy.hcl`](../../config/authorizer-policy.hcl))
  and an orphan authorizer token without the default policy;
- the `approver` user, its `openbao-authorizer-approver` marker policy and the
  `local-approvers` identity group;
- the `opencode-session` baseline policy and token role
  (`orphan`, renewable, 24h period, entity aliases `opencode-session-*`);
- the `opencode-minter` policy and AppRole, which can only call
  `auth/token/create/opencode-session`;
- an example secret at `kv/opencode/example`, plus `grantable` rules in
  `app.hcl` for `kv/data/opencode/*`, `kv/metadata/opencode/*` and
  `github/token/project-*`.

Generated material remains local:

```text
~/.config/openbao-authorizer/approver-password
~/.config/openbao-authorizer/app.hcl
~/.config/openbao-authorizer/encryption-key
~/.config/openbao-authorizer/authorizer-token
~/.config/openbao-authorizer/opencode-minter-role-id
~/.config/openbao-authorizer/opencode-minter-secret-id
```

Sign into the PWA as `approver` with the generated approver password. The app
stores only OpenBao's renewable token, encrypted server-side; the password is
not retained. The opencode plugin reads the minter role ID and secret ID files
and mints one Session Token per agent session. Never publish these files.

## Operations

```sh
systemctl --user status openbao-authorizer-openbao.service openbao-authorizer.service
systemctl --user restart openbao-authorizer-openbao.service
journalctl --user -u openbao-authorizer-openbao.service -u openbao-authorizer.service -f
```

Restarting the OpenBao unit also reprovisions it. Because the app is bound to
that unit, systemd restarts the app with the newly generated authorizer token.
The in-memory dev server forgets every Grant and Session Identity on restart;
delete `~/.local/state/openbao-authorizer/app.db` too if stale grants in the
PWA are confusing.

### Mint a Session Token by hand

The opencode plugin normally does this. To try the flow from a shell:

```sh
cd ~/.config/openbao-authorizer
export BAO_ADDR=http://127.0.0.1:18200
minter="$(bao write -field=token auth/approle/login \
  role_id="$(cat opencode-minter-role-id)" secret_id="$(cat opencode-minter-secret-id)")"
export BAO_TOKEN="$(BAO_TOKEN="${minter}" bao token create -role=opencode-session \
  -entity-alias=opencode-session-manual -metadata=title="Manual test" \
  -metadata=directory="${PWD}" -field=token)"
export OPENBAO_AUTHORIZER_URL=http://127.0.0.1:18202
bao-cred -reason "Try the local authorizer" kv/data/opencode/example
```

## Updating the application

From the repository:

```sh
make bin/openbao-authorizer bin/bao-cred
install -m 0755 bin/openbao-authorizer ~/.local/lib/openbao-authorizer/openbao-authorizer
install -m 0755 bin/bao-cred ~/.local/bin/bao-cred
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

### 1. Create and install a GitHub App

Create a GitHub App with only the repository permissions your workflows need.
Disable OAuth, device flow, webhooks, and event subscriptions unless another
component explicitly uses them. Install it only on the accounts and
repositories that agents may reach.

Broad repository administration is possible, but should be constrained by
fixed OpenBao permission sets. The app repository intentionally contains no
real account names, App IDs, installation IDs, or private keys; deployment
repositories should own those values.

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
GITHUB_APP_ID=123456
GITHUB_PERMISSION_SETS_FILE=/path/to/permission-sets.json
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

### 3. Create fixed permission sets

Use a deployment-owned JSON file with `permission_sets` and
`permission_profiles` objects, or create a repository-specific set directly:

```sh
~/.local/lib/openbao-authorizer/configure-github-project.sh \
  project-name example-org/example-repo 87654321
```

This creates `github/token/project-project-name`. The `github-token` grantable
rule lets agents request only paths matching `github/token/project-*`; requests
for `github/config`, the bare unrestricted `github/token` endpoint, or
permission-set administration are refused before an approver sees them.

### 4. Run `gh` with a Grant

Inside an opencode session the plugin has already put a Session Token in
`BAO_TOKEN`. When the token lacks access, `bao-cred` files a Grant Request with
the given reason, waits for an Approver, and retries the read once:

```sh
bao-cred -reason "Inspect the repository for the release" \
  -map GH_TOKEN=token github/token/project-project-name -- \
  gh repo view example-org/example-repo
```

Approve the item at:

```text
https://authorizer.example.com
```

Sign in there as `approver` with the current value of
`~/.config/openbao-authorizer/approver-password`. The Grant lasts at most one
hour (the `github-token` rule's `max_ttl`), so later `gh` calls in the same
session read the path without asking again. The GitHub installation token
expires at GitHub after about one hour and is never written to disk by
`bao-cred`.

## Web Push

The bootstrap environment contains a local VAPID key pair and restricts push
endpoints to these public service suffixes:

- `fcm.googleapis.com`
- `updates.push.services.mozilla.com`
- `web.push.apple.com`

The PWA service worker displays generic notifications only. Enabling or
disabling notifications is performed from the installed HTTPS PWA.
