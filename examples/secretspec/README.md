# secretspec example

[secretspec](https://secretspec.dev) can read Grants directly: `secretspec.toml`
here injects `GH_TOKEN` from `github/token/project-authorizer`. Change `item` to
another permission set, or copy the secret entry for more.

## Try it

```sh
export BAO_ADDR=https://openbao.example.com
export BAO_AUTHORIZER_ADDR=https://authorizer.example.com
bao login                                  # your own login, which may mint Named Tokens
bao-cred auth example                      # mint and store the Named Token
export BAO_IDENTITY=example                # in a project: bao-cred init writes .bao-identity instead

# 1. Get a Grant: secretspec only reads, it never files Grant Requests.
bao-cred request --reason "try secretspec" --item github/token/project-authorizer=read

# 2. Read through secretspec.
cd examples/secretspec
bao-cred run -- secretspec run -- gh repo view xtruder/openbao-authorizer             # fresh token each run
bao-cred run -- secretspec run -P cached -- gh repo view xtruder/openbao-authorizer   # reused from your keyring
```

secretspec takes the token from the provider alias's `token` credential, then
`BAO_TOKEN`/`VAULT_TOKEN`, then the `~/.vault-token` that `bao login` writes.
`bao-cred run` sets `BAO_TOKEN` for that one command to the token bao-cred
uses: inside an agent session its Session Token, else the `example` Named
Token. The Grant must reach that token: a session, project or global Grant.
`eval "$(bao-cred env)"` exports the same token to a whole shell instead.

## Reading the Named Token from the keyring

This gives secretspec the project's Named Token, never a Session Token, so
session-scope Grants don't reach it.

Instead of exporting `BAO_TOKEN`, an alias can read bao-cred's keyring entry
(service `bao-cred`, account = identity name) as its credential:

```toml
[providers]
keyring = "keyring://"

[providers.github]
uri = "openbao:///github?kv=1"

[providers.github.credentials]
token = { provider = "keyring", ref = { item = "bao-cred", field = "example" } }
```

The credential wins over `BAO_TOKEN`, and a missing entry fails instead of
falling back to `~/.vault-token`. It works only while bao-cred stores the token
in the keyring, not in its file fallback. `bao-cred auth` and `bao-cred status`
renew the token; secretspec doesn't.

## How it works

- **`kv=1`** makes the OpenBao provider do a plain read of `<mount>/<item>`.
  That is how dynamic secrets are read too, so `github` + `token/<set>` reads
  `github/token/<set>` and `field = "token"` picks the value.
- **No host in the URI** (`openbao:///github`): the address comes from
  `BAO_ADDR`.
- **The `default` profile** reads OpenBao on every run, so every run mints a
  new GitHub token and needs the caller's own Grant.
- **The `cached` profile** keeps the token in the keyring (Secret Service, e.g.
  gnome-keyring or oo7) for up to `max_age`. GitHub tokens live one hour from
  the read that minted them, and the cache entry is written right after that
  read, so a `max_age` below one hour means a cached token never outlives the
  real one; 45m leaves time for the command itself.
  `secretspec cache clear -P cached GH_TOKEN` drops it early.

## Agents: use the default profile

The keyring cache is shared by everything running as you, keyed by project,
profile and secret, not by Named Identity. A command working as another
identity would get the cached token without that identity's Grant. Agents
should use the uncached `default` profile (or `bao-cred read`). Revoking a
Grant also doesn't clear the cache: a cached token keeps working until
`max_age` or until the token expires.

secretspec doesn't honour `BAO_NO_TOKEN_FILE`. Without a `token` credential or
`BAO_TOKEN`, it uses your own `bao login` token instead of failing, so give it
the Named Token one of the two ways above.
