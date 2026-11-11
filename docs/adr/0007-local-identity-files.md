# Identity files are local to the machine, and an identity in use never expires

A Named Identity's name is the key to its project Grants: every token minted for the name carries `agent-grant-project-<name>` (ADR-0006), and anyone holding a minter login may mint any name (ADR-0005). ADR-0005 had a committed `.bao-identity` choose the name, so a checkout chose which project's Grants its tokens get. Once bao-cred mints and re-mints on its own, a clone carrying `.bao-identity: homelab`, or an agent running bao-cred in a repository it fetched, would act as `homelab` without anyone deciding that. This ADR supersedes ADR-0005's project file, lookup order and lifetime decisions.

## Decisions

- **The identity file belongs to the machine.** `bao-cred init` writes the name to `bao-identity` in the repository's common git directory (`git rev-parse --git-common-dir`): `.git/bao-identity` in a clone. Every linked worktree shares it, because its `.git` file names a gitdir whose `commondir` points back there, and git never commits or transfers that directory. bao-cred resolves this without running git. Outside repositories, `init` writes `.bao-identity` to the current directory, which covers the tree below it, so `init` in the home directory creates a personal identity for the human's own ssh and tools.
- **Lookup ignores what a checkout carries.** Walking up from the working directory, inside a repository only its `bao-identity` counts; a `.bao-identity` in the working tree is ignored. Outside repositories the nearest `.bao-identity` counts. A repository without an identity uses the next one above it. `BAO_TOKEN`, `VAULT_TOKEN`, `--identity` and `BAO_IDENTITY` still come first, and `~/.vault-token` last, unless `BAO_NO_TOKEN_FILE` is set.
- **Generated names.** `init` names the identity after the repository or directory plus six random characters (`my-app-k7q2xm`). Approvers recognise the prefix, and no other checkout or machine names the same identity by accident or by copying a file. Project Grants are therefore per machine and repository.
- **Renew on use, re-mint known names.** bao-cred renews the Named Token whenever it uses it, so a token in use never expires; Named Tokens stay periodic with ADR-0005's 32-day period. When the stored token is invalid or gone and the name is in `index.json`, meaning this machine minted it, bao-cred mints a new one with `~/.vault-token`, renewing that login as well, and the identity keeps its Grants. Names never minted here, and names removed with `logout`, need `init` or `auth`. The only manual step left is `bao login` after the login's own period lapses unused.

## Considered options

- **A committed `.bao-identity`, as in ADR-0005.** Shares the identity across clones and machines, but lets a checkout choose the Grants its tokens get.
- **An untracked `.bao-identity` in the working tree.** Linked worktrees don't share untracked files, and bao-cred can't tell it from a committed one without asking git.
- **`direnv allow`-style approval of a path for N days.** Worktrees have separate paths, and approval adds a recurring step without removing the cause: the checkout still names the identity.
- **An identity derived from the `bao login` token.** Requests would be made under a name nobody chose.

## Consequences

- **Each clone is its own identity.** The same repository on two machines, or cloned twice, has separate project Grants. `init <name>` reuses a name deliberately.
- **A personal `~/.bao-identity` reaches repositories without their own identity**, including their agents. Run `init` in a repository to separate it.
- **`init` is a trust decision of the local user.** Agents run as the same user and could run `init` themselves; the files protect against identities nobody chose, not against processes acting as the human.
