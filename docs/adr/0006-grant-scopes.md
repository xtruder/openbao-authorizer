# Grants have a session, project or global scope, each in a policy the tokens already carry

An Approver decides, per item, which Requesters a Grant reaches: **session** (the Requester's own identity, e.g. one Agent Session), **project** (a Named Identity and all its Agent Sessions) or **global** (every Named Identity and Agent Session on the server, like default grants the operator keeps extending). The Requester suggests a scope with `bao-cred request --scope`; it defaults to session inside an Agent Session and to project for a project's own Named Token.

Each scope is one Grant policy: `agent-grant-<entity id>`, attached to the session's entity as before (ADR-0001); `agent-grant-project-<name>`; and `agent-grant-global`. Named and Session Tokens are minted with the project and global policy names already on them (ADR-0005). OpenBao evaluates policies by name on every request and accepts names that don't exist yet, so when the authorizer writes or rewrites a project or global policy, every token carrying it gains or loses the access at once, with no entity or token changes.

The scopes a Requester may use follow from its token's own policies, not its metadata: project scope needs exactly one `agent-grant-project-*` policy, global scope needs `agent-grant-global`, and session scope needs an Agent Session or a token outside any project, such as a CI AppRole. A project's Named Token has no session of its own, so it can't request session scope. Approvers see the allowed scopes and may narrow or widen within them.

## Considered options

- **Identity groups per project and a global group.** Policies on a group reach its members, but the authorizer would need to create groups and manage their membership, a much broader OpenBao permission than writing `agent-grant-*` policies.
- **Attaching project and global policy names to each session entity.** Needs an entity write per new session, before its first request, and a token that never files a request would never get project Grants.
- **One policy per Grant.** Rejected in ADR-0001 for the same reasons; project and global policies are shared by many Requesters, which makes batched writes matter more.

## Consequences

- **One decision may write up to three policies.** The authorizer writes them in a fixed order and, if one fails or storing the decisions fails, rewrites those it touched from the stored Grants. A single in-process lock serializes all policy writes, since project and global policies are shared; one authorizer instance owns a database.
- **A project Grant reaches tokens minted later**, including new sessions, until it expires. A global Grant reaches every project, so the PWA marks it.
- **Tokens minted before scopes existed carry no project or global policy** and can use only session scope until re-minted with `bao-cred auth`.
- **Grants stored before scopes existed are session Grants.**
