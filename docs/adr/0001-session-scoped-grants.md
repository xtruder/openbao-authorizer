# Agent access is granted to the Session Identity before use

An **Agent Session** asks for **Permission Items** ahead of use, and an **Approver** decides each item. Every approved item becomes a **Grant**: one `path` block, carrying OpenBao's own `expiration`, in the session's single ACL policy `agent-grant-<entity id>`. That policy is attached to the **Session Identity**. OpenBao evaluates identity policies on every request, so the session's existing token gains access at once. Agents, bao-cred and tools such as secretspec keep using one token. One approval covers repeated use and batches of paths.

## Considered options

- **OpenBao control groups.** Every protected request needs its own approval, and the requester has to hold a wrapping token and unwrap the deferred response. That is too rigid for agents that read the same credentials repeatedly or need several paths for one task.
- **A new token per approval.** The approval would be scoped to one token, but agents and their tools would have to swap tokens mid-session.
- **One policy per Grant.** Approving, revoking and expiring Grants would be independent, but a batch of N approvals would cost N policy writes and N entity updates. Partial failures could leave some items granted and others not. OpenBao lets one policy repeat a path with different expirations, and each block lapses on its own, so a single session policy loses nothing.
- **One identity group per Grant or per session.** The authorizer's token could then be scoped by group name. Attaching the policy to the Session Identity creates fewer objects. As a result the authorizer's token has `update` on `identity/entity/id/*`, limited to the `policies` parameter. OpenBao 2.7 can't restrict which names go into that list: `allowed_parameters` value globs reject JSON lists and accept a comma-joined string.
- **A shared AppRole identity.** AppRole maps every login of one role to a single entity, so grants would leak across parallel sessions. Instead, Session Tokens are minted through a token role with a per-session entity alias.

## Consequences

- **Grants outlive any single Session Token.** A session resumed after an opencode restart keeps its unexpired Grants.
- **Every Grant has an expiry, and OpenBao enforces it.** Each block lapses independently, even while the authorizer is down, and the policy expires with its last block. Once a Grant expires, using that path again needs a new approval.
- **A batch of decisions is all-or-nothing.** It costs one policy write, followed by one database commit. The policy name is attached to the entity on the first approval and never detached, so revocation and expiry cost no entity writes. Policies are HCL, because JSON can't repeat a path.
- **The token role identifies Session Tokens.** The authorizer accepts a bearer token only when `lookup-self` reports the session token role and an entity. Only the minter can use that role, and the role pins one entity alias per session, so authentication needs no entity read.
- **The authorizer's OpenBao token can grant privileges.** It writes Grant policy content and can attach any non-root policy to any entity, so it must be protected like an administrative credential. The **Hard Denylist** and **Grantable Rules** are enforced by the authorizer, not by OpenBao.
- **The threat model guards against agent mistakes, not a malicious agent.** The agent runs as the same OS user as the minting credential, so it can mint baseline tokens for any session alias and use that session's Grants.
