# OpenBao Authorizer

Humans approve, item by item, the extra OpenBao permissions that an AI agent session asks for. Approved permissions apply to the session's existing OpenBao token.

## Language

**Agent Session**:
One opencode conversation in which an AI agent works, together with any subagent conversations it spawns. It is the unit of isolation: what one session is granted, another session never receives.
_Avoid_: conversation, run

**Session Token**:
The minimal OpenBao token that an **Agent Session** uses for every OpenBao call. It never gains policies of its own; it gains access only through **Grants** on its **Session Identity**.
_Avoid_: workload token, agent token

**Session Identity**:
The OpenBao identity that belongs to exactly one **Agent Session**. **Grants** attach here, so every token of that session sees them.
_Avoid_: agent identity, AppRole identity

**Grant Request**:
A batch of **Permission Items** that one **Agent Session** asks for at once, along with a required reason.
_Avoid_: control-group request, approval request

**Permission Item**:
One OpenBao path plus a set of capabilities inside a **Grant Request**. An **Approver** approves or rejects each item on its own.
_Avoid_: scope, permission

**Grantable Rule**:
An operator-defined limit on which paths and capabilities may be requested at all. A **Permission Item** outside every rule is refused before a human sees it.
_Avoid_: allowlist entry, template

**Grant**:
An approved **Permission Item**, now in effect for the requesting **Agent Session** until its expiry. Every Grant has an expiry. The expiry is chosen within the **Grantable Rule**'s limit, and the **Approver** may make it earlier.
_Avoid_: approval, lease

**Hard Denylist**:
Paths and capabilities that no **Grantable Rule** can make grantable, because granting them would let a session raise its own privileges.

**Approver**:
A human, authenticated with their own OpenBao identity, who decides **Permission Items**.

## Relationships

- An **Agent Session** has one **Session Identity** and one or more **Session Tokens** over its life.
- A **Grant Request** belongs to one **Agent Session** and contains one or more **Permission Items**.
- Each **Permission Item** must fall within a **Grantable Rule**, and an **Approver** decides it separately.
- An approved **Permission Item** becomes a **Grant** on the requesting session's **Session Identity**.

## Flagged ambiguities

- "Control group" means OpenBao's own per-request approval feature, which this system doesn't use. Don't use it as a name for **Grant Requests** or **Grants**.
