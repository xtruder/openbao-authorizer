# OpenBao Authorizer

Humans approve, item by item, the extra OpenBao permissions that a Requester, such as an AI agent session, asks for. Approved permissions apply to the Requester's existing OpenBao token.

## Language

**Requester**:
An OpenBao identity allowed by a **Requester Rule** to file **Grant Requests**. It is the unit of isolation: what one Requester is granted, another never receives.
_Avoid_: client, caller, agent (unless it is an **Agent Session**)

**Requester Rule**:
An operator-defined match, such as a token role or an auth mount, that decides which OpenBao tokens may file **Grant Requests**. Tokens matching no rule are refused.
_Avoid_: allowlist

**Agent Session**:
One kind of **Requester**: one opencode conversation in which an AI agent works, together with any subagent conversations it spawns.
_Avoid_: conversation, run

**Session Token**:
The minimal OpenBao token an **Agent Session** uses for every OpenBao call. It never gains policies of its own; it gains access only through **Grants** on its **Session Identity**.
_Avoid_: workload token, agent token

**Session Identity**:
The OpenBao identity that belongs to exactly one **Agent Session**.
_Avoid_: agent identity, AppRole identity

**Grant Request**:
A batch of **Permission Items** that one **Requester** asks for at once, along with a required reason.
_Avoid_: control-group request, approval request

**Permission Item**:
One OpenBao path plus a set of capabilities inside a **Grant Request**. An **Approver** approves or rejects each item on its own.
_Avoid_: scope, permission

**Grantable Rule**:
An operator-defined limit on which paths and capabilities may be requested at all. A **Permission Item** outside every rule is refused before a human sees it.
_Avoid_: allowlist entry, template

**Grant**:
An approved **Permission Item**, in effect for the **Requester** until its expiry. Every Grant has an expiry. The expiry is chosen within the **Grantable Rule**'s limit, and the **Approver** may make it earlier. Once it expires, using the path again needs a new approval.
_Avoid_: approval, lease

**Hard Denylist**:
Paths and capabilities that no **Grantable Rule** can make grantable, because granting them would let a Requester raise its own privileges.

**Approver**:
A human who decides **Permission Items**. They sign in to OpenBao with any auth method and hold the approver policy. An Approver never decides a **Grant Request** filed by their own identity.

## Relationships

- A **Requester** is matched by one **Requester Rule**; an **Agent Session** is a Requester whose identity is its **Session Identity**.
- A **Grant Request** belongs to one **Requester** and contains one or more **Permission Items**.
- Each **Permission Item** must fall within a **Grantable Rule**, and an **Approver** other than the Requester decides it separately.
- An approved **Permission Item** becomes a **Grant** on the Requester's identity, so every token of that identity sees it.

## Flagged ambiguities

- "Control group" means OpenBao's own per-request approval feature, which this system doesn't use. Don't use it as a name for **Grant Requests** or **Grants**.
- "Session" alone is ambiguous: an **Agent Session** is a Requester, while an Approver's browser session is an app login. Say which one.
