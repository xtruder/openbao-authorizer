# The opencode plugin injects Session Tokens through fail-closed env getters

The opencode V2 plugin gives each root session, and the subagents under it, its own Session Token, and injects it only into commands run by the agent's `shell` tool. V2's `shell` `create.before` hook can edit a command's environment but doesn't say which session the command belongs to. So the plugin uses two steps:

1. `tool` `execute.before` knows the session. It mints or renews that session's token and caches it.
2. `create.before` defines `BAO_TOKEN` and `VAULT_TOKEN` as getters. When opencode spawns the process, each getter looks up the token for `OPENCODE_SESSION_ID`, which the shell tool sets after the hooks run.

A getter that can't resolve the session returns `undefined`, so the command runs with no token rather than another session's. The details are in [`integrations/opencode/README.md`](../../integrations/opencode/README.md).

## Considered options

- **Pairing hook calls by command text.** No internals are relied on, but two sessions running the same command at once could swap tokens: it fails open.
- **A marker appended to the command.** Exact, but it shows up in the agent's transcript, and the plugin has to strip it before the shell runs.
- **Opencode's per-session environment API.** Plugins can't reach it, and it replaces the whole process environment.
- **Keeping V1 support alongside V2.** V1's `shell.env` hook carries the session ID, but the deployment runs V2. Supporting both would double the adapter code for no current user.

## Consequences

- **The plugin relies on undocumented ordering in opencode.** If that ordering changes, commands get no token, never a wrong one. The live test in `integrations/opencode` catches this. If opencode adds a session ID to `create.before`, the getters can be replaced with plain assignments.
- **Only agent `shell` tool commands get a token.** A user's `!command` and interactive terminals don't.
