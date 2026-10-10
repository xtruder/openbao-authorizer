import { readFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { Plugin, Skill } from "@opencode/plugin"
import { SessionTokenMinter, type MinterDeps } from "./mint.ts"
import { TOKEN_VARS, resolveOptions, sessionEnv, type OpenBaoOptions } from "./options.ts"
import { RootSessionResolver } from "./sessions.ts"
import { SessionTokens, errorMessage, type Logger } from "./tokens.ts"

export const PLUGIN_ID = "xtruder.openbao"

/** Name of opencode's built-in shell tool. */
export const SHELL_TOOL = "shell"

/** Absolute path of the bundled openbao-access skill. */
export const SKILL_FILE = fileURLToPath(new URL("../skills/openbao-access/SKILL.md", import.meta.url))

/**
 * The parts of the plugin context this plugin uses. Tests pass a fake; opencode
 * passes the full context.
 */
export type OpenBaoContext = Pick<Plugin.Context, "options" | "session" | "tool" | "shell" | "event" | "skill">

/** Test seams; opencode uses the defaults. */
export interface PluginDeps extends MinterDeps {
  log?: Logger
}

/**
 * Sets up Session Token injection.
 *
 * opencode's `shell` `create.before` hook carries no session ID, so the token is
 * resolved in two steps:
 * 1. `tool` `execute.before` for the shell tool knows the session. It mints or
 *    renews the root session's token and caches it.
 * 2. `shell` `create.before` defines BAO_TOKEN and VAULT_TOKEN as getters. The
 *    shell tool sets OPENCODE_SESSION_ID on the same env object after the hooks
 *    run, and the spawner reads the env when it spawns, so the getters see the
 *    session ID then. A missing session ID or token yields undefined, which the
 *    spawner drops, so the command gets no token rather than another session's
 *    or one inherited from opencode's own environment.
 */
export async function setupOpenBao(ctx: OpenBaoContext, deps: PluginDeps = {}): Promise<(() => void) | undefined> {
  const log = deps.log ?? consoleLogger
  const now = deps.now ?? Date.now

  let options: OpenBaoOptions
  try {
    options = resolveOptions(ctx.options)
  } catch (err) {
    log("error", "plugin disabled: invalid options", { error: errorMessage(err) })
    return
  }

  const minter = new SessionTokenMinter(options, { ...deps, now })
  const tokens = new SessionTokens(minter, log, now)
  const resolver = new RootSessionResolver(async (sessionID) => {
    const info = await ctx.session.get({ sessionID })
    return { id: info.id, parentID: info.parentID, title: info.title, directory: info.location.directory }
  })

  const tokenFor = (sessionID: string | undefined): string | undefined => {
    if (!sessionID) return undefined
    const root = resolver.cachedRoot(sessionID)
    return root ? tokens.peek(root)?.token : undefined
  }

  await ctx.tool.hook("execute.before", async (event) => {
    if (event.tool !== SHELL_TOOL) return
    try {
      await tokens.get(await resolver.root(event.sessionID))
    } catch (err) {
      log("error", "no Session Token for shell command", { sessionID: event.sessionID, error: errorMessage(err) })
    }
  })

  await ctx.shell.hook("create.before", (event) => {
    defineSessionEnv(event.env, options, tokenFor)
  })

  try {
    const skill = await loadSkill()
    // opencode brands and validates these fields when the skill is added.
    await ctx.skill.transform((editor) => editor.add(skill as unknown as Skill.Info))
  } catch (err) {
    log("error", "registering the openbao-access skill failed", { error: errorMessage(err) })
  }

  const controller = new AbortController()
  void watchDeletions(ctx, controller.signal, log, async (sessionID) => {
    resolver.forget(sessionID)
    // Tokens are keyed by root session, so this only matches deleted roots.
    if (tokens.has(sessionID)) await tokens.revoke(sessionID)
  })

  return () => controller.abort()
}

/**
 * Adds the OpenBao variables to a shell invocation's env. BAO_TOKEN and
 * VAULT_TOKEN are getters keyed on OPENCODE_SESSION_ID, evaluated at spawn.
 * Assigning either one replaces the getter with the assigned value, so a later
 * hook can still override it without a strict-mode TypeError.
 */
export function defineSessionEnv(
  env: Record<string, string | undefined>,
  options: OpenBaoOptions,
  tokenFor: (sessionID: string | undefined) => string | undefined,
): void {
  Object.assign(env, sessionEnv(options))
  for (const name of TOKEN_VARS) {
    Object.defineProperty(env, name, {
      enumerable: true,
      configurable: true,
      get: () => tokenFor(env.OPENCODE_SESSION_ID),
      set: (value: string | undefined) => {
        Object.defineProperty(env, name, { value, writable: true, enumerable: true, configurable: true })
      },
    })
  }
}

/** Reads the bundled skill the way opencode reads a SKILL.md: id from the directory, name and description from frontmatter. */
export async function loadSkill(file: string = SKILL_FILE) {
  const text = await readFile(file, "utf8")
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  const fields = new Map<string, string>()
  for (const line of match?.[1]?.split(/\r?\n/) ?? []) {
    const kv = line.match(/^([\w-]+):\s*(.*)$/)
    if (kv) fields.set(kv[1]!, kv[2]!.trim())
  }
  const id = path.basename(path.dirname(file))
  const description = fields.get("description")
  return {
    id,
    name: fields.get("name") ?? id,
    ...(description ? { description } : {}),
    path: file,
    content: match ? text.slice(match[0].length) : text,
  }
}

async function watchDeletions(
  ctx: OpenBaoContext,
  signal: AbortSignal,
  log: Logger,
  onDeleted: (sessionID: string) => Promise<void>,
): Promise<void> {
  while (!signal.aborted) {
    try {
      for await (const event of ctx.event.subscribe({ signal })) {
        if (event.type !== "session.deleted") continue
        const sessionID = event.data.sessionID
        void onDeleted(sessionID).catch((err) =>
          log("warn", "revoking Session Token failed", { sessionID, error: errorMessage(err) }),
        )
      }
    } catch (err) {
      if (signal.aborted) return
      log("warn", "event stream failed; resubscribing", { error: errorMessage(err) })
    }
    // The stream ended or failed; resubscribe after a pause so deletions keep revoking.
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
}

/**
 * Promise plugins get no logger from opencode; console output lands in the
 * opencode service log. Callers pass only IDs and error messages, never tokens.
 */
const consoleLogger: Logger = (level, message, extra) => {
  const line = `[opencode-openbao] ${message}${extra ? ` ${JSON.stringify(extra)}` : ""}`
  if (level === "error") console.error(line)
  else if (level === "warn") console.warn(line)
  else console.log(line)
}
