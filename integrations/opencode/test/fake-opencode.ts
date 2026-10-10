import { spawnSync } from "node:child_process"
import { setupOpenBao, type OpenBaoContext, type PluginDeps } from "../src/plugin.ts"

interface FakeSession {
  id: string
  parentID?: string
  title: string
  location: { directory: string }
}

type Callback = (event: any) => Promise<void> | void

/**
 * Stands in for the parts of opencode V2 the plugin touches, and replays the
 * shell tool's call order from opencode core 2.0.21:
 * tool execute.before → Shell.create builds env → shell create.before hooks →
 * shell tool sets OPENCODE_SESSION_ID → spawn with {...process.env, ...env}.
 */
export class FakeOpencode {
  readonly sessions = new Map<string, FakeSession>()
  readonly lookups: string[] = []
  readonly logs: Array<{ level: string; message: string; extra?: Record<string, unknown> }> = []
  readonly skills: unknown[] = []
  readonly hooks = new Map<string, Callback[]>()
  /** opencode's own process environment, the base of every shell env. */
  baseEnv: Record<string, string> = {}
  now = 1_700_000_000_000
  cleanup?: () => void
  private readonly subscribers = new Set<(event: unknown) => void>()

  addSession(id: string, parentID?: string): FakeSession {
    const s = { id, parentID, title: `title ${id}`, location: { directory: `/work/${id}` } }
    this.sessions.set(id, s)
    return s
  }

  async start(options: Record<string, unknown>, deps: PluginDeps = {}): Promise<void> {
    const register = (domain: string) => async (name: string, callback: Callback) => {
      const key = `${domain}.${name}`
      this.hooks.set(key, [...(this.hooks.get(key) ?? []), callback])
      return { dispose: async () => {} }
    }
    const ctx = {
      options,
      session: {
        get: async ({ sessionID }: { sessionID: string }) => {
          this.lookups.push(sessionID)
          const s = this.sessions.get(sessionID)
          if (!s) throw new Error(`Session not found: ${sessionID}`)
          return s
        },
      },
      tool: { hook: register("tool") },
      shell: { hook: register("shell") },
      skill: {
        transform: async (callback: (editor: { add(skill: unknown): void }) => void) => {
          callback({ add: (skill) => this.skills.push(skill) })
          return { dispose: async () => {} }
        },
      },
      event: { subscribe: ({ signal }: { signal?: AbortSignal } = {}) => this.stream(signal) },
    } as unknown as OpenBaoContext
    this.cleanup =
      (await setupOpenBao(ctx, {
        now: () => this.now,
        log: (level, message, extra) => this.logs.push({ level, message, extra }),
        ...deps,
      })) ?? undefined
  }

  /** Runs the shell tool for a session and returns the child's environment. */
  async shellTool(sessionID: string): Promise<Record<string, string>> {
    await this.trigger("tool.execute.before", { tool: "shell", sessionID, agent: "build", messageID: "m", id: "c", input: {} })
    const env = await this.createShell()
    env.AGENT = "1"
    env.OPENCODE_SESSION_ID = sessionID
    return spawnEnv(env, this.processEnv())
  }

  /** A shell created outside the shell tool (e.g. a user `!` command): no session ID is set. */
  async userShell(): Promise<Record<string, string>> {
    return spawnEnv(await this.createShell(), this.processEnv())
  }

  /** Runs only the create.before step, returning the env object before spawn. */
  async createShell(): Promise<Record<string, string | undefined>> {
    const invocation = {
      command: "env",
      cwd: "/work",
      timeout: 0,
      shell: "/bin/sh",
      env: { ...this.baseEnv, TERM: "xterm-256color", OPENCODE_TERMINAL: "1" } as Record<string, string | undefined>,
    }
    await this.trigger("shell.create.before", invocation)
    return invocation.env
  }

  /** The spawner extends env with opencode's process.env, which baseEnv models. */
  processEnv(): Record<string, string | undefined> {
    return { PATH: process.env.PATH, ...this.baseEnv }
  }

  async trigger(key: string, event: unknown): Promise<void> {
    for (const callback of this.hooks.get(key) ?? []) await callback(event)
  }

  emit(event: unknown): void {
    for (const push of this.subscribers) push(event)
  }

  async settle(): Promise<void> {
    for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0))
  }

  private async *stream(signal?: AbortSignal): AsyncGenerator<any> {
    const queue: unknown[] = []
    let wake: (() => void) | undefined
    const push = (event: unknown) => {
      queue.push(event)
      wake?.()
    }
    this.subscribers.add(push)
    const onAbort = () => wake?.()
    signal?.addEventListener("abort", onAbort)
    try {
      while (!signal?.aborted) {
        if (queue.length === 0) await new Promise<void>((resolve) => (wake = resolve))
        wake = undefined
        while (queue.length > 0 && !signal?.aborted) yield queue.shift()
      }
    } finally {
      this.subscribers.delete(push)
      signal?.removeEventListener("abort", onAbort)
    }
  }

  get subscriberCount(): number {
    return this.subscribers.size
  }
}

/** Spawns `env` the way opencode's spawner does, so getters are read at spawn time. */
export function spawnEnv(
  env: Record<string, string | undefined>,
  parent: Record<string, string | undefined> = { PATH: process.env.PATH },
): Record<string, string> {
  const res = spawnSync("env", [], { env: { ...parent, ...env }, encoding: "utf8" })
  if (res.status !== 0) throw new Error(`env failed: ${res.stderr}`)
  const out: Record<string, string> = {}
  for (const line of res.stdout.split("\n")) {
    const i = line.indexOf("=")
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1)
  }
  return out
}
