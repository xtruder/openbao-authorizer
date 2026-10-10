/** The parts of an opencode session the plugin needs. */
export interface SessionInfo {
  id: string
  parentID?: string
  title?: string
  directory?: string
}

/** Fetches one session; resolves to undefined when it doesn't exist. */
export type SessionLookup = (id: string) => Promise<SessionInfo | undefined>

const MAX_DEPTH = 64

/**
 * Resolves a session to the root of its parentID chain. Subagent sessions
 * share the root's Session Token and Session Identity.
 */
export class RootSessionResolver {
  private readonly sessions = new Map<string, SessionInfo>()
  // parentID never changes, so a resolved root stays valid for the session's life.
  private readonly roots = new Map<string, string>()

  constructor(private readonly lookup: SessionLookup) {}

  /** Records session info seen in events, saving a lookup and keeping titles current. */
  remember(info: SessionInfo): void {
    this.sessions.set(info.id, info)
  }

  /** Drops a deleted session, and every child mapped to it if it was a root. */
  forget(id: string): void {
    this.sessions.delete(id)
    this.roots.delete(id)
    for (const [child, root] of this.roots) if (root === id) this.roots.delete(child)
  }

  /** The root session ID of an already resolved session, without any lookup. */
  cachedRoot(id: string): string | undefined {
    return this.roots.get(id)
  }

  async root(id: string): Promise<SessionInfo> {
    const known = this.roots.get(id)
    const knownInfo = known && this.sessions.get(known)
    if (knownInfo) return knownInfo

    const chain: string[] = []
    let current = id
    for (;;) {
      if (chain.includes(current)) throw new Error(`session ${id} has a parentID cycle`)
      if (chain.length >= MAX_DEPTH) throw new Error(`session ${id} is nested deeper than ${MAX_DEPTH}`)
      chain.push(current)
      const info = await this.get(current)
      if (!info.parentID) {
        for (const member of chain) this.roots.set(member, info.id)
        return info
      }
      current = info.parentID
    }
  }

  private async get(id: string): Promise<SessionInfo> {
    const cached = this.sessions.get(id)
    if (cached) return cached
    const info = await this.lookup(id)
    if (!info) throw new Error(`session ${id} not found`)
    this.sessions.set(id, info)
    return info
  }
}
