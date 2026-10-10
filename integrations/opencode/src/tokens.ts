import { isExpired, needsRenewal, type SessionToken, type SessionTokenMinter } from "./mint.ts"
import type { SessionInfo } from "./sessions.ts"

export type Logger = (level: "debug" | "info" | "warn" | "error", message: string, extra?: Record<string, unknown>) => void

/**
 * Holds one Session Token per root session, in memory only. Tokens are minted
 * lazily on first use, renewed once past half their lease, and re-minted when
 * renewal fails or the token has expired.
 */
export class SessionTokens {
  private readonly tokens = new Map<string, SessionToken>()
  private readonly pending = new Map<string, Promise<SessionToken>>()

  constructor(
    private readonly minter: SessionTokenMinter,
    private readonly log: Logger,
    private readonly now: () => number = Date.now,
  ) {}

  /** Returns a usable token for the root session, minting or renewing it as needed. */
  get(root: SessionInfo): Promise<SessionToken> {
    const current = this.tokens.get(root.id)
    if (current && !needsRenewal(current, this.now())) return Promise.resolve(current)

    // Concurrent shell commands of one session must share a single mint or renewal.
    let pending = this.pending.get(root.id)
    if (!pending) {
      pending = this.refresh(root, current).finally(() => this.pending.delete(root.id))
      this.pending.set(root.id, pending)
    }
    return pending
  }

  /** The cached token of a root session, if it hasn't expired. Never mints or renews. */
  peek(rootID: string): SessionToken | undefined {
    const current = this.tokens.get(rootID)
    return current && !isExpired(current, this.now()) ? current : undefined
  }

  has(rootID: string): boolean {
    return this.tokens.has(rootID) || this.pending.has(rootID)
  }

  /** Revokes and forgets the root session's token, if one was minted. */
  async revoke(rootID: string): Promise<void> {
    await this.pending.get(rootID)?.catch(() => undefined)
    const current = this.tokens.get(rootID)
    if (!current) return
    this.tokens.delete(rootID)
    await this.minter.revoke(current)
  }

  private async refresh(root: SessionInfo, current: SessionToken | undefined): Promise<SessionToken> {
    if (current && current.renewable && !isExpired(current, this.now())) {
      try {
        const renewed = await this.minter.renew(current)
        this.tokens.set(root.id, renewed)
        return renewed
      } catch (err) {
        this.log("warn", "Session Token renewal failed; minting a new one", {
          sessionID: root.id,
          error: errorMessage(err),
        })
      }
    }
    const minted = await this.minter.mint({ session_id: root.id, title: root.title, directory: root.directory })
    this.tokens.set(root.id, minted)
    return minted
  }
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
