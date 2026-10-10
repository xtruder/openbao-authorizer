import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { writeFileSync } from "node:fs"
import path from "node:path"
import { SKILL_FILE, defineSessionEnv, loadSkill } from "../src/plugin.ts"
import { resolveOptions } from "../src/options.ts"
import { FakeOpenBao, SECRET_ID, fakeOptions } from "./fake-openbao.ts"
import { FakeOpencode, spawnEnv } from "./fake-opencode.ts"

let bao: FakeOpenBao
let oc: FakeOpencode

beforeEach(() => {
  bao = new FakeOpenBao()
  oc = new FakeOpencode()
})

afterEach(() => {
  oc.cleanup?.()
  bao.stop()
})

const tokenOf = (env: Record<string, string>) => env.BAO_TOKEN

describe("shell tool environment", () => {
  test("a shell tool command gets the root session's token and OpenBao variables", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("ses_root")
    const env = await oc.shellTool("ses_root")

    const [token, state] = bao.sessionTokens()[0]!
    expect(env.BAO_TOKEN).toBe(token)
    expect(env.VAULT_TOKEN).toBe(token)
    expect(env.BAO_ADDR).toBe(bao.address)
    expect(env.VAULT_ADDR).toBe(bao.address)
    expect(env.BAO_AUTHORIZER_ADDR).toBe("https://authorizer.example.com")
    expect(env.BAO_NO_TOKEN_FILE).toBe("1")
    expect(env.BAO_NAMESPACE).toBeUndefined()
    expect(state.alias).toBe("opencode-session-ses_root")
    expect(state.meta).toEqual({ session_id: "ses_root", title: "title ses_root", directory: "/work/ses_root" })
  })

  test("honours custom mounts, prefix, namespace and CA", async () => {
    const opts = fakeOptions(bao)
    const caCert = path.join(path.dirname(opts.roleIdFile as string), "ca.pem")
    writeFileSync(caCert, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
    await oc.start({ ...opts, approleMount: "approle-agents", tokenRole: "agents", aliasPrefix: "agent-", namespace: "team-a", caCert })
    oc.addSession("s1")
    const env = await oc.shellTool("s1")

    expect(env.BAO_NAMESPACE).toBe("team-a")
    expect(env.VAULT_NAMESPACE).toBe("team-a")
    expect(env.BAO_CACERT).toBe(caCert)
    expect(env.VAULT_CACERT).toBe(caCert)
    expect(bao.calls.map((c) => c.path)).toEqual(["auth/approle-agents/login", "auth/token/create/agents"])
    expect(bao.calls.every((c) => c.namespace === "team-a")).toBe(true)
    expect(bao.sessionTokens()[0]![1].alias).toBe("agent-s1")
  })

  test("two sessions get different tokens, even when their shells are created before either spawns", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("a")
    oc.addSession("b")
    await oc.trigger("tool.execute.before", { tool: "shell", sessionID: "a" })
    await oc.trigger("tool.execute.before", { tool: "shell", sessionID: "b" })
    const envA = await oc.createShell()
    const envB = await oc.createShell()
    envA.OPENCODE_SESSION_ID = "a"
    envB.OPENCODE_SESSION_ID = "b"

    const tokens = new Map(bao.sessionTokens().map(([token, s]) => [s.alias, token]))
    expect(spawnEnv(envB).BAO_TOKEN).toBe(tokens.get("opencode-session-b")!)
    expect(spawnEnv(envA).BAO_TOKEN).toBe(tokens.get("opencode-session-a")!)
    expect(tokens.get("opencode-session-a")).not.toBe(tokens.get("opencode-session-b")!)
  })

  test("other tools don't mint", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    await oc.trigger("tool.execute.before", { tool: "read", sessionID: "root" })
    expect(bao.calls).toHaveLength(0)
  })
})

describe("fail closed", () => {
  test("a shell without OPENCODE_SESSION_ID gets no token, not even opencode's own", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    await oc.shellTool("root")
    oc.baseEnv = { BAO_TOKEN: "human-token", VAULT_TOKEN: "human-token" }

    const env = await oc.userShell()
    expect("BAO_TOKEN" in env).toBe(false)
    expect("VAULT_TOKEN" in env).toBe(false)
    expect(env.BAO_ADDR).toBe(bao.address)
    expect(env.BAO_NO_TOKEN_FILE).toBe("1")
  })

  test("a session whose mint failed gets no token and no inherited token", async () => {
    const opts = fakeOptions(bao)
    writeFileSync(opts.secretIdFile as string, "wrong-secret")
    await oc.start(opts)
    oc.addSession("root")
    oc.baseEnv = { BAO_TOKEN: "human-token" }

    const env = await oc.shellTool("root")
    expect("BAO_TOKEN" in env).toBe(false)
    expect("VAULT_TOKEN" in env).toBe(false)
    const logged = JSON.stringify(oc.logs)
    expect(logged).toContain("invalid role or secret ID")
    expect(logged).not.toContain("wrong-secret")
    expect(logged).not.toContain(SECRET_ID)
  })

  test("a session ID that never ran the shell tool gets no token, even while another session has one", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("a")
    await oc.shellTool("a")

    const env = await oc.createShell()
    env.OPENCODE_SESSION_ID = "b"
    expect(env.BAO_TOKEN).toBeUndefined()
    expect("BAO_TOKEN" in spawnEnv(env)).toBe(false)
  })

  test("an expired token is not handed out", async () => {
    bao.sessionPeriod = 100
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    await oc.shellTool("root")
    const env = await oc.createShell()
    env.OPENCODE_SESSION_ID = "root"

    oc.now += 101_000
    expect(env.BAO_TOKEN).toBeUndefined()
  })
})

describe("defineSessionEnv", () => {
  const options = resolveOptions({
    address: "http://bao:8200",
    authorizerUrl: "http://authz",
    roleIdFile: "/r",
    secretIdFile: "/s",
  })

  test("reads the session ID and token when the property is read, not when it's defined", () => {
    const tokens = new Map<string, string>()
    const env: Record<string, string | undefined> = {}
    defineSessionEnv(env, options, (id) => (id ? tokens.get(id) : undefined))
    expect(env.BAO_TOKEN).toBeUndefined()

    env.OPENCODE_SESSION_ID = "s1"
    tokens.set("s1", "tok-1")
    expect(env.BAO_TOKEN).toBe("tok-1")
    expect(env.VAULT_TOKEN).toBe("tok-1")
    expect({ ...env }.BAO_TOKEN).toBe("tok-1")
    expect(Object.keys(env)).toContain("BAO_TOKEN")
  })

  test("an assignment replaces the getter instead of throwing", () => {
    const env: Record<string, string | undefined> = {}
    defineSessionEnv(env, options, () => "tok")
    env.BAO_TOKEN = "override"
    expect(env.BAO_TOKEN).toBe("override")
    expect(env.VAULT_TOKEN).toBe("tok")
    delete env.VAULT_TOKEN
    expect("VAULT_TOKEN" in env).toBe(false)
  })
})

describe("root session resolution", () => {
  test("nested subagents share the root's token and identity", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    oc.addSession("child", "root")
    oc.addSession("grandchild", "child")

    const fromGrandchild = await oc.shellTool("grandchild")
    const fromChild = await oc.shellTool("child")
    const fromRoot = await oc.shellTool("root")

    expect(fromGrandchild.BAO_TOKEN).toBeDefined()
    expect(fromChild.BAO_TOKEN).toBe(fromGrandchild.BAO_TOKEN!)
    expect(fromRoot.BAO_TOKEN).toBe(fromGrandchild.BAO_TOKEN!)
    expect(bao.sessionTokens().map(([, t]) => t.alias)).toEqual(["opencode-session-root"])
    expect(bao.sessionTokens()[0]![1].meta?.session_id).toBe("root")
    expect(oc.lookups).toEqual(["grandchild", "child", "root"])
  })

  test("a session that can't be resolved gets no token", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("orphan", "missing-parent")
    const env = await oc.shellTool("orphan")
    expect("BAO_TOKEN" in env).toBe(false)
    expect(oc.logs.map((l) => l.message)).toContain("no Session Token for shell command")
    expect(bao.calls).toHaveLength(0)
  })
})

describe("minting", () => {
  test("mints lazily, once per root, even for concurrent commands", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    expect(bao.calls).toHaveLength(0)

    const envs = await Promise.all([oc.shellTool("root"), oc.shellTool("root"), oc.shellTool("root")])
    await oc.shellTool("root")
    expect(new Set(envs.map(tokenOf)).size).toBe(1)
    expect(bao.callsTo("auth/token/create/opencode-session")).toHaveLength(1)
  })

  test("one AppRole login serves several roots until it nears expiry", async () => {
    bao.minterTTL = 60
    await oc.start(fakeOptions(bao))
    for (const id of ["a", "b", "c"]) oc.addSession(id)
    await oc.shellTool("a")
    oc.now += 40_000
    await oc.shellTool("b")
    expect(bao.callsTo("auth/approle/login")).toHaveLength(1)
    // A 60s TTL refreshes with 12s left, i.e. after 48s.
    oc.now += 9_000
    await oc.shellTool("c")
    expect(bao.callsTo("auth/approle/login")).toHaveLength(2)
  })

  test("logs in again when the cached minter token is rejected", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("a")
    oc.addSession("b")
    await oc.shellTool("a")
    for (const state of bao.tokens.values()) if (state.kind === "minter") state.revoked = true

    expect((await oc.shellTool("b")).BAO_TOKEN).toBeDefined()
    expect(bao.callsTo("auth/approle/login")).toHaveLength(2)
  })

  test("a failure after login logs no tokens, and the next command retries", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    bao.failNext.set("auth/token/create/opencode-session", 500)
    expect("BAO_TOKEN" in (await oc.shellTool("root"))).toBe(false)
    const logged = JSON.stringify(oc.logs)
    expect(logged).toContain("HTTP 500")
    for (const token of bao.tokens.keys()) expect(logged).not.toContain(token)

    expect((await oc.shellTool("root")).BAO_TOKEN).toBeDefined()
  })

  test("a missing credential file names the file, not its content", async () => {
    await oc.start({ ...fakeOptions(bao), roleIdFile: "/nonexistent/role-id" })
    oc.addSession("root")
    await oc.shellTool("root")
    expect(JSON.stringify(oc.logs)).toContain("cannot read roleIdFile /nonexistent/role-id")
  })
})

describe("renewal", () => {
  test("renews only once past half the token period", async () => {
    bao.sessionPeriod = 3600
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    const first = await oc.shellTool("root")

    oc.now += 1_799_000
    await oc.shellTool("root")
    expect(bao.callsTo("auth/token/renew-self")).toHaveLength(0)

    oc.now += 2_000
    const renewed = await oc.shellTool("root")
    const renewals = bao.callsTo("auth/token/renew-self")
    expect(renewals).toHaveLength(1)
    expect(renewals[0]!.token).toBe(first.BAO_TOKEN!)
    expect(renewed.BAO_TOKEN).toBe(first.BAO_TOKEN!)

    oc.now += 1_000_000
    await oc.shellTool("root")
    expect(bao.callsTo("auth/token/renew-self")).toHaveLength(1)
    expect(bao.callsTo("auth/token/create/opencode-session")).toHaveLength(1)
  })

  test("mints a new token when renewal fails", async () => {
    bao.sessionPeriod = 100
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    const first = await oc.shellTool("root")
    bao.failNext.set("auth/token/renew-self", 403)

    oc.now += 60_000
    const next = await oc.shellTool("root")
    expect(next.BAO_TOKEN).toBeDefined()
    expect(next.BAO_TOKEN).not.toBe(first.BAO_TOKEN!)
    expect(oc.logs.some((l) => l.level === "warn" && l.message.includes("renewal failed"))).toBe(true)
  })

  test("mints a new token without renewing once the token has expired", async () => {
    bao.sessionPeriod = 100
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    const first = await oc.shellTool("root")

    oc.now += 101_000
    const next = await oc.shellTool("root")
    expect(next.BAO_TOKEN).not.toBe(first.BAO_TOKEN!)
    expect(bao.callsTo("auth/token/renew-self")).toHaveLength(0)
  })
})

describe("session.deleted", () => {
  const deleted = (sessionID: string) => ({ id: "evt", type: "session.deleted", created: 0, data: { sessionID } })

  test("revokes the root session's token and stops handing it out", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    oc.addSession("child", "root")
    const first = await oc.shellTool("child")
    const pending = await oc.createShell()
    pending.OPENCODE_SESSION_ID = "child"

    oc.emit(deleted("child"))
    oc.emit(deleted("root"))
    await oc.settle()

    const revokes = bao.callsTo("auth/token/revoke-self")
    expect(revokes).toHaveLength(1)
    expect(revokes[0]!.token).toBe(first.BAO_TOKEN!)
    expect(bao.tokens.get(first.BAO_TOKEN!)!.revoked).toBe(true)
    expect(pending.BAO_TOKEN).toBeUndefined()
  })

  test("deleting a subagent keeps the root's token", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    oc.addSession("child", "root")
    const env = await oc.shellTool("child")

    oc.emit(deleted("child"))
    await oc.settle()
    expect(bao.callsTo("auth/token/revoke-self")).toHaveLength(0)
    expect((await oc.shellTool("root")).BAO_TOKEN).toBe(env.BAO_TOKEN!)
  })

  test("deleting a session that never minted calls nothing", async () => {
    await oc.start(fakeOptions(bao))
    oc.emit(deleted("idle"))
    await oc.settle()
    expect(bao.calls).toHaveLength(0)
  })

  test("revoke failures are logged, not thrown", async () => {
    await oc.start(fakeOptions(bao))
    oc.addSession("root")
    await oc.shellTool("root")
    bao.failNext.set("auth/token/revoke-self", 500)
    oc.emit(deleted("root"))
    await oc.settle()
    expect(oc.logs.some((l) => l.message === "revoking Session Token failed")).toBe(true)
  })

  test("cleanup ends the event subscription", async () => {
    await oc.start(fakeOptions(bao))
    await oc.settle()
    expect(oc.subscriberCount).toBe(1)
    oc.cleanup!()
    await oc.settle()
    expect(oc.subscriberCount).toBe(0)
  })
})

describe("setup", () => {
  test("invalid options register nothing and log an error", async () => {
    await oc.start({ address: bao.address })
    expect(oc.hooks.size).toBe(0)
    expect(oc.skills).toHaveLength(0)
    expect(oc.logs[0]!.message).toBe("plugin disabled: invalid options")
    expect(String(oc.logs[0]!.extra?.error)).toContain("authorizerUrl is required")
  })

  test("registers the openbao-access skill", async () => {
    await oc.start(fakeOptions(bao))
    expect(oc.skills).toHaveLength(1)
    const skill = oc.skills[0] as Awaited<ReturnType<typeof loadSkill>>
    expect(skill.id).toBe("openbao-access")
    expect(skill.name).toBe("openbao-access")
    expect(skill.description).toMatch(/^Use when .{40,}/)
    expect(skill.path).toBe(SKILL_FILE)
    expect(path.isAbsolute(skill.path)).toBe(true)
    expect(skill.content.startsWith("\n# OpenBao access")).toBe(true)
    expect(skill.content).not.toContain("description:")
  })
})
