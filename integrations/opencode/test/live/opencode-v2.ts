#!/usr/bin/env bun
// Live check against a real opencode V2 binary. It runs an isolated opencode
// service (own HOME and XDG dirs) with this plugin, a fake OpenBao and a
// scripted model that calls the shell tool, then checks:
//   1. the shell tool in each of two sessions of one service process gets the
//      Session Token minted for that session, and the two tokens differ;
//   2. a session shell outside the shell tool (a user `!` command) gets no
//      token, although opencode's own environment holds one;
//   3. the openbao-access skill is registered;
//   4. deleting a session revokes its token and only its token.
//
// Usage: bun test/live/opencode-v2.ts   (OPENCODE_BIN overrides the binary)
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { FakeOpenBao, fakeOptions } from "../fake-openbao.ts"
import { FakeLLM, PROBE_COMMAND, parseProbes, type Probe } from "./fake-llm.ts"

const PACKAGE_DIR = path.resolve(import.meta.dir, "../..")
const HUMAN_TOKEN = "human-token-from-opencode-env"
const bin = process.env.OPENCODE_BIN ?? Bun.which("opencode")

const failures: string[] = []
function check(ok: boolean, message: string): void {
  console.log(`${ok ? "ok  " : "FAIL"} ${message}`)
  if (!ok) failures.push(message)
}

if (!bin) {
  console.error("opencode not found; set OPENCODE_BIN")
  process.exit(2)
}

const root = mkdtempSync(path.join(os.tmpdir(), "opencode-openbao-live-"))
const home = path.join(root, "home")
const project = path.join(root, "project")
mkdirSync(home, { recursive: true })
mkdirSync(project, { recursive: true })

const bao = new FakeOpenBao()
const llm = new FakeLLM()
const env: Record<string, string> = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  HOME: home,
  XDG_CONFIG_HOME: path.join(home, ".config"),
  XDG_DATA_HOME: path.join(home, ".local/share"),
  XDG_STATE_HOME: path.join(home, ".local/state"),
  XDG_CACHE_HOME: path.join(home, ".cache"),
  FAKE_API_KEY: "fake",
  // A human token in opencode's own environment must never reach agent shells.
  BAO_TOKEN: HUMAN_TOKEN,
  VAULT_TOKEN: HUMAN_TOKEN,
}

async function opencode(args: string[], timeoutMs = 120_000): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn([bin!, ...args], { cwd: project, env, stdout: "pipe", stderr: "pipe", stdin: "ignore" })
  const timer = setTimeout(() => proc.kill(), timeoutMs)
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  clearTimeout(timer)
  return { code, stdout, stderr }
}

async function waitFor(predicate: () => boolean, timeoutMs = 15_000): Promise<boolean> {
  const end = Date.now() + timeoutMs
  while (Date.now() < end) {
    if (predicate()) return true
    await Bun.sleep(100)
  }
  return predicate()
}

const tokenForAlias = (alias: string) => bao.sessionTokens().find(([, s]) => s.alias === alias)?.[0]

try {
  const version = await opencode(["--version"])
  console.log(`opencode ${version.stdout.trim()} at ${bin}`)
  check(/\bv?2\.\d+\.\d+/.test(version.stdout), "opencode is V2")

  await Bun.spawn(["git", "init", "-q"], { cwd: project }).exited
  writeFileSync(
    path.join(project, "opencode.json"),
    JSON.stringify(
      {
        $schema: "https://opencode.ai/config.json",
        model: "fake/scripted",
        providers: {
          fake: {
            name: "Fake",
            env: ["FAKE_API_KEY"],
            package: "@opencode/ai/providers/openai-compatible",
            settings: { baseURL: llm.baseURL },
            models: { scripted: { name: "Scripted" } },
          },
        },
        plugins: [{ package: PACKAGE_DIR, options: fakeOptions(bao) }],
      },
      null,
      2,
    ),
  )

  const started = await opencode(["service", "start"])
  check(started.code === 0, `isolated service started (${started.stdout.trim() || started.stderr.trim()})`)

  // 1. Two sessions, one service process, the real shell tool.
  const sessions: string[] = []
  for (const title of ["live A", "live B"]) {
    const run = await opencode(["run", "--auto", "--format", "json", "--title", title, "run the probe"])
    const sid = run.stdout.match(/"sessionID":"(ses_[^"]+)"/)?.[1]
    check(run.code === 0 && !!sid, `opencode run "${title}" finished in session ${sid}`)
    if (run.code !== 0) console.error(run.stderr.slice(-2000))
    if (sid) sessions.push(sid)
  }

  const probes = llm.toolResults.flatMap(parseProbes)
  const bySession = new Map<string, Probe>(probes.map((p) => [p.sid, p]))
  for (const sid of sessions) {
    const probe = bySession.get(sid)
    const minted = tokenForAlias(`opencode-session-${sid}`)
    check(!!probe, `shell tool ran in ${sid}`)
    check(!!minted && probe?.bao === minted, `${sid}: BAO_TOKEN is the token minted for alias opencode-session-${sid}`)
    check(probe?.vault === probe?.bao, `${sid}: VAULT_TOKEN equals BAO_TOKEN`)
    check(probe?.addr === bao.address, `${sid}: BAO_ADDR is the plugin's address`)
    check(probe?.authz === "https://authorizer.example.com", `${sid}: BAO_AUTHORIZER_ADDR is set`)
  }
  const [a, b] = sessions
  const tokenA = a && bySession.get(a)?.bao
  const tokenB = b && bySession.get(b)?.bao
  check(!!tokenA && !!tokenB && tokenA !== tokenB, "the two sessions got different tokens")
  check(!probes.some((p) => p.bao === HUMAN_TOKEN), "no shell tool command saw opencode's own token")
  check(bao.callsTo("auth/approle/login").length === 1, "both sessions were minted by one plugin instance (one AppRole login)")

  // 2. A session shell outside the shell tool: no OPENCODE_SESSION_ID, so no token.
  if (a) {
    const out = path.join(root, "user-shell.txt")
    const shell = await opencode([
      "api",
      "post",
      `/api/session/${a}/shell`,
      "--data",
      JSON.stringify({ command: `${PROBE_COMMAND} > ${out}` }),
    ])
    const ok = await waitFor(() => {
      try {
        return readFileSync(out, "utf8").includes("probe ")
      } catch {
        return false
      }
    })
    check(shell.code === 0 && ok, "a user session shell command ran")
    const probe = ok ? parseProbes(readFileSync(out, "utf8"))[0] : undefined
    check(probe?.bao === "<unset>" && probe?.vault === "<unset>", `user session shell got no token (bao=${probe?.bao})`)
  }

  // 3. Skill registration.
  const skills = await opencode(["api", "get", `/api/skill?location[directory]=${project}`])
  check(
    skills.stdout.includes('"openbao-access"') && skills.stdout.includes(path.join(PACKAGE_DIR, "skills/openbao-access/SKILL.md")),
    "openbao-access skill is registered",
  )

  // 4. Deleting session A revokes A's token only.
  if (a && tokenA && tokenB) {
    const del = await opencode(["api", "delete", `/api/session/${a}`])
    check(del.code === 0, `deleted session ${a}`)
    const revoked = await waitFor(() => bao.tokens.get(tokenA)?.revoked === true)
    check(revoked, "session A's token was revoked")
    check(bao.tokens.get(tokenB)?.revoked === false, "session B's token was not revoked")
  }
} catch (err) {
  check(false, `unexpected error: ${err instanceof Error ? err.stack : String(err)}`)
} finally {
  await opencode(["service", "stop"], 30_000).catch(() => undefined)
  llm.stop()
  bao.stop()
  if (failures.length === 0) rmSync(root, { recursive: true, force: true })
  else console.log(`kept ${root} for inspection (opencode log: ${path.join(home, ".local/share/opencode/log")})`)
}

console.log(failures.length === 0 ? "\nall live checks passed" : `\n${failures.length} live check(s) failed`)
process.exit(failures.length === 0 ? 0 : 1)
