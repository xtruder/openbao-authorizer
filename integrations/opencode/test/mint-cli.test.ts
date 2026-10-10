import { afterEach, beforeEach, expect, test } from "bun:test"
import { writeFileSync } from "node:fs"
import path from "node:path"
import { FakeOpenBao, SECRET_ID, fakeOptions } from "./fake-openbao.ts"

const CLI = path.join(import.meta.dir, "..", "src", "mint-cli.ts")

let bao: FakeOpenBao
beforeEach(() => (bao = new FakeOpenBao()))
afterEach(() => bao.stop())

async function run(args: string[], env: Record<string, string> = {}) {
  const proc = Bun.spawn(["bun", CLI, ...args], {
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env },
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  return { stdout, stderr, code }
}

test("mints for the root of the --parent chain and prints JSON", async () => {
  const opts = fakeOptions(bao)
  const res = await run([
    "--session-id", "sub2",
    "--parent", "sub1",
    "--parent", "root",
    "--title", "e2e",
    "--directory", "/tmp/e2e",
    "--address", bao.address,
    "--role-id-file", opts.roleIdFile as string,
    "--secret-id-file", opts.secretIdFile as string,
  ])
  expect(res.stderr).toBe("")
  expect(res.code).toBe(0)
  const out = JSON.parse(res.stdout)
  expect(out).toEqual({
    session_id: "sub2",
    root_session_id: "root",
    entity_alias: "opencode-session-root",
    token: expect.stringMatching(/^s\.session-/),
    accessor: expect.any(String),
    entity_id: "entity-opencode-session-root",
    policies: ["default", "opencode-session"],
    ttl: 86400,
    renewable: true,
    expires_at: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
  })
  expect(bao.tokens.get(out.token)?.meta).toEqual({ session_id: "root", title: "e2e", directory: "/tmp/e2e" })
})

test("reads options from the environment", async () => {
  const opts = fakeOptions(bao)
  const res = await run(["--session-id", "s1"], {
    BAO_ADDR: bao.address,
    OPENCODE_OPENBAO_ROLE_ID_FILE: opts.roleIdFile as string,
    OPENCODE_OPENBAO_SECRET_ID_FILE: opts.secretIdFile as string,
    OPENCODE_OPENBAO_APPROLE_MOUNT: "approle",
    OPENCODE_OPENBAO_TOKEN_ROLE: "custom-role",
    OPENCODE_OPENBAO_ALIAS_PREFIX: "x-",
    BAO_NAMESPACE: "ns1",
  })
  expect(res.code).toBe(0)
  expect(JSON.parse(res.stdout).entity_alias).toBe("x-s1")
  expect(bao.calls.map((c) => c.path)).toEqual(["auth/approle/login", "auth/token/create/custom-role"])
  expect(bao.calls.every((c) => c.namespace === "ns1")).toBe(true)
})

test("exits 2 on usage errors", async () => {
  expect((await run([])).code).toBe(2)
  expect((await run(["--session-id", "s1"])).code).toBe(2)
  expect((await run(["--bogus"])).code).toBe(2)
})

test("exits 1 on mint failure without leaking credentials", async () => {
  const opts = fakeOptions(bao)
  writeFileSync(opts.secretIdFile as string, "not-the-secret")
  const res = await run([
    "--session-id", "s1",
    "--address", bao.address,
    "--role-id-file", opts.roleIdFile as string,
    "--secret-id-file", opts.secretIdFile as string,
  ])
  expect(res.code).toBe(1)
  expect(res.stdout).toBe("")
  expect(res.stderr).toContain("invalid role or secret ID")
  expect(res.stderr).not.toContain("not-the-secret")
  expect(res.stderr).not.toContain(SECRET_ID)
})
