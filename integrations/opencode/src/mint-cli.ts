#!/usr/bin/env bun
// Mints a Session Token exactly as the plugin does and prints it as JSON.
// Used by the e2e harness and for manual testing.
import { parseArgs } from "node:util"
import { mintSessionToken } from "./mint.ts"
import { OptionsError, resolveOptions } from "./options.ts"
import { RootSessionResolver, type SessionInfo } from "./sessions.ts"
import { errorMessage } from "./tokens.ts"

const USAGE = `usage: bun src/mint-cli.ts --session-id ID [--parent ID ...] [flags]

Mints the Session Token of an Agent Session's root session and prints JSON to stdout.

Session flags:
  --session-id ID        session to mint for (required)
  --parent ID            ancestor session, repeatable, ordered from the immediate
                         parent up to the root; the token is minted for the last one
  --title TEXT           root session title, stored in token meta
  --directory DIR        root session directory, stored in token meta (default: cwd)

OpenBao flags (fall back to the environment variable shown):
  --address URL          BAO_ADDR, then VAULT_ADDR
  --role-id-file PATH    OPENCODE_OPENBAO_ROLE_ID_FILE
  --secret-id-file PATH  OPENCODE_OPENBAO_SECRET_ID_FILE
  --approle-mount NAME   OPENCODE_OPENBAO_APPROLE_MOUNT (default approle)
  --token-role NAME      OPENCODE_OPENBAO_TOKEN_ROLE (default opencode-session)
  --alias-prefix TEXT    OPENCODE_OPENBAO_ALIAS_PREFIX (default opencode-session-)
  --namespace NS         BAO_NAMESPACE, then VAULT_NAMESPACE
  --ca-cert PATH         BAO_CACERT, then VAULT_CACERT

Exit status: 0 minted, 1 OpenBao or file error, 2 usage error.
`

async function main(argv: string[]): Promise<number> {
  let values
  try {
    ;({ values } = parseArgs({
      args: argv,
      strict: true,
      options: {
        "session-id": { type: "string" },
        parent: { type: "string", multiple: true },
        title: { type: "string" },
        directory: { type: "string" },
        address: { type: "string" },
        "role-id-file": { type: "string" },
        "secret-id-file": { type: "string" },
        "approle-mount": { type: "string" },
        "token-role": { type: "string" },
        "alias-prefix": { type: "string" },
        namespace: { type: "string" },
        "ca-cert": { type: "string" },
        help: { type: "boolean", short: "h" },
      },
    }))
  } catch (err) {
    process.stderr.write(`${errorMessage(err)}\n\n${USAGE}`)
    return 2
  }
  if (values.help) {
    process.stdout.write(USAGE)
    return 0
  }
  const sessionID = values["session-id"]
  if (!sessionID) {
    process.stderr.write(`--session-id is required\n\n${USAGE}`)
    return 2
  }

  const env = process.env
  let options
  try {
    options = resolveOptions(
      {
        address: values.address ?? env.BAO_ADDR ?? env.VAULT_ADDR,
        roleIdFile: values["role-id-file"] ?? env.OPENCODE_OPENBAO_ROLE_ID_FILE,
        secretIdFile: values["secret-id-file"] ?? env.OPENCODE_OPENBAO_SECRET_ID_FILE,
        approleMount: values["approle-mount"] ?? env.OPENCODE_OPENBAO_APPROLE_MOUNT,
        tokenRole: values["token-role"] ?? env.OPENCODE_OPENBAO_TOKEN_ROLE,
        aliasPrefix: values["alias-prefix"] ?? env.OPENCODE_OPENBAO_ALIAS_PREFIX,
        namespace: values.namespace ?? env.BAO_NAMESPACE ?? env.VAULT_NAMESPACE,
        caCert: values["ca-cert"] ?? env.BAO_CACERT ?? env.VAULT_CACERT,
      },
      { requireAuthorizerUrl: false },
    )
  } catch (err) {
    if (!(err instanceof OptionsError)) throw err
    process.stderr.write(`${err.message}\n\n${USAGE}`)
    return 2
  }

  // Build the session tree from the flags and resolve it with the plugin's resolver.
  const chain = [sessionID, ...(values.parent ?? [])]
  const sessions = new Map<string, SessionInfo>()
  chain.forEach((id, i) => sessions.set(id, { id, parentID: chain[i + 1] }))
  const rootID = chain[chain.length - 1]!
  sessions.set(rootID, { id: rootID, title: values.title, directory: values.directory ?? process.cwd() })

  try {
    const root = await new RootSessionResolver(async (id) => sessions.get(id)).root(sessionID)
    const token = await mintSessionToken(options, { session_id: root.id, title: root.title, directory: root.directory })
    const out = {
      session_id: sessionID,
      root_session_id: root.id,
      entity_alias: token.entityAlias,
      token: token.token,
      accessor: token.accessor,
      entity_id: token.entityID ?? null,
      policies: token.policies,
      ttl: token.ttl,
      renewable: token.renewable,
      expires_at: token.expiresAt === undefined ? null : new Date(token.expiresAt).toISOString(),
    }
    process.stdout.write(`${JSON.stringify(out)}\n`)
    return 0
  } catch (err) {
    process.stderr.write(`mint failed: ${errorMessage(err)}\n`)
    return 1
  }
}

process.exitCode = await main(process.argv.slice(2))
