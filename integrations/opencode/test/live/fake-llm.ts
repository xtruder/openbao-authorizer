/**
 * A scripted OpenAI-compatible chat completions endpoint. When the request
 * offers the shell tool and the conversation doesn't end in a tool result, it
 * calls `shell` with PROBE_COMMAND; otherwise it answers with plain text.
 * Tool results it receives are kept in `toolResults`.
 */
export const PROBE_COMMAND = [
  "printf 'probe sid=%s bao=%s vault=%s addr=%s authz=%s\\n'",
  '"$OPENCODE_SESSION_ID"',
  '"${BAO_TOKEN-<unset>}"',
  '"${VAULT_TOKEN-<unset>}"',
  '"${BAO_ADDR-<unset>}"',
  '"${BAO_AUTHORIZER_ADDR-<unset>}"',
].join(" ")

export interface Probe {
  sid: string
  bao: string
  vault: string
  addr: string
  authz: string
}

export function parseProbes(text: string): Probe[] {
  return [...text.matchAll(/probe sid=(\S*) bao=(\S*) vault=(\S*) addr=(\S*) authz=(\S*)/g)].map((m) => ({
    sid: m[1]!,
    bao: m[2]!,
    vault: m[3]!,
    addr: m[4]!,
    authz: m[5]!,
  }))
}

export class FakeLLM {
  readonly toolResults: string[] = []
  readonly requests: number[] = []
  private readonly server: ReturnType<typeof Bun.serve>
  private seq = 0

  constructor() {
    this.server = Bun.serve({ port: 0, fetch: (req) => this.handle(req) })
  }

  get baseURL(): string {
    return `http://127.0.0.1:${this.server.port}/v1`
  }

  stop(): void {
    this.server.stop(true)
  }

  private async handle(req: Request): Promise<Response> {
    const url = new URL(req.url)
    if (url.pathname.endsWith("/models")) return Response.json({ object: "list", data: [{ id: "scripted", object: "model" }] })
    if (!url.pathname.endsWith("/chat/completions")) return new Response("not found", { status: 404 })
    const body = (await req.json()) as {
      messages: Array<{ role: string; content: unknown }>
      tools?: Array<{ function?: { name?: string } }>
      stream?: boolean
    }
    this.requests.push(Date.now())
    const last = body.messages.at(-1)
    if (last?.role === "tool") this.toolResults.push(typeof last.content === "string" ? last.content : JSON.stringify(last.content))
    const offersShell = body.tools?.some((t) => t.function?.name === "shell") ?? false
    const id = `chatcmpl-${++this.seq}`
    const chunks: unknown[] =
      offersShell && last?.role !== "tool"
        ? [
            delta(id, {
              role: "assistant",
              tool_calls: [
                {
                  index: 0,
                  id: `call_${this.seq}`,
                  type: "function",
                  function: { name: "shell", arguments: JSON.stringify({ command: PROBE_COMMAND }) },
                },
              ],
            }),
            finish(id, "tool_calls"),
          ]
        : [delta(id, { role: "assistant", content: "probe finished" }), finish(id, "stop")]
    if (body.stream === false) {
      return Response.json({
        id,
        object: "chat.completion",
        created: 0,
        model: "scripted",
        choices: [{ index: 0, message: { role: "assistant", content: "probe finished" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      })
    }
    const sse = chunks.map((c) => `data: ${JSON.stringify(c)}\n\n`).join("") + "data: [DONE]\n\n"
    return new Response(sse, { headers: { "content-type": "text/event-stream" } })
  }
}

function delta(id: string, d: Record<string, unknown>) {
  return { id, object: "chat.completion.chunk", created: 0, model: "scripted", choices: [{ index: 0, delta: d, finish_reason: null }] }
}

function finish(id: string, reason: string) {
  return {
    id,
    object: "chat.completion.chunk",
    created: 0,
    model: "scripted",
    choices: [{ index: 0, delta: {}, finish_reason: reason }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  }
}
