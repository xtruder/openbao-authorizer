# ConnectRPC is the only authorizer API

The authorizer exposes one API, defined in `proto/` and generated with `buf`. Both the PWA and `bao-cred` use it. The same Go process serves it on its existing HTTP listener using ConnectRPC. Live updates are server-streaming RPCs: each stream sends a full snapshot on connect and on every change. Clients therefore recover from dropped connections by reconnecting, with no event IDs or replay buffer. Generated Go and TypeScript code is committed, and CI checks it against the protos.

## Considered options

- **Hand-written REST and SSE.** Two clients had to stay in step with hand-matched JSON shapes, and polling and SSE needed separate code paths.
- **grpc-go with a gRPC-Web proxy.** Browsers can't speak native gRPC, so this needs Envoy or a wrapper, and HTTP/2 end to end through the reverse proxy.
- **gRPC with a grpc-gateway REST facade.** This means two surfaces to keep consistent, and streaming through the gateway is awkward.
- **Change-hint streams.** Clients would have to re-fetch after every hint and after every reconnect. Snapshots are cheap at this data size and can't miss an update.

## Consequences

- **Authentication runs in interceptors, which cover unary and streaming RPCs alike.** Grant RPCs take `Authorization: Bearer <OpenBao token>` from a Requester. Approver RPCs use the app session cookie and a same-origin check ([ADR-0003](0003-approver-sessions.md)).
- **Reverse proxies must not buffer `/api/`.** Stream responses send `X-Accel-Buffering: no` for nginx.
- **Browser Web Push stays separate.** It delivers notifications while the PWA is closed, through the browser vendor's push service. Only its enrollment moved to RPC.
