# Talaria

*Talaria — the winged sandals of Hermes.* An **encrypted, asynchronous
remote-fetch dispatcher**: machine **A** dispatches HTTP fetch jobs, a message
queue on **B** carries them, and a runner on **C** performs each request from
inside its network and returns the result. Egress happens on C.

It is **not** a proxy — there is no tunnel and no end-to-end TLS. C performs the
request itself and returns the result as a message. The trade buys durability
(C can be offline), a trivially simple runner, fan-out to many runners, and
endpoint-side observability.

## Why this shape

C has no OS-level admin and cannot accept inbound connections, so it must dial
out — which a message queue satisfies (C is just a subscriber). A Tailscale exit
node would need a kernel TUN device (admin); frp centers on TCP/SOCKS tunneling.
Neither fits a no-admin, async, HTTP-job model.

## Architecture

```
  A (dispatcher)            B (NATS JetStream)          C (runner)
  talaria send  ──publish──▶  stream JOBS      ──pull──▶ open, HTTP fetch (egress),
   seal to C                  (work queue)               seal, publish
  talaria ◀──collect by id──  stream RESPONSES ◀────────  response
```

- **B** is stock `nats-server` (JetStream + WebSocket). Not application code; see
  `deploy/`.
- Transport is **wss://** only (TLS), through B's existing reverse proxy.
- Every job/response envelope is **end-to-end encrypted** with NaCl `box`
  (X25519). B stores only `{id, nonce, ciphertext}` — it cannot read or forge
  messages. Only the opaque job id is cleartext (it is the NATS subject).

## Build

```sh
go build -o talaria ./cmd/talaria
go test ./...          # unit + in-process JetStream e2e (no external nats-server)
```

## Setup

1. **Keys** — on A and on C:
   ```sh
   ./talaria keygen
   ```
   Keep `TALARIA_SELF_PRIV` on that machine; give the printed public key to the
   peer as its `TALARIA_PEER_PUB`. (A holds C's public key; C holds A's.)

2. **Config** — copy `.env.example` to a local env file on each of A and C and
   fill in `TALARIA_NATS_URL`, the NATS user/pass for that role, `TALARIA_SELF_PRIV`,
   and `TALARIA_PEER_PUB`.

3. **B** — deploy the queue:
   ```sh
   cd deploy && TALARIA_DISPATCHER_PASS=... TALARIA_RUNNER_PASS=... docker compose up -d
   ```
   Point the reverse proxy's `wss://` route at the container's `8443` WebSocket
   port. The native 4222 port is never exposed.

## Use

On C (keep it running — this is the egress point):
```sh
./talaria run
```

On A:
```sh
./talaria send --url https://api.ipify.org          # prints C's egress IP
./talaria send -i --url https://example.com         # -i includes response headers
./talaria send --method POST --data '{"x":1}' \
  --header 'Content-Type: application/json' --url https://httpbin.org/post
```

The dispatch library (`internal/dispatch`) exposes the same `Publish` / `Collect`
/ `Do` for an LLM tool-call on A to use directly.

## Limits & behavior

- **Response size** is bounded by NATS `max_payload` (default 1 MiB → ~760–780 KB
  usable body after base64 + seal). Larger responses return an **error**; the
  documented growth path is NATS Object Store (or Garage/S3) carrying a reference.
  Raising `max_payload` past ~8 MiB is discouraged.
- **At-least-once delivery:** a runner crash mid-fetch can redeliver the job, so a
  request may run twice. Fine for idempotent GETs; a hazard for POST/PUT.
- **Always returns:** on error/timeout the runner still publishes an error
  response, so `send` never hangs.

## Security notes

- **E2E encryption blinds B**, not Netskope. C decrypts and makes the real
  request in the clear; that egress is exactly what C's Netskope inspects — by
  design. This tool does **not** evade inspection, and is not meant to.
- **No cert pinning.** The runner/dispatcher use the system trust store so B's
  reverse-proxy TLS (and any inline inspection of the C↔B channel) is honored.
- Traffic from C looks like an automated client (Go `User-Agent`/TLS
  fingerprint, stateless single requests attributed to C's identity), not a
  browser. A can set request headers per job; the TLS fingerprint is honest by
  intent.
- The NATS auth/TLS deploy config in `deploy/` is validated at **deploy time**
  (the application tests use an open in-process server). `$JS.API.>` is broad;
  tightening it is a documented future step.
