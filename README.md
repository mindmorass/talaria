# Talaria

*Talaria — the winged sandals of Hermes.* An **encrypted, asynchronous,
multi-tenant remote-fetch dispatcher**: a **dispatcher** (A) sends HTTP fetch
jobs, a message queue on **B** carries them, and a **runner** (C) performs each
request from inside its network and returns the result. Egress happens on C.

It is **not** a proxy — no tunnel, no end-to-end TLS. C performs the request and
returns the result as a message. The trade buys durability (C can be offline), a
simple runner, fan-out to many runners, and endpoint-side observability.

## Model

- **B** is stock `nats-server` (JetStream + WebSocket). Not application code.
- Transport is **wss://** only (TLS), through B's reverse proxy.
- Every job/response is **end-to-end sealed** with NaCl `box` (X25519). B stores
  only `{id, nonce, ciphertext}`.
- **Multi-tenant** by **profile** (one NATS account per profile): subjects are
  `fetch.<profile>.jobs` / `.responses.<id>`. A runner serves one profile
  and authenticates each job's sender against an allowlist; the response is
  sealed back to that sender.
- **Auth** is NATS **decentralized JWT** (operator → account → user), one account
  per tenant for hard isolation + per-account JetStream quotas. Not an external
  IdP.

## Build

```sh
go build -o talaria ./cmd/talaria
go test ./...          # unit + in-process JetStream e2e (incl. tenant isolation)
docker build -t talaria .
```

## Provision a tenant

```sh
# Mint a tenant's keys, NATS account/user creds, and config blocks:
talaria onboard --mint-nats --out ./tenants --profile lakeview
```

This writes (0600 where secret):

```
tenants/
  operator.nk  operator.jwt        # root of trust (keep operator.nk safe)
  system_account                   # system account pubkey
  accounts/<pub>.jwt               # one per tenant account (+ system)
  preload.conf                     # operator + system_account + resolver_preload
  lakeview/
    dispatcher.env  dispatcher.creds   # -> machine A
    runner.env      runner.creds       # -> machine C
```

Re-run per tenant (it appends to `preload.conf`). For a keys-only onboarding
(bring your own NATS auth), drop `--mint-nats`.

## Deploy (Docker)

**B — broker** (`deploy/broker-operator/`): put the generated `tenants/` next to
the compose file, then:

```sh
cd deploy/broker-operator && docker compose up -d
```

Point your reverse proxy's `wss://` route at the container's `8443`. The native
4222 port is never published. (For single-tenant with static passwords instead,
use `deploy/docker-compose.yml` + `deploy/nats.conf`.)

**C — runner** (`deploy/runner/`): drop that scope's `runner.env` and
`runner.creds` beside the compose file, set `TALARIA_NATS_URL` in `runner.env` to
the broker, then:

```sh
cd deploy/runner && docker compose up -d
```

If C's egress is behind Netskope (or any inspecting proxy), mount the inspection
CA into the container and point Go at it — the container has its *own* trust
store, not the host's. Uncomment the CA volume + `SSL_CERT_FILE` in the runner
compose.

**A — dispatcher**: a one-shot CLI, from the binary or the image:

```sh
docker run --rm --env-file dispatcher.env \
  -e TALARIA_NATS_CREDS=/creds/dispatcher.creds \
  -v $PWD/dispatcher.creds:/creds/dispatcher.creds:ro \
  talaria send --url https://api.ipify.org          # prints C's egress IP
```

Or import `internal/dispatch` directly in your LLM app (same `Publish`/`Collect`
/`Do`).

## Use

```sh
talaria send --url https://example.com -i           # -i includes response headers
talaria send --method POST --data '{"x":1}' \
  --header 'Content-Type: application/json' --url https://httpbin.org/post
talaria send --profile other --url https://...       # override scope per call
```

## Limits & behavior

- **Response size** is bounded by NATS `max_payload` (default 1 MiB → ~760–780 KB
  usable after base64 + seal). Larger returns an error; growth path is NATS
  Object Store (or Garage/S3) carrying a reference. Raising past ~8 MiB is
  discouraged.
- **At-least-once:** a runner crash mid-fetch can redeliver (fine for GETs; a
  hazard for POST/PUT).
- **Always returns:** on error/timeout the runner still publishes an error
  response, so `send` never hangs.

## Security notes

- **E2E encryption blinds B**, not Netskope. C decrypts and makes the real
  request in the clear; that egress is what C's Netskope inspects — by design.
  This tool does **not** evade inspection and isn't meant to.
- **No cert pinning.** Runner/dispatcher use the system trust store so B's
  reverse-proxy TLS (and inspection of the C↔B channel) is honored.
- **Tenant isolation** is enforced on three layers: NATS account per tenant
  (routing + quotas), scoped subjects, and per-scope NaCl keys + a runner sender
  allowlist (confidentiality + authenticity). An unauthorized sender's job is
  dropped without decryption; cross-scope traffic is never delivered.
- `operator.nk` is the root of trust — guard it; `*.creds` and `*.env` contain
  secrets. All are git-ignored.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
