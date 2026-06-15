# Self-host feir

Full stack from one command (exit criterion #6). From the repo root:

```bash
export FEIR_SIGNING_SEED=$(openssl rand -hex 32)   # 32-byte Ed25519 seed; production uses a KMS
docker compose -f deploy/docker-compose.yml up --build
```

| Service | Port | What |
|---------|------|------|
| `web` | http://localhost:8088 | Svelte app (sessions, trace waterfall, verify, export) + the offline verifier at `/verifier/` |
| `server` | http://localhost:8080 | ingestion + app API (`/v2/records`, `/v2/sessions`, `/v2/dag`, `/v2/verify`, `/v2/export`, `/v2/usage`) |
| `proxy` | http://localhost:8081 | OpenAI-compatible recording proxy — point your agent's `base_url` here |

## Try it

```bash
# 1) record a decision
curl -s localhost:8080/v2/records -H 'content-type: application/json' \
  -d '{"idempotency_key":"demo-1","project_id":"proj-001","session_id":"run-1","action":"db.query","event_type":"tool_call"}'

# 2) checkpoint, then verify offline
curl -s -X POST 'localhost:8080/v2/checkpoints?project=proj-001'
curl -s 'localhost:8080/v2/verify?project=proj-001'      # -> {"ok":true,...}

# 3) export an evidence bundle and verify it with NO server, in the browser:
curl -s 'localhost:8080/v2/export?project=proj-001&mode=proof_only' > bundle.json
#    open http://localhost:8088/verifier/ and drop bundle.json in — or use the CLI:
cargo run -p feir-decision-core --bin feir-verify -- bundle bundle.json
```

## Configuration

| Env | Service | Default | Notes |
|-----|---------|---------|-------|
| `FEIR_SIGNING_SEED` | server | dev seed (**override!**) | 64 hex chars. Production: KMS-backed signing. |
| `FEIR_SIGNING_KEY_ID` | server | `k0` | published in the bundle key list |
| `FEIR_BROKER_ISSUING_SEED` | server | (none) | 64 hex chars. Enables the credential broker (`POST /v2/grants`); signs minted capabilities. Unset = off. |
| `FEIR_RESOURCE_SEED` | server | (none) | 64 hex chars. Enables the resource gateway (`POST /v2/use`, Tier-B); signs use-receipt evidence. MUST differ from `FEIR_SIGNING_SEED` and `FEIR_BROKER_ISSUING_SEED` (R2 role separation). Requires the broker. Unset = off. |
| `FEIR_RESOURCE_ID` | server | (none) | the resource's audience id; required when `FEIR_RESOURCE_SEED` is set. |
| `STRIPE_API_KEY` | server | (none) | enables usage-based metering reporting; no key = local counting only |
| `FEIR_UPSTREAM` | proxy | `https://api.openai.com` | upstream LLM |
| `FEIR_PROJECT_ID` | proxy | `default` | project the proxy records under |

> **Phase-1 limits (see `docs/coverage-limits.md`):** no per-project auth yet (deploy behind your
> own auth or single-tenant); the in-memory store is single-node (Postgres + content store are the
> production swap); raw content blobs are not bundled (commitments only). The cryptographic
> guarantees never depend on the server — verify offline.

## Experimental rails (off the critical path)

- **MCP server** (`feir-mcp`): exposes `record_decision`, `get_session_trace`, `verify_record`,
  `request_export` over stdio. `FEIR_SERVER_URL=http://localhost:8080 feir-mcp`.
- **x402** (`internal/x402`): an experimental 402 micropayment guard with spend-limit / replay /
  idempotency guards. Stripe is the real revenue path.
