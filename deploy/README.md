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
| `FEIR_COSIG_APPROVER_KEYS` | server | (none) | comma-separated ed25519 pubkeys (base64url, optional `ed25519pub:` prefix). Enables the **online M-of-N cosig flow** (`POST /v2/grants/prepare` + `/v2/grants/finalize`, ADR-0005 M6). Requires the broker. The verifier re-pins these as `cosig_approver_keys` (role-disjoint). |
| `FEIR_COSIG_THRESHOLD` | server | = #approvers | M, the cosig threshold (1 ≤ M ≤ #approvers). |
| `FEIR_DATABASE_URL` | server | (none) | Postgres DSN. Set for the **durable, serializable, append-only** store + ledger (production). Unset = in-memory (dev, NOT durable). |
| `FEIR_API_KEYS` | server | (none) | `proj-a:tok1,tok2;proj-b:tok3` — per-project API-key auth. **Unset = unauthenticated** (dev/single-tenant only). |
| `FEIR_TSA_URL` | server | (none) | RFC 3161 TSA URL — anchors every checkpoint (threat #3 backdating). The verifier pins the TSA out-of-band (`tsa_keys`/`tsa_spki_b64`). |
| `FEIR_CONTENT_DIR` / `FEIR_WITNESS_DIR` | server | (none) | durable content-store / append-only checkpoint-witness directories. |
| `STRIPE_API_KEY` | server | (none) | enables usage-based metering reporting; no key = local counting only |
| `FEIR_UPSTREAM` | proxy | `https://api.openai.com` | upstream LLM |
| `FEIR_PROJECT_ID` | proxy | `default` | project the proxy records under |

### Online grant flows (ADR-0005 M6 Cosig / M2 Delegation / M3 Native)

A cosigned/delegated grant is inherently two-phase (the approver/delegator signs a challenge that binds
the broker-minted credential): `POST /v2/grants/prepare` mints + reveals `{grant_id, credential_binding,
exp, cnf_kid, cosig_threshold}`; the approvers/delegators sign it; `POST /v2/grants/finalize` submits the
`cosignatures` (M6) / `delegation_hops` (M2) and commits.

A **native (M3)** grant is single-phase: `POST /v2/grants` with `mode:"token_exchange"` + `lease_id`
issues a grant for an externally-minted IdP/STS credential (no PoP, no minted capability); the resource
then records its effective-scope attestation with `POST /v2/introspection` (`{grant_id, credential_ref,
effective_scope, effective_exp}`), enabled automatically when `FEIR_RESOURCE_SEED` is set. The verifier
checks `credential_ref == lease_id`, `effective_scope ⊆ grant.scope`, and `effective_exp ≤ grant.exp`.

### Verifying a bundle (authentic, with the mode gates)

To enforce the Tier-B / ADR-0005 mode guarantees you must PIN the role-disjoint authority key sets — see
**[`docs/operator-verification.md`](../docs/operator-verification.md)** for the full `opts.json` and:

```bash
feir-verify bundle bundle.json opts.json   # pinned, authentic + cosig/revocation/federation/native gates
```

> **Phase-1 limits (see `docs/coverage-limits.md`):** no per-project auth yet (deploy behind your
> own auth or single-tenant); the in-memory store is single-node (Postgres + content store are the
> production swap); raw content blobs are not bundled (commitments only). The cryptographic
> guarantees never depend on the server — verify offline.

## Experimental rails (off the critical path)

- **MCP server** (`feir-mcp`): exposes `record_decision`, `get_session_trace`, `verify_record`,
  `request_export` over stdio. `FEIR_SERVER_URL=http://localhost:8080 feir-mcp`.
- **x402** (`internal/x402`): an experimental 402 micropayment guard with spend-limit / replay /
  idempotency guards. Stripe is the real revenue path.
