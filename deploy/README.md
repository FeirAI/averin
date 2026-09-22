# Self-host averin

## Source-only alpha boundary

No Docker image is supplied with this first alpha. `Dockerfile.server`,
`Dockerfile.web` and `docker-compose.yml` remain as source recipes, but their
image build, runtime dependencies and deployment behaviour have not been
validated for this alpha. This page is recipe documentation, not a turnkey
or production-readiness claim. The open Docker feature/linkage and real-TSA
validation limits are not closed by choosing source-only.

For native-build instructions, see [Quickstart](../docs/dev/QUICKSTART.md).
Toolchain and dependency prerequisites still apply; source-only does not mean
an offline or dependency-free build. The recipe command below is retained for
reference, not a validated alpha quickstart. Do not use it as evidence that
an image build or deployment has passed:

From the repo root, the existing recipe command is:

```bash
export AVERIN_SIGNING_SEED=$(openssl rand -hex 32)          # local seed example; no KMS integration validated
export AVERIN_PROXY_INBOUND_TOKEN=$(openssl rand -hex 24)   # shared secret; agents send it as X-Averin-Proxy-Token / Bearer
docker compose -f deploy/docker-compose.yml up --build
```

| Service | Port | What |
|---------|------|------|
| `web` | http://localhost:8088 | Svelte app (sessions, trace waterfall, verify, export) + the offline verifier at `/verifier/` |
| `server` | http://localhost:8080 | ingestion + app API (`/v2/records`, `/v2/sessions`, `/v2/dag`, `/v2/verify`, `/v2/export`, `/v2/usage`) |
| `proxy` | http://localhost:8081 | OpenAI-compatible recording proxy — point your agent's `base_url` here |

### Authentication boundaries

Configure network exposure and access controls explicitly; this guide does not certify safe
off-host deployment or observed listener bindings. With `AVERIN_API_KEYS` configured, the server's
`/v2/` router requires a `project` query parameter and a matching project key. A recognized
`Authorization: Bearer` header takes precedence over `X-Api-Key`. An unset configuration bypasses
this gate; a nonempty configuration that parses to zero projects prevents server startup.
`GET /healthz`, `/readyz` and `/metrics` remain outside the project-token gate. This is not a
claim of RBAC, SSO or a complete authorization audit of every handler.

Proxy inbound authentication and recorder authentication are separate. A configured
`AVERIN_PROXY_INBOUND_TOKEN` gates relay requests; the proxy's `GET /healthz` remains outside
that check. Without the inbound token, the relay is open. When the upstream needs its own
`Authorization` credential, supply the proxy credential through `X-Averin-Proxy-Token`.
The proxy removes `X-Averin-*` headers from the constructed upstream request. If it instead
consumes a Bearer header as the configured inbound credential, it removes that header too;
a separate upstream `Authorization` header supplied alongside the proxy-token header is retained.

For an auth-enabled recorder, configure `AVERIN_PROXY_AVERIN_TOKEN` as a valid key for
`AVERIN_PROJECT_ID`. The current HTTP recorder sets the request's `project` query from the
record body's `project_id` and sends its recorder token as `X-Api-Key`. Recording failures,
including non-2xx responses, are returned as errors and logged by the proxy after forwarding;
they do not make a successful upstream response proof of captured evidence. These source paths
and targeted handler/transport tests do not establish a live authenticated recording deployment.

## Illustrative requests (not a validated walkthrough)

These examples assume independently built and configured services. No compose startup,
port binding, authenticated-recording or end-to-end result is established by their
inclusion here; a source checkout alone does not supply the browser's WASM binary.

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
cargo run -p averin-decision-core --bin averin-verify -- bundle bundle.json
```

## Configuration

| Env | Service | Default | Notes |
|-----|---------|---------|-------|
| `AVERIN_SIGNING_SEED` | server | **required — no default** | 64 hex chars. KMS-backed signing is not established by this alpha validation. |
| `AVERIN_SIGNING_KEY_ID` | server | `k0` | published in the bundle key list |
| `AVERIN_BROKER_ISSUING_SEED` | server | (none) | 64 hex chars. Enables the credential broker (`POST /v2/grants`); signs minted capabilities. Unset = off. |
| `AVERIN_RESOURCE_SEED` | server | (none) | 64 hex chars. Enables the resource gateway (`POST /v2/use`, Tier-B); signs use-receipt evidence. MUST differ from `AVERIN_SIGNING_SEED` and `AVERIN_BROKER_ISSUING_SEED` (R2 role separation). Requires the broker. Unset = off. |
| `AVERIN_RESOURCE_ID` | server | (none) | the resource's audience id; required when `AVERIN_RESOURCE_SEED` is set. |
| `AVERIN_COSIG_APPROVER_KEYS` | server | (none) | comma-separated ed25519 pubkeys (base64url, optional `ed25519pub:` prefix). Enables the **online M-of-N cosig flow** (`POST /v2/grants/prepare` + `/v2/grants/finalize`, ADR-0005 M6). Requires the broker. The verifier re-pins these as `cosig_approver_keys` (role-disjoint). |
| `AVERIN_COSIG_THRESHOLD` | server | = #approvers | M, the cosig threshold (1 ≤ M ≤ #approvers). |
| `AVERIN_BROKER_ID` | server | (none) | M4 federation identity. Grants are tagged with this `broker_id` and checkpoints carry a per-broker_id `broker_grant_heads` map — verify with `federated_broker_keys[<id>]`. Requires the broker. Unset = single-broker. |
| `AVERIN_REVOCATION_SEED` | server | (none) | 64 hex chars. Enables M5 revocation (`POST /v2/revoke`); exports carry a signed `revocation_list`. MUST be role-separated from the signing/broker/resource/attestation/cosig keys. Unset = off. |
| `AVERIN_DATABASE_URL` | server | (none) | Postgres DSN for the database-backed store and ledger. One synthetic configuration was tested at `8ac16313`; production durability/isolation are not established. Unset = in-memory (dev, NOT durable). |
| `AVERIN_API_KEYS` | server | (none) | `proj-a:tok1,tok2;proj-b:tok3` — per-project API-key auth. **Unset = unauthenticated** (dev/single-tenant only). |
| `AVERIN_TSA_URL` | server | (none) | RFC 3161 TSA URL — anchors every checkpoint (threat #3 backdating). The verifier pins the TSA out-of-band (`tsa_keys`/`tsa_spki_b64`). |
| `AVERIN_CONTENT_DIR` / `AVERIN_WITNESS_DIR` | server | (none) | durable content-store / append-only checkpoint-witness directories. |
| `STRIPE_API_KEY` | server | (none) | enables usage-based metering reporting; no key = local counting only |
| `AVERIN_UPSTREAM` | proxy | `https://api.openai.com` | upstream LLM |
| `AVERIN_PROJECT_ID` | proxy | `default` | project the proxy records under |
| `AVERIN_PROXY_INBOUND_TOKEN` | proxy | **required** (compose sets `:?`) | shared secret inbound callers must present (`X-Averin-Proxy-Token` / `Bearer`). **Unset = OPEN RELAY + evidence-injection surface — bind to loopback or behind your own auth.** |
| `AVERIN_PROXY_AVERIN_TOKEN` | proxy | (none) | the averin API token the proxy sends (`X-Api-Key`) so records aren't silently 401'd when the averin server has `AVERIN_API_KEYS` auth on. A recording failure is logged (the LLM call is then NOT in the trail). |

### Online grant flows (ADR-0005 M6 Cosig / M2 Delegation / M3 Native)

A cosigned/delegated grant is inherently two-phase (the approver/delegator signs a challenge that binds
the broker-minted credential): `POST /v2/grants/prepare` mints + reveals `{grant_id, credential_binding,
exp, cnf_kid, cosig_threshold}`; the approvers/delegators sign it; `POST /v2/grants/finalize` submits the
same PoP-signed grant request plus the `cosignatures` (M6) / `delegation_hops` (M2) and commits.

A **native (M3)** grant is single-phase: `POST /v2/grants` with `mode:"token_exchange"` + `lease_id`
issues a grant for an externally-minted IdP/STS credential (no PoP, no minted capability); the resource
then records its effective-scope attestation with `POST /v2/introspection` (`{grant_id, credential_ref,
effective_scope, effective_exp}`), enabled automatically when `AVERIN_RESOURCE_SEED` is set. The verifier
checks `credential_ref == lease_id`, `effective_scope ⊆ grant.scope`, and `effective_exp ≤ grant.exp`.

### Verifying a bundle (authentic, with the mode gates)

To enforce the Tier-B / ADR-0005 mode guarantees you must PIN the role-disjoint authority key sets — see
**[`docs/operator-verification.md`](../docs/operator-verification.md)** for the full `opts.json` and:

```bash
averin-verify bundle bundle.json opts.json   # pinned, authentic + cosig/revocation/federation/native gates
```

The optional M4/M5 tiers are pinned the same way: `revocation_keys` gates **both** the disclosed
`revocation_list` and the Merkle-non-disclosure `revocation_merkle_root` (+ the bundle's `revocation_proofs`);
`federated_broker_keys` (a `{broker_id: [keys]}` map) gates per-broker federation and the `cross_broker_cert`
transitive tier. The verifier prints `revocation_merkle_status` / `transitive_grants` / federation broker counts
when those modes are active. `docs/operator-verification.md` has a "Producing the optional artifacts" section for
building a Merkle revocation root or a cross-broker cert.

> **Coverage and deployment limits:** project-token checks are optional and configuration-dependent,
> as described above; they are not a general production-security or authorization guarantee.
> The in-memory configuration is not durable. Choosing a database-backed configuration does not
> by itself establish production durability or isolation. Consult
> [coverage limits](../docs/coverage-limits.md) for evidence boundaries. Offline checks cover the
> supplied evidence under the verifier's trust assumptions, not event truth or complete action
> capture; authenticating signers requires independently trusted keys. This guide does not
> certify the retained commands, asset loading, network exposure or a live deployment.

## Experimental rails (off the critical path)

- **MCP server** (`averin-mcp`): exposes `record_decision`, `get_session_trace`, `verify_record`,
  `request_export` over stdio. `AVERIN_SERVER_URL=http://localhost:8080 averin-mcp`.
- **x402** (`internal/x402`): an experimental 402 micropayment guard with spend-limit / replay /
  idempotency guards. Stripe is the real revenue path.
