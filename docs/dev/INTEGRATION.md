# Integration

feir is designed to be used **standalone**: point any agent, proxy, or service at the ingestion API,
seal records, and verify exported bundles offline. This page covers that first; the optional
cross-plane composition (with the sibling planes) is a clearly-separated section at the end and is
**not** required to use feir.

## Standalone — the client-facing API

There are four ways to get evidence into feir, in order of integration effort:

### 1. The SDKs (`sdk/python`, `sdk/typescript`)

Thin clients over `POST /v2/records`: they build a record body, attach an idempotency key, optionally
add `Authorization: Bearer <api-key>`, submit, and return the sealed record.

**Python:**

```python
from feir import Client

c = Client("http://localhost:8080", "demo", api_key=None)   # api_key only if FEIR_API_KEYS is set
sealed = c.record("sess-1", "search", event_type="tool_call", inp="summarize the contract")
print(sealed["record_id"], sealed["content_hash"])
```

`Client(base_url, project_id, *, api_key=None, transport=None)`. `record(session_id, action, *,
idempotency_key=None, **kwargs)` builds + submits in one call; `submit(record_body, *,
idempotency_key=None)` submits a pre-built body. A random idempotency key is generated if you don't
supply one. The `**kwargs` are passed to `build_record`, whose named arguments include
`event_type` (default `tool_call`; must be a valid event type), `status`, `observed_via`, `inp`
(raw input — note the keyword is `inp`), `output`, `rationale`, `authority`, `cost_micros_usd`,
`tokens_in`/`tokens_out` (integers only — floats/bools raise `ValueError`), `parent_span_id`,
`framework`, and `extensions`. Raw `inp`/`output`/`rationale` are carried under
`extensions.content_preview` (sdk/python `client.py:86`, sdk/typescript `index.ts:93`). **Note the
limitation:** the server only converts *top-level* `input`/`output`/`rationale` to hiding commitments
(`commitLowEntropyFields`, `server.go:2063-2097` iterates exactly `["input","output","rationale"]`).
It has **no reader for `extensions.content_preview`**, so content the SDKs place there rides verbatim
into the signed body under `extensions` (the canonicalizer passes `extensions` through unchanged). The
plaintext-never-enters-the-signed-body guarantee holds **only for the top-level-field path** (the curl
in [QUICKSTART.md](QUICKSTART.md)); on the default SDK/proxy path the raw content is signed in the
clear. To get hiding commitments from a client, send the raw value at the **top level** of the record
body (or pre-commit it yourself). See SECURITY.md threat #6.

**TypeScript:**

```ts
import { Client } from "feir";

const c = new Client("http://localhost:8080", "demo", { apiKey: undefined });
const sealed = await c.record("sess-1", "llm_call", { eventType: "decision", input: "..." });
```

`new Client(baseUrl, projectId, { apiKey?, transport? })`; `record(sessionId, action, opts)` and
`submit(recordBody, idempotencyKey?)` mirror the Python client (custom `transport` is injectable for
testing or non-`fetch` runtimes).

### 2. The OpenAI-compatible recording proxy (`feir-proxy`)

Zero-code-change capture of LLM I/O: point your agent's `base_url` at the proxy; it forwards to the
upstream LLM and records `llm_call` evidence (secret-scrubbed) to a feir server. Configure with
`FEIR_UPSTREAM`, `FEIR_SERVER_URL`, `FEIR_PROJECT_ID` — see [CONFIGURATION.md](CONFIGURATION.md).
**Set `FEIR_PROXY_INBOUND_TOKEN`** (else it is an open relay + evidence-injection surface).

### 3. OTel / OpenInference (`POST /v2/otel/traces`)

If you already emit OpenTelemetry/OpenInference spans, POST them with `?project=<id>` and feir maps
each span to a record (content-addressed for idempotency). You record only what you instrument
(Level-2 honesty).

### 4. Raw HTTP

`POST /v2/records` directly (see [API.md](API.md)). This is the lowest-level path and the one the
SDKs wrap.

### Verifying offline (the point of the whole thing)

Whatever you ingest with, evidence is meant to be **verified without trusting the server**:

```bash
curl -s 'http://localhost:8080/v2/export?project=demo' > export.json
feir-verify bundle export.json              # internal consistency
feir-verify bundle export.json opts.json    # authentic, with your out-of-band pinned keys
```

The same verifier runs in the browser (`verifier/`) and via the cgo FFI (`core.VerifyBundleWith`).
For the `opts.json` role-key reference, see [`../operator-verification.md`](../operator-verification.md).

### Authority elevation (standalone)

If you run your own policy engine or human-approval service, you can get records elevated past the
forgeable `caller_declared`:

1. Have that service sign the authority evidence triple with its own key (off the feir server).
2. Pin its public key on the server: `FEIR_POLICY_ENGINE_PUBKEY` (source `policy_engine_signed`)
   and/or `FEIR_HUMAN_SIGNED_PUBKEY` (source `human_signed`).
3. Records carrying that source + a verifying `evidence_sig` are stamped the elevated source at
   ingest; an auditor pinning the same keys reads them as `verified`.

The credential broker (`POST /v2/grants`) + resource gateway (`POST /v2/use`) are also fully usable
standalone if you want Tier-A grant accountability and Tier-B use receipts for your own resources —
they don't require any sibling plane.

---

## Optional: composition with the sibling planes

> feir ships and is useful on its own. The combined four-plane OS (govder DECIDES · vultrino
> ENFORCES · feir PROVES · leria METERS) is a separate, later product. This section documents only
> the **cross-plane contracts** an integrator needs — not that product.

feir is the **PROVE** plane: it seals offline-verifiable evidence of what the other planes decided,
enforced, or metered. The composition is just the standalone client API above, called by a sibling:

### Contract feir exposes to any plane

- **Seal evidence:** `POST /v2/records` with the plane's payload under `extensions` (the only
  freeform-tolerated object), `project_id`/`session_id`/`idempotency_key` at top level, and **integer
  micros only** (no floats — the RCP canonicalizer rejects them).
- **Elevate authority:** the plane signs the authority `evidence_sig` with its own key, and the feir
  operator pins that key via `FEIR_POLICY_ENGINE_PUBKEY` / `FEIR_HUMAN_SIGNED_PUBKEY` /
  `FEIR_AUTHORITY_KEYS` so the seals elevate to `policy_engine_signed` / `human_signed` rather than
  `caller_declared`.
- **Typed evidence categories:** the optional `record_kind` field (`budget-exhausted`,
  `chargeback-posted`) is preserved through verify/export, so a board view can filter
  `GET /v2/export?record_kind=budget-exhausted` without parsing `extensions`.

### leria (METER) → feir  *(shipped contract)*

leria seals spend-governance evidence — budget exhaustion and chargeback — as ordinary records under
`extensions`, using the typed `record_kind` (`budget-exhausted` / `chargeback-posted`). feir needs no
special-casing: there is **no source allowlist** (`authority.source` is a trust-level enum, not an
identity), so leria seals like any caller and its records verify/export as first-class typed
evidence. Background: [`../HANDOFF-leria-records.md`](../HANDOFF-leria-records.md).

### govder (DECIDE) → feir  *(elevation contract)*

govder's runtime seals budget verdicts under `policy_engine_signed` and kill/approval legs under
`human_signed`, signed with per-(tenant, role) authority keys. The feir operator pins the matching
public keys (`FEIR_POLICY_ENGINE_PUBKEY` + `FEIR_HUMAN_SIGNED_PUBKEY`) so every seal **elevates to
verified** at ingest rather than normalizing down to `caller_declared`. This pattern (one key per
source, role-separated) is exactly the four-plane end-to-end harness wiring (see govder's
`e2e/bootstrap_test.go`, which is the authoritative example of how feir-server is built, configured,
and run in composition).

### vultrino (ENFORCE) ↔ feir  *(design note, not yet wired)*

[`../vultrino-integration.md`](../vultrino-integration.md) specifies how vultrino (the enforcement
plane) would seal an offline-verifiable proof of every gated action into feir — using the same
`POST /v2/records` + broker/resource contracts above. It is explicitly a **design note**: no code in
the feir tree depends on it. Treat it as the map a future wiring commit follows, not a shipped
feature.
