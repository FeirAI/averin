# Integration

averin is designed to be used **standalone**: point any agent, proxy, or service at the ingestion API,
seal records, and verify exported bundles offline. This page covers that first; the optional
cross-plane composition (with the sibling planes) is a clearly-separated section at the end and is
**not** required to use averin.

## Standalone — the client-facing API

There are four ways to get evidence into averin, in order of integration effort:

### 1. The SDKs (`sdk/python`, `sdk/typescript`)

Thin clients over `POST /v2/records`: they build a record body, attach an idempotency key, optionally
add `Authorization: Bearer <api-key>`, submit, and return the sealed record.

**Python:**

```python
from averin import Client

c = Client("http://localhost:8080", "demo", api_key=None)   # api_key only if AVERIN_API_KEYS is set
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
import { Client } from "averin";

const c = new Client("http://localhost:8080", "demo", { apiKey: undefined });
const sealed = await c.record("sess-1", "llm_call", { eventType: "decision", input: "..." });
```

`new Client(baseUrl, projectId, { apiKey?, transport? })`; `record(sessionId, action, opts)` and
`submit(recordBody, idempotencyKey?)` mirror the Python client (custom `transport` is injectable for
testing or non-`fetch` runtimes).

### 2. The OpenAI-compatible recording proxy (`averin-proxy`)

Zero-code-change capture of LLM I/O: point your agent's `base_url` at the proxy; it forwards to the
upstream LLM and records `llm_call` evidence (secret-scrubbed) to a averin server. Configure with
`AVERIN_UPSTREAM`, `AVERIN_SERVER_URL`, `AVERIN_PROJECT_ID` — see [CONFIGURATION.md](CONFIGURATION.md).
**Set `AVERIN_PROXY_INBOUND_TOKEN`** (else it is an open relay + evidence-injection surface).

### 3. OTel / OpenInference (`POST /v2/otel/traces`)

If you already emit OpenTelemetry/OpenInference spans, POST them with `?project=<id>` and averin maps
each span to a record (content-addressed for idempotency). You record only what you instrument
(Level-2 honesty). Prompt/completion/tool payloads (both the exact semconv keys and the indexed
`llm.input_messages.*` / `gen_ai.prompt.*` / `gen_ai.completion.*` / … forms) are folded into the
record's `input`/`output`/`rationale` so they follow the top-level commitment path rather than riding
verbatim in `extensions.otel_attrs`; credential-bearing attribute keys are redacted first. See
[API.md](API.md#post-v2oteltraces).

### 4. Raw HTTP

`POST /v2/records` directly (see [API.md](API.md)). This is the lowest-level path and the one the
SDKs wrap.

### Verifying offline (the point of the whole thing)

Whatever you ingest with, evidence is meant to be **verified without trusting the server**:

```bash
curl -s 'http://localhost:8080/v2/export?project=demo' > export.json
averin-verify bundle export.json              # internal consistency
averin-verify bundle export.json opts.json    # authentic, with your out-of-band pinned keys
```

The same verifier runs in the browser (`verifier/`) and via the cgo FFI (`core.VerifyBundleWith`).
For the `opts.json` role-key reference, see [`../operator-verification.md`](../operator-verification.md).

### Authority elevation (standalone)

If you run your own policy engine or human-approval service, you can get records elevated past the
forgeable `caller_declared`:

1. Have that service sign the authority evidence triple with its own key (off the averin server).
2. Pin its public key on the server: `AVERIN_POLICY_ENGINE_PUBKEY` (source `policy_engine_signed`),
   `AVERIN_HUMAN_SIGNED_PUBKEY` (source `human_signed`), and/or `AVERIN_DELEGATE_SIGNED_PUBKEY`
   (source `delegate_signed`). If the signing key differs **per averin project** (it does for govder,
   which derives per `(tenant, role)`), pin per project:
   `AVERIN_AUTHORITY_KEYS="<project>:<source>=<pubkey>,..."`.
3. Records carrying that source + a verifying `evidence_sig` are stamped the elevated source at
   ingest; an auditor pinning the same keys reads them as `verified`.
4. **A claim that does not verify is rejected, not downgraded.** By default
   (`AVERIN_REQUIRE_PINNED_AUTHORITY`, now `1`) a record claiming an elevated source averin cannot
   verify for its project gets a retryable `500` and is not sealed at all. Align the pins **before**
   pointing a signing producer at averin, or the producer's seals will fail loudly.

The credential broker (`POST /v2/grants`) + resource gateway (`POST /v2/use`) are also fully usable
standalone if you want Tier-A grant accountability and Tier-B use receipts for your own resources —
they don't require any sibling plane.

---

## Optional: composition with the sibling planes

> averin ships and is useful on its own. The combined four-plane OS (govder DECIDES · vultrino
> ENFORCES · averin PROVES · leria METERS) is a separate, later product. This section documents only
> the **cross-plane contracts** an integrator needs — not that product.

averin is the **PROVE** plane: it seals offline-verifiable evidence of what the other planes decided,
enforced, or metered. The composition is just the standalone client API above, called by a sibling:

### Contract averin exposes to any plane

- **Seal evidence:** `POST /v2/records` with the plane's payload under `extensions` (the only
  freeform-tolerated object), `project_id`/`session_id`/`idempotency_key` at top level, and **integer
  micros only** (no floats — the RCP canonicalizer rejects them).
- **Elevate authority:** the plane signs the authority `evidence_sig` with its own key, and the averin
  operator pins that key via `AVERIN_POLICY_ENGINE_PUBKEY` / `AVERIN_HUMAN_SIGNED_PUBKEY` /
  `AVERIN_DELEGATE_SIGNED_PUBKEY` / `AVERIN_AUTHORITY_KEYS` (per `(project, source)`) so the seals
  elevate to `policy_engine_signed` / `human_signed` / `delegate_signed`. An unpinned or misaligned
  claim is **rejected** at ingest by default, not silently downgraded to `caller_declared`.
- **Typed evidence categories:** the optional `record_kind` field (`budget-exhausted`,
  `chargeback-posted`) is preserved through verify/export, so a board view can filter
  `GET /v2/export?record_kind=budget-exhausted` without parsing `extensions`.

### leria (METER) → averin  *(shipped contract)*

leria seals spend-governance evidence — budget exhaustion and chargeback — as ordinary records under
`extensions`, using the typed `record_kind` (`budget-exhausted` / `chargeback-posted`). averin needs no
special-casing: there is **no source allowlist** (`authority.source` is a trust-level enum, not an
identity), so leria seals like any caller and its records verify/export as first-class typed
evidence.

### govder (DECIDE) → averin  *(elevation contract)*

govder's runtime seals budget verdicts under `policy_engine_signed`, kill/approval legs under
`human_signed`, and delegate-agent approvals under `delegate_signed` — signed with **per-(tenant, role)**
authority keys. The averin operator pins the matching public keys so every seal **elevates to verified**
at ingest rather than being rejected (or, under the fail-open opt-out, normalizing down to
`caller_declared`). Derive them with `GOVDER_AUTHORITY_SEED=... go run ./cmd/govder-derive-pubkeys
<tenant>` in govder, which prints `AVERIN_POLICY_ENGINE_PUBKEY`, `AVERIN_HUMAN_SIGNED_PUBKEY`, and
`AVERIN_DELEGATE_SIGNED_PUBKEY`.

> **Multi-tenant.** A govder tenant *is* an averin project and the key is derived per `(tenant, role)`,
> so the three single-key variables above are only sufficient for a **single-tenant** deployment. With
> more than one tenant, run `govder-derive-pubkeys` once per tenant and pin per project:
> `AVERIN_AUTHORITY_KEYS="acmeco:policy_engine_signed=<hex>,acmeco:human_signed=<hex>,acmeco:delegate_signed=<hex>,globex:..."`.
> A single global pin can only ever elevate one tenant.

Cross-plane integration tests exercising this wiring live in the FeirOS repositories, not in this
repo; that harness is a **single-tenant** wiring, so it exercises the global-pin form only.

### vultrino (ENFORCE) ↔ averin  *(design note, not yet wired)*

[`../vultrino-integration.md`](../vultrino-integration.md) specifies how vultrino (the enforcement
plane) would seal an offline-verifiable proof of every gated action into averin — using the same
`POST /v2/records` + broker/resource contracts above. It is explicitly a **design note**: no code in
the averin tree depends on it. Treat it as the map a future wiring commit follows, not a shipped
feature.
