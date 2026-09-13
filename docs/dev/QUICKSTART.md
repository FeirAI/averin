# Quickstart: build & run averin

This walks you from a clean checkout to a running server and a verified record — standalone, no
other service involved.

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Rust toolchain | pinned by `rust-toolchain.toml` (**1.92.0**) | builds `averin-decision-core` (the crypto core). rustup auto-installs the pin + the `wasm32` / `i686` targets on first build. |
| Go | **1.25.13** (pinned in `server/go.mod`) | builds the server (cgo-links the Rust staticlib). |
| A C toolchain (cgo) | clang/gcc | the Go server uses cgo to call the Rust core. |
| `openssl` (or any 32-byte hex source) | any | to mint a signing seed. |

Docker Compose files remain as source recipes, not a validated image-build or deployment
path for this source-only alpha. The stack examples below are not a turnkey walkthrough.
For the verifier/SDK suites: **Bun** (verifier + TS SDK), **Python 3 + pytest** (Python SDK).
Their prerequisites and local dependency acquisition still apply.

## 1. Build from source

The server cgo-links a **prebuilt** Rust staticlib, so the order matters: build the Rust core
first, then the Go binary.

```bash
# Rust integrity core -> target/debug/libaverin_decision_core.a (the cgo link target).
cargo build -p averin-decision-core

# Go server (cgo links the staticlib built above).
cd server && go build -o averin-server ./cmd/averin-server
```

The `Makefile` wraps this so the staticlib is never stale (a real footgun — editing `core/` then
running `go test` would link an **old** trust root):

```bash
make core          # = cargo build -p averin-decision-core
make check-staticlib   # fails if the .a is older than core/ source
```

To build the offline verify CLI and run it against a shipped fixture (no server needed):

```bash
cargo run -p averin-decision-core --bin averin-verify -- bundle spec/fixtures/bundle-valid.json
```

Expected: `RESULT: PASS (integrity) — every record sealed, linked, and checkpoint-consistent.`

## 2. Run the server

The only required input is a 64-hex (32-byte) Ed25519 signing **seed**. With nothing else set,
the server runs in dev mode: in-memory store, no auth (it logs loud warnings about both).

```bash
AVERIN_SIGNING_SEED=$(openssl rand -hex 32) AVERIN_ADDR=127.0.0.1:8080 ./averin-server
# logs: averin-server listening on 127.0.0.1:8080 (pubkey ed25519pub:...)
```

Without `AVERIN_API_KEYS` set, the API is unauthenticated, so keep it on loopback.

On startup the server displays a public key. Authenticate that key through an independently
trusted channel before treating it as an auditor's trust root; display alone is not authentication. Health check:

```bash
curl -s localhost:8080/healthz      # -> ok
```

See [CONFIGURATION.md](CONFIGURATION.md) for every env var (Postgres, auth, content store,
witness, TSA anchoring, the credential broker, the resource gateway).

## 3. End-to-end: record → verify → checkpoint → export

### Seal a record

`POST /v2/records` accepts a single record object or a JSON array (batch). `project_id`,
`session_id`, and an idempotency key (`idempotency_key` field **or** `Idempotency-Key` header) are
required; the server stamps every server-controlled field, replaces low-entropy `input`/`output`/
`rationale` with hiding commitments, links the record into the session DAG, and signs it.

```bash
curl -s -X POST localhost:8080/v2/records \
  -H 'Content-Type: application/json' \
  -d '{
    "project_id": "demo",
    "session_id": "sess-1",
    "idempotency_key": "r1",
    "event_type": "decision",
    "action": "llm_call",
    "input": "summarize the contract"
  }'
```

Response (`201 Created`) — note `input` is now `input_commit` (the plaintext never enters the
signed body), and the server filled in `content_hash`, `sig`, `causal_prev_hashes`, `display_seq`,
`record_id`, `key`, etc.:

```json
{
  "results": [
    {
      "created": true,
      "record": {
        "schema_version": "2",
        "canon_version": "rcp-1",
        "domain": "flightrecorder.record.v2",
        "record_id": "4c4ddf23-...",
        "project_id": "demo",
        "session_id": "sess-1",
        "event_type": "decision",
        "action": "llm_call",
        "observed_via": "sdk",
        "status": "ok",
        "input_commit": { "alg": "sha256", "commitment": "sha256:f3e1...", "low_entropy": true },
        "causal_prev_hashes": [],
        "display_seq": 0,
        "content_hash": "sha256:be74...",
        "sig": "ed25519:LMLp...",
        "key": { "signing_key_id": "k0", "key_epoch": 0, "key_status": "active", "key_valid_from": "2026-01-01T00:00:00.000Z" }
      }
    }
  ]
}
```

### Self-verify (server-side report)

```bash
curl -s 'localhost:8080/v2/verify?project=demo'
```

Returns the verification report. Before any checkpoint is cut, the top-level `ok` is `false`
(the latest frontier is uncommitted), but the records and DAG already prove out:

```json
{ "ok": false, "records_total": 1, "records_proven": 1, "dag_ok": true, "dag_heads": 1,
  "chain_ok": true, "checkpoints_total": 0, "grant_accountability": "not_applicable",
  "action_completeness": "not_claimed", "resource_trust": "assumed_truthful",
  "keys_externally_pinned": false }
```

### Cut a checkpoint (commit the frontier)

A checkpoint seals the current set of session heads into the hash-chained checkpoint chain — the
"as-of" line that makes the full `ok:true` verdict reachable.

```bash
curl -s -X POST 'localhost:8080/v2/checkpoints?project=demo'
# 201 {"checkpoint":{"checkpoint_id":"cp-demo-0","checkpoint_seq":0,"frontier":[...], ...}}
```

Re-run `GET /v2/verify?project=demo` and `ok` is now `true`.

### Export a bundle and verify it OFFLINE

```bash
curl -s 'localhost:8080/v2/export?project=demo' > export.json
cargo run -p averin-decision-core --bin averin-verify -- bundle export.json
```

The export carries records, checkpoint history and public keys, plus configured optional
anchors, disclosures and attestations. Local verification checks the supplied evidence;
bundle-supplied keys establish consistency, not independently authenticated identity.
Native RFC 3161 verification needs its build feature; browser/WASM reports those anchors
as `Unsupported`. This is not a guarantee about dependency acquisition or asset-loading egress.

To **authenticate** against an out-of-band trust root (rather than the bundle's own key claims) and
unlock the role gates, pass an `opts.json` pinning the role-disjoint keys — see
[`../operator-verification.md`](../operator-verification.md):

```bash
cargo run -p averin-decision-core --bin averin-verify -- bundle export.json opts.json
```

## Docker Compose source recipes (not validated for this alpha)

The following command and service URLs describe the retained recipe, not a tested
image-build, clean-machine setup or deployment path. Services must be independently
built and configured before using examples that depend on them.

```bash
AVERIN_SIGNING_SEED=$(openssl rand -hex 32) docker compose -f deploy/docker-compose.yml up --build
```

- web app: <http://localhost:8088>  (offline verifier under `/verifier/`)
- ingestion/app API: <http://localhost:8080>
- OpenAI-compatible proxy: <http://localhost:8081> (point your agent's `base_url` here)
