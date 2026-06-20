# Quickstart: build & run feir

This walks you from a clean checkout to a running server and a verified record — standalone, no
other service involved.

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Rust toolchain | pinned by `rust-toolchain.toml` (**1.92.0**) | builds `feir-decision-core` (the crypto core). rustup auto-installs the pin + the `wasm32` / `i686` targets on first build. |
| Go | **1.25+** (`server/go.mod` declares `go 1.25.0`) | builds the server (cgo-links the Rust staticlib). |
| A C toolchain (cgo) | clang/gcc | the Go server uses cgo to call the Rust core. |
| `openssl` (or any 32-byte hex source) | any | to mint a signing seed. |

For the full self-host stack you also need **Docker + Docker Compose** (bundles Postgres, the web
SPA, and the recording proxy). For the verifier/SDK suites: **Bun** (verifier + TS SDK),
**Python 3 + pytest** (Python SDK).

## 1. Build from source

The server cgo-links a **prebuilt** Rust staticlib, so the order matters: build the Rust core
first, then the Go binary.

```bash
# Rust integrity core -> target/debug/libfeir_decision_core.a (the cgo link target).
cargo build -p feir-decision-core

# Go server (cgo links the staticlib built above).
cd server && go build -o feir-server ./cmd/feir-server
```

The `Makefile` wraps this so the staticlib is never stale (a real footgun — editing `core/` then
running `go test` would link an **old** trust root):

```bash
make core          # = cargo build -p feir-decision-core
make check-staticlib   # fails if the .a is older than core/ source
```

To build the offline verify CLI and run it against a shipped fixture (no server needed):

```bash
cargo run -p feir-decision-core --bin feir-verify -- bundle spec/fixtures/bundle-valid.json
```

Expected: `RESULT: PASS (integrity) — every record sealed, linked, and checkpoint-consistent.`

## 2. Run the server

The only required input is a 64-hex (32-byte) Ed25519 signing **seed**. With nothing else set,
the server runs in dev mode: in-memory store, no auth (it logs loud warnings about both).

```bash
FEIR_SIGNING_SEED=$(openssl rand -hex 32) ./feir-server
# logs: feir-server listening on :8080 (pubkey ed25519pub:...)
```

On startup it prints the public key — that is the verifying key an auditor pins. Health check:

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
cargo run -p feir-decision-core --bin feir-verify -- bundle export.json
```

The export carries the records, the checkpoint history, the public keys, and (where configured)
anchors / disclosures / attestations. The verifier re-derives every hash, signature, DAG edge, and
checkpoint link with **no network and no trust in the server**. The same Rust core runs in the
browser (WASM, under `verifier/`) and on CI.

To **authenticate** against an out-of-band trust root (rather than the bundle's own key claims) and
unlock the role gates, pass an `opts.json` pinning the role-disjoint keys — see
[`../operator-verification.md`](../operator-verification.md):

```bash
cargo run -p feir-decision-core --bin feir-verify -- bundle export.json opts.json
```

## Self-host the full stack (Docker Compose)

Brings up Postgres (durable append-only store), the server, the OpenAI-compatible recording proxy,
and the web SPA:

```bash
FEIR_SIGNING_SEED=$(openssl rand -hex 32) docker compose -f deploy/docker-compose.yml up --build
```

- web app: <http://localhost:8088>  (offline verifier under `/verifier/`)
- ingestion/app API: <http://localhost:8080>
- OpenAI-compatible proxy: <http://localhost:8081> (point your agent's `base_url` here)
