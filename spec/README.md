# spec/

Machine-readable contracts for averin's record and checkpoint formats, plus
the test data the verifiers are checked against.

| Path | What it is |
|---|---|
| `decision-record.schema.json`, `checkpoint.schema.json` | JSON Schemas for the record and checkpoint shapes. |
| `schema-v2.md`, `rcp-v1.md` | Prose specifications for the record schema and the checkpoint protocol. |
| `fixtures/` | Example bundles used by the Rust, Go, and JavaScript test suites. |
| `golden-vectors/` | Canonicalization and signature vectors that every verifier implementation must reproduce byte for byte. |

## Test material only

Everything under `fixtures/` and `golden-vectors/` is intended for tests.
Do not use any key, seed, signature, or identifier from here outside a test.
The development signing seed in `golden-vectors/sign-vectors.json` is a
publicly known sequential byte pattern:
real Ed25519 material, chosen so that anyone can reproduce the vectors, and
refused by the server when `AVERIN_REQUIRE_PROD_SECRETS` is set to `1` or
`true`. This note states intended use; it is not a per-fixture provenance
audit.

Regenerating a vector is a deliberate act; see the test that owns it.
