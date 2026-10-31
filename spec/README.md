# spec/

Machine-readable contracts for averin's record and checkpoint formats, plus
the test data the verifiers are checked against.

| Path | What it is |
|---|---|
| `decision-record.schema.json`, `checkpoint.schema.json` | JSON Schemas for the record and checkpoint shapes. |
| `schema-v2.md`, `rcp-v1.md` | Prose specifications for the record schema and the checkpoint protocol. |
| `authority-subject-v1.md`, `authority-subject-v1.json` | Authority subject v1: the projection a v3 authority signature approves, its digest and signature preimages, and the authority verdict vocabulary (`.md`), with the machine-readable field policy (`.json`). |
| `grant-pop-v2.md` | Brokered grant proof of possession v2: the signed byte sequence, identifier and request validation rules, and the offline-verification limits. |
| `fixtures/` | Example bundles used by the Rust, Go, and JavaScript test suites. |
| `golden-vectors/` | Canonicalization, signature, authority-subject and broker-preimage vectors that every verifier implementation must reproduce byte for byte (positive cases only; see `rcp-v1.md` section 11). |
| `../vectors/refusal-classes.v1.json` | Closed vocabularies (14 reason classes, 4 entry points) of the gateway refusal record (`record_kind` `gateway-refusal`). core, the server and a test pin their copies to this file; vultrino and feir-os vendor it under the vectors lock. |
| `fixtures/canonical-shape-vectors.json` | Cross-implementation rows for the canonical-set and closed-member rules (feir-ops#16), replayed by the Rust, WASM and cgo tests. Signed by the TEST-ONLY seed-0 key of `fixtures/bundle-valid.json`. |
| `test-keys.json` | **TEST-ONLY** public keys behind the new vectors (`fixtures/capstone-with-refusals-v3.json`, `fixtures/gateway-refusal-vectors.json`, `verifier/samples/refusals*.json`). Seed = sha256 of a public label, so anyone can recompute them. Never pin one in a deployment. |

## Test material only

Everything under `fixtures/` and `golden-vectors/` is intended for tests.
Do not use any key, seed, signature, or identifier from here outside a test.
The development signing seed in `golden-vectors/sign-vectors.json` is a
publicly known sequential byte pattern:
real Ed25519 material, chosen so that anyone can reproduce the vectors, and
refused by the server unless `AVERIN_DEV_MODE=1` is set (the production gate,
`AVERIN_REQUIRE_PROD_SECRETS`, is on by default). This note states intended use; it is not a per-fixture provenance
audit.

Regenerating a vector is a deliberate act; see the test that owns it.
