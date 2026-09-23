# Plan 003: Bind authority evidence to the authorized record content

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH.
- Category: security / protocol migration. Depends on: 001; align new report states with 002's contract.
- Planned at Averin `e81aa90adaf7ca90bb78f397839b51935e81c699`, Govder `a9a2948`, 2026-09-23.
- Work in separate branches/worktrees in each repository. First run `git diff --stat e81aa90..HEAD -- core server spec formal sdk` in Averin and `git diff --stat a9a2948..HEAD -- internal/authority internal e2e` in Govder. Reconcile drift; do not checkout or commit across the umbrella directory. Update the plan index after review; no publishing implied.

## Why this matters

A record sealer or producer who possesses valid authority evidence can attach it to a changed body with the same project and record ID. The authority signature remains valid without obtaining another authority decision. Closing this gap requires coordinated producer changes, not simply another hash field in Averin's report.

## Current state

`core/src/authority.rs:61` builds:

```rust
lp_str_into(&mut p, AUTHORITY_SIG_TAG); // averin.authority.v2
lp_str_into(&mut p, source);
lp_str_into(&mut p, project_id);
lp_str_into(&mut p, record_id);
p.extend_from_slice(evidence_hash.as_bytes());
```

`verify_authority_with_key` returns `Verified` for that signature; it does not derive a body commitment. The file's lines 18–21 already require future historical versions to be explicitly downgraded rather than silently lost. Govder's `internal/authority/preimage.go:84` reproduces these bytes, and `signer.go:143` signs the evidence before Averin's final body exists.

Averin's `server/internal/api/server.go:1530` adds defaults, receipt time, display sequence, lineage, causal parents and key metadata. Grant evidence is currently signed in `buildGrantRecord` before the credential hiding commitment is constructed. A naive hash of the final record would be circular and unavailable to external authorities.

## Scope

Averin: `core/src/{authority,verify,ffi}.rs`, FFI headers/bindings in `server/internal/core/`, authority assembly/normalization in `server/internal/api/`, protocol schemas/vectors in `spec/`, SDK evidence helpers, formal preimage/catalogue/oracle/mutants, report UI status readers and relevant docs. Govder: `internal/authority/` plus actual call sites constructing and emitting Averin records, their tests and e2e fixtures. Inventory those call sites before edits. No changes to policy decisions, secret handling, metering, record hash v2, or append-only historical evidence.

## Target contract

Define a versioned authority-subject projection of the fully normalized semantic record. It includes project/record/session/agent identity, action/status, authority source and meaningful metadata, input/output/credential commitments and extensions. Unknown semantic fields are included by default or rejected by the versioned schema; never silently excluded. Exclude only an enumerated set of recorder-envelope fields unavailable to the authority (receipt/display/DAG/signing envelope) and recursive proof fields (`evidence_sig`, subject digest, final record hash/signature). Document exactly which envelope facts are authenticated only by the recorder. Do not claim the authority approved event truth or every envelope byte.

Freeze semantic defaults, lineage and hiding commitments before authority approval. An authority must receive/reconstruct and approve that actual subject, not sign an opaque caller-provided hash without relating it to its decision. Producers supply finalized semantic data; ingest may add the defined envelope but cannot mutate the subject after approval. Keep the implementation helper internal unless a reviewed workflow demonstrates a new public prepare endpoint is necessary.

Make the projection a machine-readable versioned schema with this field policy:

| Field group | v3 treatment |
|---|---|
| `project_id`, `record_id`, session/agent/span identity, action/status, schema/domain/canonical version | Required final value before signing; included |
| `agent_ts`, semantic defaults, lineage, input/output/credential commitments, extensions, meaningful authority metadata | Finalized before signing; included; reject an ingest that would silently alter them |
| `received_ts`, `display_seq`, `causal_prev_hashes`, recorder `key` envelope | Enumerated recorder-only exclusions; recorder signature still authenticates them |
| Record `content_hash`/`sig`, authority evidence signature and subject-commitment field | Excluded derived/self-referential proof material |
| New/unknown field | Included unless the versioned schema explicitly rejects it; exclusion-list expansion requires protocol review |

Inventory authority producers by source and role before editing: policy/human/delegate signatures come from external authorities including Govder; broker/resource/void/introspection `gateway_enforced` envelopes are local Averin producers. Migrate every newly emitted elevated authority envelope to v3, while preserving the existing Tier-B grant/use evidence payload and its independent rederivation checks wherever possible. Changing the envelope need not redesign those embedded payloads. Include Govder's `internal/averin/adapter.go` and actual signer call sites in the inventory.

Use `averin.authority.v3` with explicit version/projection identification and a framed body commitment in addition to source/project/record/evidence hash. Version selection is explicit: malformed/unknown v3 fails, never falls back to v2. Old v2 remains cryptographically verifiable as `legacy_unbound`, cannot satisfy a body-bound-authority requirement, and is not rewritten. Preserve existing stronger Tier-B rederivation checks.

## Steps and verification

1. Specify the complete projection, exclusion list, canonical bytes and compatibility matrix. Add vectors for semantic defaults, unknown extensions, hiding commitments and every exclusion. Add tests reproducing the v2 substitution and requiring v3 failure.
   **Verify:** `cargo test -p averin-decision-core --test golden` and Govder `go test ./internal/authority/...` pass for historical vectors; new negative vectors reproduce the intended changed contract.
2. Implement production-called subject/preimage helpers and versioned Rust verification/FFI. Thread `legacy_unbound` through reports and policy checks, keeping pinned-key and rotation checks. Add the v3 family and separation/binding theorem to Lean, oracle corpus and tag inventory.
   **Verify:** `cargo test --workspace`, `make formal-lean formal-refinement`, and `cargo clippy --workspace --all-targets -- -D warnings` pass.
3. Reorder local broker/resource/void/introspection builders so authority signing occurs after subject finalization. Update generic ingest and Govder's signer/emitter together; rejection must occur before consuming/sealing on invalid authority. Preserve batch all-or-nothing behavior.
   **Verify:** Averin `make test-server` against disposable Postgres; Govder `make test lint`; Rust↔Go↔Govder shared preimage vectors agree byte-for-byte.
4. Roll out verifier dual-reading first, then v3-producing clients, then require v3 for new elevated ingest under an explicit deployment policy. Historical v2 exports remain readable and visibly weaker. Run the integrated producer flow and regenerate WASM through the established build/pin path.
   **Verify:** Averin `make test`; in Govder `go test -tags e2e ./e2e/ -timeout 600s -v -run TestFourPlaneE2E`. All four real planes pass; no historical evidence bytes change.

## Test plan and done criteria

Model after `core/tests/adversarial.rs`, server authority/batch tests and Govder `internal/authority/preimage_test.go`/`averin_xcheck_test.go`. Mutate every bound field while holding the authority proof fixed, and separately reseal with a legitimate recorder key: v3 must not elevate. Test substituted project/ID, removed/unknown versions, v2 compatibility, authority-key rotation, normalization equivalence, commitment changes and server defaults. A new semantic field must either affect the subject or fail schema validation. Add a mutation omitting the subject commitment and require the gate to kill it.

For every enumerated recorder-only exclusion, test that legitimate recorder-envelope changes do not falsely invalidate the authority proof, while ordinary record-integrity verification still catches an unsigned modification. The tests must make the two different signature claims explicit.

## STOP conditions and maintenance

Stop if a producer cannot reconstruct the subject, approval would cover only attacker-supplied opaque hashes, or success requires broad exclusions such as all extensions. Return a concrete subject-construction redesign before proceeding. Never backfill signatures into immutable records. Every future record-schema change must review the authority projection and the cross-plane vectors. Fetch dependencies through Socket Firewall only.
