# Authority subject v1

`spec/authority-subject-v1.json` is the machine-readable field policy. The v3
authority signature approves the final semantic record, including any extension
key admitted by the record schema. It does not attest that the action happened.
The recorder's separate record signature authenticates the entire sealed record.

The subject is the RCP-v1 canonical Decision Record with only these top-level
members removed: `received_ts`, `display_seq`, `causal_prev_hashes`, `key`,
`content_hash`, and `sig`. Inside `authority`, remove only `evidence_sig` and
`subject_digest`. The last two fields are recursive proof material. The first
four are recorder-owned receipt, display, causal, and signing-key envelope.
`idempotency_key` is an ingest control that is removed before a record exists.
`anchored_ts`, if supplied, is semantic and stays bound. Unknown top-level
members fail the closed record schema; new admitted fields and every nested
`extensions` member are bound unless this versioned policy is reviewed.

Before approval, the producer fixes the project, record, session, agent, span,
and parent-span identities; agent timestamp; schema/domain/canonical versions;
event type, action, observation path, status; all authority metadata; lineage;
input/output/rationale/credential commitments; and extensions. Missing required
semantic fields make a v3 proof invalid. An ingest handler must not silently
default or overwrite any of these after approval. External v3 producers must
send commitments rather than raw `input`, `output`, or `rationale`, since the
recorder's random hiding nonce would otherwise change the subject after signing.

The digest is `sha256:hex(SHA-256(LP("averin.authority.subject.digest.v1") ||
LP("averin.authority.subject.v1") || RCP(subject)))`. The Ed25519 signature
preimage is `LP("averin.authority.v3") || LP("averin.authority.subject.v1") ||
LP(source) || LP(project_id) || LP(record_id) || LP(evidence_hash) ||
LP(subject_digest)`. `LP` is a four-byte big-endian length followed by UTF-8.
The signer must receive and approve the structured subject; signing a caller's
opaque digest is insufficient.

An absent proof version with no v3 fields is historical v2. A valid v2 signature
is `legacy_unbound`: its key and embedded evidence still verify, including role
key rotation and independent Tier-B evidence rederivation, but it cannot satisfy
a body-bound authorization claim. Any unknown, incomplete, or malformed v3
version is `failed` and never falls back. New elevated ingest can require v3
under an explicit deployment policy while historical exports remain readable.
No historical authority bytes are rewritten.
