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
members fail the verifier's closed top-level key set; new admitted fields and every nested
`extensions` member are bound unless this versioned policy is reviewed. Unknown members inside
`authority` are not rejected by the verifier (it does not allow-list nested objects), but any
member other than `evidence_sig` and `subject_digest` is bound into the digest.

Before approval, the producer fixes the project, record, session, agent, span,
and parent-span identities; agent timestamp; schema/domain/canonical versions;
event type, action, observation path, status; all authority metadata; the span and
parent-span identity, including any copy of it inside `extensions.feir_evidence`;
input/output/rationale/credential commitments; and extensions. Missing required
semantic fields make a v3 proof invalid.

averin's server does not leave those fields untouched. Before it checks a v3 proof it fills fixed
values and defaults:

- `schema_version` `"2"`, `canon_version` `"rcp-1"` and `domain` `"flightrecorder.record.v2"` are
  set unconditionally.
- An absent `agent_ts` becomes the server time, an absent `record_id` a new UUID, an absent
  `span_id` `span-` plus a new UUID, and an absent `parent_span_id` `null`.
- An absent `agent_id` or `agent_version` becomes `unknown`, `event_type` becomes `decision`,
  `action` the empty string, `observed_via` `sdk`, and `status` `ok`.
- When `extensions.feir_evidence` is an object, its `capture_authority` is set to the record's
  `observed_via` and its `lineage` to the record's `session_id`, `span_id` and `parent_span_id`.

Because the signature binds the exact projected subject, a signer must have signed those exact
values. If it did not, the digest or signature check fails and the record is refused (fail
closed); the server never re-signs or downgrades a failed v3 claim. For an external v3 record the
server also requires explicit `record_id`, `span_id` and `agent_ts`, and an explicit
`parent_span_id` (`null` is allowed), because the recorder cannot mint them after an authority has
approved the subject. External v3 producers must
send commitments rather than raw `input`, `output`, or `rationale`, since the
recorder's random hiding nonce would otherwise change the subject after signing.

The digest is `sha256:hex(SHA-256(LP("averin.authority.subject.digest.v1") ||
LP("averin.authority.subject.v1") || RCP(subject)))`. The Ed25519 signature
preimage is `LP("averin.authority.v3") || LP("averin.authority.subject.v1") ||
LP(source) || LP(project_id) || LP(record_id) || LP(evidence_hash) ||
LP(subject_digest)`. `LP` is a four-byte big-endian length followed by UTF-8.
The signer must receive and approve the structured subject; signing a caller's
opaque digest is insufficient.

An external v3 record must declare `proof_version` `v3` and `subject_projection`
`averin.authority.subject.v1`, and its `authority.source` must be `policy_engine_signed`,
`human_signed` or `delegate_signed`: the key is the one the deployment pinned for that project and
source. A v3 `gateway_enforced` record is signed by the recorder's own broker or resource key for
grants and uses it records itself, and an external request on the generic ingest path claiming it is refused.

The verifier classifies authority with this closed vocabulary:

- `none`: no authority block.
- `declared`: `caller_declared`, or an unknown source; forgeable, taken at face value.
- `unverifiable`: a well-formed verified-source claim, but no authority keys were pinned to check it.
- `legacy_unbound`: a valid historical v2 signature under a pinned key (see below).
- `verified`: a v3 proof whose digest matches the record body and whose signature verifies under a
  pinned key.
- `failed`: evidence missing or malformed, a malformed or unknown v3 version, a digest mismatch, or
  no pinned key verifies the signature.

An absent proof version with no v3 fields is historical v2. A valid v2 signature
is `legacy_unbound`: its key and embedded evidence still verify, including role
key rotation and independent Tier-B evidence rederivation, but it cannot satisfy
a body-bound authorization claim. Any unknown, incomplete, or malformed v3
version is `failed` and never falls back. New elevated ingest can require v3
under an explicit deployment policy while historical exports remain readable.
No historical authority bytes are rewritten.
