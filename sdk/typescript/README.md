# averin TypeScript SDK

For an externally approved v3 record, assign `record_id`, `span_id`, and `agent_ts` and provide
precomputed hiding commitments for any content. Call `prepareV3AuthoritySubject(draft)` from
`@averin/sdk`. Give the returned structured record to the external authority, attach its
`subject_digest` and `evidence_sig` to `authority`, then call
`client.submit(prepared, "stable-idempotency-key")` with that same record. Preparation fills
server semantic defaults and FEIR lineage before approval. Submission adds only the
idempotency key outside the signed subject. The server checks the proof against the record it
seals; the SDK does not sign an opaque digest.
