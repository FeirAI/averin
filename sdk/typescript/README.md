# averin TypeScript SDK

For an externally approved v3 record, assign `record_id`, `span_id`, and `agent_ts` and provide
precomputed hiding commitments for any content. Call `prepareV3AuthoritySubject(draft)` from
`@averin/sdk`. Give the returned structured record to the external authority, attach its
`subject_digest` and `evidence_sig` to `authority`, then call
`client.submit(prepared, "stable-idempotency-key")` with that same record. Preparation fills
server semantic defaults and FEIR lineage before approval. Submission adds only the
idempotency key outside the signed subject. The server checks the proof against the record it
seals; the SDK does not sign an opaque digest.

An `authority` object is passed through unchanged and may carry only the members the record schema lists; the
server answers `400` for any other member in the default enforce mode. Put custom fields in `extensions`.

`new Client(baseUrl, projectId, { apiKey })` sends the key as an `Authorization: Bearer` header and
posts to `/v2/records?project=<projectId>` (URL-encoded, equal to the record's `project_id`), which is
where the server's project-key check reads the project. A server with `AVERIN_API_KEYS` set (required
unless `AVERIN_DEV_MODE=1`) accepts a token with the write role for that project and refuses any other
with `401`, which the built-in transport raises as an `AverinError`. A custom `transport` receives that URL.
