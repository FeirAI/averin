# Brokered grant proof of possession v2

All online brokered grant routes require `pop_version: 2`, including committed
retries. Historical v1 signatures retain their original offline rules. Native `token_exchange`
grants use their separate authentication contract. The agent signs an Ed25519
signature over `SHA256(subject || BE8(issued_at) || BE8(request_expires_at))`.
`subject` is the following byte sequence in **exactly this order**:

```
LP4("averin.broker.pop.v2")
LP4(project_id) LP4(idempotency_key) LP4(session_id)
LP4(agent_id) LP4(action) LP4(resource) LP4(scope)
LP4(effective_scope_class) LP4(agent_pubkey)
LP4(authorizing_principal) LP4(justification) LP4("capability")
BE8(effective_use_limit) BE8(ttl_seconds) BE8(delegation_chain_length)
LP4(delegation_chain[0]) ... LP4(delegation_chain[n-1])
```

`LP4(x)` is a four-byte unsigned big-endian length followed by the exact UTF-8
bytes. `BE8(x)` is an eight-byte signed integer in two's-complement big-endian
form. The signature covers the exact bytes of every string: no case folding, trimming,
Unicode normalization or JSON reserialization is applied to what is signed. The server
nevertheless checks the opaque identifiers before it looks anything up or verifies the
signature, because the recorder's RCP canonicalization would otherwise give the lookup and
the sealed record different identities. A request is rejected with 400 if any of
`project_id`, `session_id`, `idempotency_key`, `agent_id`, `action`, `resource`, `scope`,
`authorizing_principal`, `lease_id` or any `delegation_chain` entry is not valid UTF-8, is not
NFC-normalized (decided by the shipped Rust canonicalizer), or contains a NUL (U+0000). The
`?project=` query parameter and the `Idempotency-Key` header are checked the same way. Other
fields, including `justification`, are not subject to this check and remain byte-exact end to end.
Every LP4 field must fit in 32 bits; producers and the server reject an
oversized field before signing or verification, with no truncated length frame.
The public key must be canonical unpadded base64url. Absent scope class resolves
to `single_operation`; non-bounded use limit is zero; absent delegation chain is
empty. The server resolves body/header idempotency and body/authenticated-route
project before verifying the signature, and rejects conflicting representations.
The server rejects unsupported versions and never silently retries verification
under v1.

Request validation, as the server applies it to an online brokered grant (rejections are 400
unless stated):

- `project_id`, `session_id` and `idempotency_key` must be non-empty. `agent_id`, `action`,
  `resource` and `scope` must be non-blank after trimming whitespace, while the signature is still
  over the untrimmed bytes.
- `idempotency_key` must not start with a reserved prefix: `denial:`, `grant-void:` or `refusal:`.
- `ttl_seconds` is a whole number of seconds, positive and at most one hour (3600). A request that
  proves possession but exceeds the cap is refused as a policy denial.
- `issued_at` must be positive, `request_expires_at` must be later than `issued_at`, and the
  difference must be at most 15 minutes (900 seconds).
- `scope_class`, if present, is one of `single_operation`, `bounded_reuse`, `session_grant`,
  `batch_grant`; `use_limit` is at least 1 for `bounded_reuse` and zero for every other class.
- `agent_pubkey` must be canonical unpadded base64url of a 32-byte Ed25519 key, and `agent_sig` a
  64-byte base64url Ed25519 signature that verifies over the challenge above.
- Scope policy: a `single_operation` or `bounded_reuse` grant whose `scope` is too broad (a
  wildcard, a privileged namespace such as `iam` or `admin`, or an authority-minting or delegating
  verb) is refused as a policy denial. `session_grant` and `batch_grant` are accepted and are
  Tier-A-only coarsenings.

The request expiry must exceed its issue time by at most 15 minutes. The server
accepts 30 seconds of clock skew at each edge. A fresh grant or prepare requires
a currently valid proof. Finalize also requires the original pending proof and
prepare deadline to remain valid. A matching committed retry may return the
original result after request expiry, but cannot mint or extend a capability.
`SHA256(subject)` is the semantic retry digest signed into grant evidence; only
the signature and freshness envelope are excluded. A durable caller may re-sign
the same subject after restart. A changed project, idempotency key, session,
scope, TTL, authorization context, or other subject field conflicts with the
existing grant or pending operation.

New capability descriptors include signed integer `version: 2` and string
`project_id`. The resource compares `project_id` with the authenticated route
project before revocation and consumption. This rollout denies historical
descriptors without the signed claim online at cutoff. Historical records and
signatures remain verifiable under v1.

Offline verification of a v2 grant is narrower than the server's online check. The verifier checks
that the grant evidence carries `pop_version` 2, that its `project_id` equals the sealed record's
`project_id`, and that `request_hash` has the form `sha256:` plus 64 lowercase hex characters (and,
when the credential descriptor is disclosed, that its `version` and `project_id` agree). It cannot
re-verify `agent_sig` or the subject, because neither is stored in the record.

The shared preimage example lives in
[`golden-vectors/broker-preimages.json`](golden-vectors/broker-preimages.json).
