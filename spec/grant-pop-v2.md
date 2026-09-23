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
form. All strings, including opaque IDs and justification, are byte-exact; no
case folding, trimming, Unicode normalization or JSON reserialization applies.
The public key must be canonical unpadded base64url. Absent scope class resolves
to `single_operation`; non-bounded use limit is zero; absent delegation chain is
empty. The server resolves body/header idempotency and body/authenticated-route
project before verifying the signature, and rejects conflicting representations.
The server rejects unsupported versions and never silently retries verification
under v1.

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
project before revocation and consumption. Historical descriptors without this
claim require authoritative sealed-grant/descriptor lookup or are denied online
after cutoff. Historical records and signatures remain verifiable under v1.

The shared preimage example lives in
[`golden-vectors/broker-preimages.json`](golden-vectors/broker-preimages.json).
