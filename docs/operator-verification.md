# Operator guide: offline verification + role-disjoint key pinning

feir's guarantees are enforced **offline**, by a verifier that needs no server. A bundle
(`GET /v2/export`) carries the records, the checkpoint history, and the public keys; the verifier
re-derives every hash, signature, DAG edge, checkpoint chain, anchor, and the Tier-B / ADR-0005 mode
gates from the bundle alone. The server is never in the trust path.

There are two verification postures:

| Posture | How | Proves |
|---|---|---|
| **Internal consistency** | `feir-verify bundle b.json` (no opts) | the bundle is self-consistent under **its own** key claims — integrity, DAG, checkpoint chain, omission/fork/tamper. It does **not** authenticate against an out-of-band trust root. |
| **Pinned (authentic)** | `feir-verify bundle b.json opts.json` | the above **plus** every role's evidence verifies under the keys **you** pinned out-of-band, which is what unlocks the Tier-B / mode gates (cosig, revocation, federation, native, attestation, taxonomy) and the `attested_complete_*` capstone. |

Browser (`/verifier/`) and FFI (`core.VerifyBundleWith`) take the same `opts` object.

## The role-disjoint key sets (`opts.json`)

Each set authorizes exactly **one** role. They **MUST be pairwise disjoint** — a key shared across
two roles is a **fatal configuration error** (the verifier aborts), because it would let one authority
sign across a role boundary (e.g. a broker self-attesting, or a resource self-validating a taxonomy).
Pin only the sets you want to enforce; an omitted set leaves that mode `unevaluated`/`absent`
(fail-closed — it never silently passes).

```jsonc
{
  // Tier-A grant accountability (ADR 0002/0003): the credential broker's recording key(s).
  "broker_authority_keys": ["ed25519pub:<broker-recording-key>"],

  // Tier-B use receipts (ADR 0003 R2): the resource gateway's recording key(s). Also the M3
  // native introspection-transcript signer (feir.resource.introspection.v1).
  "resource_authority_keys": ["ed25519pub:<resource-recording-key>"],

  // D3/D7 time anchoring: the TSA key(s) (or "tsa_spki_b64" for an RFC 3161 TSA's DER SPKI).
  "tsa_keys": ["ed25519pub:<tsa-key>"],

  // D4 operation taxonomy (MF5): the SIGNED taxonomy artifact + its issuer key(s) + the pinned
  // content digest + version it must match to reach `validated` (a signed-but-unpinned taxonomy stays untrusted).
  "taxonomy": { /* the signed taxonomy doc */ },
  "taxonomy_keys": ["ed25519pub:<taxonomy-issuer-key>"],
  "taxonomy_digest": "sha256:<digest of the taxonomy minus sig>",
  "taxonomy_version": 1,

  // D7 deployment attestation: the attestation issuer key(s) (role-separated, so a broker/resource cannot self-attest).
  "attestation_keys": ["ed25519pub:<attestation-issuer-key>"],

  // M6 Cosig: the M-of-N grant-approval GOVERNANCE keys. A grant declaring cosig_threshold is
  // Tier-B-eligible only if >= M distinct keys here cosigned it.
  "cosig_approver_keys": ["ed25519pub:<approver-1>", "ed25519pub:<approver-2>"],

  // M5 Revocation: the revocation issuer key(s) (role-separated, so a broker cannot sign its own
  // revocation). Covers BOTH the disclosed `revocation_list` AND the Merkle-non-disclosure
  // `revocation_merkle_root` (each verified under this same role). For the Merkle variant the bundle ALSO
  // carries `revocation_merkle_root` + a `revocation_proofs` map (see "Producing the optional artifacts").
  "revocation_keys": ["ed25519pub:<revocation-issuer-key>"],

  // M4 Federation (per-broker_id authority): a MAP of broker_id -> its authority key set. When set,
  // a grant carrying that broker_id elevates ONLY under its own broker's keys. Every set above must be
  // disjoint from the UNION of all per-broker sets too.
  "federated_broker_keys": { "broker-A": ["ed25519pub:<A>"], "broker-B": ["ed25519pub:<B>"] },

  // Generic non-broker authority (policy engine / approval service) for BrokerRole::None records. MAY
  // equal broker_authority_keys (self-host), but must be disjoint from every other role.
  "authority_keys": ["ed25519pub:<policy-engine-key>"]
}
```

All keys are base64url-no-pad ed25519 public keys with an `ed25519pub:` prefix (the form
`feir-server` logs at startup, and the form `core.PubKey()` returns).

## What each mode means in the report

- `grant_accountability` — every credential grant verified under `broker_authority_keys` (Tier-A).
- `broker_trust: sequence_verified` — the grant-transparency log is a gapless, anchored prefix (D6); no suppression.
- `cosig_status: satisfied` — every cosigned grant met its M-of-N (M6).
- `delegation_status: verified` — every per-hop delegation chain re-walked + monotone (M2).
- `revocation_status` — disclosed-list mode (M5): `fresh`/`absent` pass; `stale`/`revoked_present` block the capstone.
- `revocation_merkle_status` — Merkle-non-disclosure mode (M5): when `fresh`, EVERY Tier-B use **and** every native credential must carry a per-grant proof in the bundle's `revocation_proofs` map — a non-membership proof to proceed, a membership/missing/forged proof blocks it (fail-closed; the revoked set is never disclosed). `stale` blocks the capstone; `absent` is the baseline. `revocation_nonmembership_verified` counts grants proven NOT revoked.
- `introspection_status: attested` — every native (token_exchange) credential's resource-signed transcript verified (M3); the native surface reaches `attested_complete_over_introspected_surface`. A native credential that a fresh revocation list/root marks revoked is blocked here too (it can never be `attested`).
- `federation_status: sequence_verified` — every broker's per-`broker_id` log verified, no `cross_broker_suppression` (M4).
- `transitive_grants` — grants from an UNPINNED subject broker that elevated to `transitive` trust via a `cross_broker_cert` signed by a PINNED issuer broker (M4 optional). The cert binds the subject's KEY (not just its id), and the subject key is rejected if it collides with any non-broker role.
- `action_completeness` — the D8 capstone (`attested_complete_over_brokered_surface` / `..._introspected_surface` / `claimed_over_manifest` / `not_claimed`), **always** bounded by `resource_trust: assumed_truthful` (MF1 — the irreducible resource TCB).

## Producing the optional M4/M5 artifacts

Most modes are produced automatically by the broker/resource on the recording path (and via the online
`/v2/grants/*`, `/v2/use*`, `/v2/introspection` flows). Two OPTIONAL tiers are assembled at bundle/checkpoint
time from a role-separated key:

- **Merkle-non-disclosure revocation (M5).** A revocation authority (a key disjoint from the broker it
  revokes) builds a sorted Merkle tree over the revoked grant_ids, signs the root, and attaches
  `revocation_merkle_root` + a per-grant `revocation_proofs` map to the bundle — committing to the revoked set
  **without disclosing it**:
  - Go: `broker.BuildRevocationTree(revokedIDs)` → `api.BuildRevocationMerkleRoot(core, revKey, issuedAt, notAfter, tree)`
    for the signed root; `tree.NonMembershipProof(gid)` / `tree.MembershipProof(gid)` for each grant in the bundle.
  - Verify with `revocation_keys` pinned; under a fresh root **every** use and native credential needs a proof
    (a missing proof is fail-closed → blocked).
- **Cross-broker cert (M4 transitive trust).** A PINNED issuer broker A vouches for an UNPINNED subject broker
  B's authority key over a `(scope, resource)`:
  - Go: `broker.CrossBrokerCert(issuerID, subjectID, subjectPub, scope, resource, notAfter, issuerKey)`, embedded
    in B's `grant_evidence.cross_broker_cert`.
  - Verify with only A pinned in `federated_broker_keys`; B's grant elevates to `transitive` and is counted in
    `transitive_grants`.

> These two tiers are currently produced via the library/SDK at bundle-assembly time; server HTTP endpoints that
> emit a per-broker `broker_grant_heads` map (federation) and the revocation artifacts directly into the
> checkpoint/export flow are the remaining wiring follow-up.

## Running it

```bash
# build the CLI once
cargo build --release --bin feir-verify

# internal consistency
target/release/feir-verify bundle bundle.json

# authentic + mode gates (pin the keys you printed from feir-server's startup log / your KMS)
target/release/feir-verify bundle bundle.json opts.json
```

A non-zero exit = FAIL. The keys you pin here are the out-of-band trust root — distribute them through a
channel independent of the server (the server can produce a bundle, but it can never make the verifier
accept one its pinned keys don't authenticate).
