# averin formal verification

averin's product claim is Level 1 of `docs/coverage-limits.md`: *a record sealed by this key has
not been altered since, and sits in a verifiable history.* This directory holds machine-checked
evidence for the assumptions that claim rests on. There are three layers, each used where it is
strongest, plus a gate that keeps them in sync with the code.

| Layer | Tool | What it covers | Run |
|---|---|---|---|
| Unbounded proofs over a model | Lean 4 (`lean/`) | canonical-JSON injectivity, UTF-8, LP framing, domain separation of every hashed and signed preimage, the seal theorem, commitment binding, DAG no-omission, checkpoint-chain uniqueness | `cd lean && lake build --wfail && ./check-axioms.sh` |
| Bounded proofs over the real Rust | Kani / CBMC (`run-kani.sh`) | base64url alphabet bijection, `sha256:<hex>` digest-string injectivity and canonicality, exact LP framing, exact key order (parser-level harnesses in an extended set) | `bash formal/run-kani.sh` |
| Protocol and concurrency models | TLA+ / TLC (`tla/`) | gapless grant-transparency log under failures and lost rollbacks; consume-before-act ledger with multiple gateways, releases and TTL sweeps | `bash formal/tla/run-tlc.sh` |
| Model/code drift gate | `check-refinement.py` | every tag, domain, preimage schema, escape rule and DAG/chain check the proofs assume still appears in `core/src` | `python3 formal/check-refinement.py` |

## The seal, precisely

`Averin.Seal.record_seal_sound` (and `checkpoint_seal_sound`):

> If a record body's signature verifies under the pinned key, the body is **exactly** one the key
> holder sealed, unless SHA-256 has a collision.

Everything between "signature verifies" and "same body" is proved, not assumed:

1. **Signature domain separation** (`Preimage.signed_families_disjoint`). The message families
   signed with Ed25519 are record, checkpoint, taxonomy, revocation, Merkle root, attestation,
   authority evidence, and test anchor. They are pairwise disjoint *for all field values*. A
   signature from one context can never verify in another, even if two roles share a key, so
   role-key disjointness is defence in depth. `signed_message_long` adds that, given the
   verifier's own digest validation, none of them can equal the raw 32-byte digests that the
   broker challenge families sign.
2. **No delimiter injection** (`Encoding.encodeFields_inj`, `Family.msg_inj`). Every preimage
   is `LP(tag) ‖ fields ‖ tail?`, and equal bytes imply equal fields.
3. **Canonical JSON is injective** (`Canon.ser_injective`). The model covers `write_string`'s
   exact escape table (quotes, backslashes, all C0 controls), shortest-decimal integers,
   arbitrary nesting, and members in serialization order. Rust sorts members by UTF-16 key, and
   `ser` is injective on the sorted form.
4. **UTF-8 is injective** (`utf8_inj`), derived from Lean core's verified encoder.
5. **Hash binding** (`recordHashOf_binding`). Equal content hashes mean equal bodies, or an
   explicit collision `x ≠ y ∧ H x = H y`. `record_ne_checkpoint_hash` rules out
   record/checkpoint type confusion.

Cryptography is never axiomatised as injective. SHA-256 compresses, so that axiom would be false
and every theorem vacuous. Hash results carry an explicit collision disjunct. Ed25519
unforgeability is a hypothesis about which messages were signed. `check-axioms.sh` fails the
build if any headline theorem depends on more than Lean's three standard axioms.

Other results:

* `Seal.commitment_binding`: a hiding commitment opens to exactly one
  `(field_domain, nonce, value)`.
* `Dag.bundle_eq_closure`: under the checks `dag.rs` and `validate_chain` perform (parents
  resolve, acyclic, latest frontier equals the heads), a bundle's records are **exactly** the
  ancestor-closure, in the *signed* history, of the latest checkpoint's frontier. No omission,
  no injection. `earlier_checkpoint_closed` gives the same guarantee for every earlier frontier.
* `Chain.unique_history`: two chains that pass the checks and end in the same checkpoint hash
  are identical, or the hash has a collision. The latest signed checkpoint commits the whole
  history.

### What the model does **not** cover (trust boundary)

* **SHA-256 and Ed25519.** These are standard assumptions. `sign.rs` uses `verify_strict`.
* **NFC.** The model starts from post-NFC scalar values. NFC-equivalent inputs are
  *intentionally* the same record (RCP §4). Anything that deduplicates or authorizes on raw,
  un-normalized bytes will disagree with `content_hash`.
* **The link from each Lean definition to its Rust function.** This is checked in three ways:
  textually by `check-refinement.py`, on small inputs by Kani, and byte-for-byte by the golden
  vectors. It is not a mechanised refinement proof. To get one, translate `canon.rs`/`hashx.rs`
  into Lean with Aeneas or prove them in place with Verus (see below).
* **Offline-verifier verdict logic** (`verify.rs` Tier-B joins, capstone, key status). This is
  covered by the adversarial suite and the audit fixes, not by a proof yet. The monotonicity
  property is the natural next theorem: *deleting unsigned data (anchors, revocation data,
  disclosures) never improves the verdict*.
* **Authority evidence is not bound to the record body.** The authority preimage signs
  `(source, project_id, record_id, evidence_hash)`. For generic `human_signed` /
  `policy_engine_signed` records, nothing re-derives `evidence_hash` from the record. A holder of
  the signing key can therefore move a valid evidence triple onto a different body with the same
  `record_id` and it still reads `verified`. Closing this needs an `averin.authority.v3` preimage
  that adds a body commitment. That is a coordinated producer change and has not been made yet.

## Kani (bounded, real code)

The harnesses live next to the code (`#[cfg(kani)] mod kani_proofs` in `b64.rs`, `hashx.rs` and
`canon.rs`). `run-kani.sh` runs them with `--no-default-features` (no `getrandom`) and
`-Z stubbing`.

**Default set** (each harness finishes in seconds on a 4-core, 16 GB runner; CI runs these):

- `alphabet_is_a_bijection`: base64url `val` and `ENC` are mutually inverse over the 64 symbols,
  and every other byte is rejected.
- `hex_byte_roundtrip` and `hex_digit_is_canonical`: every byte round-trips through two
  lowercase hex digits, and each digit value has exactly one accepted spelling. Hex is written
  and read at fixed width, so `"sha256:" ‖ hex_lower(d)` is injective and canonical for every
  length. This is the `fmt` hypothesis in `Seal.lean`.
- `lp_into_frames_exactly`: `lp_into` emits exactly `uint32_be(len) ‖ b`.
- `utf16_key_order_is_exact`: member-key order is total, antisymmetric, and `Equal` only for
  equal keys.

**Extended set** (`run-kani.sh --extended`): base64 tail canonicality (non-zero trailing bits
rejected) and whole-chunk round trip, strict UTF-16 decoder
versus std, integer round trip and single spelling, `write_string` inverted by the parser, and
parser panic-freedom. These harnesses symbolically execute the full RCP parser and heap `String`
growth. On the 16 GB machine used for this work CBMC ran out of memory or passed a 25-minute
timeout, so **they are not claimed as verified**. Run them on a larger runner, or shrink them
further. The same properties are covered today by the Lean `Canon` proof over the model, the
golden vectors, the adversarial suite, and the audit's 200k-document differential fuzz.

## TLA+ (server protocols)

`tla/GrantLog.tla` models the broker_seq grant-transparency log. Allocate, seal and insert run
under `ingestMu`. Failures may lose their rollback, clients may retry or give up, and
`createCheckpoint` signs the recorded set. Each configuration fixes one implementation variant:

| Config | Variant | Result |
|---|---|---|
| `GrantLog_current.cfg` | pre-fix server (no release on error) | **violates** `AnchoredGapless`: grant A fails after allocating 1, B records 2, the checkpoint signs `{2}`, and the project fails verification forever |
| `GrantLog_release_lost.cfg` | release on error, but the Postgres DELETE can fail | **violates** `AnchoredGapless` |
| `GrantLog_failclosed.cfg` | plus fail-closed checkpoint, unconditional release | **violates** `HoleFree`: an orphaned seq, released later while higher seqs exist, becomes a permanent mid-sequence hole, so no gapless checkpoint can ever be signed again. The audit missed this; TLC found it. |
| `GrantLog_fixed.cfg` | release on error, only while the seq is still the max, plus fail-closed checkpoint | all invariants hold (3,350 states) |

`tla/ConsumeLedger.tla` models consume-before-act. Several gateways race on one ledger through
`INSERT … ON CONFLICT DO NOTHING`, release on provable non-action, and run the TTL sweep.
`AtMostOncePerKey` holds when `Retention ≥ MaxTTL`, which is the floor `main.go` enforces. With a
shorter retention, TLC finds a live key pruned mid-flight.

`tla/run-tlc.sh` runs every configuration and checks its **expected** outcome. The fixed designs
must pass, and each unsafe variant must still produce its counterexample.

## Tool choice: why not K, and why not a separate Z3 layer

* **K framework: no.** K is strongest when you need a full executable semantics for a
  *language* (KEVM for EVM bytecode, for example) and want to verify programs against it. averin
  is a Rust core plus a Go server, and neither has a production-grade K semantics. Building one
  would cost person-years and still leave the Rust↔K gap. The properties that matter here are
  about data encodings and protocols, which Lean and TLA+ express directly.
* **Z3 as its own layer: no.** Kani already hands bit-precise questions about the *actual* Rust
  to a SAT/SMT backend, which is strictly better than hand-encoding a second model in Z3. The
  unbounded facts (injectivity for all lengths and nesting depths, closure over any DAG) are
  induction proofs, which SMT does not do well. A Z3 model would be a third, unconnected copy of
  the semantics.
* **What *would* add value next:**
  1. **Aeneas** (Rust → Lean) or **Verus** for `canon.rs`, `hashx.rs`, `b64.rs` and
     `record.rs`. This replaces the textual refinement gate with a mechanised proof that the Rust
     *is* the Lean model. It is the one real gap left in the seal argument.
  2. A Lean model of the verifier verdict. Prove monotonicity under deletion of unsigned fields,
     and that the capstone implies `ok ∧ keys_externally_pinned`. This would have caught audit
     findings A and D by construction.
  3. Apalache or TLC on the checkpoint/anchor pipeline across replicas, if multi-instance
     deployment becomes supported.
