# averin formal verification

averin's product claim is Level 1 of `docs/coverage-limits.md`: *a record sealed by this key has
not been altered since, and sits in a verifiable history.* This directory holds machine-checked
evidence for the assumptions that claim rests on. There are three layers, each used where it is
strongest, plus a refinement gate that keeps them in sync with the code and a mutation suite
that keeps the gates honest.

[`claims.json`](claims.json) is the reviewable claim inventory: each entry names its implementation
or model symbols, assumptions, proof or test, supported target and recurring CI job.
`make check-claims` verifies that the referenced files, symbols and job IDs exist. This textual check
does not prove that a test covers the stated behavior or that a model refines the production code;
those claims still require review. In particular, the Lean theorems are unbounded **for the model**,
Kani proves bounded properties of selected real-code harnesses, and the Rust/Lean oracle samples a
fixed corpus. The TLA+ recovery liveness result depends on its retry and fairness assumptions.

| Layer | Tool | What it covers | Run |
|---|---|---|---|
| Unbounded proofs over a model | Lean 4 (`lean/`) | canonical-JSON injectivity, UTF-8, LP framing, domain separation of every message a key signs and every tagged or verifier-recomputed preimage (catalogue includes JSON challenges, capability tokens, raw keys, Merkle nodes, the RFC 3161 imprint string and server id derivations; untagged server-local digests are listed as out of scope), the seal theorem for a key shared across every signing role, commitment binding, DAG no-omission, checkpoint-chain uniqueness | `cd lean && lake build --wfail && ./check-axioms.sh` |
| Bounded proofs over the real Rust | Kani / CBMC (`run-kani.sh`) | base64url alphabet bijection, `sha256:<hex>` digest-string injectivity and canonicality, exact LP framing, key order equal to UTF-16 code-unit order and transitive (parser-level and base64 chunk harnesses in an extended set) | `bash formal/run-kani.sh` |
| Protocol and concurrency models | TLA+ / TLC (`tla/`) | grant-transparency log, consume-before-act ledger, and two-replica project transactions with checkpoints, ambiguous commits, crash/restart, pending grants and revocations | `bash formal/tla/run-tlc.sh` |
| Refinement gate | executable Lean oracle (`lean/Oracle`, `oracle/`) + tag inventory (`check-refinement.py`) + golden vectors | the Rust produces byte-for-byte what the Lean definitions compute (canonical JSON, escapes, integers, LP/BE framing, every preimage family, record/checkpoint hash preimages), and every Rust domain tag is a Lean family | `cd lean && lake build oracle && lake exe oracle ../oracle/inputs.json ../oracle/expected.json`, then `cargo test -p averin-decision-core --test oracle` and `python3 formal/check-refinement.py` |
| Gate regression suite | `check-mutants.sh` + `mutants/*.patch` | eight known Rust drifts, each of which must be caught by at least one gate | `bash formal/check-mutants.sh` |

## The seal, precisely

`Averin.Seal.record_seal_sound` (and `checkpoint_seal_sound`):

> A signature cannot be replayed across contexts even if roles share a key: if a record body's
> signature verifies under the pinned key, the body is **exactly** one the key holder sealed,
> unless SHA-256 has a collision.

The signer model (`Seal.HonestSigner`) lets the same key also sign checkpoints, every other
signed family with *arbitrary* field values, raw 32-byte challenge digests, and **any** message whose
first byte is not `0x00` (every seal message starts with `0x00`). That last disjunct covers the JSON
grant PoP challenge, the base64url capability-token text the broker key signs
(`broker.go::mint`, first byte `e`), the denial salt, and any unframed text added later. So the
"shared key" sentence is the theorem, not a gloss on it.
Giving two signed families the same tag breaks the build.

Everything between "signature verifies" and "same body" is proved, not assumed:

1. **Signature domain separation** (`Preimage.signed_families_disjoint`). The message families
   signed with Ed25519 are record, checkpoint, taxonomy, revocation, Merkle root, attestation,
   authority evidence, and test anchor. They are pairwise disjoint *for all field values*. A
   signature from one context can never verify in another, even if two roles share a key, so
   role-key disjointness is defence in depth. `signed_message_long` adds that, given the
   verifier's own digest validation, none of them can equal the raw 32-byte digests that the
   broker challenge families sign.
   `Catalogue.lean` covers every remaining message a key signs and every remaining tagged or
   verifier-recomputed preimage: the JSON grant PoP challenge, the capability-token text, the
   denial salt, the raw key under `cnf_kid`, the credential-binding descriptor, the RFC 3161
   imprint string,
   the `uuidV5Shaped` server ids, and the RFC 6962 Merkle leaf and node. It proves each one
   disjoint from every framed family, by first byte or by length. That argument used to live
   only in prose.
   It also proves the server ids injective *only* for NUL-free project ids and exhibits the
   collision otherwise. The server therefore rejects NUL in `project_id`, `idempotency_key` and
   `record_id`.
   Out of scope, and listed as such in `Catalogue.lean`: untagged, unsigned server-local SHA-256
   inputs that the verifier never recomputes (content addresses, witness fork id, idempotency
   digests, token comparison, cache keys). Each is compared only with a digest of its own kind.
   `check-refinement.py` sweeps every `averin.*` literal in `core/src`, `server/internal`,
   `server/cmd`, `sdk/`, `verifier/` and `web/src`, and fails unless each is a Lean family or
   catalogue tag (see "Refinement gate" below).
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
unforgeability is a hypothesis about which messages were signed. `check-axioms.sh` audits **every**
declaration in the `Averin` namespace (the script prints the count), not a hand-picked list. That
includes the oracle glue in `Averin.Oracle` (`utf8c_eq`, `recordPre_spec`, `checkpointPre_spec`),
which ties the executable oracle to the definitions in `Seal`. The build fails if any of them
depends on anything beyond `propext`, `Classical.choice` and `Quot.sound`, which also catches
`sorry` and `native_decide`, both of which are axioms. It also rejects `axiom`, `admit`,
`partial def`, `implemented_by` and `extern` tokens in `Averin/` and `Oracle/` (the oracle's JSON
decoder is fuel-bounded rather than `partial` for this reason).

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
* **The link from each Lean definition to its Rust function.** This is checked by running the
  model: the executable oracle evaluates the Lean definitions over a fixed corpus and the Rust must
  reproduce the bytes (see "Refinement gate" below). Kani adds symbolic checks on small inputs, and
  the golden vectors pin cross-implementation bytes. This is differential testing over a corpus, not
  a mechanised refinement proof: a drift the corpus does not exercise can pass. To get a proof,
  translate `canon.rs`/`hashx.rs` into Lean with Aeneas or prove them in place with Verus (see
  below).
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

## Refinement gate (CI job `formal-refinement`)

Three checks, each doing what it is good at:

1. **Executable Lean oracle.** `lean/Oracle/Main.lean` is a `lean_exe` that imports the model and
   evaluates the same definitions the theorems are about (`Canon.ser`, `Canon.escChar`,
   `Canon.serInt`, `lp`, `be32`, `be64`, `Family.msg` for every family in `Preimage.lean`, and the
   record/checkpoint hash preimages inside `Seal.recordHashOf`/`checkpointHashOf`) over
   `oracle/inputs.json`, and writes the bytes as hex to `oracle/expected.json`. CI rebuilds the
   oracle, regenerates the file and fails on `git diff`, so the committed expectations are exactly
   the model's output. `core/tests/oracle.rs` then asserts that the real Rust functions produce the
   same bytes. Preimages are compared before SHA-256 wherever the Rust exposes them (hidden `pub`
   builders in `record.rs`, `checkpoint.rs`, `commit.rs`, `sign.rs`, `authority.rs`, `anchor.rs`,
   which the hash functions themselves call). The `verify.rs` challenge builders only return
   digests, so for those the test compares against SHA-256 of the model's preimage.
   * The oracle makes the two choices the model leaves to its caller. It sorts object members by
     UTF-16 code unit (implemented independently of `canon.rs`). It encodes UTF-8 with the
     runtime's `String.toUTF8`, and `Oracle.utf8c_eq` proves that encoder equal to the model's
     `Averin.utf8`. `recordPre_spec`/`checkpointPre_spec` prove the emitted preimages are the ones
     inside `Seal`.
   * The corpus covers every C0 control, DEL, U+2028/U+2029, the U+E000..U+FFFF vs astral key
     order (where UTF-8 byte order and UTF-16 order disagree), nested empty arrays and objects,
     i64 extremes, a record with every top-level key, a checkpoint, and one sample per preimage
     family with distinct field values, so a swapped field changes bytes. The oracle fails if a
     family in the catalogue has no sample, and the Rust test fails on a family it has no
     builder for.
   * The test also checks that the verifier rejects any record or checkpoint outside the model's
     pinned `domain` and `canon_version = "rcp-1"`.
2. **Tag inventory** (`check-refinement.py`). Every domain-separation tag literal in the code must
   be a `Family` tag in `Preimage.lean` or a `Catalogue.lean` tag, and every family's tag must still
   be used. The sweep lexes `core/src`, `server/internal`, `server/cmd`, `sdk/`, `verifier/` and
   `web/src` (tests excluded): comments are dropped and every string literal is searched, including
   Go raw strings, JS template strings and literals containing `//`. A tag built at runtime cannot
   be seen textually, so the sweep rejects its pieces: every literal starting with `averin.` or
   `flightrecorder.` must be a whole versioned tag, which rules out unversioned names, format
   templates (`"averin.%s.v1"`, `format!("averin.{k}.v1")`) and split pieces (`"averin." + x`),
   unless it is allowlisted with a reason (like the OTel attribute `averin.session`). A bare
   `".v1"` literal is rejected too. This is the one check that is textual by design, and it only sees tagged
   preimages; the untagged digests are listed as out of scope in `Catalogue.lean`.
3. **Golden vectors** (`cargo test --test golden`), the committed cross-implementation contract.

## Mutation suite (CI job `formal-mutants`)

`check-mutants.sh` applies each `mutants/*.patch` to a scratch copy of the tree (`core/`, `spec/`,
`formal/` and the directories the tag inventory sweeps), runs the gates, and passes only if every mutant is killed. It first checks that every
gate passes on the unmutated tree, so a broken gate cannot count as a kill. For m3 and m4 the named
Kani harness must itself report `VERIFICATION:- FAILED`.

| Mutant | Drift | Killed by (local run) |
|---|---|---|
| m1 | authority preimage: `LP(project_id)` and `LP(record_id)` swapped | oracle |
| m2 | `write_string` drops DEL (`ser` no longer injective) | oracle |
| m3 | `utf16_cmp` replaced by byte order | Kani `utf16_key_order_is_exact`, oracle, golden |
| m4 | `lp_into` writes a 2-byte length | Kani `lp_into_frames_exactly`, oracle, golden |
| m5 | commitment preimage drops `LP(field_domain)` | oracle |
| m6 | `compute_content_hash` strips an extra field | oracle, golden |
| m7 | `verify_content_hash` stops pinning `canon_version` | oracle (pinned-constants check) |
| m8 | `verify.rs` taxonomy tag renamed | tag inventory |

A new drift class gets a new patch here before the gate that catches it is called done.

## Kani (bounded, real code)

The harnesses live next to the code (`#[cfg(kani)] mod kani_proofs` in `b64.rs`, `hashx.rs` and
`canon.rs`). `run-kani.sh` runs them with `--no-default-features` (no `getrandom`) and
`-Z stubbing`.

**Default set** (each harness finishes in under two minutes on a 4-core, 16 GB runner; CI runs
these):

- `alphabet_is_a_bijection`: base64url `val` and `ENC` are mutually inverse over the 64 symbols,
  and every other byte is rejected.
- `hex_byte_roundtrip` and `hex_digit_is_canonical`: every byte round-trips through two
  lowercase hex digits, and each digit value has exactly one accepted spelling. Hex is written
  and read at fixed width, so `"sha256:" ‖ hex_lower(d)` is injective and canonical for every
  length. This is the `fmt` hypothesis in `Seal.lean`.
- `lp_into_frames_exactly`: `lp_into` emits exactly `uint32_be(len) ‖ b`.
- `utf16_key_order_is_exact`: for every pair of keys of one or two scalars, `utf16_cmp` equals
  the lexicographic order of their UTF-16 code units, computed independently per scalar. One case
  is pinned to U+E000..U+FFFF against astral scalars, where byte order disagrees. Loops are fully
  unrolled, so a byte-order `utf16_cmp` (mutant m3) fails with a counterexample, not an unwinding
  bound.
- `utf16_key_order_is_transitive`: `a ≤ b ∧ b ≤ c ⇒ a ≤ c` for any three single-scalar keys, and
  `Equal` only for equal keys, so sorting members is well defined.

**Extended set** (`run-kani.sh --extended`): base64 tail canonicality (non-zero trailing bits
rejected), the full 4-symbol chunk (`full_chunk_is_canonical`: every accepted 4-symbol spelling
is `encode` of the 3 bytes it decodes to, which completes "every byte string has exactly one
accepted spelling" chunk by chunk; it ran out of memory under an 8 GB cap after about 12 minutes
locally because `decode`'s error path formats a `char`, which pulls Unicode tables into CBMC),
strict UTF-16 decoder
versus std, integer round trip and single spelling, `write_string` inverted by the parser, and
parser panic-freedom. These harnesses symbolically execute the full RCP parser and heap `String`
growth. On the 16 GB machine used for this work CBMC ran out of memory or passed a 25-minute
timeout, so **they are not claimed as verified**. Run them on a larger runner, or shrink them
further. The same properties are covered today by the Lean `Canon` proof over the model, the
golden vectors, the adversarial suite, and the audit's 200k-document differential fuzz.

## TLA+ (server protocols)

`tla/GrantLog.tla` models the broker_seq grant-transparency log:

- Allocate, seal and insert run under `ingestMu`.
- A commit can be *ambiguous*: the server sees an error and frees `ingestMu` while the
  transaction is still open at the database. It later lands or aborts in a separate step, so an
  operator void can interleave with it.
- Releases can be lost.
- Clients may retry or give up.
- `createCheckpoint` signs the recorded set.
- An operator may void a reserved, unrecorded seq with a signed `grant_void` tombstone. The voided
  seq stays in the allocation max, and the voided grant id is retired: a later allocation for it is
  refused (409), as in the Go server.
- Two void guards are modelled as independent switches. `AgeFromLastAttempt` is a guard on the
  void itself: its minimum age is measured from the grant's last attempt, so none of its commits
  can still be open. `UniqueIndex` is not a void guard; it acts on the landing: once a tombstone
  holds the grant's record_id, an in-flight insert of that grant can only abort. Migration 0002
  falls back to a non-unique index when a historical duplicate exists.
- The model has one global `ingestMu` and one attempt map, i.e. **one server process**. In Go the
  latest-attempt map is per process, so on a multi-replica deployment only the UNIQUE index closes
  the race; `void_index_only` is the result that carries over, `void_age_only` is not.

There is no `CONSTRAINT`: TLC's liveness checking is unsound under one. Allocation beyond a bound
is disabled inside `Begin`, and every passing config also asserts `BoundNotBinding`, so the bound
never cuts a behaviour. `run-tlc.sh` fails if a config declares a constraint or TLC warns about
one.

Each configuration fixes one implementation variant and asserts **one** outcome:

| Config | Variant | Expected result |
|---|---|---|
| `GrantLog_current.cfg` | pre-fix server (no release on error) | **violates** `AnchoredGapless`: grant A fails after allocating 1, B records 2, the checkpoint signs `{2}`, and the project fails verification forever |
| `GrantLog_release_lost.cfg` | release on error, but the Postgres DELETE can fail, no fail-closed checkpoint | **violates** `AnchoredGapless` |
| `GrantLog_failclosed.cfg` | fail-closed checkpoint, release not restricted to the max or to freshly allocated seqs | **violates** `HoleFree`: an orphan released while higher seqs exist becomes a permanent mid-sequence hole |
| `GrantLog_reuse_release.cfg` | release a seq that a retry *reused* after an ambiguous commit | **violates** `NoDuplicateSeq`: the late commit and the next grant share a seq |
| `GrantLog_void_race.cfg` | void age measured from the *allocation*, no UNIQUE index | **violates** `NoDuplicateSeq`: the first attempt fails, a retry reuses the seq and its commit is left open, the void passes the age check, the retry lands, and the seq is held by the grant and the tombstone |
| `GrantLog_void_age_only.cfg` | void age from the last attempt, no UNIQUE index (one process) | `AnchoredGapless` and `NoDuplicateSeq` hold (2.45M states) |
| `GrantLog_void_index_only.cfg` | UNIQUE index, void age from the allocation | `AnchoredGapless` and `NoDuplicateSeq` hold (2.98M states: a different graph, in which voids do race in-flight retries) |
| `GrantLog_void_backstop.cfg` | as `void_index_only`, non-vacuity | **violates** `NoVoidDuringFlight`: a grant is voided while a retry of it is in flight, and only the index stops that retry landing |
| `GrantLog_void_reachable.cfg` | shipped design, non-vacuity | **violates** `NoVoid`: the guarded void is reachable, so the passing configs exercise it |
| `GrantLog_fixed.cfg` | shipped design: release only fresh, max seqs; fail-closed checkpoint; operator void with both guards | `AnchoredGapless` and `NoDuplicateSeq` hold, exhaustively for 3 grants (2.45M states; with the age guard in force the void never races an in-flight insert, so this is the same graph as `void_age_only`) |
| `GrantLog_wedge.cfg` | no void; clients may never retry | **violates** `CheckpointRecovers`: an orphaned seq wedges checkpointing forever |
| `GrantLog_fair_retry.cfg` | no void; every client retries until it commits | `CheckpointRecovers` holds |
| `GrantLog_void_starved.cfg` | operator void; a client may retry forever with every attempt failing | **violates** `CheckpointRecovers`: each retry restarts the void's last-attempt age, so the void is never enabled |
| `GrantLog_fixed_live.cfg` | operator void; clients may give up at any point, and a grant retried forever eventually commits | `CheckpointRecovers` holds, with strong fairness on the operator and weak fairness on open transactions resolving, for 2 grants (liveness over 3 grants is too slow for CI) |

`GrantLog` retains the historical age-based recovery design and its
`GrantLog_void_starved.cfg` counterexample. The current durable protocol is
modeled separately in `tla/GrantRecovery.tla`. A supported grant transaction
owns the exact project guard; an authorized recovery inserts one immutable
fence after earlier transactions drain, then a second guarded transaction
records the landed grant or atomically inserts the void, marker and terminal
result. A failed grant may retry forever without changing the fence. Crashes
stutter after any transition, and a competing operation cannot replace the
first operator's identity. The safe config checks no duplicate sequence, no
late grant after void, a winning record for every terminal result, and eventual
resolution. That liveness result assumes open database transactions eventually
commit or abort, and the authorized operator is eventually scheduled at a
guard opening and for reconciliation. It makes no progress claim during a
permanent database outage. `GrantRecovery_old_writer.cfg` deliberately enables
an already-running pre-fence writer and finds a duplicate-sequence
counterexample; the deployment credential/session cutoff is therefore part of
the protocol, not an optional operational convenience.

`tla/ConsumeLedger.tla` models consume-before-act. Several gateways race on one ledger through
`INSERT … ON CONFLICT DO NOTHING`, release on provable non-action, and run the TTL sweep.
`AtMostOncePerKey` holds when `Retention ≥ MaxTTL`, which is the floor `main.go` enforces
(`ConsumeLedger_safe.cfg`). With a shorter retention, TLC finds the **replay**, where the
resource acts twice on one key (`ConsumeLedger_short_retention_replay.cfg`). It also finds a live
in-flight key being pruned (`ConsumeLedger_short_retention.cfg`).

`tla/ProjectTx.tla` models two replicas with separate local caches and a
database project guard. Its core safety exploration splits a record's frontier
read from commit, permits an unknown commit acknowledgement and crash/restart,
and attaches anchors only after checkpoint commit. With serialization disabled,
TLC finds `NoFrontierFork` and `NoCheckpointFork` counterexamples. Its separate
operational exploration treats revoke/use and pending/finalize as atomic project
transactions, then shows that consulting a stale replica cache violates
`NoRevokedUse` or `NoGhostFinalize`. The safe configurations check the named
safety invariants. The split avoids a product-state explosion; it does not
establish liveness, model SQL error handling, or prove code refinement. Tests
with independent PostgreSQL pools exercise the corresponding transaction order.

`tla/run-tlc.sh` runs every configuration and checks its **expected** outcome. The fixed designs
must pass, and each unsafe variant must still produce the counterexample named above. TLC is
pinned to the immutable `v1.7.4` release and verified by sha256.

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
     `record.rs`. This replaces the corpus-based oracle gate with a mechanised proof that the Rust
     *is* the Lean model. It is the one real gap left in the seal argument.
  2. A Lean model of the verifier verdict. Prove monotonicity under deletion of unsigned fields,
     and that the capstone implies `ok ∧ keys_externally_pinned`. This would have caught audit
     findings A and D by construction.
  3. Apalache or TLC on the checkpoint/anchor pipeline across replicas, if multi-instance
     deployment becomes supported.
