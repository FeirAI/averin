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
| Gate regression suite | `check-mutants.sh` + `mutants/*.patch` | known Rust drifts, each of which must be caught by at least one gate | `bash formal/check-mutants.sh` |
| Deterministic differential fuzz | `run-fuzz.sh`, `fuzz/regressions.tsv`, `core/tests/rcp_fuzz.rs` | sampled RCP lexical acceptance/rejection and canonical bytes, native C ABI parity, browser WASM parity, base64url round trips | `bash formal/run-fuzz.sh pr` |

## Reproducible RCP fuzz complement

`bash formal/run-fuzz.sh pr` runs 500 generated cases plus 21 fixed cases; the weekly
`scheduled` mode runs 5,000 generated cases. Both use seed `20260923` and Rust 1.92.0
(`rust-toolchain.toml`), `Cargo.lock`, and Bun 1.3.14. The runner emits and compares two
complete corpora for the same seed, prints their SHA-256, then replays every case through
a freshly built WASM core via the browser verifier wrapper. CI uses `ubuntu-latest`, a
40-minute job timeout, and runs PR mode on pushes and pull requests and scheduled mode
each Sunday. A regression saved in `fuzz/regressions.tsv` is checked on every run,
including its exact canonical bytes for accepted cases. Add a newly minimized input
there as UTF-8 hex with `A` or `R`
and its expected canonical UTF-8 hex (`21` for the reject marker `!`).
Set `FUZZ_SEED` to replay or explore another decimal `u64` seed locally; CI fixes the default.

The generator's valid branch uses RCP's JSON grammar, i64 endpoint literals, escaped
controls and surrogate pairs, decomposed Unicode, unsorted object keys, and arrays/objects
up to four generated levels. The invalid branch samples forbidden integer spellings,
fractions/exponents, out-of-range integers, lone surrogates, bad escapes, raw controls,
post-NFC duplicate keys, trailing data, and truncated structures. Fixed cases cover the
256/257 nesting boundary, a 16,384-byte string, and an 8,192-byte key, beyond the short
Kani symbolic inputs. Each accepted value must round-trip through parse/serialize and
match its saved expected bytes where specified; each forbidden class must reject without
panic. Every case without an interior NUL must agree with the native C-string ABI. The
browser wrapper rejects raw NUL before calling its C-string WASM export, and all other
cases must agree with the WASM canonicalizer. Random byte strings of length 0–64 also
round-trip through base64url and reject padding. These are finite sampled checks, not a
proof over arbitrary inputs or a permissive JSON parser equivalence claim; schema rules
for specific record types are outside this campaign.

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
* **Offline-verifier verdict logic** (`verify.rs` Tier-B joins, capstone, key status). `Verdict.lean`
  proves inclusion of supported claims when supporting attachments are removed while signed
  records/checkpoints, pins, policy and authenticated adverse evidence remain fixed. The Lean
  executable decider agrees with its inductive evidence rules and refutes immutable committed
  grant-ID equivocation between actual grant records for every attachment set. The production
  immutable-fact projection also includes duplicate record IDs and checkpoint project conflicts;
  those have direct bundle tests but are not encoded by `CommittedContradiction`. This is a model proof plus differential Rust oracle,
  not a mechanised refinement of the verifier's extraction passes. Independently signed adverse
  revocations, validated contradictory commitment openings and conflicting verified TSA anchors
  must be enforced while present; removing one changes the fixed adverse evidence and can
  improve a decision, so a blanket deletion theorem would be false.
* **Historical v2 authority evidence is not bound to the semantic record body.** It remains
  readable as `legacy_unbound` and retains its historical signature and join checks. The v3
  authority proof binds the structured semantic subject and is reported as `verified`; only
  that body-bound state can satisfy the stronger authorization and completeness claims.

`spec/fixtures/verdict-generated.json` is the shared end-to-end verdict corpus. Its 92 rows
store exact `bundle_json` and caller `opts_json` strings, then native Rust, cgo, and browser WASM
compare the bundle digest, all typed claims, legacy `ok`, completeness label, and violation count.
The positive inputs come from a v3 signed grant/use/PoP Rust test, a real Go two-phase capstone
export, and a real Go native grant/introspection capstone export; each generator asserts its
positive claim before emitting a fixture. The Rust `write_generated_verdict_corpus` test expands
every anchor subset in these small histories and combinations of removable attachments, including
nested Merkle paths. It also keeps the cp0-only failed-PoP intent and independently signed adverse
revocation cases. Regenerate these fixtures only with a freshly rebuilt Rust staticlib before Go
tests, then review changed expected decisions rather than accepting them automatically.

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
Kani harness must itself report `VERIFICATION:- FAILED`. The same named-counterexample rule
applies to m2, m9–m13 and m22–m24 (m14 dies to native gates only); an unwind failure, tool error,
or timeout does not count.
For m15–m21 the designated native test must complete and fail; an unrelated failure does not
kill the mutant. The optional `MUTANTS_ONLY` selection still runs the full unmutated baseline and
accepts only exact patch basenames.

| Mutant | Drift | Killed by (local run) |
|---|---|---|
| m1 | authority preimage: `LP(project_id)` and `LP(record_id)` swapped | oracle |
| m2 | `write_string` drops DEL (`ser` no longer injective) | Kani string case `string_escape_roundtrip_00128` (`"\x7f"`, confirmed on the current source), oracle |
| m3 | UTF-16 sort key of astral scalars broken (byte-order-like key) | Kani `utf16_key_order_is_exact_steered` (confirmed on final source), oracle, golden |
| m4 | `lp_into` writes a 2-byte length | Kani `lp_into_frames_exactly`, oracle, golden |
| m5 | commitment preimage drops `LP(field_domain)` | oracle |
| m6 | `compute_content_hash` strips an extra field | oracle, golden |
| m7 | `verify_content_hash` stops pinning `canon_version` | oracle (pinned-constants check) |
| m8 | `verify.rs` taxonomy tag renamed | tag inventory |
| m9 | base64url one-byte tail accepts nonzero trailing bits | Kani `one_byte_tail_is_canonical` (confirmed) |
| m10 | base64url two-byte tail accepts nonzero trailing bits | Kani `two_byte_tail_is_canonical` (pending full suite) |
| m11 | full base64url chunk writes wrong fourth symbol | Kani `full_chunk_is_canonical` (pending full suite) |
| m12 | strict UTF-16 decoder rejects one valid low surrogate | Kani `utf16_strict_matches_std` (pending full suite) |
| m13 | parser accepts negative zero | Kani shard `accepted_integer_spelling_2_minus` (confirmed on final source) |
| m14 | truncated `\u` escape check inverted | oracle, golden (native only: `parse_never_panics` is not verified; the Kani string case for `"\u0001"` under this mutant did not finish symbolic execution in 50 minutes) |
| m15 | v3 authority signature preimage drops the semantic subject digest | oracle, golden |
| m16 | capstone omits offline PoP verification | verdict differential (`capstone_4`) |
| m17 | missing pinned revocation evidence treated as clean | verdict differential (missing-freshness cases) |
| m18 | partial closure skips a failing PoP | adversarial partial-anchor regression |
| m19 | failed-PoP intent consumes its outcome | adversarial orphan-outcome regression |
| m20 | fresh Merkle root accepted without a non-membership path | verdict differential (`missing_path`) |
| m21 | disclosure completeness counts only supplied openings | two-grant adversarial regression |
| m22 | `Int(0)` serializes as `1` | Kani `integer_roundtrip_zero` (confirmed on final source) |
| m23 | numeric input takes the general parser route | Kani fail-closed route guard in `integer_roundtrip_zero` (confirmed on final source) |
| m24 | `utf16_units` preallocates half its input length | Kani fail-closed growth guard G1 in `utf16_key_order_is_transitive` (confirmed on final source) |

A new drift class gets a new patch here before the gate that catches it is called done.

## Kani (bounded, real code)

The harnesses live next to the code (`#[cfg(kani)] mod kani_proofs` in `b64.rs`, `hashx.rs` and
`canon.rs`). `run-kani.sh` runs them with `--no-default-features` (no `getrandom`); every
result must be one exact harness with `VERIFICATION:- SUCCESSFUL`, `0 of N failed` and no failed
property (`check-kani-success.py`). Unwinding assertions stay on everywhere, so a bound that is too
small fails the proof. A timeout, out-of-memory kill or interruption is a failure, never a pass.
`run-kani.sh --harness NAME` runs one named proof or shard.

**Sharded families.** Where one harness is too large for CBMC, the original domain is split into
disjoint shards that all call one unchanged assertion body. `check-kani-shards.py` (spelling and
key order) and `check-kani-domains.py` (integers) parse the actual shard tables from the source,
pin the shared bodies and macros (no extra assumption or stub), and enumerate the original domain
to prove every input lies in exactly one shard. `run-kani-shards.sh FAMILY` runs every shard,
records `PASS`/`FAIL` per shard against a digest of the proof sources (so an interrupted batch
resumes without trusting stale results), and fails unless every shard passes.

**Replacements in proofs.** No reachable parser, NFC or target function is replaced. Exactly three
replacements exist, each attached with `#[kani::stub]` only to the named harnesses below;
`check-kani-shards.py` pins their bodies and attachment sites and `check-kani-success.py` requires
each harness to report exactly its allowlisted stub lines:

- *Numeric route guard* (integer harnesses): the top-level general parser, which a numeric spelling
  never reaches, is replaced by an unconditional panic. The numeric entry, number scanner,
  trailing-data check and serializer stay production code. Mutant m23 (numeric input forced onto
  the general route) must hit the guard.
- *A1, a std-permitted behavior selection* (integer harnesses and string cases): `<*const u8>::align_offset`
  returns `usize::MAX`. std documents that "it is permissible for the implementation to always
  return `usize::MAX`. Only your algorithm's performance can depend on getting a usable offset
  here, not its correctness." The proofs therefore cover std's UTF-8 validator on its
  byte-at-a-time path; the word-at-a-time fast path (documented to give the same result) and its
  internal panic-freedom stay inside the trusted Rust std boundary. Without A1, CBMC treats the
  heap alignment as symbolic and `String::from_utf8` in `serialize()` (and the string
  adapter's `from_utf8`) does not finish, even on concrete data.
- *G1, a fail-closed std-path guard* (key-order harnesses): `Vec::push` asserts
  `len < capacity` and then runs exactly std's non-growth branch (write at `len`, set the length to
  `len + 1`). It supplies no behavior std would not; a push that would reallocate is a
  counterexample. `utf16_units` preallocates `with_capacity(s.len())` and never needs more (native
  test `utf16_units_fit_their_preallocation`); mutant m24 halves that capacity and must hit the
  guard. The proofs rely on std's semantics for the non-growth path.

`#![cfg_attr(kani, feature(allocator_api))]` in `core/src/lib.rs` exists only so G1 can name
`Vec<T, A>`; production builds are unchanged.

**Default set** (CI job `formal-kani`, `bash formal/run-kani.sh`; measured with Kani 0.68.0 /
CBMC 6.11 on a 10-core, 24 GB host, one solver at a time):

- `alphabet_is_a_bijection`: base64url `val` and `ENC` are mutually inverse over the 64 symbols,
  and every other byte is rejected.
- `hex_byte_roundtrip` and `hex_digit_is_canonical`: every byte round-trips through two
  lowercase hex digits, and each digit value has exactly one accepted spelling. Hex is written
  and read at fixed width, so `"sha256:" ‖ hex_lower(d)` is injective and canonical for every
  length. This is the `fmt` hypothesis in `Seal.lean`.
- `lp_into_frames_exactly`: `lp_into` emits exactly `uint32_be(len) ‖ b`.
- `utf16_key_order_is_exact` (family, G1): for every pair of keys of one or two arbitrary scalars,
  `utf16_cmp` (the production `utf16_units` plus `units_lt`) equals the lexicographic order of
  their UTF-16 code units computed independently by `char::encode_utf16`. Four shards, one per
  pair of scalar counts (1 or 2 per key), plus `utf16_key_order_is_exact_steered`, which pins
  U+E000..U+FFFF against astral scalars where byte order disagrees (mutant m3 fails there with a
  counterexample). 279 s wall for all five, peak 3.6 GB.
- `utf16_key_order_is_transitive` (G1): `a ≤ b ∧ b ≤ c ⇒ a ≤ c` for any three single-scalar keys,
  and `Equal` only for equal keys. 142 s, peak 4.0 GB.

**Extended set** (`run-kani.sh --extended`; CI job `formal-kani-extended`, one matrix job per
harness or family):

- `one_byte_tail_is_canonical`, `two_byte_tail_is_canonical`, `full_chunk_is_canonical`: base64
  tails reject non-zero trailing bits, and every accepted 4-symbol spelling is `encode` of the 3
  bytes it decodes to, over the full 2-, 3- and 4-symbol domains (about 5 s each).
- `utf16_strict_matches_std` (kissat): `decode_utf16_strict` agrees with std's strict decoder on
  every 1- and 2-unit sequence. 1,641 s wall and 7.9 GB peak on an idle host; 5,796 s wall and
  6.6 GB peak for the final-source rerun on a loaded host (load average 15-23).
- `integer_roundtrip` (numeric guard, A1): for every `n` in [-99,999, 99,999] the typed parser
  returns exactly `Int(n)` for `n.to_string()` and `serialize()` restores that spelling. The
  original unsplit harness runs in 118-142 s, peak under 6.3 GB (process-group maximum). Its eleven checked sign/decimal-width
  shards remain available through `--harness` (the zero shard is the m22/m23 detector).
- `accepted_integer_spelling` (family): every numeric literal of 1..=4 bytes over
  `0-9 - + . e E` that the parser accepts is in canonical form (no leading zero, no `-0`, no sign
  `+`, fraction or exponent). 60 shards, one per concrete (length, first byte), with the other
  bytes symbolic over the whole alphabet, plus the lemma `spelling_alphabet_is_exact`. 757 s wall
  for all 61 on an idle host (834 s on the final-source rerun), peak under 1 GB. Mutant m13 (`-0` accepted) fails `accepted_integer_spelling_2_minus`.
- `string_escape_roundtrip` (family, A1): `write_string` never emits a raw control byte and the
  real parser (real NFC included) returns exactly `Str(s)` for every string `s` of at most two
  scalars, each any ASCII scalar, U+00E9 or U+1F600: 1 + 130 + 130² = 17,031 strings. With a
  symbolic byte, CBMC's symbolic execution cannot fix the escaper's output length or the
  parser's cursor and does not finish (a single symbolic printable-ASCII byte times out after
  400-500 s even with A1 and growth guards), so the domain is checked exhaustively: one harness
  per concrete case id of `string_proof_case`. `gen-kani-string-cases.py` generates the table
  `core/src/kani_string_cases.rs`; `check-kani-shards.py` regenerates and compares it, pins the
  mapping and case body, and re-derives the domain to prove each string occurs exactly once; the
  native test `string_proof_cases_are_exactly_the_domain` checks the Rust mapping itself.
  Measured per case: about 6 s of CBMC for ASCII strings (125 s for 10 cases in one invocation
  including the build), about 30 s for strings mixing U+00E9 or U+1F600 with other scalars;
  the pair U+1F600 U+1F600 (case 17030) was still in symbolic execution of NFC's
  decomposition sort after a 60-minute wall limit (3,265 s CPU, 2.4 GB peak). A 20-case smoke
  run across every class passed 19 cases; case 17030 did not finish. **The full 17,031-case run has not been performed yet**; it is
  scheduled once, on the final parser, and is not claimed until every case reports success.
  `run-kani-shards.sh string_escape_roundtrip` runs it with resume; `KANI_SHARD_GROUP=64` batches
  cases per Kani invocation and `KANI_SHARD_SLICE=I/26` selects a CI matrix slice.
- `parse_never_panics` is **not verified and not run by any gate**. Its original domain is every
  valid UTF-8 string of 0 to 5 bytes (`raw: [u8; 5]`, any `len <= 5`, parsed only when
  `from_utf8` succeeds), with real NFC. Concrete enumeration is impossible (at least 128^5,
  about 3.4 × 10^10, strings), and symbolic bytes defeat CBMC's symbolic execution: once a byte
  is symbolic the parser cursor becomes symbolic and every route is explored. Measured with A1:
  three symbolic ASCII bytes did not finish symbolic execution in 580 s (1.7 GB), nor did five;
  `Parser::parse_string` alone on a symbolic 5-byte state timed out after 900 s (1.4 GB), while
  the leaf `Parser::next_utf8_char` is panic-free for every state (8 s). Function contracts cannot
  split `parse_string` (its byte loop, escapes, UTF-16 decoding and NFC share one function), and
  a hand-written `kani::Arbitrary` for `CanonValue` would be unsound. The harness stays in the
  tree unchanged; unbounded parser panic-freedom is being pursued through the Aeneas/Lean
  toolchain instead. Mutant m14 (a truncated `\u` escape check inverted) dies to native gates only.

**Resources and timeouts.** On a shared workstation run proofs under `kani-watchdog.sh`, which
kills the whole process group (cargo, CBMC and CBMC's external SAT solver, whose process is
named after its CNF file) on an RSS limit (default 12 GiB), low host free memory (default 20%)
or a wall limit. A kill is a resource failure, never a proof or a counterexample. A plain
`timeout` around `run-kani.sh` is not enough: it can leave CBMC running. Solver time varies
several-fold with host load: `utf16_strict_matches_std` took 1,641 s on an idle host and
5,796 s at load average 15-23, and its mutation-suite baseline exceeded a 7,200 s limit under
heavier load before passing with 21,600 s. CI jobs therefore keep generous explicit timeouts
(the job limit is the backstop), and a timeout is always a failure.

The Lean model, golden vectors, adversarial tests and the deterministic fuzz campaign complement
these bounded claims; none makes an unverified Kani harness verified.

## TLA+ (server protocols)

`tla/GrantLog.tla` models the historical broker_seq grant-transparency log
and its pre-fence age-based recovery design:

- Allocate, seal and insert run under its modeled `ingestMu`.
- A commit can be *ambiguous*: the server sees an error and frees `ingestMu` while the
  transaction is still open at the database. It later lands or aborts in a separate step, so an
  operator void can interleave with it.
- Releases can be lost.
- Clients may retry or give up.
- `createCheckpoint` signs the recorded set.
- An operator may void a reserved, unrecorded seq with a signed `grant_void` tombstone. The voided
  seq stays in the allocation max, and the voided grant id is retired: a later allocation for it is
  refused (409).
- Two void guards are modelled as independent switches. `AgeFromLastAttempt` is a guard on the
  void itself: its minimum age is measured from the grant's last attempt, so none of its commits
  can still be open. `UniqueIndex` is not a void guard; it acts on the landing: once a tombstone
  holds the grant's record_id, an in-flight insert of that grant can only abort. Migration 0002
  falls back to a non-unique index when a historical duplicate exists.
- The model has one global `ingestMu` and one attempt map, i.e. **one historical server process**.
  The current Go protocol uses a persisted project guard and fence instead. The old model remains
  useful because it exhibits the starvation and unsafe-writer counterexamples that motivated the
  replacement.

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
| `GrantLog_void_reachable.cfg` | historical age-based design, non-vacuity | **violates** `NoVoid`: the guarded void is reachable, so the passing configs exercise it |
| `GrantLog_fixed.cfg` | historical age-based design: release only fresh, max seqs; fail-closed checkpoint; operator void with both guards | `AnchoredGapless` and `NoDuplicateSeq` hold, exhaustively for 3 grants (2.45M states; with the age guard in force the void never races an in-flight insert, so this is the same graph as `void_age_only`) |
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
  2. Prove the production verifier's evidence-pass-to-fact projection refines `Verdict.lean`;
     the current executable corpus is differential, not a universal source-level proof. The
     capstone intentionally requires externally pinned signer and role provenance while legacy
     `ok` remains a separate integrity/diagnostic Boolean.
  3. Apalache or TLC on the checkpoint/anchor pipeline across replicas, if multi-instance
     deployment becomes supported.
