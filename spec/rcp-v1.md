# Record Canonical Profile (RCP) v1

`canon_version: "rcp-1"`

The single, language-agnostic definition of how a record/checkpoint body is turned into
the exact bytes that get hashed and signed. The Rust `decision-core` is the reference
implementation; the WASM build and verify CLI compile from that same crate. The golden
vectors in `/spec/golden-vectors/` are the byte-for-byte contract every implementation
(present and future, any language) MUST reproduce. **Defends threat #10 (verifier skew).**

RCP v1 is a *constrained superset of JCS (RFC 8785)*: it adopts JCS serialization and adds
rules JCS leaves open (exact integer range, NFC, post-NFC duplicate-key rejection,
a closed top-level record key set, algorithm-prefixed digests, explicit domain separation).

> **Unknown fields: what averin enforces.** averin's verifier enforces a closed set of
> TOP-LEVEL record keys (an unknown top-level key, or a missing required one, fails the record).
> It does not allow-list nested objects (`authority`, `key`, `content`, `tokens`, the
> `*_commit` blocks) or checkpoint members: the JSON Schemas declare `additionalProperties: false`
> for them, but the schemas are advisory and the core does not run them. A nested member the
> verifier does not recognise is still bound by `content_hash` (for a checkpoint, by
> `checkpoint_hash`), so it cannot be altered after sealing; it is just not rejected on sight.

> **Authority of this profile over the JSON Schema.** The JSON Schemas in `/spec/*.schema.json`
> document *structure*; they CANNOT express RCP rules and MUST NOT be treated as sufficient
> validation. In particular JSON Schema `type: integer` accepts `1.0` / `1e0`, which RCP
> rejects. A conforming implementation MUST run the RCP **lexical** parse (this document)
> first; the schema is advisory.

---

## 1. Canonical value model

A canonical body is a JSON object restricted to these value kinds:

| Kind | Allowed | Notes |
|------|---------|-------|
| object | yes | keys are strings; **duplicate keys invalid** — see §5 (checked *after* NFC) |
| array | yes | order preserved (arrays are ordered data, never re-sorted) — see §7 |
| string | yes | valid Unicode scalar values only; **NFC-normalized**; §4 escaping |
| integer | yes | **signed 64-bit**, exact range — see §3 |
| boolean | yes | `true` / `false` |
| null | yes | **`absent` ≠ `null`** — see §6 |
| **float / number with fraction or exponent** | **NO** | parse error (threat #10). Money is integer micros. |

## 2. Serialization (JCS-based)

1. UTF-8 output, **no insignificant whitespace** (no spaces/newlines between tokens).
2. Object member keys sorted ascending by **UTF-16 code-unit** lexicographic order
   (RFC 8785 §3.2.3): compare the `u16` sequences of `key.encode_utf16()` element-wise; the
   shorter sequence sorts first when one is a prefix of the other. Equal keys cannot occur
   (duplicates already rejected, §5).
3. Arrays serialize in their existing element order — never sorted (§7).
4. No trailing commas; member separator `,`; key/value separator `:` (no surrounding space).

## 3. Numbers — integers only, signed 64-bit

* Every number in a signed body MUST be an integer literal. Any literal containing `.`, `e`,
  or `E`, or any non-integer JSON number, is a **parse error**.
* **Exact range:** `[-9223372036854775808, 9223372036854775807]` (signed 64-bit, i64). A value
  outside this range is a **parse error** — there is no "arbitrary precision" mode in RCP v1.
  (`cost_micros_usd` up to ~$9.2e12 fits; ample for Phase 1.) The reference core may use a
  wider integer type for intermediate arithmetic but MUST reject out-of-range values before
  hashing. TypeScript/JS SDKs MUST serialize these via `BigInt` (not `number`) to avoid f64
  precision loss above 2^53.
* Canonical integer text: optional leading `-` for negatives, then the shortest decimal digit
  string with **no leading zeros** (`0` is `0`, never `-0` or `00`), **no `+`**, **no decimal
  point**, **no exponent**.
* Non-canonical integer spellings are **rejected on parse** (fail-closed), not silently
  re-normalized: `00`, `01`, `-01`, **and `-0`** are all parse errors. (Zero is written `0`.)

## 4. Strings

* String values and keys MUST be valid Unicode (only Unicode **scalar values**). A JSON string
  containing an **unpaired surrogate** escape (`\uD800`–`\uDFFF` without a valid pair) or any
  encoding that does not decode to scalar values is a **parse error** (do not substitute
  U+FFFD).
* All string values and keys are Unicode **NFC-normalized**. The pipeline order is fixed:
  **JSON unescape → validate scalar values → NFC-normalize → (then) duplicate-key check (§5) →
  UTF-16 key sort (§2) → escape (below)**.
* Escaping is JCS-minimal: escape only `"` → `\"`, `\` → `\\`, and the C0 controls
  `U+0000..U+001F`. Use the short escapes `\b \t \n \f \r` where defined; all other controls
  use lowercase `\u00xx`. **Every other code point is emitted literally as UTF-8** (no
  `\uXXXX` for non-ASCII, no forward-slash escaping).

### 4.1 Input grammar and limits (averin behaviour)

These are the limits of averin's parser and verifier, stated so an independent implementation can
match them or knowingly differ:

* JSON insignificant whitespace (space, tab, LF, CR) is tolerated around tokens on input; it is
  never emitted (§2). Any data after the top-level value is a parse error.
* A raw control byte (below U+0020) inside a string is a parse error, as is any backslash escape
  that JSON does not define.
* Nesting of more than 256 levels of arrays and objects is a parse error.
* A bundle larger than 256 MiB (268435456 bytes) is refused before parsing, with a failing report.
* Ed25519 verification is strict (`verify_strict`): a signature whose scalar is not canonical, or
  whose public key or `R` component is small-order, is rejected. A public key that does not decode
  to a curve point is rejected when loaded.
* base64url decoding (§8) rejects padding, characters outside the URL-safe alphabet, a length
  that is 1 modulo 4, and non-zero trailing bits, so a byte string has exactly one accepted
  encoding.

## 5. Duplicate keys (checked after NFC)

* Within any single object, duplicate member keys are **invalid** and MUST cause a parse error.
* The check is performed **after** JSON unescaping and NFC normalization (§4): if two raw keys
  normalize to the same NFC string (e.g. `"é"` and `"é"`), the object is **rejected** —
  not collapsed, not last-write-wins. This applies recursively to every nested object.

## 6. Absence vs null

* A field that is *semantically not present* is **omitted** from the body.
* A field that is *present with an explicit null value* serializes as `null`.
* These are distinct and produce different bytes. Schemas declare, per field, whether `null`
  is meaningful (e.g. `parent_span_id: null` = "explicitly a root span") or whether the field
  must be omitted when absent. Implementations MUST NOT coerce one into the other.

## 7. Arrays, and "set" fields

* RCP never reorders arrays. Some schema fields are *semantically sets* (e.g.
  `causal_prev_hashes`, checkpoint `frontier`). To keep them deterministic, **the schema
  requires those fields to already be sorted ascending by byte order and de-duplicated** before
  canonicalization; a set field that is unsorted or contains duplicates is a schema violation
  (the producer must normalize it). RCP itself applies no reordering — it only serializes.
* **averin today.** The rule above binds producers, and averin's recorder meets it: the server
  discards any caller-supplied `causal_prev_hashes` and seals the sorted, de-duplicated union of the
  session's current heads (plus any parent the server itself forces, such as the intent a use outcome
  must link to), and checkpoint frontiers are sorted and de-duplicated when they are built.
  averin's verifier does not currently reject an unsorted or duplicated set. It treats a record's
  parents as a set (duplicates collapsed) and compares the latest checkpoint's `frontier` with the
  DAG heads as sets. A stricter independent verifier MAY reject such input.

## 8. Algorithm agility

* Every hash and signature is **algorithm-prefixed** (multicodec-style):
  `sha256:<lowercase-hex, exactly 64 chars>`, `ed25519:<base64url-no-pad, decodes to exactly
  64 bytes>`. Ed25519 public keys: `ed25519pub:<base64url-no-pad, exactly 32 bytes>`.
* Verifiers select the primitive from the prefix and MUST reject malformed length/encoding;
  unknown prefix ⇒ explicit "unsupported algorithm" failure (never a silent pass).
  averin's verifier reports a missing or unknown signature or key prefix as a bad-prefix error
  (`missing/incorrect algorithm prefix`), not under a separate "unsupported algorithm" name. It
  is still a failure and never a pass.

## 9. Domain separation & the hash/sign preimages

`content_hash` and `sig` are **excluded** from the canonical body (you cannot hash a field that
contains its own hash). Define two length-prefix helpers (length-prefixing prevents
delimiter-injection ambiguity):

```
LP(s)  = uint32_be( byte_len(utf8(s)) )  ‖ utf8(s)      // for strings
LB(b)  = uint32_be( byte_len(b) )        ‖ b            // for raw byte strings
```

### 9.1 Record `content_hash`

```
body'      = record object with keys "content_hash" and "sig" removed
canon      = RCP-serialize(body')                       // §2–§7
preimage   = LP(domain) ‖ LP(canon_version) ‖ canon     // domain, canon_version ∈ body'
content_hash = "sha256:" ‖ lowerhex( SHA-256(preimage) )
```

A verifier recomputes `content_hash` and additionally checks that the `domain` /
`canon_version` it bound into the preimage equal the values inside `body'` (mismatch ⇒ fail).
This is not redundant: it makes the bound context cryptographically inseparable from the
declared context, so a body cannot be reinterpreted under a different profile/domain.

### 9.2 Record `sig`

```
sig_preimage = LP("averin.record.sig.v1") ‖ utf8(content_hash)
sig          = "ed25519:" ‖ base64url_nopad( Ed25519-sign(sk, sig_preimage) )
```

Signing the `content_hash` (a collision-resistant commitment to the whole body) under a
distinct signing-domain tag separates the signing context from the hashing context and
prevents a `content_hash` from being replayed as some other signed message.

### 9.3 Hiding commitments (low-entropy fields — threat #6)

```
nonce       = exactly 32 random bytes (revealed only on selective disclosure)
field_domain ∈ { "input", "output", "rationale", "credential" } // CLOSED registry; derived from the
                                                        // containing field (input_commit→"input";
                                                        // "credential" is the broker grant descriptor,
                                                        // ADR 0004 D1)
value_bytes = the exact octet sequence of the field content as stored in the content store;
              for an inline text value, NFC-normalized UTF-8 of the string
commitment  = "sha256:" ‖ lowerhex( SHA-256(
                 LP("averin.commit.v1") ‖ LP(field_domain) ‖ LB(nonce) ‖ LB(value_bytes) ) )
```

Nonce and value are bound as **raw byte strings** (`LB`), never re-encoded to base64 first, so
there is no encoding ambiguity. Disclosure reveals `(value_bytes, nonce)`; the verifier
recomputes and matches. Hashes are for integrity, never secrecy — sensitive content is
additionally protected by encryption + access control.

**Disclosure wire form (averin).** A bundle MAY carry a top-level `disclosures` array (absent or
`null` means none). Each entry is `{record_id, field, value_b64, nonce_hex}`:

* `field` is one of the closed `field_domain` values (`input`, `output`, `rationale`, `credential`);
* `value_b64` is the disclosed `value_bytes`, base64url without padding (§8 decoding rules);
* `nonce_hex` is the 32-byte nonce as exactly 64 lowercase hex characters.

The verifier decodes `value_b64` to octets and feeds them to the commitment unchanged. No NFC
normalization is applied to disclosed octets; NFC applies only when the recorder derives
`value_bytes` from an inline string. The record named by `record_id` must carry a
`<field>_commit.commitment` to match against. A second entry for the same `(record_id, field)`
pair is rejected, and a revealed value that does not match its commitment fails the bundle.

### 9.4 Checkpoint `checkpoint_hash` / `sig`

A checkpoint body carries its own `schema_version: "2"`, `canon_version: "rcp-1"`, and
`domain: "flightrecorder.checkpoint.v2"`. The `anchor` block, `checkpoint_hash`, and `sig` are
**excluded** from the body before hashing (the anchor is filled in *after* signing). Otherwise
identical to §9.1/§9.2 with the checkpoint `domain` and sig tag `"averin.checkpoint.sig.v1"`.

---

## 10. Frontier checkpoints — deterministic definition

Let `R` = the set of all Decision Records of one project committed up to (and including) a
checkpoint, keyed by `content_hash` (duplicates by content_hash collapse to one — threat #8).

* **head:** a record whose `content_hash` does **not** appear in the `causal_prev_hashes` of
  any record in `R`.
* **`frontier`** = the `content_hash`es of all heads, **de-duplicated and sorted ascending by
  byte order** of the ASCII `sha256:<hex>` string (§7 set rule).
* **`record_count`** = `|R|` (count of distinct `content_hash`es). Monotonic non-decreasing
  across checkpoint sequence.
* **`checkpoint_seq`** = per-project monotonic counter starting at `0`, incrementing by exactly
  `1`; **no gaps, no duplicates**.
* **`prev_checkpoint_hash`** = the previous checkpoint's `checkpoint_hash` (`null` only for
  `checkpoint_seq == 0`), forming a hash-linked checkpoint chain.

### 10.1 Verification algorithm (offline, given records + full checkpoint history + tokens + keys)

1. **Records:** recompute each `content_hash`; verify `sig` against the key valid for its
   `key_epoch`; collapse duplicate `content_hash`es.
2. **DAG:** every `causal_prev_hash` MUST resolve to a present record; the graph MUST be
   acyclic. A missing parent ⇒ *omission detected*. (Segment mode: a bundle that carries a `segment`
   member, a month of history with a base checkpoint, does not reject a parent that is absent from
   its records. A parent that is a member of the base checkpoint's frontier resolves to that base;
   any other absent parent is counted as an earlier-month reference and reported, and for a
   segment with a base the report then lists record completeness as not evaluated.)
3. **Checkpoint chain:** in `checkpoint_seq` order, recompute each `checkpoint_hash`; verify
   `sig`; verify `prev_checkpoint_hash` continuity and that `checkpoint_seq` increases by
   exactly 1 with no gaps; verify `record_count` is non-decreasing.
4. **Frontier soundness (threat #1, omission):** every `content_hash` in every checkpoint's
   `frontier` MUST resolve to a present record. A frontier head missing from the bundle ⇒
   *omission detected*. Recompute the head-set of the present records and confirm it is
   consistent with the latest checkpoint's `frontier`.
5. **Anchor (threats #3, #1):** for each checkpoint, verify its external-anchor token binds the
   `checkpoint_hash` and extract the anchor time `T`; `T` MUST be non-decreasing with
   `checkpoint_seq`. A backdated record cannot precede an anchor that already committed a
   frontier without it. The exact anchor inputs and averin's semantics are in §10.1.1.
6. **Fork detection (threat #2) — and its honest limit:** two checkpoints from the same project
   with the same `checkpoint_seq` but different `checkpoint_hash`, or two sharing the same
   `prev_checkpoint_hash`, signed by the same key, are a **fork**. This is detectable **only if
   both chains are observed** — e.g. via the customer-controlled, object-locked **witness copy**
   (which is append-only and outside vendor control). A verifier given only one internally
   consistent chain CANNOT detect that a *parallel* chain was suppressed. This is the stated
   limit of single-key self-host (threat #15); the witness/anchor is what closes it, partially.

#### 10.1.1 Anchor schemes and semantics (averin verifier)

An anchor block carries `scheme` and `token_b64` (base64url without padding, §8, for both schemes).
Two schemes exist.

* **`rfc3161`.** `token_b64` is a DER RFC 3161 TimeStampToken. It is checked against a DER
  `SubjectPublicKeyInfo` of the TSA that the auditor pinned out of band. The token's
  `messageImprint` MUST be SHA-256 over the ASCII text of the prefixed checkpoint hash, that is
  the 71 bytes `sha256:<64 lowercase hex>`, and NOT over the raw 32-byte digest. The anchor time
  `T` is the token's `genTime` truncated to whole seconds and written
  `YYYY-MM-DDThh:mm:ss.000Z`. The anchor block's own `anchored_ts` is not used for this scheme.
  Token verification is compiled in only with the `rfc3161` build feature; a build without it
  reports every `rfc3161` anchor as unsupported, which is a failure, never a pass.
* **`test-anchor`.** `token_b64` is a 64-byte Ed25519 signature by a TSA key pinned out of band,
  over `LP("averin.anchor.v1") ‖ LP(checkpoint_hash) ‖ LP(anchored_ts)` (`LP` as in §9, with
  `checkpoint_hash` the prefixed string and `anchored_ts` the block's own string). `T` is the
  block's `anchored_ts`. The producer also writes a `tsa_key_id` member; the verifier does not
  read it and simply tries each pinned TSA key. In code this scheme is described as a hermetic
  scheme for fixtures and development, and averin's recorder produces only `rfc3161` anchors.
  The verifier does not refuse `test-anchor` in any mode: whenever an Ed25519 TSA key is pinned,
  a valid `test-anchor` is accepted like any other anchor. An auditor therefore must not pin a
  test TSA key in a real audit.
* Any other `scheme` value fails.

Semantics as implemented:

* Anchors are optional. A checkpoint with no anchor, or a bundle verified with no TSA key pinned,
  is not a verification failure: the anchor is simply not verified (the report counts anchors
  attached separately from anchors verified), and everything that needs a verified anchor (the
  §10.2 anchored-before rule, anchored-time freshness checks) is unavailable, so trust is lower.
* Anchors are verified only when TSA keys are pinned (Ed25519 keys for `test-anchor`, SPKIs for
  `rfc3161`), and only on a checkpoint whose own hash and signature verified. An anchor that is
  present but fails to verify under the pinned TSA trust is reported as an issue and fails the
  verdict; it is not silently ignored.
* Only verified anchors are compared for time order. Their times MUST be canonical
  `YYYY-MM-DDThh:mm:ss.mmmZ` UTC timestamps (a non-canonical time is a failure), and a decrease
  across increasing `checkpoint_seq` is reported as backdating. Checkpoints without a verified
  anchor are skipped, so partial anchoring cannot cause a false ordering failure.
* An anchor on a later checkpoint also dates what that checkpoint commits: every record in the
  causal closure of its `frontier`, and every earlier checkpoint reachable through the
  `prev_checkpoint_hash` chain.
* A pinned Ed25519 TSA key that the auditor marks `compromised` or `revoked` never has its anchors
  honored; a `rotated` key's anchors are honored only for times at or before the rotation. (Pinned
  RFC 3161 SPKIs carry no such lifecycle.)

### 10.2 Key-epoch & compromise semantics (enforceable form)

The `key` block records `key_epoch`, validity window, `key_status`
(`active|retired|revoked|compromised`), and — when status is `revoked`/`compromised` — a
`status_changed_at` timestamp that MUST itself be attested (`key_attestation_ref`, e.g. an
anchored key-status statement). Verifier rule that is actually enforceable from the fields:

> A record signed by a `compromised` (or `revoked`) key is trustworthy **only if** there
> exists an anchored checkpoint whose external-anchor time `T ≤ status_changed_at` that
> transitively commits the record's `content_hash` (i.e. the record was sealed and externally
> anchored *before* the compromise). Otherwise the record is reported as **untrusted**
> (integrity-of-bytes may still verify, but provenance is not trustworthy).

Without `status_changed_at` + an anchor predating it, a compromised-key record MUST be reported
untrusted — never silently passed.

**averin today.** The producer requirements above stand. averin's verifier does not read
`key_valid_from`, `key_valid_until`, `key_attestation_ref` or `rotation_prev_key_sig`, so a record
signed outside its stated validity window is not rejected on that basis, and `status_changed_at` is
not checked against any attestation. What it does:

* The status, and its time, come from the bundle's `keys[]` entry (`key_status`,
  `status_changed_at`) and, when the auditor pins signing keys, from the pinned key list. Under
  pinning the bundle's own `status_changed_at` is ignored, so a bundle cannot future-date a
  compromise.
* The effective status is the worst of the record's `key.key_status`, the bundle entry's and the
  pin's, ranked `active` < `retired` < `revoked` < `compromised` < anything else.
* `retired` is treated like `active`. A missing or unrecognised status counts as `unknown`, the
  worst rank, and the record is reported untrusted. (A `keys[]` entry that omits `key_status`
  defaults to `active`; a record whose own `key` block omits it counts as `unknown`.)
* Rotation is verified through separate signed `key_rotations` statements, which extend a pinned
  key set, not through `rotation_prev_key_sig`.

### 10.3 Bundle layout and trust roots (averin verifier)

averin's verifier reads these members of the top-level bundle object: `project_id`, `keys`,
`records`, `checkpoints`, `disclosures` (§9.3), `key_rotations` and `segment`, plus optional
members for higher-level claims (`revocation_list`, `revocation_merkle_root`, `revocation_proofs`,
`deployment_attestation`, `coverage_manifest`). Each `keys[]` entry is read for `signing_key_id`,
`key_epoch`, `public_key`, `key_status` and `status_changed_at`. Pinned trust roots and policy
(signing keys, TSA keys, authority keys, claim requests) are not bundle members: the verifier takes
them as a separate options object beside the bundle. The field-level definition of the bundle is the
implementation (`core/src/verify.rs`); it is not yet specified in this document.

**Trust model.** With no externally pinned signing keys, the verifier trusts the bundle's own
`keys[]`. The report then says `keys_externally_pinned=false`, and the headline is `CONSISTENT`
(the requested claim holds only under the bundle's own, unpinned keys) rather than `PASS`. An outside verifier that wants independence from the bundle's producer MUST
pin keys (and TSA keys) obtained out of band.

---

## 11. Golden vectors

`/spec/golden-vectors/` holds these files, which the Rust test suites (and, for the broker
preimages, the Go server tests) read:

* `canon.json`: seven canonicalization cases (key ordering including a supplementary-plane
  character, integer boundaries, `null` versus absent, string escaping, NFC, nested `extensions`),
  each with the input, its hex, the canonical bytes and their hex.
* `record-basic.json`: a Decision Record body, its canonical bytes and its `content_hash` (§9.1).
* `record-sealed.json`: a sealed record (a full Decision Record with `sig`).
* `sign-vectors.json`: a fixed Ed25519 test seed, the record body, `content_hash`, `sig` and a
  hiding commitment (§9.2, §9.3).
* `authority-subject-v3.json`, `authority-sdk-v3.json`: the authority subject digest and preimage
  (see `authority-subject-v1.md`).
* `broker-preimages.json`: broker-side preimages and roots (grant PoP v2, use PoP, cosignature,
  delegation, introspection, federation, revocation, grant-log head); see `grant-pop-v2.md`.
* `revocation-v2.json`: revocation leaf, state and tree cases.

The vectors are positive cases. The rejection cases (out-of-range integer, duplicate key including
post-NFC duplicates, unpaired surrogate, non-canonical integer spellings) and the checkpoint-chain
cases (frontier omission, forks, a broken `prev_checkpoint_hash` link) are exercised in the Rust
test suites under `core/tests/` and in the unit tests of `core/src/`, not shipped as vectors. A
conforming implementation MUST reproduce the vectors byte for byte; the rejection rules of §1 to
§5 apply whether or not a vector exists for them.
