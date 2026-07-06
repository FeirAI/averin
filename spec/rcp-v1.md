# Record Canonical Profile (RCP) v1

`canon_version: "rcp-1"`

The single, language-agnostic definition of how a record/checkpoint body is turned into
the exact bytes that get hashed and signed. The Rust `decision-core` is the reference
implementation; the WASM build and verify CLI compile from that same crate. The golden
vectors in `/spec/golden-vectors/` are the byte-for-byte contract every implementation
(present and future, any language) MUST reproduce. **Defends threat #10 (verifier skew).**

RCP v1 is a *constrained superset of JCS (RFC 8785)*: it adopts JCS serialization and adds
rules JCS leaves open (exact integer range, NFC, post-NFC duplicate-key rejection,
unknown-field rejection, algorithm-prefixed digests, explicit domain separation).

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

## 8. Algorithm agility

* Every hash and signature is **algorithm-prefixed** (multicodec-style):
  `sha256:<lowercase-hex, exactly 64 chars>`, `ed25519:<base64url-no-pad, decodes to exactly
  64 bytes>`. Ed25519 public keys: `ed25519pub:<base64url-no-pad, exactly 32 bytes>`.
* Verifiers select the primitive from the prefix and MUST reject malformed length/encoding;
  unknown prefix ⇒ explicit "unsupported algorithm" failure (never a silent pass).

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
   acyclic. A missing parent ⇒ *omission detected*.
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
   frontier without it.
6. **Fork detection (threat #2) — and its honest limit:** two checkpoints from the same project
   with the same `checkpoint_seq` but different `checkpoint_hash`, or two sharing the same
   `prev_checkpoint_hash`, signed by the same key, are a **fork**. This is detectable **only if
   both chains are observed** — e.g. via the customer-controlled, object-locked **witness copy**
   (which is append-only and outside vendor control). A verifier given only one internally
   consistent chain CANNOT detect that a *parallel* chain was suppressed. This is the stated
   limit of single-key self-host (threat #15); the witness/anchor is what closes it, partially.

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

---

## 11. What the golden vectors pin

For each vector in `/spec/golden-vectors/`: the input body (pretty JSON), the exact canonical
bytes (hex), the `content_hash`, a fixed Ed25519 keypair (test seed), and the resulting `sig`.
Vectors include: key ordering incl. supplementary-plane chars, NFC edge cases (incl. a
post-NFC duplicate-key *rejection* case), integer boundaries (i64 min/max, and an out-of-range
*rejection* case), `null` vs absent, unpaired-surrogate *rejection*, nested `extensions`, a full
Decision Record, and a checkpoint chain with frontier. CI fails on any byte divergence across
the Rust lib, the WASM build, and the CLI.
