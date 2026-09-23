/-!
# Byte framing: `LP`/`LB`, `BE8`, and schema-level injectivity

Models `core/src/hashx.rs::lp_into` and the `lp4`/`be8` helpers in `core/src/verify.rs`.

Every hashed or signed preimage in averin is a concatenation of

* length-prefixed byte strings `LP(b) = uint32_be(len b) ‖ b`,
* fixed-width fields (`BE8(n)`, a raw 32-byte accumulator, a 1-byte Merkle tag), and
* at most one trailing unframed field (the `utf8(content_hash)` tail of a signature preimage,
  or the canonical JSON body of a record hash).

`encodeFields_inj` proves that such a concatenation is injective in its fields: two preimages
built from the same schema are byte-equal only when every field is equal. That is the
no-ambiguity half of domain separation; `Averin.Preimage` supplies the cross-family half.

Bytes are modelled as `Nat`s. Nothing here needs them to be `< 256`: every theorem is about
equality of the lists, and the Rust encoders only ever emit values in range.
-/

namespace Averin

abbrev Bytes := List Nat

/-- `2^32`: the largest length `LP` can frame (`MAX_LP_LEN + 1`). -/
def lpLimit : Nat := 4294967296

/-- `uint32_be(n)` — the RCP §9 length prefix. -/
def be32 (n : Nat) : Bytes :=
  [n / 16777216 % 256, n / 65536 % 256, n / 256 % 256, n % 256]

/-- `BE8(n)` — the 8-byte big-endian integer framing used by the broker challenges. -/
def be64 (n : Nat) : Bytes :=
  [n / 72057594037927936 % 256, n / 281474976710656 % 256, n / 1099511627776 % 256,
   n / 4294967296 % 256, n / 16777216 % 256, n / 65536 % 256, n / 256 % 256, n % 256]

/-- `LP(b) = uint32_be(|b|) ‖ b`. -/
def lp (b : Bytes) : Bytes := be32 b.length ++ b

@[simp] theorem be32_length (n : Nat) : (be32 n).length = 4 := rfl
@[simp] theorem be64_length (n : Nat) : (be64 n).length = 8 := rfl

theorem be32_inj {m n : Nat} (hm : m < lpLimit) (hn : n < lpLimit) (h : be32 m = be32 n) :
    m = n := by
  simp only [be32, lpLimit, List.cons.injEq, and_true] at h hm hn
  omega

theorem be64_inj {m n : Nat} (hm : m < 18446744073709551616) (hn : n < 18446744073709551616)
    (h : be64 m = be64 n) : m = n := by
  simp only [be64, List.cons.injEq, and_true] at h
  omega

/-- The core framing lemma: an `LP` field followed by anything is uniquely decodable. -/
theorem lp_append_inj {a b r s : Bytes} (ha : a.length < lpLimit) (hb : b.length < lpLimit)
    (h : lp a ++ r = lp b ++ s) : a = b ∧ r = s := by
  simp only [lp, List.append_assoc] at h
  have hp := List.append_inj h (by simp)
  have hlen : a.length = b.length := be32_inj ha hb hp.1
  exact List.append_inj hp.2 hlen

theorem lp_inj {a b : Bytes} (ha : a.length < lpLimit) (hb : b.length < lpLimit)
    (h : lp a = lp b) : a = b := by
  have := lp_append_inj (r := []) (s := []) ha hb (by simpa using h)
  exact this.1

/-! ## Schema-level framing -/

/-- One field of a preimage schema. -/
inductive Field where
  /-- `LP(b)`. -/
  | framed
  /-- A fixed-width field of exactly `n` bytes (`BE8`, a raw digest, a one-byte tag). -/
  | fixed (n : Nat)
deriving DecidableEq, Repr

/-- A field value is admissible for its kind: `LP` needs a 32-bit length, fixed fields their width. -/
def Field.admits : Field → Bytes → Prop
  | .framed, b => b.length < lpLimit
  | .fixed n, b => b.length = n

def Field.encode : Field → Bytes → Bytes
  | .framed, b => lp b
  | .fixed _, b => b

theorem Field.encode_append_inj {f : Field} {a b r s : Bytes} (ha : f.admits a) (hb : f.admits b)
    (h : f.encode a ++ r = f.encode b ++ s) : a = b ∧ r = s := by
  cases f with
  | framed => exact lp_append_inj ha hb h
  | fixed n =>
    simp only [Field.admits] at ha hb
    exact List.append_inj h (by omega)

/--
Encode a schema: fields in order, then an unframed `tail`. Every averin preimage is an instance
(`tail = []` when the schema has no trailing unframed field).
-/
def encodeFields : List Field → List Bytes → Bytes → Bytes
  | f :: fs, v :: vs, tail => f.encode v ++ encodeFields fs vs tail
  | _, _, tail => tail

/-- All values admissible for the schema, one per field. -/
def Admits : List Field → List Bytes → Prop
  | [], [] => True
  | f :: fs, v :: vs => f.admits v ∧ Admits fs vs
  | _, _ => False

/--
**Framing injectivity.** Two preimages built from the same schema with admissible fields are
byte-equal only if every field — and the unframed tail — is equal.
-/
theorem encodeFields_inj :
    ∀ (fs : List Field) (vs ws : List Bytes) (t u : Bytes),
      Admits fs vs → Admits fs ws →
      encodeFields fs vs t = encodeFields fs ws u → vs = ws ∧ t = u
  | [], [], [], t, u, _, _, h => by simpa [encodeFields] using h
  | [], [], _ :: _, _, _, _, hw, _ => by simp [Admits] at hw
  | [], _ :: _, _, _, _, hv, _, _ => by simp [Admits] at hv
  | _ :: _, [], _, _, _, hv, _, _ => by simp [Admits] at hv
  | _ :: _, _ :: _, [], _, _, _, hw, _ => by simp [Admits] at hw
  | f :: fs, v :: vs, w :: ws, t, u, hv, hw, h => by
    simp only [Admits] at hv hw
    simp only [encodeFields] at h
    obtain ⟨hvw, hrest⟩ := Field.encode_append_inj hv.1 hw.1 h
    obtain ⟨hs, htu⟩ := encodeFields_inj fs vs ws t u hv.2 hw.2 hrest
    exact ⟨by rw [hvw, hs], htu⟩

/-- Framing is a left prefix: the first `LP` field of any preimage is recoverable. -/
theorem encodeFields_lp_head {fs gs : List Field} {v w : Bytes} {vs ws : List Bytes} {t u : Bytes}
    (hv : v.length < lpLimit) (hw : w.length < lpLimit)
    (h : encodeFields (.framed :: fs) (v :: vs) t = encodeFields (.framed :: gs) (w :: ws) u) : v = w := by
  simp only [encodeFields, Field.encode] at h
  exact (lp_append_inj hv hw h).1

end Averin
