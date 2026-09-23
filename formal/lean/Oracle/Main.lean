import Averin
import Lean.Data.Json

/-!
# Executable oracle: the Lean model, run

`lake exe oracle <inputs.json> <expected.json>` evaluates the *same definitions the proofs are
about* (`Canon.ser`, `Canon.escChar`, `Canon.serInt`, `lp`/`be32`/`be64`, `Family.msg` for every
preimage family, the record/checkpoint hash preimages of `Seal`) over the corpus in
`formal/oracle/inputs.json`, and writes the resulting bytes (lowercase hex) to
`formal/oracle/expected.json`. `core/tests/oracle.rs` then asserts that the real Rust functions
produce byte-identical output. CI regenerates the file and fails on any diff, so the committed
expectations are provably the model's output, and the Rust test pins the Rust to them.

Everything below is glue: JSON decoding, a UTF-16 member sort, hex printing. The only modelling
choices it makes are the two the Lean model leaves to its caller, both stated where they happen:

* **Member order.** `Canon.ser` writes object members in list order; `canon.rs` sorts them by
  UTF-16 code unit first (RCP §2). `sortMembers` implements that sort here, independently of the
  Rust (`utf16Units`, a lexicographic compare on code-unit lists).
* **UTF-8.** `Averin.utf8` is `noncomputable` (it goes through `List.utf8Encode`). `utf8c` is the
  runtime's `String.toUTF8`, and `utf8c_eq` proves it *is* `Averin.utf8`, so every byte emitted
  here is the byte string the theorems quantify over.
-/

namespace Averin.Oracle

open Lean (Json)
open Averin Averin.Canon Averin.Preimage

/-! ## Computable UTF-8, proved equal to the model's `utf8` -/

/-- UTF-8 bytes of a scalar sequence, computably (the runtime's `String.toUTF8`). -/
def utf8c (l : List Char) : Bytes := (String.ofList l).toUTF8.data.toList.map UInt8.toNat

/-- `utf8c` is exactly the model's (noncomputable) `Averin.utf8`. -/
theorem utf8c_eq (l : List Char) : utf8c l = utf8 l := by
  have h : (String.ofList l).toUTF8 = l.utf8Encode := by
    rw [← String.toByteArray_ofList]; rfl
  simp only [utf8c, utf8, h]

/-! ## Record / checkpoint hash preimages (pre-SHA-256), tied to `Seal` -/

/-- The bytes `record.rs::hash_body` feeds SHA-256 for a record body (content_hash/sig stripped). -/
def recordPre (body : CV) : Bytes := recordHash.msg [ascii "rcp-1"] (utf8c (ser body))

/-- The bytes `compute_checkpoint_hash` feeds SHA-256 (anchor/checkpoint_hash/sig stripped). -/
def checkpointPre (body : CV) : Bytes := checkpointHash.msg [ascii "rcp-1"] (utf8c (ser body))

/-- The oracle's record preimage is the one inside `Seal.recordHashOf`. -/
theorem recordPre_spec (H fmt : Bytes → Bytes) (body : CV) :
    Seal.recordHashOf H fmt body = fmt (H (recordPre body)) := by
  simp [Seal.recordHashOf, recordPre, utf8c_eq]

/-- The oracle's checkpoint preimage is the one inside `Seal.checkpointHashOf`. -/
theorem checkpointPre_spec (H fmt : Bytes → Bytes) (body : CV) :
    Seal.checkpointHashOf H fmt body = fmt (H (checkpointPre body)) := by
  simp [Seal.checkpointHashOf, checkpointPre, utf8c_eq]

/-! ## RCP §2 member order: UTF-16 code units -/

/-- UTF-16 code units of one scalar value. -/
def utf16Char (c : Char) : List Nat :=
  if c.toNat < 0x10000 then [c.toNat]
  else
    let v := c.toNat - 0x10000
    [0xD800 + v / 0x400, 0xDC00 + v % 0x400]

def utf16Units (s : List Char) : List Nat := s.flatMap utf16Char

/-- Lexicographic `≤` on code-unit sequences (a proper prefix sorts first). -/
def lexLe : List Nat → List Nat → Bool
  | [], _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a < b then true else if b < a then false else lexLe as bs

def sortMembers (ms : List (List Char × CV)) : List (List Char × CV) :=
  ms.mergeSort (fun a b => lexLe (utf16Units a.1) (utf16Units b.1))

def toMembers : List (List Char × CV) → Members
  | [] => .nil
  | (k, v) :: rest => .cons k v (toMembers rest)

def toCVs : List CV → CVs
  | [] => .nil
  | v :: rest => .cons v (toCVs rest)

/-! ## Corpus decoding

A corpus value is JSON with one twist: an object is written `{"obj": [[key, value], …]}` so the
member order in the file is explicit (and deliberately unsorted). Everything else is literal:
`null`, booleans, integers, strings, arrays. -/

abbrev M := Except String

def jsonInt (j : Json) : M Int := do
  match j with
  | .num n => if n.exponent = 0 then pure n.mantissa else throw s!"non-integer {j.compress}"
  | _ => throw s!"expected an integer, got {j.compress}"

/-- Total (fuel-bounded, so no `partial def` escapes the axiom gate); `toCV` passes the compressed
text length, which bounds the nesting depth. -/
def toCVF : Nat → Json → M CV
  | 0, j => throw s!"nesting too deep at {j.compress}"
  | fuel + 1, j => do
    match j with
    | .null => pure .null
    | .bool b => pure (.bool b)
    | .num _ => pure (.int (← jsonInt j))
    | .str s => pure (.str s.toList)
    | .arr xs => pure (.arr (toCVs (← xs.toList.mapM (toCVF fuel))))
    | .obj _ =>
      let pairs ← (← (← j.getObjVal? "obj").getArr?).toList.mapM fun p => do
        match p with
        | .arr #[k, v] => pure ((← k.getStr?).toList, ← toCVF fuel v)
        | _ => throw s!"object member must be [key, value], got {p.compress}"
      let sorted := sortMembers pairs
      -- RCP §5: keys are unique. A duplicate would make the model's text ambiguous to compare.
      let keys := sorted.map (·.1)
      if keys.eraseDups.length != keys.length then throw s!"duplicate key in {j.compress}"
      pure (.obj (toMembers sorted))

def toCV (j : Json) : M CV := toCVF (j.compress.length + 1) j

/-! ## Hex output -/

def hexNibble (n : Nat) : Char := hexDigit (n % 16)

def hex (b : Bytes) : String :=
  String.ofList (b.flatMap fun x => [hexNibble (x / 16), hexNibble x])

def unhex (s : String) : M Bytes := do
  let cs := s.toList
  if cs.length % 2 != 0 then throw s!"odd-length hex {s}"
  let v (c : Char) : M Nat :=
    if '0' ≤ c ∧ c ≤ '9' then pure (c.toNat - 48)
    else if 'a' ≤ c ∧ c ≤ 'f' then pure (c.toNat - 87)
    else throw s!"bad hex digit in {s}"
  let rec go : List Char → M Bytes
    | a :: b :: rest => do
      let hi ← v a
      let lo ← v b
      pure ((hi * 16 + lo) :: (← go rest))
    | _ => pure []
  go cs

def jstr (s : String) : String := (Json.str s).compress

/-! ## Preimage families -/

/-- Every family the model catalogues. A family without a corpus sample fails the run, so a new
family in `Preimage.lean` cannot be added without a byte-level check against the Rust. -/
def allFamilies : List Family := signedFamilies ++ hashFamilies ++ [grantHeadSeed]

/-- Families whose sample is a whole canonical body (the `records`/`checkpoints` sections). -/
def bodyFamilies : List String := [recordHash.name, checkpointHash.name]

/-- A sample field: `{"s": text}` (UTF-8 of the text), `{"u64": n}` (`be64 n`), `{"hex": h}` (raw). -/
def fieldBytes (j : Json) : M Bytes := do
  if let .ok s := j.getObjValAs? String "s" then return utf8c s.toList
  if let .ok n := j.getObjVal? "u64" then
    let i ← jsonInt n
    if i < 0 ∨ i ≥ 18446744073709551616 then throw s!"u64 out of range {i}"
    return be64 i.toNat
  if let .ok h := j.getObjValAs? String "hex" then return ← unhex h
  throw s!"bad field {j.compress}"

def checkField : Field → Bytes → M Unit
  | .framed, b => if b.length < lpLimit then pure () else throw "field too long"
  | .fixed n, b => if b.length = n then pure () else throw s!"fixed field needs {n} bytes, got {b.length}"

def familyMsg (j : Json) : M (String × Bytes) := do
  let name ← j.getObjValAs? String "family"
  let some F := allFamilies.find? (·.name == name) | throw s!"unknown family {name}"
  let fields ← (← (← j.getObjVal? "fields").getArr?).toList.mapM fieldBytes
  if fields.length != F.schema.length then
    throw s!"{name}: {fields.length} fields, schema has {F.schema.length}"
  for (f, b) in F.schema.zip fields do checkField f b
  let tail ← match j.getObjVal? "tail" with
    | .ok .null | .error _ => pure none
    | .ok t => some <$> fieldBytes t
  match F.tailed, tail with
  | true, some t => pure (name, F.msg fields t)
  | false, none => pure (name, F.msg fields [])
  | true, none => throw s!"{name} needs a tail"
  | false, some _ => throw s!"{name} takes no tail"

/-! ## Body hashes -/

def strMember (ms : Members) (k : String) : Option (List Char) :=
  match ms with
  | .nil => none
  | .cons k' (.str v) rest => if k' = k.toList then some v else strMember rest k
  | .cons _ _ rest => strMember rest k

/-- A hash sample must carry the pinned domain and `canon_version = "rcp-1"` (what `Seal` models). -/
def bodyPre (F : Family) (pre : CV → Bytes) (j : Json) : M (String × Bytes) := do
  let name ← j.getObjValAs? String "name"
  let v ← toCV (← j.getObjVal? "body")
  let .obj ms := v | throw s!"{name}: body must be an object"
  if strMember ms "domain" != some F.tag.toList then throw s!"{name}: domain must be {F.tag}"
  if strMember ms "canon_version" != some "rcp-1".toList then
    throw s!"{name}: canon_version must be rcp-1"
  pure (name, pre v)

/-! ## Driver -/

def arrOf (j : Json) (k : String) : M (List Json) := do pure (← (← j.getObjVal? k).getArr?).toList

def row (fields : List (String × String)) : String :=
  "    {" ++ ", ".intercalate (fields.map fun (k, v) => jstr k ++ ": " ++ v) ++ "}"

def section_ (name : String) (rows : List String) : String :=
  "  " ++ jstr name ++ ": [\n" ++ ",\n".intercalate rows ++ "\n  ]"

def run (inp : Json) : M String := do
  let canon ← (← arrOf inp "canon").mapM fun c => do
    let name ← c.getObjValAs? String "name"
    let v ← toCV (← c.getObjVal? "value")
    pure (row [("name", jstr name), ("hex", jstr (hex (utf8c (ser v))))])
  let esc ← (← arrOf inp "esc").mapM fun c => do
    let n ← jsonInt c
    if n < 0 ∨ n ≥ 0x110000 ∨ (0xD800 ≤ n ∧ n < 0xE000) then throw s!"not a scalar value {n}"
    pure (row [("cp", toString n), ("hex", jstr (hex (utf8c (escChar (Char.ofNat n.toNat)))))])
  let ints ← (← arrOf inp "ints").mapM fun c => do
    let n ← jsonInt c
    pure (row [("int", toString n), ("hex", jstr (hex (utf8c (serInt n))))])
  let lps ← (← arrOf inp "lp").mapM fun c => do
    let b ← unhex (← c.getStr?)
    pure (row [("in", jstr (hex b)), ("hex", jstr (hex (lp b)))])
  let be32s ← (← arrOf inp "be32").mapM fun c => do
    let n ← jsonInt c
    if n < 0 ∨ n ≥ lpLimit then throw s!"be32 out of range {n}"
    pure (row [("n", toString n), ("hex", jstr (hex (be32 n.toNat)))])
  -- Written as decimal strings: values above i64::MAX are not RCP integers.
  let be64s ← (← arrOf inp "be64").mapM fun c => do
    let str ← c.getStr?
    let some n := str.toNat? | throw s!"be64: not a decimal {str}"
    if n ≥ 18446744073709551616 then throw s!"be64 out of range {n}"
    pure (row [("n", jstr str), ("hex", jstr (hex (be64 n)))])
  let fams ← (← arrOf inp "families").mapM familyMsg
  let recs ← (← arrOf inp "records").mapM (bodyPre recordHash recordPre)
  let cps ← (← arrOf inp "checkpoints").mapM (bodyPre checkpointHash checkpointPre)
  -- Completeness: every catalogued family has a byte-level sample.
  for F in allFamilies do
    let covered := fams.any (·.1 == F.name) ||
      (F.name == recordHash.name && !recs.isEmpty) ||
      (F.name == checkpointHash.name && !cps.isEmpty)
    unless covered do throw s!"no corpus sample for family {F.name}"
  let famRows := fams.map fun (n, b) => row [("family", jstr n), ("hex", jstr (hex b))]
  let bodyRows (xs : List (String × Bytes)) := xs.map fun (n, b) => row [("name", jstr n), ("hex", jstr (hex b))]
  pure <| "{\n" ++ ",\n".intercalate [
    section_ "canon" canon, section_ "esc" esc, section_ "ints" ints, section_ "lp" lps,
    section_ "be32" be32s, section_ "be64" be64s, section_ "families" famRows,
    section_ "records" (bodyRows recs), section_ "checkpoints" (bodyRows cps)] ++ "\n}\n"

end Averin.Oracle

open Averin.Oracle in
def main (args : List String) : IO UInt32 := do
  let (inPath, outPath) := match args with
    | [i, o] => (i, o)
    | _ => ("../oracle/inputs.json", "../oracle/expected.json")
  let text ← IO.FS.readFile inPath
  match Lean.Json.parse text >>= run with
  | .ok out =>
    IO.FS.writeFile outPath out
    IO.println s!"oracle: wrote {outPath}"
    pure 0
  | .error e =>
    IO.eprintln s!"oracle: {e}"
    pure 1
