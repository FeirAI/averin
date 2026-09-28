import Aeneas
import Extracted.Types
open Aeneas Aeneas.Std Result ControlFlow Error

/-!
# External functions used by the extracted production code (hand-written, audited)

Aeneas extracts the production serializer, framing, hash-string and preimage code from `core/src`
itself (`Extracted/Funs.lean`). The calls it has no body for are defined here; this file is the
whole trusted interface between that code and the rest of the world.
`formal/production/check-glue.py` checks that it defines exactly the externals Aeneas requested.

**Permitted trusted primitives** (the only `axiom`s; `Refinement/Audit.lean` fails on any other):

* `AverinTrusted.nfc` — Unicode NFC normalization, `unicode-normalization` 0.1.25 behind
  `canon::nfc`. Modelled as an arbitrary total function of the input bytes: no property of it is
  assumed, so every theorem holds for whatever the crate computes.
* `AverinTrusted.sha256` — SHA-256, `sha2` 0.10.9 behind `hashx::sha256`, likewise an arbitrary
  total function. Collision resistance is never assumed; theorems exhibit explicit collisions.

**Rust standard-library facts** (definitions, not axioms; they model `String`/`str`, which Aeneas
maps to Lean's `String` and to `Slice U8`):

* `str::as_bytes` is the identity (Aeneas represents `&str` by its UTF-8 bytes).
* `String::as_bytes` / `Deref<Target = str>` give the UTF-8 encoding of the string (Lean's
  `String.toByteArray`); a Rust `String` never exceeds `usize::MAX` bytes, and the model fails
  (never succeeds wrongly) beyond that.
* `String::from_utf8` returns `Ok` with exactly the given bytes when they are valid UTF-8 (Lean's
  verified decoder `String.fromUTF8?`), else `Err`.
* `String::is_empty` is true exactly when the string has no UTF-8 bytes (used by the verdict
  kernel's seal and anchor checks).
* `String::clone` returns an equal string (used by the parser's duplicate-key bookkeeping).

**Toolchain adjustment.** Aeneas elaborates string literals with `Aeneas.Std.toStr`, whose default
bound proof is `decide +native` (an extra axiom). `averin_decision_core.toStr` below shadows it
inside the generated namespace with the same function and a kernel-checked bound proof.
-/

namespace AverinTrusted

/-- Unicode NFC normalization (`unicode-normalization` 0.1.25). Trusted primitive. -/
axiom nfc : Str → String

/-- SHA-256 (`sha2` 0.10.9). Trusted primitive. -/
axiom sha256 : Slice Std.U8 → Array Std.U8 32#usize

end AverinTrusted

namespace AverinGlue

def u8OfUInt8 (x : UInt8) : Std.U8 := ⟨x.toBitVec⟩

def uint8OfU8 (x : Std.U8) : UInt8 := ⟨x.bv⟩

/-- The UTF-8 bytes of a Rust `String` (Lean's `String` is its UTF-8 byte array). -/
def stringBytes (s : String) : List Std.U8 := s.toByteArray.data.toList.map u8OfUInt8

def stringSlice (s : String) : Result (Slice Std.U8) :=
  if h : (stringBytes s).length ≤ Usize.max then ok (Slice.from (stringBytes s) h) else fail .panic

end AverinGlue

/-- String literal to `Str`: `Aeneas.Std.toStr` with a kernel-checked bound proof. -/
def averin_decision_core.toStr (s : String)
    (h : s.toByteArray.size ≤ U32.max := by simp only [Aeneas.Std.U32.max_eq]; decide) : Str :=
  Aeneas.Std.toStr s h

@[rust_fun "core::str::{str}::as_bytes"]
def core.str.Str.as_bytes (s : Str) : Result (Slice Std.U8) := ok s

@[rust_fun "alloc::string::{alloc::string::String}::as_bytes"]
def alloc.string.String.as_bytes (s : String) : Result (Slice Std.U8) := AverinGlue.stringSlice s

/-- `String::is_empty`: the string has no UTF-8 bytes (Rust's `len() == 0`). Total. -/
@[rust_fun "alloc::string::{alloc::string::String}::is_empty"]
def alloc.string.String.is_empty (s : String) : Result Bool :=
  ok (decide (AverinGlue.stringBytes s = []))

/-- `String::clone`: an equal string (the parser's key bookkeeping). Total. -/
@[rust_fun "alloc::string::{core::clone::Clone<alloc::string::String>}::clone"]
def alloc.string.String.Insts.CoreCloneClone.clone (s : String) : Result String := ok s

@[rust_fun
  "alloc::string::{core::ops::deref::Deref<alloc::string::String, str>}::deref"]
def alloc.string.String.Insts.CoreOpsDerefDerefStr.deref (s : String) : Result Str :=
  AverinGlue.stringSlice s

@[rust_fun "alloc::string::{alloc::string::String}::from_utf8"]
def alloc.string.String.from_utf8 (v : alloc.vec.Vec Std.U8) :
    Result (core.result.Result String alloc.string.FromUtf8Error) :=
  match String.fromUTF8? ⟨(v.val.map AverinGlue.uint8OfU8).toArray⟩ with
  | some s => ok (.Ok s)
  | none => ok (.Err ())

/-- `canon::nfc` (opaque to Charon): the trusted NFC primitive. -/
noncomputable def canon.nfc (s : Str) : Result String := ok (AverinTrusted.nfc s)

/-- `hashx::sha256` (opaque to Charon): the trusted SHA-256 primitive. -/
noncomputable def hashx.sha256 (d : Slice Std.U8) : Result (Array Std.U8 32#usize) :=
  ok (AverinTrusted.sha256 d)
