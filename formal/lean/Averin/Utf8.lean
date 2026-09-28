import Averin.Encoding

/-!
# UTF-8 is injective

The canonical text of a body is hashed as its UTF-8 bytes (`canon.as_bytes()` in
`record.rs::hash_body`). `utf8_inj` discharges the last step from "equal preimage bytes" to
"equal canonical characters", using only Lean core's verified UTF-8 encoder
(`String.toByteArray_ofList`, `String.toByteArray_inj`). No axiom is introduced.
-/

namespace Averin

/-- UTF-8 bytes of a scalar-value sequence (`str::as_bytes`). -/
noncomputable def utf8 (l : List Char) : Bytes := l.utf8Encode.data.toList.map UInt8.toNat

theorem map_toNat_inj : ∀ {a b : List UInt8}, a.map UInt8.toNat = b.map UInt8.toNat → a = b
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | x :: a, y :: b, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    rw [UInt8.toNat_inj.mp h.1, map_toNat_inj h.2]

theorem utf8_inj {a b : List Char} (h : utf8 a = utf8 b) : a = b := by
  have h1 := map_toNat_inj h
  have h2 : a.utf8Encode = b.utf8Encode := ByteArray.ext (Array.toList_inj.mp h1)
  rw [← String.toByteArray_ofList, ← String.toByteArray_ofList, String.toByteArray_inj] at h2
  have := congrArg String.toList h2
  simpa [String.toList_ofList] using this

end Averin
