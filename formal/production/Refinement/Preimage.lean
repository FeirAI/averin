import Refinement.Hash
import Averin.Seal

/-!
# Record, checkpoint and signature preimages

* `body_preimage_model`: `record::body_preimage` returns exactly
  `LP(utf8 domain) ‖ LP(utf8 canon_version) ‖ utf8 (ser m)`, where `domain`/`canon_version` are the
  string values of the body's first members with those raw keys and `m` is the model value of the
  body with the stripped members removed (`CanonObjStrip`).
* `record_preimage_model` / `checkpoint_preimage_model`: the production strip lists are
  `[content_hash, sig]` and `[anchor, checkpoint_hash, sig]`.
* `sign_preimage_model`: `sign::preimage` is `LP(tag) ‖ content_hash`, `none` exactly when the tag
  is too long to frame; for the production tags it is never `none` (`sign_preimage_record_tag`).
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core
open Averin Averin.Canon

namespace Refinement

/-! ## Member lookup -/

/-- The value of the first member whose raw key has UTF-8 bytes `key` (`CanonValue::get`). -/
noncomputable def fieldOf (members : List (String × canon.CanonValue)) (key : List Nat) :
    Option canon.CanonValue :=
  (members.find? (fun p => decide (keyIs key p))).map (·.2)

theorem member_loop_ok : ∀ (m : Nat) (members : alloc.vec.Vec (String × canon.CanonValue))
    (key : Str) (i j : Std.Usize), members.val.length - i.val = m →
    canon.member_loop members key i = ok j →
    i.val ≤ j.val ∧ j.val ≤ max i.val members.val.length ∧
    (∀ t (ht : t < members.val.length), i.val ≤ t → t < j.val →
      ¬ keyIs (vals (strSlice key).val) members.val[t]) ∧
    (∀ (hj : j.val < members.val.length), keyIs (vals (strSlice key).val) members.val[j.val]) := by
  intro m
  induction m with
  | zero =>
    intro members key i j hm h
    unfold canon.member_loop at h
    dsimp only at h
    split at h
    · rename_i hlt; have : i.val < members.val.length := by scalar_tac
      omega
    · simp at h; subst h
      exact ⟨le_refl _, by omega, fun t _ h1 h2 => by omega, fun hj => by omega⟩
  | succ m ih =>
    intro members key i j hm h
    unfold canon.member_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hi : i.val < members.val.length := by scalar_tac
      obtain ⟨⟨k, v⟩, hkv, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hkv⟩ := vec_index_ok hkv
      obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
      have hs1v := stringSlice_ok hs1
      obtain ⟨s2, hs2, h⟩ := bind_eq_ok.mp h
      simp [core.str.Str.as_bytes] at hs2
      have hs2' : strSlice key = s2 := hs2
      obtain ⟨b, hb, h⟩ := bind_eq_ok.mp h
      have hbv : b = !decide (vals s1.val = vals s2.val) := by
        simp only [core.cmp.impls.PartialEqShared.ne, core.cmp.PartialEq.ne.default] at hb
        obtain ⟨e, he, hb⟩ := bind_eq_ok.mp hb
        have := slice_eq_u8_ok he
        simp at hb; rw [← this, hb]; simp
      have hkey : keyIs (vals (strSlice key).val) members.val[i.val] ↔ vals s1.val = vals s2.val := by
        rw [← hkv, hs2']; simp only [keyIs, hs1v]
      split at h
      · rename_i hbt
        obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
        have hi2v := uadd_ok hi2; simp at hi2v
        obtain ⟨r1, r2, r3, r4⟩ := ih members key i2 j (by omega) h
        have hne : ¬ keyIs (vals (strSlice key).val) members.val[i.val] := by
          rw [hkey]; rw [hbt] at hbv; simpa using hbv.symm
        refine ⟨by omega, by omega, ?_, r4⟩
        intro t ht h1 h2
        by_cases hti : t = i.val
        · subst hti; exact hne
        · exact r3 t ht (by omega) h2
      · rename_i hbf
        simp at h; subst h
        have hmatch : keyIs (vals (strSlice key).val) members.val[i.val] := by
          rw [hkey]; have : b = false := by simpa using hbf
          rw [this] at hbv; simpa using hbv.symm
        exact ⟨le_refl _, by omega, fun t _ h1 h2 => by omega, fun _ => hmatch⟩
    · rename_i hge; have : ¬ i.val < members.val.length := by scalar_tac
      simp at h; subst h
      exact ⟨le_refl _, by omega, fun t _ h1 h2 => by omega, fun hj => by omega⟩

theorem member_ok {members : alloc.vec.Vec (String × canon.CanonValue)} {key : Str}
    {r : Option canon.CanonValue} (h : canon.member (.Object members) key = ok r) :
    r = fieldOf members.val (vals (strSlice key).val) := by
  unfold canon.member at h
  simp only at h
  obtain ⟨j, hj, h⟩ := bind_eq_ok.mp h
  obtain ⟨r1, r2, r3, r4⟩ := member_loop_ok _ members key 0#usize j rfl hj
  simp at r1 r2
  unfold fieldOf
  split at h
  · rename_i hlt
    have hlt' : j.val < members.val.length := by scalar_tac
    obtain ⟨⟨k, v⟩, hkv, h⟩ := bind_eq_ok.mp h
    obtain ⟨_, hkv⟩ := vec_index_ok hkv
    simp at h; subst h
    have hf : members.val.find? (fun p => decide (keyIs (vals (strSlice key).val) p)) =
        some members.val[j.val] := by
      rw [List.find?_eq_some_iff_getElem]
      refine ⟨by simpa using r4 hlt', j.val, hlt', rfl, ?_⟩
      intro t ht
      simpa using r3 t (by omega) (by simp) ht
    rw [hf, ← hkv]; rfl
  · rename_i hge
    have hge' : ¬ j.val < members.val.length := by scalar_tac
    simp at h; subst h
    have hf : members.val.find? (fun p => decide (keyIs (vals (strSlice key).val) p)) = none := by
      rw [List.find?_eq_none]
      intro p hp
      obtain ⟨t, ht, rfl⟩ := List.getElem_of_mem hp
      simpa using r3 t ht (by simp) (by omega)
    rw [hf]; rfl

/-- Every production value's serialization is covered by `write_canonical_model`. -/
theorem valuesOk (members : alloc.vec.Vec (String × canon.CanonValue)) : ValuesOk members :=
  fun p _ out w h => write_canonical_model _ p.2 rfl out w h

theorem lit_vals (s : String) (h) (hs : ∀ c ∈ s.toList, c.toNat < 0x80) :
    vals (strSlice (averin_decision_core.toStr s h)).val = Averin.Preimage.ascii s := by
  simp only [strSlice, averin_decision_core.toStr]
  rw [toStr_vals, utf8_ascii _ hs]
  rfl

/-- **Record/checkpoint body preimage.** -/
theorem body_preimage_model {value : canon.CanonValue} {strip : Slice Str}
    {pre : alloc.vec.Vec Std.U8}
    (h : record.body_preimage value strip = ok (.Ok pre)) :
    ∃ members d cv m, value = .Object members ∧
      fieldOf members.val (Averin.Preimage.ascii "domain") = some (.Str d) ∧
      fieldOf members.val (Averin.Preimage.ascii "canon_version") = some (.Str cv) ∧
      (utf8 d.toList).length < lpLimit ∧ (utf8 cv.toList).length < lpLimit ∧
      CanonObjStrip members.val (stripKeys strip) m ∧
      vals pre.val = lp (utf8 d.toList) ++ lp (utf8 cv.toList) ++ utf8 (ser m) := by
  unfold record.body_preimage at h
  split at h
  all_goals try (simp at h; done)
  rename_i members
  obtain ⟨o, ho, h⟩ := bind_eq_ok.mp h
  have hov := member_ok ho
  rw [lit_vals _ _ (by decide)] at hov
  rcases o with _ | cvd
  · simp at h
  cases cvd
  all_goals try (simp at h; done)
  rename_i d
  simp only at h
  obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
  have ho1v := member_ok ho1
  rw [lit_vals _ _ (by decide)] at ho1v
  rcases o1 with _ | cvv
  · simp at h
  cases cvv
  all_goals try (simp at h; done)
  rename_i cv
  simp only at h
  obtain ⟨s2, hs2, h⟩ := bind_eq_ok.mp h
  have hs2v := stringSlice_ok hs2
  obtain ⟨⟨b, p1⟩, hp1, h⟩ := bind_eq_ok.mp h
  have hp1v := lp_str_into_model hp1
  cases b
  · simp at h
  obtain ⟨hlen1, hp1v⟩ := hp1v.1 rfl
  obtain ⟨s3, hs3, h⟩ := bind_eq_ok.mp h
  have hs3v := stringSlice_ok hs3
  obtain ⟨⟨b1, p2⟩, hp2, h⟩ := bind_eq_ok.mp h
  have hp2v := lp_str_into_model hp2
  cases b1
  · simp at h
  obtain ⟨hlen2, hp2v⟩ := hp2v.1 rfl
  obtain ⟨⟨b2, p3⟩, hp3, h⟩ := bind_eq_ok.mp h
  cases b2
  · simp at h
  simp at h; subst h
  obtain ⟨m, hm, hp3v⟩ := write_object_ok (valuesOk members) hp3
  have e2 : vals (strSlice s2).val = utf8 d.toList := hs2v
  have e3 : vals (strSlice s3).val = utf8 cv.toList := hs3v
  refine ⟨members, d, cv, m, rfl, hov.symm, ho1v.symm, ?_, ?_, hm, ?_⟩
  · have := congrArg List.length e2; simp at this; rw [← this]; simpa using hlen1
  · have := congrArg List.length e3; simp at this; rw [← this]; simpa using hlen2
  · rw [hp3v, hp2v, hp1v, e2, e3]
    simp [alloc.vec.Vec.new]

/-- The raw keys a record's `content_hash` does not cover. -/
def recordStrip : List (List Nat) := [Averin.Preimage.ascii "content_hash", Averin.Preimage.ascii "sig"]

/-- The raw keys a checkpoint's `checkpoint_hash` does not cover. -/
def checkpointStrip : List (List Nat) :=
  [Averin.Preimage.ascii "anchor", Averin.Preimage.ascii "checkpoint_hash", Averin.Preimage.ascii "sig"]

/-- The body a hash commits to: its raw `domain`/`canon_version` strings and the model value of the
body without the stripped members. -/
def BodyDenotes (ts : List (List Nat)) (value : canon.CanonValue) (d cv : String) (m : CV) : Prop :=
  ∃ members, value = .Object members ∧
    fieldOf members.val (Averin.Preimage.ascii "domain") = some (.Str d) ∧
    fieldOf members.val (Averin.Preimage.ascii "canon_version") = some (.Str cv) ∧
    (utf8 d.toList).length < lpLimit ∧ (utf8 cv.toList).length < lpLimit ∧
    CanonObjStrip members.val ts m

/-- The preimage bytes `LP(domain) ‖ LP(canon_version) ‖ utf8 (ser m)`. -/
noncomputable def preimageBytes (d cv : String) (m : CV) : Bytes :=
  lp (utf8 d.toList) ++ lp (utf8 cv.toList) ++ utf8 (ser m)

/-- **Record preimage.** -/
theorem record_preimage_model {body : canon.CanonValue} {pre : alloc.vec.Vec Std.U8}
    (h : record.record_preimage body = ok (.Ok pre)) :
    ∃ d cv m, BodyDenotes recordStrip body d cv m ∧ vals pre.val = preimageBytes d cv m := by
  unfold record.record_preimage at h
  obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
  simp only [lift_eq_ok] at hs; subst hs
  obtain ⟨members, d, cv, m, e1, e2, e3, e4, e5, e6, e7⟩ := body_preimage_model h
  have hstrip : stripKeys (Std.Array.to_slice (Std.Array.make 2#usize
      [averin_decision_core.toStr "content_hash", averin_decision_core.toStr "sig"])) = recordStrip := by
    simp only [stripKeys, Std.Array.to_slice, Slice.from_val, Std.Array.make_val, List.map_cons,
      List.map_nil, recordStrip]
    rw [lit_vals _ _ (by decide), lit_vals _ _ (by decide)]
  rw [hstrip] at e6
  exact ⟨d, cv, m, ⟨members, e1, e2, e3, e4, e5, e6⟩, e7⟩

/-- **Checkpoint preimage.** -/
theorem checkpoint_preimage_model {body : canon.CanonValue} {pre : alloc.vec.Vec Std.U8}
    (h : checkpoint.checkpoint_preimage body = ok (.Ok pre)) :
    ∃ d cv m, BodyDenotes checkpointStrip body d cv m ∧ vals pre.val = preimageBytes d cv m := by
  unfold checkpoint.checkpoint_preimage at h
  obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
  simp only [lift_eq_ok] at hs; subst hs
  obtain ⟨members, d, cv, m, e1, e2, e3, e4, e5, e6, e7⟩ := body_preimage_model h
  have hstrip : stripKeys (Std.Array.to_slice (Std.Array.make 3#usize
      [averin_decision_core.toStr "anchor", averin_decision_core.toStr "checkpoint_hash",
        averin_decision_core.toStr "sig"])) = checkpointStrip := by
    simp only [stripKeys, Std.Array.to_slice, Slice.from_val, Std.Array.make_val, List.map_cons,
      List.map_nil, checkpointStrip]
    rw [lit_vals _ _ (by decide), lit_vals _ _ (by decide), lit_vals _ _ (by decide)]
  rw [hstrip] at e6
  exact ⟨d, cv, m, ⟨members, e1, e2, e3, e4, e5, e6⟩, e7⟩

theorem hash_of_preimage_ok {r : core.result.Result (alloc.vec.Vec Std.U8) record.PreimageFault}
    {s : String}
    (h : (do
      let cf ← core.result.Result.Insts.CoreOpsTry.branch r
      match cf with
      | core.ops.control_flow.ControlFlow.Continue val => do
        let s1 ← hashx.sha256_prefixed (alloc.vec.Vec.deref val)
        ok (core.result.Result.Ok s1)
      | core.ops.control_flow.ControlFlow.Break residual =>
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual String
          (core.convert.FromSame record.PreimageFault) residual) = ok (.Ok s)) :
    ∃ pre, r = .Ok pre ∧ utf8 s.toList =
      Refinement.fmtP (vals (AverinTrusted.sha256 (alloc.vec.Vec.deref pre)).val) := by
  obtain ⟨cf, hcf, h⟩ := bind_eq_ok.mp h
  cases r with
  | Ok pre =>
    simp [core.result.Result.Insts.CoreOpsTry.branch] at hcf; subst hcf
    simp only at h
    obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
    simp at h; subst h
    exact ⟨pre, rfl, sha256_prefixed_model hs1⟩
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch] at hcf; subst hcf
    simp only [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at h
    obtain ⟨v, hv, h⟩ := bind_eq_ok.mp h
    simp at h

/-- **Record `content_hash`**: the digest string of the record preimage. -/
theorem record_hash_model {body : canon.CanonValue} {s : String}
    (h : record.record_hash body = ok (.Ok s)) :
    ∃ pre d cv m, record.record_preimage body = ok (.Ok pre) ∧ BodyDenotes recordStrip body d cv m ∧
      vals pre.val = preimageBytes d cv m ∧
      utf8 s.toList = fmtP (vals (AverinTrusted.sha256 (alloc.vec.Vec.deref pre)).val) := by
  unfold record.record_hash at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok.mp h
  obtain ⟨pre, rfl, hs⟩ := hash_of_preimage_ok h
  obtain ⟨d, cv, m, hb, hp⟩ := record_preimage_model hr
  exact ⟨pre, d, cv, m, hr, hb, hp, hs⟩

/-- **Generic body hash** (`record::body_hash`, behind the public `hash_body`). -/
theorem body_hash_model {value : canon.CanonValue} {strip : Slice Str} {s : String}
    (h : record.body_hash value strip = ok (.Ok s)) :
    ∃ pre, record.body_preimage value strip = ok (.Ok pre) ∧
      utf8 s.toList = fmtP (vals (AverinTrusted.sha256 (alloc.vec.Vec.deref pre)).val) := by
  unfold record.body_hash at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok.mp h
  obtain ⟨pre, rfl, hs⟩ := hash_of_preimage_ok h
  exact ⟨pre, hr, hs⟩

/-- **Checkpoint `checkpoint_hash`.** -/
theorem checkpoint_hash_model {body : canon.CanonValue} {s : String}
    (h : checkpoint.checkpoint_hash body = ok (.Ok s)) :
    ∃ pre d cv m, checkpoint.checkpoint_preimage body = ok (.Ok pre) ∧
      BodyDenotes checkpointStrip body d cv m ∧ vals pre.val = preimageBytes d cv m ∧
      utf8 s.toList = fmtP (vals (AverinTrusted.sha256 (alloc.vec.Vec.deref pre)).val) := by
  unfold checkpoint.checkpoint_hash at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok.mp h
  obtain ⟨pre, rfl, hs⟩ := hash_of_preimage_ok h
  obtain ⟨d, cv, m, hb, hp⟩ := checkpoint_preimage_model hr
  exact ⟨pre, d, cv, m, hr, hb, hp, hs⟩

end Refinement
