/-!
# RCP v1 canonical serialization is injective

Models `core/src/canon.rs::CanonValue::serialize` (`spec/rcp-v1.md` §2–§4) at the level of
Unicode scalar values (`Char`). The byte-level text is `utf8(ser v)`; UTF-8 injectivity is proved
separately in `Averin.Utf8`.

**Security role.** A `content_hash` commits to `utf8(ser body)`. If two *different* canonical
bodies serialized to the same characters, one signature would authenticate two meanings — the
seal would be ambiguous. `ser_injective` proves that cannot happen: equal canonical text implies
equal values, for every value in the model (arbitrary nesting, arbitrary strings including
quotes, backslashes and every C0 control, and every `i64`/`Int`).

**Model boundary.**
* Strings are post-NFC scalar-value sequences (the parser rejects lone surrogates and
  NFC-normalizes before any hashing, RCP §4); `ser` escapes exactly as `write_string`.
* Object members are serialized in list order. Rust sorts members by UTF-16 key before writing;
  the hashed text is therefore `ser (sortMembers v)`, and injectivity of `ser` is exactly what is
  needed for the sorted form. (That sorting forgets member order is the intended RCP semantics.)
* Integers are unbounded `Int`s written in shortest decimal with `-` for negatives; RCP restricts
  them to `i64`, and `-0` / leading zeros cannot arise from `ser`.
-/

namespace Averin.Canon

mutual
/-- `CanonValue` (canon.rs). -/
inductive CV where
  | null
  | bool (b : Bool)
  | int (i : Int)
  | str (s : List Char)
  | arr (xs : CVs)
  | obj (ms : Members)
/-- Array elements. -/
inductive CVs where
  | nil
  | cons (v : CV) (vs : CVs)
/-- Object members, in serialization order. -/
inductive Members where
  | nil
  | cons (k : List Char) (v : CV) (ms : Members)
end

/-! ## Decimal integers -/

def digitChar (d : Nat) : Char := Char.ofNat (48 + d)

/-- Shortest decimal digits of `n` (no leading zeros; `0` is `"0"`). -/
def digits (n : Nat) : List Char :=
  if n < 10 then [digitChar n] else digits (n / 10) ++ [digitChar (n % 10)]
termination_by n
decreasing_by omega

def isDigit (c : Char) : Bool := 48 ≤ c.toNat && c.toNat ≤ 57

def ofDigits (l : List Char) : Nat := l.foldl (fun acc c => acc * 10 + (c.toNat - 48)) 0

theorem digitChar_toNat' : ∀ d, d < 10 → (digitChar d).toNat = 48 + d := by decide

theorem digitChar_toNat {d : Nat} (h : d < 10) : (digitChar d).toNat = 48 + d :=
  digitChar_toNat' d h

theorem digitChar_isDigit {d : Nat} (h : d < 10) : isDigit (digitChar d) = true := by
  simp [isDigit, digitChar_toNat h]; omega

theorem digits_all (n : Nat) : ∀ c ∈ digits n, isDigit c = true := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    rw [digits]
    split
    · intro c hc; simp at hc; subst hc; exact digitChar_isDigit (by omega)
    · intro c hc
      simp only [List.mem_append, List.mem_singleton] at hc
      rcases hc with hc | hc
      · exact ih (n / 10) (by omega) c hc
      · subst hc; exact digitChar_isDigit (by omega)

theorem digits_ne_nil (n : Nat) : digits n ≠ [] := by
  rw [digits]; split <;> simp

theorem ofDigits_digits (n : Nat) : ofDigits (digits n) = n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    rw [digits]
    split
    · simp [ofDigits, digitChar_toNat (by omega : n < 10)]
    · have ih' := ih (n / 10) (by omega)
      simp only [ofDigits, List.foldl_append, List.foldl_cons, List.foldl_nil] at ih' ⊢
      rw [ih', digitChar_toNat (by omega : n % 10 < 10)]
      omega

theorem digits_inj {m n : Nat} (h : digits m = digits n) : m = n := by
  have := congrArg ofDigits h
  rwa [ofDigits_digits, ofDigits_digits] at this

/-- The characters that may follow a scalar inside canonical text: a separator, a closer, or EOF. -/
def Stop (r : List Char) : Prop :=
  r = [] ∨ ∃ x rs, r = x :: rs ∧ isDigit x = false

/-- A maximal run of digits is uniquely determined when both continuations stop. -/
theorem digitRun_inj : ∀ {a b r u : List Char},
    (∀ c ∈ a, isDigit c = true) → (∀ c ∈ b, isDigit c = true) → Stop r → Stop u →
    a ++ r = b ++ u → a = b ∧ r = u
  | [], [], _, _, _, _, _, _, h => by simpa using h
  | [], y :: b, r, u, _, hb, hr, _, h => by
    simp only [List.nil_append, List.cons_append] at h
    rcases hr with hr | ⟨x, rs, hx, hxd⟩
    · subst hr; simp at h
    · subst hx; simp only [List.cons.injEq] at h
      rw [h.1, hb y (by simp)] at hxd; simp at hxd
  | x :: a, [], r, u, ha, _, _, hu, h => by
    simp only [List.nil_append, List.cons_append] at h
    rcases hu with hu | ⟨y, us, hy, hyd⟩
    · subst hu; simp at h
    · subst hy; simp only [List.cons.injEq] at h
      rw [← h.1, ha x (by simp)] at hyd; simp at hyd
  | x :: a, y :: b, r, u, ha, hb, hr, hu, h => by
    simp only [List.cons_append, List.cons.injEq] at h
    obtain ⟨hxy, hrest⟩ := h
    have := digitRun_inj (fun c hc => ha c (by simp [hc])) (fun c hc => hb c (by simp [hc]))
      hr hu hrest
    exact ⟨by rw [hxy, this.1], this.2⟩

def serInt (i : Int) : List Char :=
  if i < 0 then '-' :: digits i.natAbs else digits i.toNat

theorem serInt_inj {i j : Int} {r u : List Char} (hr : Stop r) (hu : Stop u)
    (h : serInt i ++ r = serInt j ++ u) : i = j ∧ r = u := by
  have hdig : ∀ n, ∃ c t, digits n = c :: t ∧ isDigit c = true := by
    intro n
    match hd : digits n with
    | [] => exact absurd hd (digits_ne_nil n)
    | c :: t => exact ⟨c, t, rfl, digits_all n c (by rw [hd]; simp)⟩
  have minus_nd : isDigit '-' = false := by decide
  unfold serInt at h
  split at h <;> split at h
  · simp only [List.cons_append, List.cons.injEq, true_and] at h
    obtain ⟨h1, h2⟩ := digitRun_inj (digits_all _) (digits_all _) hr hu h
    exact ⟨by have := digits_inj h1; omega, h2⟩
  · obtain ⟨c, t, hc, hcd⟩ := hdig j.toNat
    rw [hc] at h; simp only [List.cons_append, List.cons.injEq] at h
    rw [← h.1, minus_nd] at hcd; simp at hcd
  · obtain ⟨c, t, hc, hcd⟩ := hdig i.toNat
    rw [hc] at h; simp only [List.cons_append, List.cons.injEq] at h
    rw [h.1, minus_nd] at hcd; simp at hcd
  · obtain ⟨h1, h2⟩ := digitRun_inj (digits_all _) (digits_all _) hr hu h
    exact ⟨by have := digits_inj h1; omega, h2⟩

/-! ## Strings (RCP §4 JCS-minimal escaping, exactly `write_string`) -/

/-- Lowercase hex digit (`hex_digit` in canon.rs). -/
def hexDigit (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hexVal (c : Char) : Nat := if c.toNat ≤ 57 then c.toNat - 48 else c.toNat - 87

theorem hexVal_hexDigit : ∀ n, n < 16 → hexVal (hexDigit n) = n := by decide

/-- `write_string`'s per-character escape. -/
def escChar (c : Char) : List Char :=
  if c = '"' then ['\\', '"']
  else if c = '\\' then ['\\', '\\']
  else if c.toNat = 8 then ['\\', 'b']
  else if c.toNat = 9 then ['\\', 't']
  else if c.toNat = 10 then ['\\', 'n']
  else if c.toNat = 12 then ['\\', 'f']
  else if c.toNat = 13 then ['\\', 'r']
  else if c.toNat < 32 then ['\\', 'u', '0', '0', hexDigit (c.toNat / 16), hexDigit (c.toNat % 16)]
  else [c]

def escStr : List Char → List Char
  | [] => []
  | c :: s => escChar c ++ escStr s

def serStr (s : List Char) : List Char := '"' :: (escStr s ++ ['"'])

/-- The inverse of one `escChar` token (what the RCP parser's escape decoder does). -/
def unescOne : List Char → Option (Char × List Char)
  | [] => none
  | c :: r =>
    if c = '\\' then
      match r with
      | d :: r' =>
        if d = '"' then some ('"', r')
        else if d = '\\' then some ('\\', r')
        else if d = 'b' then some (Char.ofNat 8, r')
        else if d = 't' then some (Char.ofNat 9, r')
        else if d = 'n' then some (Char.ofNat 10, r')
        else if d = 'f' then some (Char.ofNat 12, r')
        else if d = 'r' then some (Char.ofNat 13, r')
        else if d = 'u' then
          match r' with
          | _ :: _ :: h1 :: h2 :: r'' => some (Char.ofNat (hexVal h1 * 16 + hexVal h2), r'')
          | _ => none
        else none
      | [] => none
    else if c = '"' then none
    else some (c, r)

theorem char_eq_of_toNat {c : Char} {n : Nat} (h : c.toNat = n) : c = Char.ofNat n := by
  subst h; exact (Char.ofNat_toNat c).symm

theorem unescOne_escChar (c : Char) (r : List Char) : unescOne (escChar c ++ r) = some (c, r) := by
  unfold escChar
  by_cases h1 : c = '"'
  · subst h1; rfl
  by_cases h2 : c = '\\'
  · subst h2; rfl
  simp only [h1, h2, if_false]
  by_cases h3 : c.toNat = 8
  · simp only [h3, if_true]; rw [char_eq_of_toNat h3]; rfl
  by_cases h4 : c.toNat = 9
  · simp only [h4, if_true]; rw [char_eq_of_toNat h4]; rfl
  by_cases h5 : c.toNat = 10
  · simp only [h5, if_true]; rw [char_eq_of_toNat h5]; rfl
  by_cases h6 : c.toNat = 12
  · simp only [h6, if_true]; rw [char_eq_of_toNat h6]; rfl
  by_cases h7 : c.toNat = 13
  · simp only [h7, if_true]; rw [char_eq_of_toNat h7]; rfl
  simp only [h3, h4, h5, h6, h7, if_false]
  by_cases h8 : c.toNat < 32
  · simp only [h8, if_true, List.cons_append, List.nil_append]
    simp only [unescOne]
    simp only [if_true]
    have e1 := hexVal_hexDigit (c.toNat / 16) (by omega)
    have e2 := hexVal_hexDigit (c.toNat % 16) (by omega)
    simp only [show ('u' = '"') = False by decide, show ('u' = '\\') = False by decide,
      show ('u' = 'b') = False by decide, show ('u' = 't') = False by decide,
      show ('u' = 'n') = False by decide, show ('u' = 'f') = False by decide,
      show ('u' = 'r') = False by decide, if_false, e1, e2]
    rw [show c.toNat / 16 * 16 + c.toNat % 16 = c.toNat by omega, Char.ofNat_toNat]
  · simp only [h8, if_false, List.singleton_append, unescOne, h1, h2, if_false]

theorem escChar_ne_nil (c : Char) : ∃ x t, escChar c = x :: t ∧ x ≠ '"' := by
  unfold escChar
  by_cases h1 : c = '"'
  · rw [if_pos h1]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h1]
  by_cases h2 : c = '\\'
  · rw [if_pos h2]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h2]
  by_cases h3 : c.toNat = 8
  · rw [if_pos h3]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h3]
  by_cases h4 : c.toNat = 9
  · rw [if_pos h4]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h4]
  by_cases h5 : c.toNat = 10
  · rw [if_pos h5]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h5]
  by_cases h6 : c.toNat = 12
  · rw [if_pos h6]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h6]
  by_cases h7 : c.toNat = 13
  · rw [if_pos h7]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h7]
  by_cases h8 : c.toNat < 32
  · rw [if_pos h8]; exact ⟨_, _, rfl, by decide⟩
  rw [if_neg h8]
  exact ⟨c, [], rfl, h1⟩

/-- **String injectivity.** Escaped contents followed by the closing quote determine the string. -/
theorem escStr_inj : ∀ {s t : List Char} {r u : List Char},
    escStr s ++ '"' :: r = escStr t ++ '"' :: u → s = t ∧ r = u
  | [], [], _, _, h => by simpa [escStr] using h
  | [], d :: t, r, u, h => by
    obtain ⟨x, xs, hx, hne⟩ := escChar_ne_nil d
    simp only [escStr, hx, List.nil_append, List.cons_append, List.cons.injEq] at h
    exact absurd h.1.symm hne
  | c :: s, [], r, u, h => by
    obtain ⟨x, xs, hx, hne⟩ := escChar_ne_nil c
    simp only [escStr, hx, List.nil_append, List.cons_append, List.cons.injEq] at h
    exact absurd h.1 hne
  | c :: s, d :: t, r, u, h => by
    simp only [escStr, List.append_assoc] at h
    have hc := unescOne_escChar c (escStr s ++ '"' :: r)
    have hd := unescOne_escChar d (escStr t ++ '"' :: u)
    rw [h] at hc
    rw [hc] at hd
    simp only [Option.some.injEq, Prod.mk.injEq] at hd
    obtain ⟨hcd, hrest⟩ := hd
    have := escStr_inj hrest
    exact ⟨by rw [hcd, this.1], this.2⟩

theorem serStr_inj {s t r u : List Char} (h : serStr s ++ r = serStr t ++ u) : s = t ∧ r = u := by
  simp only [serStr, List.cons_append, List.cons.injEq, true_and, List.append_assoc,
    ] at h
  exact escStr_inj h

/-! ## Values -/

mutual
/-- `CanonValue::serialize` (members already in their serialization order). -/
def ser : CV → List Char
  | .null => ['n', 'u', 'l', 'l']
  | .bool true => ['t', 'r', 'u', 'e']
  | .bool false => ['f', 'a', 'l', 's', 'e']
  | .int i => serInt i
  | .str s => serStr s
  | .arr xs => '[' :: (serElems xs true ++ [']'])
  | .obj ms => '{' :: (serMembers ms true ++ ['}'])
/-- Array elements; `first` suppresses the leading `,`. -/
def serElems : CVs → Bool → List Char
  | .nil, _ => []
  | .cons v vs, first => (if first then [] else [',']) ++ (ser v ++ serElems vs false)
/-- Object members `"k":v`; `first` suppresses the leading `,`. -/
def serMembers : Members → Bool → List Char
  | .nil, _ => []
  | .cons k v ms, first =>
    (if first then [] else [',']) ++ (serStr k ++ (':' :: (ser v ++ serMembers ms false)))
end

/-- Syntactic class of the first character of a serialized value. -/
def headClass (c : Char) : Nat :=
  if c = 'n' then 0 else if c = 't' then 1 else if c = 'f' then 2
  else if c = '"' then 4 else if c = '[' then 5 else if c = '{' then 6
  else if isDigit c ∨ c = '-' then 3 else 7

def CV.cls : CV → Nat
  | .null => 0 | .bool true => 1 | .bool false => 2 | .int _ => 3
  | .str _ => 4 | .arr _ => 5 | .obj _ => 6

theorem ser_head (v : CV) : ∃ c t, ser v = c :: t ∧ headClass c = v.cls := by
  cases v with
  | null => exact ⟨_, _, rfl, by decide⟩
  | bool b => cases b <;> exact ⟨_, _, rfl, by decide⟩
  | str s => exact ⟨_, _, rfl, by simp only [CV.cls]; decide⟩
  | arr xs => exact ⟨_, _, rfl, by simp only [CV.cls]; decide⟩
  | obj ms => exact ⟨_, _, rfl, by simp only [CV.cls]; decide⟩
  | int i =>
    simp only [ser, serInt, CV.cls]
    split
    · exact ⟨_, _, rfl, by decide⟩
    · match hd : digits i.toNat with
      | [] => exact absurd hd (digits_ne_nil _)
      | c :: t =>
        refine ⟨c, t, rfl, ?_⟩
        have hc := digits_all i.toNat c (by rw [hd]; simp)
        have hn : ¬ (c = 'n' ∨ c = 't' ∨ c = 'f' ∨ c = '"' ∨ c = '[' ∨ c = '{') := by
          intro h; rcases h with h | h | h | h | h | h <;> (subst h; simp [isDigit] at hc)
        simp only [headClass]
        simp only [not_or] at hn
        simp [hn.1, hn.2.1, hn.2.2.1, hn.2.2.2.1, hn.2.2.2.2.1, hn.2.2.2.2.2, hc]

/-- A value's text never starts with `]` or `}` or `,` — the closers/separators used to delimit it. -/
theorem ser_head_ne (v : CV) : ∃ c t, ser v = c :: t ∧ c ≠ ']' ∧ c ≠ '}' ∧ c ≠ ',' := by
  obtain ⟨c, t, h, hc⟩ := ser_head v
  have hle : v.cls ≤ 6 := by
    cases v with
    | bool b => cases b <;> simp [CV.cls]
    | _ => simp [CV.cls]
  refine ⟨c, t, h, ?_, ?_, ?_⟩ <;> intro e <;> subst e
  · have : headClass ']' = 7 := by decide
    omega
  · have : headClass '}' = 7 := by decide
    omega
  · have : headClass ',' = 7 := by decide
    omega

theorem stop_of_sep {x : Char} {rs : List Char} (h : x = ',' ∨ x = ']' ∨ x = '}') :
    Stop (x :: rs) := by
  right; refine ⟨x, rs, rfl, ?_⟩
  rcases h with h | h | h <;> subst h <;> decide

theorem serElems_stop (vs : CVs) (r : List Char) : Stop (serElems vs false ++ ']' :: r) := by
  cases vs with
  | nil => exact stop_of_sep (rs := r) (by simp)
  | cons v vs => simp only [serElems]; exact stop_of_sep (by simp)

theorem serMembers_stop (ms : Members) (r : List Char) :
    Stop (serMembers ms false ++ '}' :: r) := by
  cases ms with
  | nil => exact stop_of_sep (rs := r) (by simp)
  | cons k v ms => simp only [serMembers]; exact stop_of_sep (by simp)

mutual
/-- **Canonical serialization is injective** (with any stopping continuation). -/
theorem ser_inj : ∀ (a b : CV) (r u : List Char), Stop r → Stop u →
    ser a ++ r = ser b ++ u → a = b ∧ r = u
  | a, b, r, u, hr, hu, h => by
    obtain ⟨ca, ta, ha, hca⟩ := ser_head a
    obtain ⟨cb, tb, hb, hcb⟩ := ser_head b
    have hcls : a.cls = b.cls := by
      rw [ha, hb] at h; simp only [List.cons_append, List.cons.injEq] at h
      rw [← hca, ← hcb, h.1]
    match a, b, hcls with
    | .null, .null, _ => simpa [ser] using h
    | .bool true, .bool true, _ => simpa [ser] using h
    | .bool false, .bool false, _ => simpa [ser] using h
    | .int i, .int j, _ =>
      have := serInt_inj hr hu (by simpa [ser] using h)
      exact ⟨by rw [this.1], this.2⟩
    | .str s, .str t, _ =>
      have := serStr_inj (by simpa [ser] using h)
      exact ⟨by rw [this.1], this.2⟩
    | .arr xs, .arr ys, _ =>
      simp only [ser, List.cons_append, List.cons.injEq, true_and, List.append_assoc,
        ] at h
      have := elems_inj xs ys true r u h
      exact ⟨by rw [this.1], this.2⟩
    | .obj ms, .obj ns, _ =>
      simp only [ser, List.cons_append, List.cons.injEq, true_and, List.append_assoc,
        ] at h
      have := members_inj ms ns true r u h
      exact ⟨by rw [this.1], this.2⟩

theorem elems_inj : ∀ (xs ys : CVs) (first : Bool) (r u : List Char),
    serElems xs first ++ ']' :: r = serElems ys first ++ ']' :: u → xs = ys ∧ r = u
  | .nil, .nil, _, r, u, h => by simpa [serElems] using h
  | .nil, .cons w ws, first, r, u, h => by
    obtain ⟨c, t, hw, hc, _, hc3⟩ := ser_head_ne w
    cases first <;> simp [serElems, hw] at h
    · exact absurd h.1.symm hc
  | .cons v vs, .nil, first, r, u, h => by
    obtain ⟨c, t, hv, hc, _, _⟩ := ser_head_ne v
    cases first <;> simp [serElems, hv] at h
    · exact absurd h.1 hc
  | .cons v vs, .cons w ws, first, r, u, h => by
    simp only [serElems, List.append_assoc] at h
    have h' := List.append_cancel_left h
    have hv := ser_inj v w _ _ (serElems_stop vs r) (serElems_stop ws u) h'
    have hvs := elems_inj vs ws false r u hv.2
    exact ⟨by rw [hv.1, hvs.1], hvs.2⟩

theorem members_inj : ∀ (ms ns : Members) (first : Bool) (r u : List Char),
    serMembers ms first ++ '}' :: r = serMembers ns first ++ '}' :: u → ms = ns ∧ r = u
  | .nil, .nil, _, r, u, h => by simpa [serMembers] using h
  | .nil, .cons k v ns, first, r, u, h => by
    cases first
    · simp only [serMembers, serStr, Bool.false_eq_true, ↓reduceIte, List.cons_append,
        List.nil_append, List.append_assoc, List.cons.injEq] at h
      exact absurd h.1 (by decide)
    · simp only [serMembers, serStr, ↓reduceIte, List.nil_append, List.cons_append,
        List.cons.injEq] at h
      exact absurd h.1 (by decide)
  | .cons k v ms, .nil, first, r, u, h => by
    cases first
    · simp only [serMembers, serStr, Bool.false_eq_true, ↓reduceIte, List.cons_append,
        List.nil_append, List.append_assoc, List.cons.injEq] at h
      exact absurd h.1 (by decide)
    · simp only [serMembers, serStr, ↓reduceIte, List.nil_append, List.cons_append,
        List.cons.injEq] at h
      exact absurd h.1 (by decide)
  | .cons k v ms, .cons k' v' ns, first, r, u, h => by
    simp only [serMembers, List.append_assoc] at h
    have h' := List.append_cancel_left h
    obtain ⟨hk, hrest⟩ := serStr_inj h'
    simp only [List.cons_append, List.append_assoc, List.cons.injEq, true_and] at hrest
    have hv := ser_inj v v' _ _ (serMembers_stop ms r) (serMembers_stop ns u) hrest
    have hms := members_inj ms ns false r u hv.2
    exact ⟨by rw [hk, hv.1, hms.1], hms.2⟩
end

/-- **RCP §2–§4 injectivity (headline).** Equal canonical text ⇒ equal canonical value. -/
theorem ser_injective {a b : CV} (h : ser a = ser b) : a = b :=
  (ser_inj a b [] [] (Or.inl rfl) (Or.inl rfl) (by simpa using h)).1

end Averin.Canon
