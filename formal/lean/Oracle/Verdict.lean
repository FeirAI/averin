import Averin.Verdict
import Lean.Data.Json

/-!
Differential verdict corpus. These finite abstract records and attachments are passed through
`Averin.Verdict.decideClaim`, the executable definition related to `Supports`. The Rust unit
test in `verify/verdict.rs` constructs corresponding checked facts and compares every decision.
This checks the pure production kernel; it does not prove `verify.rs` extracts those facts from
untrusted bundle bytes. End-to-end adversarial fixtures check that separate projection boundary.
-/

namespace Averin.Oracle.Verdict

open Averin.Verdict

def bit (n k : Nat) : Bool := n / (2 ^ k) % 2 == 1

def record : Record := {
  id := 1, hash := 11, signer := 1, roleKey := 2, grantId := 7,
  contributesRole := true, grantRecord := true
}

def capstone : CapstoneChecks := {
  manifest := true, twoPhase := true, noIncompleteIntent := true,
  uses := [1], matched := [1], popVerified := [1], actionVerified := [1],
  twoPhaseCompleted := [1], taxonomy := true, grantLog := true,
  attestation := true, noViolation := true, noPending := true,
  boundedReuse := true, cosignatures := true, delegation := true,
  revocation := true, federation := true, coverage := true,
  nativePresent := false, introspection := false
}

def facts (n : Nat) : Fixed := {
  records := [record], sealed := [1],
  roleSigned := if bit n 2 then [1] else [],
  pinnedSigners := if bit n 0 then [1] else [],
  pinnedRoles := if bit n 2 then [2] else [],
  checkpoint := 10, changedAt := some 6,
  revoked := if bit n 6 then [7] else [],
  usedGrantIds := [7],
  adverseOpening := false, adverseAnchor := false, checkedContradiction := false,
  revocationIssuerPinned := true, disclosedFresh := bit n 4, merkleFresh := false,
  policy := ⟨.authorized, .pinned, true, false⟩,
  brokeredUseValid := bit n 3, introspectedUseValid := false,
  capstone,
  temporalPolicy := false, evalTime := 8, maxAge := 5, minWatermark := 3,
  receipts := [], cutoffs := [], histUseValid := false,
  historicalContradiction := false
}

def attachments (n : Nat) : List Attachment :=
  (if bit n 1 then [.anchor 10 5] else []) ++
  (if bit n 5 then [.attestation 10] else []) ++
  (if bit n 7 then [.disclosure 1] else [])

-- Every supporting bit is present; bit 6 is the independent adverse revocation statement.
def full : Nat := 191

def changedCapstone (n : Nat) : CapstoneChecks :=
  let c := capstone
  match n with
  | 0 => { c with manifest := false }
  | 1 => { c with twoPhase := false }
  | 2 => { c with noIncompleteIntent := false }
  | 3 => { c with matched := [] }
  | 4 => { c with popVerified := [] }
  | 5 => { c with actionVerified := [] }
  | 6 => { c with twoPhaseCompleted := [] }
  | 7 => { c with taxonomy := false }
  | 8 => { c with grantLog := false }
  | 9 => { c with attestation := false }
  | 10 => { c with noViolation := false }
  | 11 => { c with noPending := false }
  | 12 => { c with boundedReuse := false }
  | 13 => { c with cosignatures := false }
  | 14 => { c with delegation := false }
  | 15 => { c with revocation := false }
  | 16 => { c with federation := false }
  | 17 => { c with coverage := false }
  | 18 => { c with uses := [] }
  | 19 => { c with nativePresent := true }
  | _ => c

def decisionString : Decision → String
  | .satisfied => "satisfied"
  | .insufficient => "insufficient"
  | .refuted => "refuted"

def row (name : String) (f : Fixed) (a : List Attachment) : String :=
  let field (key : String) (claim : Claim) :=
    s!"\"{key}\":\"{decisionString (decideClaim f a claim)}\""
  "  {\"name\":\"" ++ name ++ "\"," ++ ",".intercalate [
    field "integrity" .integrity,
    field "authenticated" .authenticated,
    field "authorized" .authorized,
    field "historical_authorized_as_of_snapshot" .historicalAuthorized,
    field "temporal" .temporal,
    field "complete_brokered" .completeBrokered,
    field "complete_introspected" .completeIntrospected] ++ "}"

/-- Plan 009 cases over one validated receipt of grant 7 with ordinal 4. The supporting base is
the fully supported `full` fact set; bits select the historical inputs:
0 policy selected · 1 snapshot attached · 2 snapshot stale · 3 receipt ordinal present ·
4 receipt validated · 5 cutoff 9 (after) · 6 cutoff 4 (equality: at/after) · 7 grant totally
revoked · 8 historical use obligations hold · 9 snapshot watermark 2 (below the minimum 3). -/
def histFacts (n : Nat) : Fixed :=
  let f := facts full
  { f with
    revoked := if bit n 7 then [7] else [],
    temporalPolicy := bit n 0,
    receipts := [⟨1, 7, if bit n 3 then some 4 else none, bit n 4⟩],
    cutoffs := (if bit n 5 then [(7, 9)] else []) ++ (if bit n 6 then [(7, 4)] else []),
    histUseValid := bit n 8 }

def histAttachments (n : Nat) : List Attachment :=
  let boundary := if bit n 2 then 1 else 5
  let watermark := if bit n 9 then 2 else 10
  (if bit n 1 then [.snapshot boundary watermark false] else []) ++ attachments full

def run : String :=
  let ordinary := (List.range 256).map fun n => row s!"bits_{n}" (facts n) (attachments n)
  let capstoneCases := (List.range 20).map fun n =>
    row s!"capstone_{n}" { facts full with capstone := changedCapstone n } (attachments full)
  let f := facts full
  let both := { f with policy := { f.policy with revocation := .both } }
  let both := { both with merkleFresh := true }
  let anchorless := { f with changedAt := none }
  let anchorless := { anchorless with revocationIssuerPinned := false }
  let anchorless := { anchorless with policy :=
    { anchorless.policy with requireDisclosure := false } }
  let other := { record with id := 2 }
  let other := { other with hash := 12 }
  let other := { other with contributesRole := false }
  let other := { other with grantRecord := false }
  let noncontributor := { f with records := [record, { other with grantId := 8 }] }
  let noncontributor := { noncontributor with sealed := [1, 2] }
  let nonGrantSharedGid := { f with records := [record, other] }
  let nonGrantSharedGid := { nonGrantSharedGid with sealed := [1, 2] }
  let introspected := { f with brokeredUseValid := false }
  let introspected := { introspected with introspectedUseValid := true }
  let nativeCapstone := { capstone with uses := [] }
  let nativeCapstone := { nativeCapstone with nativePresent := true }
  let nativeCapstone := { nativeCapstone with introspection := true }
  let introspected := { introspected with capstone := nativeCapstone }
  let otherConflict := { record with id := 2 }
  let otherConflict := { otherConflict with hash := 12 }
  let conflict := { f with records := [record, otherConflict] }
  let conflict := { conflict with sealed := [1, 2] }
  let conflict := { conflict with roleSigned := [1, 2] }
  let adverseCases := [
    row "adverse_opening" { f with adverseOpening := true } (attachments full),
    row "adverse_anchor" { f with adverseAnchor := true } (attachments full),
    row "checked_contradiction" { f with checkedContradiction := true } (attachments full),
    row "missing_seal" { f with sealed := [] } (attachments full),
    row "missing_path" both (attachments full),
    row "present_path" both (.path 7 :: attachments full),
    row "anchorless_default" anchorless [],
    row "required_attestation_missing" { f with
      policy := { f.policy with requireAttestation := true } }
      ((attachments full).filter (· != .attestation 10)),
    row "noncontributor_role" noncontributor (attachments full),
    row "non_grant_shared_gid" nonGrantSharedGid (attachments full),
    row "introspected" introspected (attachments full),
    row "committed_conflict" conflict (.disclosure 2 :: attachments full)
  ]
  let histCases := (List.range 1024).map fun n =>
    row s!"hist_{n}" (histFacts n) (histAttachments n)
  -- Named plan 009 cases: an ordinal beyond the watermark, a Merkle snapshot with and without
  -- the per-grant path, a contradiction among blocked receipts, and a future boundary time.
  let hf := histFacts 0x11B
  let histSpecial := [
    row "hist_beyond_watermark" { hf with receipts := [⟨1, 7, some 11, true⟩] }
      (histAttachments 0x11B),
    row "hist_merkle_missing_path" hf (.snapshot 5 10 true :: attachments full),
    row "hist_merkle_path" hf (.path 7 :: .snapshot 5 10 true :: attachments full),
    row "hist_contradiction" { hf with historicalContradiction := true } (histAttachments 0x11B),
    row "hist_future_boundary" hf (.snapshot 9 10 false :: attachments full),
    -- An authenticated cutoff decides at/after even when the Merkle path is missing.
    row "hist_merkle_missing_path_at_cutoff" { hf with cutoffs := [(7, 4)] }
      (.snapshot 5 10 true :: attachments full),
    -- The caller's revocation mode selects the snapshot kinds the claim needs.
    row "hist_disclosed_mode_merkle_snapshot"
      { hf with policy := { hf.policy with revocation := .disclosed } }
      (.path 7 :: .snapshot 5 10 true :: attachments full),
    row "hist_merkle_mode_list_snapshot"
      { hf with policy := { hf.policy with revocation := .merkle } } (histAttachments 0x11B),
    row "hist_merkle_mode_merkle_snapshot"
      { hf with policy := { hf.policy with revocation := .merkle } }
      (.path 7 :: .snapshot 5 10 true :: attachments full),
    row "hist_both_mode_list_only"
      { hf with policy := { hf.policy with revocation := .both } } (histAttachments 0x11B),
    row "hist_both_mode_both_snapshots"
      { hf with policy := { hf.policy with revocation := .both } }
      (.path 7 :: .snapshot 5 10 true :: histAttachments 0x11B),
    row "hist_issuer_unpinned" { hf with revocationIssuerPinned := false } (histAttachments 0x11B)
  ]
  "[\n" ++ ",\n".intercalate
    (ordinary ++ capstoneCases ++ adverseCases ++ histCases ++ histSpecial) ++ "\n]\n"

end Averin.Oracle.Verdict

def main (args : List String) : IO UInt32 := do
  let outPath := args.headD "../oracle/verdict-expected.json"
  IO.FS.writeFile outPath Averin.Oracle.Verdict.run
  IO.println s!"verdict-oracle: wrote {outPath}"
  pure 0
