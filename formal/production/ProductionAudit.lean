import Lean
open Lean Elab Command

namespace ProductionAudit

/-! Axiom and escape-hatch audit over EVERY declaration of this package: the Aeneas-generated
production code (`Extracted.*`), its hand-written glue (`Extracted.FunsExternal`/`TypesExternal`),
the refinement proofs (`Refinement.*`) and the Averin model compiled here (`Averin.*`).

* Each declaration may depend only on Lean's three standard axioms and the two permitted trusted
  primitives `AverinTrusted.nfc` and `AverinTrusted.sha256` (collected transitively, so this also
  covers every Aeneas/mathlib lemma the proofs use). `sorry` (`sorryAx`) and `native_decide` /
  `decide +native` (`Lean.ofReduceBool` and its auxiliary axioms) are axioms and fail here.
* The only `axiom` declarations in these modules are those two primitives.
* No declaration is `opaque`, `@[extern]` or `@[implemented_by]`.
* The Averin model part uses only the three standard axioms (as in `formal/lean/check-axioms.sh`).
* The verdict-kernel refinement (every declaration of `Refinement.VerdictLists`,
  `Refinement.Verdict` and `Refinement.VerdictClaims`, and the extracted kernel `verify.verdict.*`)
  uses only the three standard axioms: the claims say its theorems assume neither NFC nor SHA-256.
  The seal and parser theorems may use the two trusted primitives, as stated.
* The headline theorems exist and depend on no more than the permitted set; the verdict headline
  theorems (the manifest's `verify::verdict::*` entries and the `VerdictClaims` results listed
  below) on no more than the standard axioms.
* `selfTest` checks that the classification rejects a trusted primitive in a verdict declaration.
-/

def ourModule (m : Name) : Bool :=
  (`Extracted).isPrefixOf m || (`Refinement).isPrefixOf m || (`Averin).isPrefixOf m

/-- Modules whose every declaration must use only the standard axioms (the verdict refinement). -/
def standardOnlyModules : Array Name :=
  #[`Refinement.VerdictLists, `Refinement.Verdict, `Refinement.VerdictClaims]

/-- Whether declaration `n` of module `md` is held to the standard axioms only: the Averin model,
the verdict refinement modules, and the extracted verdict kernel (`verify.verdict.*`). -/
def standardOnly (md n : Name) : Bool :=
  (`Averin).isPrefixOf md || standardOnlyModules.contains md || (`verify.verdict).isPrefixOf n

/-- The axioms of `axs` not permitted for declaration `n` of module `md`. -/
def disallowed (md n : Name) (axs : Array Name) : Array Name :=
  let standard : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]
  let trusted : Array Name := #[`AverinTrusted.nfc, `AverinTrusted.sha256]
  let ok := if standardOnly md n then standard else standard ++ trusted
  axs.filter (fun a => !ok.contains a)

/-- The verdict production theorems the claims name (plan 012 phase B); standard axioms only. -/
def verdictHeadline : Array Name :=
  #[`Refinement.decide_claims_refines, `Refinement.production_support_erasure,
    `Refinement.production_satisfied_supports, `Refinement.production_requested_supports,
    `Refinement.production_committed_contradiction_refuted,
    `Refinement.production_capstone_prerequisites,
    `Refinement.production_introspected_capstone_prerequisites,
    `Refinement.production_historical_requires_policy, `Refinement.production_historical_supports,
    `Refinement.production_historical_requires_order,
    `Refinement.production_historical_requires_snapshot, `Refinement.production_at_or_after_refutes,
    `Refinement.production_total_revocation_refutes, `Refinement.corresponds_exists]

/-- Negative self-test of the classification: a trusted primitive is rejected in the verdict
modules and the extracted kernel, accepted in a seal/parser module, and never accepted in the model. -/
def selfTest : CommandElabM Unit := do
  let nfc := #[`AverinTrusted.nfc]
  unless (disallowed `Refinement.VerdictClaims `Refinement.x nfc) == nfc do
    throwError "production axiom audit self-test: NFC accepted in Refinement.VerdictClaims"
  unless (disallowed `Extracted.Funs `verify.verdict.decide_claims nfc) == nfc do
    throwError "production axiom audit self-test: NFC accepted in the extracted verdict kernel"
  unless (disallowed `Averin.Canon `Averin.x nfc) == nfc do
    throwError "production axiom audit self-test: NFC accepted in the Averin model"
  unless (disallowed `Refinement.Parse `Refinement.Parse.x nfc).isEmpty do
    throwError "production axiom audit self-test: NFC rejected in the parser refinement"
  unless (disallowed `Refinement.Verdict `Refinement.x #[`sorryAx]) == #[`sorryAx] do
    throwError "production axiom audit self-test: sorryAx accepted"

/-- Run the audit (defined here, outside the Aeneas-extended syntax, and called from
`scripts/Audit.lean` once the whole package is loaded). -/
def runAudit : CommandElabM Unit := do
  selfTest
  let env ← getEnv
  let standard : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]
  let trusted : Array Name := #[`AverinTrusted.nfc, `AverinTrusted.sha256]
  let mut bad : Array (Name × Name) := #[]
  let mut badDecl : Array (Name × String) := #[]
  let mut count := 0
  let mut declaredAxioms : Array Name := #[]
  for (name, info) in env.constants.toList do
    let some idx := env.getModuleIdxFor? name | continue
    let md := env.header.moduleNames[idx.toNat]!
    unless ourModule md do continue
    count := count + 1
    let isAx : Bool := match info with | .axiomInfo _ => true | _ => false
    let isOpaque : Bool := match info with | .opaqueInfo _ => true | _ => false
    if isAx then declaredAxioms := declaredAxioms.push name
    if isOpaque then badDecl := badDecl.push (name, "opaque")
    if isExtern env name then badDecl := badDecl.push (name, "extern")
    if (Compiler.implementedByAttr.getParam? env name).isSome then
      badDecl := badDecl.push (name, "implemented_by")
    let axs ← liftCoreM <| collectAxioms name
    for a in disallowed md name axs do
      bad := bad.push (name, a)
  let extraAxioms := declaredAxioms.filter (fun a => !trusted.contains a)
  let missingAxioms := trusted.filter (fun a => !declaredAxioms.contains a)
  unless extraAxioms.isEmpty && missingAxioms.isEmpty do
    throwError m!"production axiom audit ({count} declarations): axioms declared beyond the trusted primitives {extraAxioms}; trusted primitives not found {missingAxioms}"
  unless badDecl.isEmpty do
    throwError m!"production axiom audit: forbidden declarations {badDecl}"
  unless bad.isEmpty do
    throwError m!"production axiom audit: non-permitted axioms {bad}"
  if count < 500 then
    throwError m!"production axiom audit: only {count} declarations found — is the import broken?"
  -- every theorem the manifest maps an extracted function to, plus the composition theorems
  let manifest ← match Json.parse (← IO.FS.readFile "manifest.json") with
    | .ok j => pure j
    | .error e => throwError m!"production axiom audit: manifest.json: {e}"
  let some (.obj extracted) := (manifest.getObjVal? "extracted").toOption
    | throwError "production axiom audit: manifest.json has no `extracted` map"
  let mut headline : Array Name := #[`Refinement.canon_functional, `Refinement.canon_perm_members,
    `Refinement.utf16_units_model, `Refinement.fmtP_inj, `Refinement.fmtM_inj, `Refinement.prodH_len]
  for (_, v) in extracted.toArray do
    let some arr := v.getArr?.toOption | throwError "production axiom audit: bad manifest entry {v}"
    for t in arr do
      let some str := t.getStr?.toOption | throwError "production axiom audit: bad theorem name {t}"
      headline := headline.push str.toName
  let mut verdictCount := 0
  for n in verdictHeadline do
    headline := headline.push n
  let mut seen : Array Name := #[]
  for n in headline do
    if seen.contains n then continue
    seen := seen.push n
    unless env.contains n do
      throwError m!"production axiom audit: headline theorem {n} is missing"
    let axs ← liftCoreM <| collectAxioms n
    let isVerdict := verdictHeadline.contains n ||
      (extracted.toArray.any fun (k, v) => k.startsWith "verify::verdict::" &&
        (v.getArr?.toOption.getD #[]).any (fun t => t.getStr?.toOption == some n.toString))
    if isVerdict then
      verdictCount := verdictCount + 1
      let extra := axs.filter (fun a => !standard.contains a)
      unless extra.isEmpty do
        throwError m!"production axiom audit: verdict theorem {n} depends on {extra} (standard axioms only)"
    logInfo m!"{n}: {axs}"
  if verdictCount < verdictHeadline.size then
    throwError m!"production axiom audit: only {verdictCount} verdict headline theorems checked"
  logInfo m!"production axiom audit: OK — {count} declarations; declared axioms {declaredAxioms}; axioms: standard + {trusted}; verdict refinement ({verdictCount} headline theorems, modules {standardOnlyModules}, verify.verdict.*): standard only"

end ProductionAudit
