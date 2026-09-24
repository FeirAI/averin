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
* The headline theorems exist and depend on no more than the permitted set.
-/

def ourModule (m : Name) : Bool :=
  (`Extracted).isPrefixOf m || (`Refinement).isPrefixOf m || (`Averin).isPrefixOf m

/-- Run the audit (defined here, outside the Aeneas-extended syntax, and called from
`scripts/Audit.lean` once the whole package is loaded). -/
def runAudit : CommandElabM Unit := do
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
    let ok := if (`Averin).isPrefixOf md then standard else standard ++ trusted
    for a in axs do
      unless ok.contains a do
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
  for n in headline do
    unless env.contains n do
      throwError m!"production axiom audit: headline theorem {n} is missing"
    let axs ← liftCoreM <| collectAxioms n
    logInfo m!"{n}: {axs}"
  logInfo m!"production axiom audit: OK — {count} declarations; declared axioms {declaredAxioms}; axioms: standard + {trusted}"

end ProductionAudit
