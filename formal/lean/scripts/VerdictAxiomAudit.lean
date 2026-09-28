import Lean
import Averin
import Oracle.Verdict
open Lean Elab Command

/-- Escape hatches that are not axioms, by attribute (however attached: `@[..]`, `attribute [..] x`,
an attribute list): an `axiom`/`opaque` constant (`partial def` compiles to one), an `unsafe` one,
`@[extern]` or `@[implemented_by]`, for every constant defined in a module accepted by `ours`. -/
def escapeHatches (env : Environment) (ours : Name → Bool) : Array (Name × String) := Id.run do
  let mut bad : Array (Name × String) := #[]
  for (name, info) in env.constants.toList do
    let some idx := env.getModuleIdxFor? name | continue
    unless ours env.header.moduleNames[idx.toNat]! do continue
    match info with
    | .axiomInfo _ => bad := bad.push (name, "axiom")
    | .opaqueInfo _ => bad := bad.push (name, "opaque")
    | _ => pure ()
    if info.isUnsafe then bad := bad.push (name, "unsafe")
    if isExtern env name then bad := bad.push (name, "extern")
    if (Compiler.implementedByAttr.getParam? env name).isSome then bad := bad.push (name, "implemented_by")
  return bad

def ourModule (m : Name) : Bool := (`Averin).isPrefixOf m || (`Oracle).isPrefixOf m

/- The verdict oracle defines its own `main`, so it cannot be loaded together with Oracle.Main
in AxiomAudit. Audit this exact module and require a sentinel declaration from it. -/
#eval show CommandElabM Unit from do
  let env ← getEnv
  let allowed : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]
  unless env.contains ``Averin.Oracle.Verdict.run do
    throwError m!"verdict axiom audit: Oracle.Verdict is not loaded"
  let mut bad : Array (Name × Name) := #[]
  let mut count := 0
  for (name, _) in env.constants.toList do
    if ((`Averin.Oracle.Verdict).isPrefixOf name || name == `main) && !name.isInternal then
      count := count + 1
      let axs ← liftCoreM <| collectAxioms name
      for a in axs do
        unless allowed.contains a do
          bad := bad.push (name, a)
  let hatches := escapeHatches env ourModule
  unless hatches.isEmpty do
    throwError m!"verdict axiom audit: escape hatches {hatches}"
  if count < 5 then
    throwError m!"verdict axiom audit: only {count} declarations found"
  unless bad.isEmpty do
    throwError m!"verdict axiom audit: non-standard axioms {bad}"
  logInfo m!"verdict axiom audit: OK — {count} declarations, standard axioms only"
