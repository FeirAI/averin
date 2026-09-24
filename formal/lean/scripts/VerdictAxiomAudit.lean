import Lean
import Averin
import Oracle.Verdict
open Lean Elab Command

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
  if count < 5 then
    throwError m!"verdict axiom audit: only {count} declarations found"
  unless bad.isEmpty do
    throwError m!"verdict axiom audit: non-standard axioms {bad}"
  logInfo m!"verdict axiom audit: OK — {count} declarations, standard axioms only"
