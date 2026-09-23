import Lean
import Averin
import Oracle.Main
open Lean Elab Command

/- Every declaration under `Averin` (theorems and definitions alike, including the oracle glue
`Averin.Oracle.*` and its spec lemmas `utf8c_eq`, `recordPre_spec`, `checkpointPre_spec`) may depend only on Lean's
three standard axioms. `sorry` (`sorryAx`) and `native_decide` (`Lean.ofReduceBool`) are axioms,
so they are caught here too. -/
#eval show CommandElabM Unit from do
  let env ← getEnv
  let allowed : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]
  let mut bad : Array (Name × Name) := #[]
  let mut count := 0
  for (name, _) in env.constants.toList do
    if ((`Averin).isPrefixOf name || name == `main) && !name.isInternal then
      count := count + 1
      let axs ← liftCoreM <| collectAxioms name
      for a in axs do
        unless allowed.contains a do
          bad := bad.push (name, a)
  unless env.contains ``Averin.Oracle.recordPre_spec do
    throwError m!"axiom audit: the oracle module is not loaded"
  if count < 100 then
    throwError m!"axiom audit: only {count} Averin declarations found — is the import broken?"
  unless bad.isEmpty do
    throwError m!"axiom audit: non-standard axioms {bad}"
  logInfo m!"axiom audit: OK — {count} Averin declarations, standard axioms only"
