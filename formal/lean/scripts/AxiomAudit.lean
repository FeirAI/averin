import Lean
import Averin
open Lean Elab Command

/- Every declaration under `Averin` (theorems and definitions alike) may depend only on Lean's
three standard axioms. `sorry` (`sorryAx`) and `native_decide` (`Lean.ofReduceBool`) are axioms,
so they are caught here too. -/
#eval show CommandElabM Unit from do
  let env ← getEnv
  let allowed : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]
  let mut bad : Array (Name × Name) := #[]
  let mut count := 0
  for (name, _) in env.constants.toList do
    if (`Averin).isPrefixOf name && !name.isInternal then
      count := count + 1
      let axs ← liftCoreM <| collectAxioms name
      for a in axs do
        unless allowed.contains a do
          bad := bad.push (name, a)
  if count < 100 then
    throwError m!"axiom audit: only {count} Averin declarations found — is the import broken?"
  unless bad.isEmpty do
    throwError m!"axiom audit: non-standard axioms {bad}"
  logInfo m!"axiom audit: OK — {count} Averin declarations, standard axioms only"
