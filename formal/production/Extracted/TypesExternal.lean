import Aeneas
open Aeneas Aeneas.Std Result ControlFlow Error

/-!
# External types used by the extracted production code (hand-written, audited)

Aeneas leaves every type it has no model for to this file. The only one is the error type of
`String::from_utf8`, whose single use is an arm the extracted code never inspects (the `panic!` in
`hashx::ascii_string` and `CanonValue::serialize`). Any model works; `Unit` adds no assumption.
`formal/production/check-glue.py` checks that this file defines exactly the types Aeneas requested.
-/

/-- `alloc::string::FromUtf8Error`: never inspected. -/
def alloc.string.FromUtf8Error : Type := Unit
