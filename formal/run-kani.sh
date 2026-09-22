#!/usr/bin/env bash
# Bounded model checking (Kani/CBMC) of the integrity core's encoders and parser, over the Rust code as
# written. Complements the unbounded Lean model in formal/lean (see formal/README.md).
set -euo pipefail

cd "$(dirname "$0")/.."

run_harness() {
  cargo kani -p averin-decision-core --no-default-features -Z stubbing --harness "$1"
}

# b64.rs — base64url is a bijection on the lengths the verifier decodes.
run_harness decode_inverts_encode
run_harness accepted_encoding_is_unique
# hashx.rs — the "sha256:<hex>" digest string is injective; LP framing is exact.
run_harness hex_roundtrip
run_harness hex32_is_canonical
run_harness lp_into_frames_exactly
# canon.rs — the parser/serializer implement the Lean model on small inputs.
run_harness integer_roundtrip
run_harness accepted_integer_spelling_is_canonical
run_harness string_escape_roundtrip
run_harness utf16_strict_matches_std
run_harness utf16_key_order_is_exact
run_harness parse_never_panics
