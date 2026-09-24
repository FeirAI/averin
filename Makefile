# Canonical local workflow. The headline footgun this guards: `go test` in server/ links a PREBUILT rust
# staticlib (server/internal/core: #cgo LDFLAGS .../target/debug/libaverin_decision_core.a). Edit core/ but
# forget to rebuild it and the Go tests pass against a STALE trust root. `make test-server` always rebuilds
# the staticlib first; `make check-staticlib` fails if it is older than core source.
.PHONY: all core wasm check-staticlib test-core test-server test-server-postgres test-verifier test deny vuln supply-chain check-claims

all: test

# Rust integrity core -> the cgo staticlib (debug profile; matches the cgo LDFLAGS path).
# The server's product-facing verifier evaluates real RFC 3161 anchors, so the native
# cgo trust root must include that feature (the intentionally lean WASM build does not).
core:
	cargo build -p averin-decision-core --features rfc3161

# Verifier trust root: rebuild the wasm, refresh its pinned digest + the in-page pin (see SUPPLY-CHAIN.md).
wasm:
	./verifier/build.sh

check-staticlib:
	./scripts/check-staticlib-fresh.sh

test-core:
	cargo test --workspace

# Rebuild the staticlib FIRST so the linked core is never stale, then run the Go suite.
test-server: core
	cd server && go vet ./... && go test -a ./...

# Real-Postgres API/store gate; requires a disposable Postgres 16 DSN. The JSON gate
# rejects absent/skipped named race tests, including skipped children of a passing parent.
test-server-postgres: core check-staticlib
	@test -n "$(AVERIN_TEST_DATABASE_URL)" || (echo 'AVERIN_TEST_DATABASE_URL is required' >&2; exit 1)
	python3 -m unittest discover -s scripts -p test_check_go_test_events.py
	cd server && bash -o pipefail -c 'go test -json -count=1 ./internal/api/... ./internal/store/... ./internal/pgledger/... ./internal/pgdurable/... ./internal/pgschema/... ./internal/resourceshim/... | python3 ../scripts/check-go-test-events.py'

check-claims:
	python3 -m unittest discover -s scripts -p test_check_claims.py
	python3 scripts/check-claims.py

test-verifier: wasm
	cd verifier && bun test

test: test-core test-server test-verifier

# Supply-chain gates (mirror CI). deny: RustSec advisories + licenses + sources + bans (deny.toml).
deny:
	cargo deny check advisories licenses sources bans

vuln:
	cd server && go run golang.org/x/vuln/cmd/govulncheck@latest ./...

supply-chain: deny vuln

# Formal verification gates (see formal/README.md). Needs elan/Lean 4.30.0, cargo-kani 0.68, Java.
.PHONY: formal formal-lean formal-refinement formal-mutants formal-kani formal-tla
formal: formal-lean formal-refinement formal-mutants formal-kani formal-tla

formal-lean:
	cd formal/lean && lake build --wfail && ./check-axioms.sh

formal-refinement:
	python3 formal/check-refinement.py
	cd formal/lean && lake build --wfail oracle && lake exe oracle ../oracle/inputs.json ../oracle/expected.json
	cd formal/lean && lake build --wfail verdict_oracle && lake exe verdict_oracle ../oracle/verdict-expected.json
	git diff --exit-code -- formal/oracle/expected.json
	git diff --exit-code -- formal/oracle/verdict-expected.json
	cargo test -p averin-decision-core --test oracle
	cargo test -p averin-decision-core --lib verdict_differential

formal-mutants:
	bash formal/check-mutants.sh

formal-kani:
	bash formal/run-kani.sh

formal-tla:
	bash formal/tla/run-tlc.sh
