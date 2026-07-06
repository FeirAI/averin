# Canonical local workflow. The headline footgun this guards: `go test` in server/ links a PREBUILT rust
# staticlib (server/internal/core: #cgo LDFLAGS .../target/debug/libaverin_decision_core.a). Edit core/ but
# forget to rebuild it and the Go tests pass against a STALE trust root. `make test-server` always rebuilds
# the staticlib first; `make check-staticlib` fails if it is older than core source.
.PHONY: all core wasm check-staticlib test-core test-server test-verifier test deny vuln supply-chain

all: test

# Rust integrity core -> the cgo staticlib (debug profile; matches the cgo LDFLAGS path).
core:
	cargo build -p averin-decision-core

# Verifier trust root: rebuild the wasm, refresh its pinned digest + the in-page pin (see SUPPLY-CHAIN.md).
wasm:
	./verifier/build.sh

check-staticlib:
	./scripts/check-staticlib-fresh.sh

test-core:
	cargo test --workspace

# Rebuild the staticlib FIRST so the linked core is never stale, then run the Go suite.
test-server: core
	cd server && go vet ./... && go test ./...

test-verifier: wasm
	cd verifier && bun test

test: test-core test-server test-verifier

# Supply-chain gates (mirror CI). deny: RustSec advisories + licenses + sources + bans (deny.toml).
deny:
	cargo deny check advisories licenses sources bans

vuln:
	cd server && go run golang.org/x/vuln/cmd/govulncheck@latest ./...

supply-chain: deny vuln
