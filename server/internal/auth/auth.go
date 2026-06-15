// Package auth is project-scoped API-key authentication for the feir app/ingestion API.
//
// Phase 1 shipped with NO authorization (any caller who could reach an endpoint could read or write
// any project's data — see api/server.go handleDAG and docs/coverage-limits.md). This package is the
// minimal closing of that gap: a bearer/api-key check that the request is authorized for the project
// it names. It is NOT the full authz story — RBAC, SSO, scoped/expiring tokens, and per-route
// permissions are still Phase 2. This only answers one question: "is this token valid for this
// project?"
//
// Security-relevant choices (commented inline where they live):
//   - Fail-closed: a project with no keys configured DENIES everything. The only way to allow-all is
//     to explicitly opt in with NewOpenStore(), which is documented dev-only.
//   - Constant-time comparison (crypto/subtle) so a wrong token can't be recovered byte-by-byte from
//     response-timing differences.
//   - Tokens are never logged or echoed back; 401 bodies are generic.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
)

// KeyStore answers whether a token authorizes access to a project. Implementations MUST compare
// tokens in constant time and MUST fail closed (unknown project / no configured keys => false).
type KeyStore interface {
	ValidFor(project, token string) bool
}

// MapStore is an in-memory KeyStore: project -> set of accepted tokens. Safe for concurrent use.
//
// A project with no entry (or an empty token set) is DENIED — there is no implicit "any token is
// fine" state. This is the fail-closed default; use NewOpenStore for the explicit dev-only opposite.
type MapStore struct {
	mu   sync.RWMutex
	keys map[string][]string // project -> accepted tokens
}

// NewMapStore builds a MapStore. The initial map is project -> list of valid tokens; it is copied so
// later mutation of the caller's map does not affect the store. A nil/empty map denies everything.
func NewMapStore(initial map[string][]string) *MapStore {
	ks := &MapStore{keys: make(map[string][]string, len(initial))}
	for project, tokens := range initial {
		ks.keys[project] = append([]string(nil), tokens...)
	}
	return ks
}

// Add registers a token as valid for a project (idempotent). Empty project or token is ignored — an
// empty token must never become a valid credential.
func (ks *MapStore) Add(project, token string) {
	if project == "" || token == "" {
		return
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, t := range ks.keys[project] {
		if t == token {
			return
		}
	}
	ks.keys[project] = append(ks.keys[project], token)
}

// ValidFor reports whether token is accepted for project. It fails closed: an empty token, an empty
// project, or a project with no configured keys all return false.
//
// Comparison is constant-time (crypto/subtle.ConstantTimeCompare) to avoid leaking how many leading
// bytes of a guess were correct via timing. We still iterate every candidate and OR the results
// (rather than early-returning on first match) so the work — and thus the time — does not depend on
// which key matched or whether an earlier key was a near-miss.
func (ks *MapStore) ValidFor(project, token string) bool {
	if project == "" || token == "" {
		return false // fail-closed: no anonymous / empty-token access
	}
	ks.mu.RLock()
	tokens := ks.keys[project]
	ks.mu.RUnlock()

	// Compare SHA-256 digests, not raw tokens: this fixes the comparison length to 32 bytes so
	// neither the configured key length nor whether a project exists is leaked via timing. For an
	// unknown/empty-keyset project we still run one comparison against a dummy digest so the timing
	// profile is uniform with a present project (no project-existence oracle).
	got := sha256.Sum256([]byte(token))
	var match int
	if len(tokens) == 0 {
		var dummy [32]byte
		subtle.ConstantTimeCompare(got[:], dummy[:])
		return false // fail-closed
	}
	for _, want := range tokens {
		w := sha256.Sum256([]byte(want))
		match |= subtle.ConstantTimeCompare(got[:], w[:]) // OR-accumulate; visit every candidate
	}
	return match == 1
}

// openStore is the explicit, dev-only "allow everything" KeyStore. See NewOpenStore.
type openStore struct{}

// ParseKeys parses the FEIR_API_KEYS wire format "proj-a:tok1,tok2;proj-b:tok3" into a MapStore.
// Empty projects/tokens are skipped. Returns the store and the number of projects with >=1 key, so
// callers can refuse to start in a silent deny-all (zero keys) configuration.
func ParseKeys(raw string) (*MapStore, int) {
	m := map[string][]string{}
	for _, entry := range strings.Split(raw, ";") {
		proj, toks, ok := strings.Cut(strings.TrimSpace(entry), ":")
		proj = strings.TrimSpace(proj)
		if !ok || proj == "" {
			continue
		}
		for _, t := range strings.Split(toks, ",") {
			if t = strings.TrimSpace(t); t != "" {
				m[proj] = append(m[proj], t)
			}
		}
	}
	return NewMapStore(m), len(m)
}

// NewOpenStore returns a KeyStore that authorizes ALL tokens for ALL projects — including the empty
// token / no Authorization header at all (Middleware short-circuits to allow when the store is open).
//
// DEV-ONLY. This intentionally defeats the authentication this package exists to provide. It is here
// so local/single-tenant deployments can keep Phase-1 behavior on purpose and visibly, instead of
// authn being silently absent. NEVER use it in a multi-tenant or internet-exposed deployment.
func NewOpenStore() KeyStore { return openStore{} }

// ValidFor always returns true — open mode. (Even an empty token passes; Middleware treats open
// stores specially so a missing header is also allowed.)
func (openStore) ValidFor(_, _ string) bool { return true }

// IsOpen reports whether ks is the dev-only allow-all store, so callers (and Middleware) can detect
// and, if they like, warn about running without authentication.
func IsOpen(ks KeyStore) bool {
	_, ok := ks.(openStore)
	return ok
}

// Middleware returns net/http middleware that enforces project-scoped API-key auth.
//
// It reads the credential from EITHER:
//   - Authorization: Bearer <token>   (case-insensitive scheme), or
//   - X-Api-Key: <token>
//
// and reads the project from the query parameter named projectParam (default "project" when empty).
// If the token is not ValidFor that project it writes a generic 401 JSON body and does not call the
// next handler. The token is never written to the response or any log.
//
// Open stores (NewOpenStore) bypass the check entirely, so a deployment that has deliberately chosen
// no-auth does not require clients to send a dummy header.
func Middleware(ks KeyStore, projectParam string) func(http.Handler) http.Handler {
	if projectParam == "" {
		projectParam = "project"
	}
	open := IsOpen(ks)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if open {
				next.ServeHTTP(w, r) // dev-only allow-all; no credential required
				return
			}
			project := r.URL.Query().Get(projectParam)
			token := tokenFromRequest(r)
			// ValidFor fails closed for empty project/token and for unconfigured projects, so we do not
			// special-case "missing header" here — it naturally 401s.
			if !ks.ValidFor(project, token) {
				unauthorized(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// tokenFromRequest extracts the API token. Authorization: Bearer <t> wins; otherwise X-Api-Key. The
// returned string is the raw token with surrounding whitespace trimmed; "" means no usable credential
// was presented.
func tokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		// Scheme is case-insensitive per RFC 7235; the token value is not.
		if rest, ok := cutBearer(h); ok {
			return strings.TrimSpace(rest)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

// cutBearer splits "Bearer <token>" with a case-insensitive scheme. ok is false if h is not a Bearer
// header, so a malformed Authorization value falls through to X-Api-Key rather than being mistaken
// for a token.
func cutBearer(h string) (token string, ok bool) {
	const scheme = "bearer"
	if len(h) < len(scheme)+1 {
		return "", false
	}
	if !strings.EqualFold(h[:len(scheme)], scheme) || h[len(scheme)] != ' ' {
		return "", false
	}
	return h[len(scheme)+1:], true
}

// unauthorized writes a generic 401. The body deliberately reveals nothing about whether the project
// exists, whether a token was sent, or why it failed — to avoid being a project/credential oracle.
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	// WWW-Authenticate advertises the scheme without leaking anything (RFC 7235).
	w.Header().Set("WWW-Authenticate", `Bearer realm="feir"`)
	w.WriteHeader(http.StatusUnauthorized)
	// Static body, no token, no project name.
	w.Write([]byte(`{"error":"unauthorized"}`))
}
