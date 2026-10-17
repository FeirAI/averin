// Package auth is project-scoped API-key authentication for the averin app/ingestion API.
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
	"time"
)

// KeyStore answers whether a token authorizes access to a project. Implementations MUST compare
// tokens in constant time and MUST fail closed (unknown project / no configured keys => false).
type KeyStore interface {
	ValidFor(project, token string) bool
}

// Role is the scope of an API token. Roles are ordered: admin includes write includes read.
type Role int

const (
	// RoleRead may call read-only routes (GET): verify, export, list, DAG, sessions, usage, posture.
	RoleRead Role = iota + 1
	// RoleWrite may also add evidence (POST records, grants, use, otel ...).
	RoleWrite
	// RoleAdmin may also revoke grants and create checkpoints. Any route not classified is admin.
	RoleAdmin
)

// String returns the wire name of the role.
func (r Role) String() string {
	switch r {
	case RoleRead:
		return "read"
	case RoleWrite:
		return "write"
	case RoleAdmin:
		return "admin"
	}
	return "none"
}

// Allows reports whether a token holding r may call a route that needs `need`. A zero or unknown
// role allows nothing.
func (r Role) Allows(need Role) bool { return r >= RoleRead && r <= RoleAdmin && r >= need }

// ParseRole parses "read", "write" or "admin" (exact, lower case). Anything else is an error so a
// typo in the key file never silently becomes a stronger or weaker role.
func ParseRole(s string) (Role, bool) {
	switch s {
	case "read":
		return RoleRead, true
	case "write":
		return RoleWrite, true
	case "admin":
		return RoleAdmin, true
	}
	return 0, false
}

// RoleStore is a KeyStore that knows each token's role and expiry. RoleFor reports the role of a token
// that is valid for the project at `now`; an unknown, empty or expired token is (0, false).
type RoleStore interface {
	KeyStore
	RoleFor(project, token string, now time.Time) (Role, bool)
	// Now is the clock the store judges expiry by; the middleware passes it back into RoleFor.
	Now() time.Time
}

type keyEntry struct {
	digest   [32]byte
	role     Role
	notAfter time.Time // zero = no expiry
}

// live reports whether the entry has not expired at now. The expiry instant itself is expired.
func (e keyEntry) live(now time.Time) bool { return e.notAfter.IsZero() || now.Before(e.notAfter) }

// MapStore is an in-memory RoleStore: project -> accepted tokens, each with a role and optional expiry.
// Safe for concurrent use.
//
// A project with no entry (or an empty token set) is DENIED. There is no implicit "any token is fine"
// state. This is the fail-closed default; use NewOpenStore for the explicit dev-only opposite.
type MapStore struct {
	mu   sync.RWMutex
	keys map[string][]keyEntry // project -> accepted tokens (stored as SHA-256 digests)
	now  func() time.Time
}

// NewMapStore builds a MapStore. The initial map is project -> list of valid tokens; each becomes an
// admin token with no expiry (the legacy behavior). It is copied so later mutation of the caller's map
// does not affect the store. A nil/empty map denies everything.
func NewMapStore(initial map[string][]string) *MapStore {
	ks := &MapStore{keys: make(map[string][]keyEntry, len(initial)), now: time.Now}
	for project, tokens := range initial {
		for _, t := range tokens {
			ks.Add(project, t)
		}
	}
	return ks
}

// WithClock replaces the clock used to judge expiry (tests).
func (ks *MapStore) WithClock(now func() time.Time) *MapStore {
	ks.mu.Lock()
	ks.now = now
	ks.mu.Unlock()
	return ks
}

// Add registers an admin token with no expiry for a project (idempotent). Empty project or token is
// ignored: an empty token must never become a valid credential.
func (ks *MapStore) Add(project, token string) {
	if token == "" {
		return
	}
	ks.AddScoped(project, token, RoleAdmin, time.Time{})
}

// AddScoped registers a token with a role and an optional expiry (zero = none). Adding the same
// project+token again replaces its role and expiry. An invalid role is ignored (never stronger by accident).
func (ks *MapStore) AddScoped(project, token string, role Role, notAfter time.Time) {
	if token == "" {
		return
	}
	ks.addDigest(project, sha256.Sum256([]byte(token)), role, notAfter)
}

// AddDigest is AddScoped for a token whose SHA-256 is configured instead of the token itself.
func (ks *MapStore) AddDigest(project string, digest [32]byte, role Role, notAfter time.Time) {
	ks.addDigest(project, digest, role, notAfter)
}

func (ks *MapStore) addDigest(project string, digest [32]byte, role Role, notAfter time.Time) {
	if project == "" || !role.Allows(RoleRead) {
		return
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, e := range ks.keys[project] {
		if e.digest == digest {
			ks.keys[project][i] = keyEntry{digest: digest, role: role, notAfter: notAfter}
			return
		}
	}
	ks.keys[project] = append(ks.keys[project], keyEntry{digest: digest, role: role, notAfter: notAfter})
}

// ValidFor reports whether token is accepted for project at any role. It fails closed: an empty token,
// an empty project, a project with no configured keys and an expired token all return false.
func (ks *MapStore) ValidFor(project, token string) bool {
	_, ok := ks.RoleFor(project, token, ks.clock())
	return ok
}

// Now returns the store's current time (the injected clock, or the wall clock).
func (ks *MapStore) Now() time.Time { return ks.clock() }

func (ks *MapStore) clock() time.Time {
	ks.mu.RLock()
	f := ks.now
	ks.mu.RUnlock()
	return f()
}

// RoleFor returns the role of token for project if it matches an unexpired entry. When the same token is
// configured twice for a project (same digest) there is one entry, so there is one role.
//
// Comparison is over SHA-256 digests in constant time (crypto/subtle) and visits every candidate, so
// neither the configured key length, nor which key matched, nor whether a project exists is leaked
// through timing. A project with no keys still runs one comparison against a dummy digest.
func (ks *MapStore) RoleFor(project, token string, now time.Time) (Role, bool) {
	if project == "" || token == "" {
		return 0, false // fail-closed: no anonymous / empty-token access
	}
	ks.mu.RLock()
	entries := ks.keys[project]
	ks.mu.RUnlock()

	got := sha256.Sum256([]byte(token))
	if len(entries) == 0 {
		var dummy [32]byte
		subtle.ConstantTimeCompare(got[:], dummy[:])
		return 0, false // fail-closed
	}
	var role, matched int
	for _, e := range entries {
		eq := subtle.ConstantTimeCompare(got[:], e.digest[:])
		live := 0
		if e.live(now) {
			live = 1
		}
		hit := eq & live
		role = subtle.ConstantTimeSelect(hit, int(e.role), role)
		matched |= hit
	}
	if matched != 1 {
		return 0, false
	}
	return Role(role), true
}

// ContainsToken is used at startup to keep recovery credentials disjoint from ordinary credentials
// across every configured project. Expired tokens still count: a recovery token must not equal any
// token that was ever configured.
func (ks *MapStore) ContainsToken(token string) bool {
	if token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var match int
	for _, entries := range ks.keys {
		for _, e := range entries {
			match |= subtle.ConstantTimeCompare(got[:], e.digest[:])
		}
	}
	return match == 1
}

// openStore is the explicit, dev-only "allow everything" KeyStore. See NewOpenStore.
type openStore struct{}

// ParseKeys parses the AVERIN_API_KEYS wire format "proj-a:tok1,tok2;proj-b:tok3" into a MapStore.
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

// Middleware returns net/http middleware that enforces project-scoped API-key auth with every valid
// token treated as admin (no per-route scope). Use MiddlewareRoles for scoped tokens.
func Middleware(ks KeyStore, projectParam string) func(http.Handler) http.Handler {
	return MiddlewareRoles(ks, projectParam, func(*http.Request) Role { return RoleAdmin })
}

// MiddlewareRoles enforces project-scoped API-key auth and, for a RoleStore, the role each request needs.
//
// It reads the credential from EITHER:
//   - Authorization: Bearer <token>   (case-insensitive scheme), or
//   - X-Api-Key: <token>
//
// and reads the project from the query parameter named projectParam (default "project" when empty).
// An unknown, expired or wrong-project token gets a generic 401. A valid token whose role is below
// need(r) gets a generic 403. Neither response carries the token or project. A KeyStore that is not a
// RoleStore is checked with ValidFor and treated as admin.
//
// Open stores (NewOpenStore) bypass the check entirely, so a deployment that has deliberately chosen
// no-auth does not require clients to send a dummy header.
func MiddlewareRoles(ks KeyStore, projectParam string, need func(*http.Request) Role) func(http.Handler) http.Handler {
	if projectParam == "" {
		projectParam = "project"
	}
	open := IsOpen(ks)
	rs, scoped := ks.(RoleStore)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if open {
				next.ServeHTTP(w, r) // dev-only allow-all; no credential required
				return
			}
			project := r.URL.Query().Get(projectParam)
			token := tokenFromRequest(r)
			if !scoped {
				if !ks.ValidFor(project, token) {
					unauthorized(w)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			role, ok := rs.RoleFor(project, token, rs.Now())
			if !ok {
				unauthorized(w)
				return
			}
			if !role.Allows(need(r)) {
				forbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DenyAll is the middleware for a server with no token configured and no explicit dev mode: it answers
// every request 401 and never calls the next handler.
func DenyAll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { unauthorized(w) })
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
	w.Header().Set("WWW-Authenticate", `Bearer realm="averin"`)
	w.WriteHeader(http.StatusUnauthorized)
	// Static body, no token, no project name.
	w.Write([]byte(`{"error":"unauthorized"}`))
}

// forbidden writes a generic 403 for a valid token whose role is too low for the route.
func forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"forbidden"}`))
}
