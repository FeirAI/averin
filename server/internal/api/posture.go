package api

import (
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/feirai/averin/server/internal/auth"
)

// PostureSchema is the version of the GET /v2/posture body; the deploy-time posture verifier
// refuses a version it does not know.
const PostureSchema = 1

// Posture is what main tells the server about the guards this process was started with, beyond
// what the server already holds (auth store, authority-pin switches). The zero value claims
// nothing: no guard on, no durable store.
type Posture struct {
	// RequireProdSecrets is AVERIN_REQUIRE_PROD_SECRETS (the startup gate that refuses an empty API
	// key set, an empty database URL and the well-known dev signing seed).
	RequireProdSecrets bool
	// DurableStore is true when the Postgres store is wired (AVERIN_DATABASE_URL set).
	DurableStore bool
	// SigningSeedIsDev is true when the signing seed is the committed, globally known dev seed.
	SigningSeedIsDev bool
	// CoreRustc is the rustc that built the linked decision-core staticlib, stamped at link time
	// by the build scripts (-ldflags "-X main.coreRustc=..."). Empty when the build did not stamp it.
	CoreRustc string
	// Region is the cell's region label (AVERIN_REGION; "" = not declared), reported so the deploy-time
	// verifier can require every plane of a cell to name the same region. averin does not interpret it.
	Region string
	// SchemaVersion is the Postgres schema version this binary understands (pgschema.CurrentSchemaVersion).
	// 0 when storage is in-memory.
	SchemaVersion int
	// RuntimeRoleVerified is true when startup ran pgschema.CheckRuntime on the Postgres credential and it
	// passed (a failure is fatal, so a serving Postgres-backed process reports true). False in-memory.
	RuntimeRoleVerified bool
	// DevMode is true when AVERIN_DEV_MODE=1 selected development mode (open API allowed, in-memory store,
	// dev seed, production gate and strict proofs off by default). The deploy-time verifier refuses it.
	DevMode bool
}

// MaxRegionLen bounds a region label.
const MaxRegionLen = 64

// ParseRegion validates a raw AVERIN_REGION value: lower-case letters, digits and hyphens, at most
// MaxRegionLen bytes, starting with a letter (for example "eu-central-1"). Empty (after trimming) means
// not declared and returns "". Anything else is an error, so a typo stops startup instead of being
// reported as a region the operator did not mean.
func ParseRegion(raw string) (string, error) {
	r := strings.TrimSpace(raw)
	if r == "" {
		return "", nil
	}
	if len(r) > MaxRegionLen {
		return "", fmt.Errorf("region is %d bytes, over the %d-byte cap", len(r), MaxRegionLen)
	}
	for i := 0; i < len(r); i++ {
		c := r[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9' && i > 0) || (c == '-' && i > 0)) {
			return "", fmt.Errorf("region %q must be lower-case letters, digits and hyphens, starting with a letter", r)
		}
	}
	return r, nil
}

// WithPosture records the startup guard state GET /v2/posture reports.
func (s *Server) WithPosture(p Posture) *Server {
	s.posture = p
	return s
}

func buildInfoPosture(coreRustc string) map[string]any {
	out := map[string]any{"go_version": runtime.Version()}
	if coreRustc != "" {
		out["core_rustc"] = coreRustc
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			switch kv.Key {
			case "vcs.revision":
				out["vcs_revision"] = kv.Value
			case "vcs.modified":
				out["vcs_modified"] = kv.Value == "true"
			}
		}
	}
	return out
}

// handlePosture is GET /v2/posture: a read-only report of the guards this process runs with, for
// the deploy-time verifier. It sits under the ordinary /v2 project API-key auth (the route needs
// ?project=<p> and that project's bearer), so on a keyed deployment only a key holder reads it; on an
// unauthenticated deployment it answers anyone, and reports api_keys_configured=false, which is
// exactly the violation. Booleans and build identifiers only: no key, no seed, no DSN.
func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	keyed := s.auth != nil && !auth.IsOpen(s.auth)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"schema":                       PostureSchema,
		"plane":                        "averin",
		"build":                        buildInfoPosture(s.posture.CoreRustc),
		"require_prod_secrets":         s.posture.RequireProdSecrets,
		"api_keys_configured":          keyed,
		"durable_store":                s.posture.DurableStore,
		"signing_seed_is_dev":          s.posture.SigningSeedIsDev,
		"require_pinned_authority":     s.requirePinnedAuthority,
		"require_body_bound_authority": s.requireBodyBoundAuthority,
		"region":                       s.posture.Region,
		"schema_version":               s.posture.SchemaVersion,
		"runtime_role_verified":        s.posture.RuntimeRoleVerified,
		"dev_mode":                     s.posture.DevMode,
	})
}
