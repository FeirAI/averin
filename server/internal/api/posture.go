package api

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"sort"
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

// relAverinAPIKey names the shared-secret relationship between averin and the planes that call it
// (govder, vultrino, the feir-os broker): the project bearer they send is one averin accepts. The
// string is the same in every plane and in feir-os deploy/posture/evaluate.jq, and is part of the
// fingerprinted message.
const relAverinAPIKey = auth.FingerprintRelationship

// secretFingerprints is the keyed fingerprint of every API key this process ACCEPTS (FEI-40), so the
// verifier can compare them with the fingerprints of the keys the calling planes SEND. Empty when the
// deployment is open or unkeyed (nothing is accepted by value). Never a key.
func (s *Server) secretFingerprints() map[string][]string {
	out := map[string][]string{}
	if ms, ok := s.auth.(*auth.MapStore); ok && ms != nil {
		if fps := ms.Fingerprints(); len(fps) > 0 {
			out[relAverinAPIKey] = fps
		}
	}
	return out
}

// authorityPinsReport lists every pinned external authority key as {project, source, pubkey} (FEI-40
// relationship D). The values are PUBLIC verifying keys, so they are reported as they are (no
// fingerprint): the deploy-time verifier compares them for equality with the keys govder derives from
// its authority seed. Project "" is the global default pin. Sorted so the report is deterministic.
func (s *Server) authorityPinsReport() []map[string]string {
	out := make([]map[string]string, 0, len(s.policyEngineKeys))
	for pin, key := range s.policyEngineKeys {
		out = append(out, map[string]string{"project": pin.project, "source": pin.source, "pubkey": hex.EncodeToString(key)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["project"] != out[j]["project"] {
			return out[i]["project"] < out[j]["project"]
		}
		return out[i]["source"] < out[j]["source"]
	})
	return out
}

// approverBindingSinceReport is the approver-binding cutover as GET /v2/posture reports it: the
// canonical string, or null when none is set. A cutover in the far future switches the policy off as
// surely as require_approver_binding=false does, so the verifier needs to see both.
func (s *Server) approverBindingSinceReport() any {
	if s.approverBindingSince == "" {
		return nil
	}
	return s.approverBindingSince
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
		"secret_fingerprints":          s.secretFingerprints(),
		"authority_pins":               s.authorityPinsReport(),
		"region":                       s.posture.Region,
		"schema_version":               s.posture.SchemaVersion,
		"runtime_role_verified":        s.posture.RuntimeRoleVerified,
		"dev_mode":                     s.posture.DevMode,
		"require_approver_binding":     s.requireApproverBinding,
		"approver_binding_since":       s.approverBindingSinceReport(),
	})
}
