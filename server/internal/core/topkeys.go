package core

import "sort"

// AllowedTopKeys mirrors ALLOWED_TOP_KEYS in core/src/record.rs (the closed set of permitted
// top-level record keys). It exists so the HTTP layer can refuse an unknown key before anything is
// sealed (batch atomicity). TestAllowedTopKeysParity pins it against the Rust source; the Rust core
// stays the authority, and seal still refuses an unknown key if this list ever lags.
var AllowedTopKeys = map[string]struct{}{}

func init() {
	for _, k := range allowedTopKeyList {
		AllowedTopKeys[k] = struct{}{}
	}
}

var allowedTopKeyList = []string{
	"schema_version",
	"canon_version",
	"domain",
	"record_id",
	"project_id",
	"agent_id",
	"agent_version",
	"session_id",
	"span_id",
	"parent_span_id",
	"causal_prev_hashes",
	"display_seq",
	"agent_ts",
	"received_ts",
	"anchored_ts",
	"event_type",
	"record_kind",
	"action",
	"observed_via",
	"input_commit",
	"output_commit",
	"rationale_commit",
	"credential_commit",
	"status",
	"tokens",
	"cost_micros_usd",
	"authority",
	"content",
	"content_hash",
	"sig",
	"key",
	"framework",
	"extensions",
}

// Closed member sets of the caller-influenced nested objects, mirroring ALLOWED_AUTHORITY_KEYS,
// ALLOWED_POLICY_SNAPSHOT_REF_KEYS, ALLOWED_CONTENT_KEYS, ALLOWED_TOKENS_KEYS and ALLOWED_COMMIT_KEYS in
// core/src/record.rs (decision-record.schema.json `additionalProperties:false`). They let the HTTP layer
// refuse an unknown nested member with a 400 before anything is sealed (batch atomicity). The record `key`
// block is not mirrored: the server overwrites it. TestNestedKeysParity pins each list against the Rust
// source; the Rust core stays the authority, and seal and verify still refuse if a list here lags.
var (
	AllowedAuthorityKeys         = []string{"source", "enforcement_point", "decision_basis", "policy_hash", "policy_snapshot_ref", "grant_id", "grant_type", "authorizing_principal", "delegation_chain", "evidence_hash", "evidence_sig", "proof_version", "subject_projection", "subject_digest", "evaluated_at", "expires_at", "nonce"}
	AllowedPolicySnapshotRefKeys = []string{"uri", "digest", "object_version"}
	AllowedContentKeys           = []string{"uri", "digest", "length", "content_type", "enc_key_id", "object_version"}
	AllowedTokensKeys            = []string{"in", "out"}
	AllowedCommitKeys            = []string{"alg", "commitment", "low_entropy"}
	// CommitFields are the top-level record fields that hold a commitment object.
	CommitFields = []string{"input_commit", "output_commit", "rationale_commit", "credential_commit"}
)

// UnknownNestedMember returns "<object>.<key>" for the first member of a caller-influenced nested object
// that the closed schema does not list, or "" when every member is allowed. Only objects are checked: a
// non-object hides no member. Member order is map order, so with several unknown members the one named is
// not stable; the caller only needs a refusal that names one of them.
func UnknownNestedMember(rec map[string]any) string {
	check := func(object string, v any, allowed []string) string {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		var bad []string
		for k := range m {
			if !contains(allowed, k) {
				bad = append(bad, k)
			}
		}
		if len(bad) == 0 {
			return ""
		}
		sort.Strings(bad)
		return object + "." + bad[0]
	}
	if bad := check("authority", rec["authority"], AllowedAuthorityKeys); bad != "" {
		return bad
	}
	if a, ok := rec["authority"].(map[string]any); ok {
		if bad := check("authority.policy_snapshot_ref", a["policy_snapshot_ref"], AllowedPolicySnapshotRefKeys); bad != "" {
			return bad
		}
	}
	if bad := check("content", rec["content"], AllowedContentKeys); bad != "" {
		return bad
	}
	if bad := check("tokens", rec["tokens"], AllowedTokensKeys); bad != "" {
		return bad
	}
	for _, f := range CommitFields {
		if bad := check(f, rec[f], AllowedCommitKeys); bad != "" {
			return bad
		}
	}
	return ""
}

func contains(list []string, k string) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}
