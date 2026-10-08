package core

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
