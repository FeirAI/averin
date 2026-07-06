package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The leria integration ask: an OPTIONAL typed top-level `record_kind` ∈ {budget-exhausted,
// chargeback-posted}, a SIBLING of event_type (leria still sets event_type:"decision"). These tests
// cover the acceptance criteria from leria/docs/_meta/averin-integration-handoff.md: a conforming
// budget-exhausted / chargeback-posted record ingests, hash-chains, and (the seal-but-fail-verify
// trap) VERIFIES — no UnknownField — and /v2/export is filterable by record_kind in proof_only and
// full_evidence; averin signs with its own seed and normalizes any sent authority to caller_declared.

// a conforming budget-exhausted seal: required project_id/session_id/idempotency_key, the leria
// payload under extensions, integer micros (no floats), record_kind set, event_type still "decision".
const budgetExhaustedRecord = `{
  "project_id": "tenant_acme",
  "session_id": "budget:bdg_7f3a",
  "idempotency_key": "leria:budget.exhausted:bdg_7f3a:1718800000",
  "event_type": "decision",
  "action": "budget.exhausted",
  "record_kind": "budget-exhausted",
  "cost_micros_usd": 5000000,
  "extensions": {
    "budget_id": "bdg_7f3a",
    "budget_scope": "cost-center",
    "scope_id": "cc_ml_platform",
    "asset": "usd",
    "limit_micros": 5000000,
    "consumed_micros": 5037421,
    "confidence": "high",
    "degrade_mode": "throttle",
    "ceiling_mode": "soft",
    "occurred_at": "2026-06-19T14:00:00.000Z"
  }
}`

// Acceptance #1: a conforming budget-exhausted record is accepted, hash-chained, returns an id, AND
// GET /v2/verify over a chain containing it PASSES (verify_sealed raises no UnknownField).
func TestLeriaBudgetExhaustedIngestsAndVerifies(t *testing.T) {
	h := newSrv(t)
	rec, created := postRecord(t, h, budgetExhaustedRecord)
	if !created {
		t.Fatalf("budget-exhausted record should be created: %v", rec)
	}
	if rec["record_kind"] != "budget-exhausted" {
		t.Fatalf("record_kind not preserved through the seal: %v", rec["record_kind"])
	}
	if rec["event_type"] != "decision" {
		t.Fatalf("record_kind must be a sibling of event_type, not replace it: %v", rec["event_type"])
	}
	if !strings.HasPrefix(asString(rec["content_hash"]), "sha256:") {
		t.Fatalf("no content_hash (not hash-chained): %v", rec)
	}
	if !strings.HasPrefix(asString(rec["record_id"]), "") || rec["record_id"] == "" {
		t.Fatalf("no record id returned: %v", rec)
	}
	if !strings.HasPrefix(asString(rec["sig"]), "ed25519:") {
		t.Fatalf("not sealed with averin's signing key: %v", rec)
	}

	// checkpoint then verify the whole project offline via the Rust core — must NOT raise UnknownField.
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=tenant_acme", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	code, report := do(t, h, "GET", "/v2/verify?project=tenant_acme", "")
	if code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("verify not ok over a chain containing record_kind (%d): %s", code, report)
	}
	if strings.Contains(report, "unknown top-level field") || strings.Contains(report, "UnknownField") {
		t.Fatalf("record_kind must not be an UnknownField on verify: %s", report)
	}
	if !strings.Contains(report, `"records_proven":1`) {
		t.Fatalf("expected the budget-exhausted record proven: %s", report)
	}
}

// Acceptance #2: chargeback-posted incl. a supersede-and-reseal (version+1, supersedes_chargeback_id,
// SAME session_id) — both verify as part of the SAME chain.
func TestLeriaChargebackSupersedeVerifiesInSameChain(t *testing.T) {
	h := newSrv(t)
	const session = "chargeback:cc_ml_platform:2026-04-01"
	v1 := `{
      "project_id": "tenant_acme",
      "session_id": "` + session + `",
      "idempotency_key": "leria:chargeback.posted:cb_001:v1",
      "event_type": "decision",
      "action": "chargeback.posted",
      "record_kind": "chargeback-posted",
      "cost_micros_usd": 5037421,
      "extensions": {
        "chargeback_id": "cb_001",
        "version": 1,
        "supersedes_chargeback_id": null,
        "cost_center": "cc_ml_platform",
        "asset": "usd",
        "amount_micros": 5037421,
        "period_start": "2026-04-01T00:00:00.000Z",
        "period_end": "2026-06-30T23:59:59.999Z",
        "reconciliation_status": "provisional"
      }
    }`
	r1, created := postRecord(t, h, v1)
	if !created || r1["record_kind"] != "chargeback-posted" {
		t.Fatalf("chargeback v1 not created with record_kind: %v", r1)
	}

	// supersede-and-reseal: version+1, supersedes_chargeback_id set, SAME session_id -> chains to v1.
	v2 := `{
      "project_id": "tenant_acme",
      "session_id": "` + session + `",
      "idempotency_key": "leria:chargeback.posted:cb_001:v2",
      "event_type": "decision",
      "action": "chargeback.posted",
      "record_kind": "chargeback-posted",
      "cost_micros_usd": 5100000,
      "extensions": {
        "chargeback_id": "cb_001",
        "version": 2,
        "supersedes_chargeback_id": "cb_001",
        "cost_center": "cc_ml_platform",
        "asset": "usd",
        "amount_micros": 5100000,
        "period_start": "2026-04-01T00:00:00.000Z",
        "period_end": "2026-06-30T23:59:59.999Z",
        "reconciliation_status": "final"
      }
    }`
	r2, created := postRecord(t, h, v2)
	if !created {
		t.Fatalf("chargeback v2 supersede should be created: %v", r2)
	}
	// v2 chains to v1 (same session => causal parent is v1's content_hash).
	parents, _ := r2["causal_prev_hashes"].([]any)
	if len(parents) != 1 || parents[0] != r1["content_hash"] {
		t.Fatalf("supersede must chain to the original seal on the same session, got parents=%v", parents)
	}

	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=tenant_acme", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	code, report := do(t, h, "GET", "/v2/verify?project=tenant_acme", "")
	if code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("verify not ok over the chargeback chain (%d): %s", code, report)
	}
	if strings.Contains(report, "unknown top-level field") {
		t.Fatalf("record_kind must not be an UnknownField: %s", report)
	}
	if !strings.Contains(report, `"records_proven":2`) {
		t.Fatalf("both chargeback records (v1 + supersede) should be proven: %s", report)
	}
}

// Acceptance #3: GET /v2/export surfaces leria records, filterable by record_kind, in proof_only and
// full_evidence. The full bundle stays intact (it verifies); the filter adds a typed filtered_records view.
func TestLeriaExportFilterableByRecordKind(t *testing.T) {
	h := newSrv(t)
	// one budget-exhausted, one chargeback-posted, and a plain non-leria record on a third session.
	postRecord(t, h, budgetExhaustedRecord)
	postRecord(t, h, `{
      "project_id": "tenant_acme",
      "session_id": "chargeback:cc_x:2026-04-01",
      "idempotency_key": "leria:chargeback.posted:cb_x:v1",
      "event_type": "decision",
      "action": "chargeback.posted",
      "record_kind": "chargeback-posted",
      "cost_micros_usd": 100,
      "extensions": { "chargeback_id": "cb_x", "version": 1, "amount_micros": 100, "asset": "usd" }
    }`)
	postRecord(t, h, `{"idempotency_key":"plain1","project_id":"tenant_acme","session_id":"s_plain","action":"db.read"}`)

	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=tenant_acme", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}

	// proof_only, filtered to budget-exhausted: exactly one filtered record, and it is the budget one.
	code, exp := do(t, h, "GET", "/v2/export?project=tenant_acme&mode=proof_only&record_kind=budget-exhausted", "")
	if code != http.StatusOK {
		t.Fatalf("filtered export (%d): %s", code, exp)
	}
	filtered := decodeFilteredRecords(t, exp)
	if len(filtered) != 1 {
		t.Fatalf("expected exactly 1 budget-exhausted record, got %d:\n%s", len(filtered), exp)
	}
	if filtered[0]["record_kind"] != "budget-exhausted" {
		t.Fatalf("filtered record is the wrong kind: %v", filtered[0]["record_kind"])
	}
	if !strings.Contains(exp, `"record_kind_filter":"budget-exhausted"`) {
		t.Fatalf("export should echo the record_kind_filter: %s", exp)
	}
	// the canonical bundle is left INTACT (all 3 records still present) so it still verifies.
	if got := countBundleRecords(t, exp); got != 3 {
		t.Fatalf("the canonical records array must NOT be pruned (verify depends on it), got %d", got)
	}

	// full_evidence, filtered to chargeback-posted: exactly one filtered record, the chargeback one.
	code, exp = do(t, h, "GET", "/v2/export?project=tenant_acme&mode=full_evidence&record_kind=chargeback-posted", "")
	if code != http.StatusOK {
		t.Fatalf("filtered full_evidence export (%d): %s", code, exp)
	}
	filtered = decodeFilteredRecords(t, exp)
	if len(filtered) != 1 || filtered[0]["record_kind"] != "chargeback-posted" {
		t.Fatalf("expected exactly 1 chargeback-posted record, got %v:\n%s", filtered, exp)
	}

	// an unknown record_kind is a 400 (a typo must not masquerade as "no matching evidence").
	if code, resp := do(t, h, "GET", "/v2/export?project=tenant_acme&record_kind=bogus-kind", ""); code != http.StatusBadRequest {
		t.Fatalf("unknown record_kind should 400, got (%d): %s", code, resp)
	}

	// no filter => no filtered_records view, the bundle is the full bundle (back-compat).
	_, exp = do(t, h, "GET", "/v2/export?project=tenant_acme&mode=proof_only", "")
	if strings.Contains(exp, `"filtered_records"`) {
		t.Fatalf("an unfiltered export must not carry filtered_records: %s", exp)
	}
}

// Acceptance #4: averin signs with its own seed; a sent authority block normalizes to caller_declared.
// (record_kind does not change the authority model — the seam is one-directional, leria is an author.)
func TestLeriaRecordKindAuthorityNormalizedToCallerDeclared(t *testing.T) {
	h := newSrv(t)
	withAuthority := `{
      "project_id": "tenant_acme",
      "session_id": "budget:bdg_9",
      "idempotency_key": "leria:budget.exhausted:bdg_9:1",
      "event_type": "decision",
      "action": "budget.exhausted",
      "record_kind": "budget-exhausted",
      "cost_micros_usd": 1,
      "authority": { "source": "policy_engine_signed" },
      "extensions": { "budget_id": "bdg_9", "asset": "usd", "limit_micros": 1, "consumed_micros": 2 }
    }`
	rec, _ := postRecord(t, h, withAuthority)
	auth, _ := rec["authority"].(map[string]any)
	if auth == nil || auth["source"] != "caller_declared" {
		t.Fatalf("a sent authority must normalize to caller_declared (leria is an author, not a signer): %v", rec["authority"])
	}
	if !strings.HasPrefix(asString(rec["sig"]), "ed25519:") {
		t.Fatalf("averin must sign the record with its own seed: %v", rec)
	}
}

// off-enum record_kind is rejected at ingest (the Rust closed-key gate admits the key, not the value,
// so the server enforces the closed value-set — else a bad kind would seal+verify yet dodge the filter).
func TestLeriaOffEnumRecordKindRejected(t *testing.T) {
	h := newSrv(t)
	bad := `{"idempotency_key":"k","project_id":"p","session_id":"s","record_kind":"made-up-kind","action":"x"}`
	if code, resp := do(t, h, "POST", "/v2/records", bad); code != http.StatusBadRequest {
		t.Fatalf("off-enum record_kind should 400, got (%d): %s", code, resp)
	}
}

// ---- helpers ----

func decodeFilteredRecords(t *testing.T, exportJSON string) []map[string]any {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(exportJSON), &obj); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	raw, ok := obj["filtered_records"]
	if !ok {
		t.Fatalf("export missing filtered_records: %s", exportJSON)
	}
	var recs []map[string]any
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatalf("decode filtered_records: %v", err)
	}
	return recs
}

func countBundleRecords(t *testing.T, exportJSON string) int {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(exportJSON), &obj); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	var recs []json.RawMessage
	if err := json.Unmarshal(obj["records"], &recs); err != nil {
		t.Fatalf("decode records: %v", err)
	}
	return len(recs)
}
