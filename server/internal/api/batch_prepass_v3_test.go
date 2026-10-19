package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

func prepassV3Item(idem string) string {
	rec := map[string]any{
		"idempotency_key": idem,
		"schema_version":  "2", "canon_version": "rcp-1", "domain": "flightrecorder.record.v2",
		"project_id": "p1", "record_id": "rv3-" + idem, "session_id": "s1", "agent_id": "a1",
		"agent_version": "1", "span_id": "sp-" + idem, "parent_span_id": nil,
		"agent_ts": "2026-01-01T00:00:00.000Z", "event_type": "decision",
		"action": "approve", "status": "ok", "observed_via": "sdk",
		"input_commit": map[string]any{"alg": "sha256", "commitment": "sha256:" + strings.Repeat("2", 64), "low_entropy": true},
		"extensions": map[string]any{
			"feir_evidence": map[string]any{
				"capture_authority": "sdk",
				"lineage":           map[string]any{"session_id": "s1", "span_id": "sp-" + idem, "parent_span_id": nil},
			},
		},
		"authority": map[string]any{
			"source": "human_signed", "enforcement_point": "sdk",
			"evidence_hash": "sha256:" + strings.Repeat("1", 64),
			"evidence_sig":  "ed25519:" + strings.Repeat("A", 86),
			"proof_version": "v3", "subject_projection": "averin.authority.subject.v1",
			"subject_digest": "sha256:" + strings.Repeat("3", 64),
		},
	}
	b, _ := json.Marshal(rec)
	return string(b)
}

// TestBatchPrePassV3FailedElevationDecidesLikeIngestOne: a v3 claim whose elevation fails is REJECTED by
// ingestOne whatever the strict flag (never a downgrade), so the pre-pass must reject the whole batch with the
// same 500 (and never call Error() on a nil error, which used to panic with the flag off).
func TestBatchPrePassV3FailedElevationDecidesLikeIngestOne(t *testing.T) {
	for _, strict := range []bool{false, true} {
		h := api.New(mustCore(t), store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithRequirePinnedAuthority(strict).Routes()
		// ingestOne's own decision for the item, on a fresh server.
		single := api.New(mustCore(t), store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithRequirePinnedAuthority(strict).Routes()
		wantCode, wantBody := do(t, single, "POST", "/v2/records", prepassV3Item("bad"))
		if wantCode != http.StatusInternalServerError || !strings.Contains(wantBody, "v3 proof failed") {
			t.Fatalf("strict=%v: ingestOne decision unexpected (%d): %s", strict, wantCode, wantBody)
		}
		okItem := `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"ok"}`
		batch := "[" + okItem + "," + prepassV3Item("bad") + "]"
		code, body := do(t, h, "POST", "/v2/records", batch)
		if code != wantCode || body != wantBody {
			t.Fatalf("strict=%v: batch got (%d) %s, want ingestOne's (%d) %s", strict, code, body, wantCode, wantBody)
		}
		if _, created := postRecord(t, h, okItem); !created {
			t.Fatalf("strict=%v: the earlier item of the rejected batch must not have been sealed", strict)
		}
	}
}

// With the strict flag off a failed v2 elevation is downgraded and sealed by ingestOne, so the pre-pass must
// not reject the batch.
func TestBatchPrePassV2FailedElevationNotStrictStillSeals(t *testing.T) {
	h := api.New(mustCore(t), store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithRequirePinnedAuthority(false).Routes()
	batch := `[{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"ok"},
	           {"idempotency_key":"k2","project_id":"p1","session_id":"s1","authority":{"source":"policy_engine_signed"}}]`
	if code, resp := do(t, h, "POST", "/v2/records", batch); code != http.StatusCreated {
		t.Fatalf("non-strict v2 failed elevation must downgrade and seal (201), got %d: %s", code, resp)
	}
}
