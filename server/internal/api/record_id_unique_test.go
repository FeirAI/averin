package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestRecordIDUniquePerProject: two /v2/records under the SAME caller-chosen record_id (different idempotency
// keys, different content) used to BOTH 201 — the export then failed offline verification forever ("duplicate
// record_id") and the second record's disclosure secret was silently dropped (disclosures are keyed
// (record_id, field), ON CONFLICT DO NOTHING). The second must be a 409 that persists nothing, while an exact
// idempotent replay of the first still collapses (201, created:false) and the bundle still verifies.
func TestRecordIDUniquePerProject(t *testing.T) {
	h := newSrv(t)
	first := `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","record_id":"rid-1","action":"a","input":"one"}`
	if _, created := postRecord(t, h, first); !created {
		t.Fatal("first record must be created")
	}
	dup := `{"idempotency_key":"k2","project_id":"p1","session_id":"s1","record_id":"rid-1","action":"b","input":"two"}`
	if code, resp := do(t, h, "POST", "/v2/records", dup); code != http.StatusConflict {
		t.Fatalf("a different record under an existing record_id must 409, got %d: %s", code, resp)
	}
	if _, created := postRecord(t, h, first); created {
		t.Fatal("an exact idempotent replay must collapse (created:false)")
	}
	// the same record_id in ANOTHER project is independent.
	if _, created := postRecord(t, h, strings.Replace(dup, `"p1"`, `"p2"`, 1)); !created {
		t.Fatal("the same record_id in another project must be accepted")
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, resp)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("bundle must verify (no duplicate record_id) (%d): %s", code, report)
	}
}

// TestRecordIDConflictRejectsWholeBatch: a record_id collision in a LATER batch item (with a stored record, or
// with an earlier item of the same batch) must reject the WHOLE batch before anything is sealed — never
// commit the earlier items and then fail.
func TestRecordIDConflictRejectsWholeBatch(t *testing.T) {
	h := newSrv(t)
	postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","record_id":"taken"}`)
	batch := `[{"idempotency_key":"k2","project_id":"p1","session_id":"s1","record_id":"fresh"},
	           {"idempotency_key":"k3","project_id":"p1","session_id":"s1","record_id":"taken"}]`
	if code, resp := do(t, h, "POST", "/v2/records", batch); code != http.StatusConflict {
		t.Fatalf("a batch with a record_id collision must 409, got %d: %s", code, resp)
	}
	inBatch := `[{"idempotency_key":"k4","project_id":"p1","session_id":"s1","record_id":"twice"},
	             {"idempotency_key":"k5","project_id":"p1","session_id":"s1","record_id":"twice"}]`
	if code, resp := do(t, h, "POST", "/v2/records", inBatch); code != http.StatusConflict {
		t.Fatalf("two batch items sharing a record_id must 409, got %d: %s", code, resp)
	}
	// nothing from either rejected batch was sealed: both earlier items are brand new now.
	if _, created := postRecord(t, h, `{"idempotency_key":"k2","project_id":"p1","session_id":"s1","record_id":"fresh"}`); !created {
		t.Fatal("the first item of the rejected batch must NOT have been committed")
	}
	if _, created := postRecord(t, h, `{"idempotency_key":"k4","project_id":"p1","session_id":"s1","record_id":"twice"}`); !created {
		t.Fatal("the first item of the rejected in-batch-duplicate batch must NOT have been committed")
	}
}

// TestRecordIDBrokerNamespacesReserved: grant ids (and introspection record_ids) are PUBLIC UUIDv5 functions of
// (project, idempotency_key); with record_id unique per project a generic record pre-seeded under one would
// squat it and make the later grant fail. The UUIDv5 shape and the ADR 0005 introspection-/revocation-
// prefixes are reserved for caller-supplied record_ids (400); a v4 UUID is still accepted.
func TestRecordIDBrokerNamespacesReserved(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("grant (%d): %s", code, resp)
	}
	// the grant_id a squatter would target (here: the NEXT grant's id is equally derivable).
	for _, rid := range []string{
		"6f1c2a4e-9b3d-5c7e-8f00-112233445566", // UUIDv5 shape (deterministic grant/introspection ids)
		"introspection-x",
		"revocation-x",
		"use-x",
	} {
		body := `{"idempotency_key":"sq-` + rid + `","project_id":"p1","session_id":"s1","record_id":"` + rid + `"}`
		if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusBadRequest || !strings.Contains(resp, "reserved") {
			t.Fatalf("record_id %q must be reserved (400), got %d: %s", rid, code, resp)
		}
	}
	if _, created := postRecord(t, h, `{"idempotency_key":"v4","project_id":"p1","session_id":"s1","record_id":"6f1c2a4e-9b3d-4c7e-8f00-112233445566"}`); !created {
		t.Fatal("a caller-chosen UUIDv4 record_id must still be accepted")
	}
}
