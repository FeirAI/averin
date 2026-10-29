package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// feir-ops#16: /v2/records refuses an unknown member inside a caller-influenced nested object with a 400
// that names it, in enforce mode; the closed member sets equal the schema's, so every allowed member is
// accepted; `extensions` stays open.

var nestedBad = []struct{ name, field, member string }{
	{"authority", `"authority":{"source":"x","bogus":1}`, "authority.bogus"},
	{"policy_snapshot_ref", `"authority":{"policy_snapshot_ref":{"uri":"u","bogus":1}}`, "authority.policy_snapshot_ref.bogus"},
	{"content", `"content":{"uri":"u","bogus":1}`, "content.bogus"},
	{"tokens", `"tokens":{"in":1,"out":2,"total":3}`, "tokens.total"},
	{"input_commit", `"input_commit":{"alg":"a","bogus":1}`, "input_commit.bogus"},
	{"output_commit", `"output_commit":{"alg":"a","bogus":1}`, "output_commit.bogus"},
	{"rationale_commit", `"rationale_commit":{"alg":"a","bogus":1}`, "rationale_commit.bogus"},
	{"credential_commit", `"credential_commit":{"alg":"a","bogus":1}`, "credential_commit.bogus"},
}

func TestRecordsRefuseUnknownNestedMemberWith400(t *testing.T) {
	h := newServer(t).Routes()
	for i, c := range nestedBad {
		body := fmt.Sprintf(`{"idempotency_key":"n-%d","project_id":"p1","session_id":"s1","action":"db.read",%s}`, i, c.field)
		code, resp := do(t, h, "POST", "/v2/records", body)
		if code != http.StatusBadRequest || !strings.Contains(resp, c.member) {
			t.Fatalf("%s: want 400 naming %q, got %d: %s", c.name, c.member, code, resp)
		}
	}
}

func TestBatchIsAtomicOnUnknownNestedMember(t *testing.T) {
	h := newServer(t).Routes()
	batch := `[{"idempotency_key":"b-1","project_id":"p1","session_id":"s1","action":"db.read"},` +
		`{"idempotency_key":"b-2","project_id":"p1","session_id":"s1","action":"db.write","tokens":{"in":1,"out":2,"total":3}}]`
	code, body := do(t, h, "POST", "/v2/records", batch)
	if code != http.StatusBadRequest || !strings.Contains(body, "tokens.total") {
		t.Fatalf("a batch with an unknown nested member must be 400 naming it, got %d: %s", code, body)
	}
	if _, dag := do(t, h, "GET", "/v2/dag?project=p1&session=s1", ""); strings.Contains(dag, "db.read") {
		t.Fatalf("an earlier batch item must not persist; dag: %s", dag)
	}
}

func TestRecordsAcceptEveryAllowedNestedMemberAndOpenExtensions(t *testing.T) {
	h := newServer(t).Routes()
	body := `{"idempotency_key":"ok-1","project_id":"p1","session_id":"s1","action":"db.read",` +
		`"authority":{"source":"caller_declared","enforcement_point":"e","decision_basis":"b","policy_hash":"h","policy_snapshot_ref":{"uri":"u","digest":"d","object_version":"v"},` +
		`"authorizing_principal":"p","evaluated_at":"2026-01-01T00:00:00.000Z","expires_at":"2026-01-01T00:01:00.000Z","nonce":"n"},` +
		`"tokens":{"in":1,"out":2},"content":{"uri":"u","digest":"d","length":1,"content_type":"t","enc_key_id":"k","object_version":"v"},` +
		`"extensions":{"anything":{"goes":[1,{"deep":null}]}}}`
	if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusCreated {
		t.Fatalf("a record carrying every allowed member must be accepted, got %d: %s", code, resp)
	}
}
