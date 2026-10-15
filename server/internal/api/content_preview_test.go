package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

const (
	secretPrompt = "transfer 4200 EUR from IBAN PT50000201231234567890154 to Ana Costa"
	secretAnswer = "ok, queued for Ana Costa"
	secretWhy    = "customer asked by phone"
)

// legacyBody is what the SDKs, the recording proxy and the MCP server sent before AVE-02.
func legacyBody(idem string) string {
	return `{"idempotency_key":"` + idem + `","project_id":"p1","session_id":"s1","action":"llm.call",` +
		`"extensions":{"content_preview":{"input":"` + secretPrompt + `","output":"` + secretAnswer + `","rationale":"` + secretWhy + `"}}}`
}

func TestLegacyContentPreviewIsCommittedNotSignedAndCanBeErased(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := content.NewEncryptedFSStore(t.TempDir(), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(c, store.NewMem(), "k0").WithContent(cs).Routes()
	rec, created := postRecord(t, h, legacyBody("legacy-1"))
	if !created {
		t.Fatal("not created")
	}
	sealed := mustJSON(t, rec)
	for _, plain := range []string{secretPrompt, secretAnswer, secretWhy, "IBAN", "Ana Costa", "content_preview"} {
		if strings.Contains(sealed, plain) {
			t.Fatalf("the signed record still carries %q in the clear: %s", plain, sealed)
		}
	}
	for _, f := range []string{"input_commit", "output_commit", "rationale_commit"} {
		if _, ok := rec[f]; !ok {
			t.Fatalf("no %s on the sealed record: %s", f, sealed)
		}
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, resp)
	}
	// The text is still disclosable while retained, and the bundle proves it ...
	_, exp := do(t, h, "GET", "/v2/export?project=p1&mode=selective_disclosure", "")
	rep := c.VerifyBundle(exp)
	if !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"disclosures_verified":3`) || !strings.Contains(rep, `"cleartext_content_records":0`) {
		t.Fatalf("committed legacy text must verify and leave no cleartext records: %s", rep)
	}
	// ... and after retention the text is gone while the chain still verifies.
	if n, err := cs.PurgeOlderThan(time.Now().Add(time.Hour)); err != nil || n != 3 {
		t.Fatalf("purge removed=%d err=%v", n, err)
	}
	_, after := do(t, h, "GET", "/v2/export?project=p1&mode=selective_disclosure", "")
	for _, plain := range []string{secretPrompt, secretAnswer, secretWhy} {
		if strings.Contains(after, plain) {
			t.Fatalf("erased text %q still exported", plain)
		}
	}
	if rep := c.VerifyBundle(after); !strings.Contains(rep, `"ok":true`) {
		t.Fatalf("history must stay verifiable after erasure: %s", rep)
	}
}

func TestContentPreviewInABatchIsAlsoCommitted(t *testing.T) {
	h := newSrv(t)
	code, resp := do(t, h, "POST", "/v2/records", "["+legacyBody("b1")+","+strings.Replace(legacyBody("b2"), secretPrompt, "second prompt", 1)+"]")
	if code != http.StatusCreated {
		t.Fatalf("batch (%d): %s", code, resp)
	}
	if strings.Contains(resp, secretPrompt) || strings.Contains(resp, "second prompt") || strings.Contains(resp, "content_preview") {
		t.Fatalf("batch response carries cleartext: %s", resp)
	}
}

func TestContentPreviewShapesThatWouldBeSignedVerbatimAreRefused(t *testing.T) {
	h := newSrv(t)
	base := func(ext, extra string) string {
		return `{"idempotency_key":"r","project_id":"p1","session_id":"s1","action":"a",` + extra + `"extensions":{"content_preview":` + ext + `}}`
	}
	cases := map[string]string{
		"unknown key would be signed in the clear": base(`{"input":"x","notes":"free text"}`, ""),
		"not an object":                  base(`"just a string"`, ""),
		"array":                          base(`["a"]`, ""),
		"duplicate of a top-level field": base(`{"input":"x"}`, `"input":"y",`),
	}
	for name, body := range cases {
		if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, code, resp)
		}
	}
}

func TestV3AuthorityRecordCannotCarryARawPreview(t *testing.T) {
	h := newSrv(t)
	body := `{"idempotency_key":"v3","project_id":"p1","session_id":"s1","action":"a",` +
		`"authority":{"source":"human_signed","proof_version":3},` +
		`"extensions":{"content_preview":{"input":"` + secretPrompt + `"}}}`
	code, resp := do(t, h, "POST", "/v2/records", body)
	if code != http.StatusBadRequest || !strings.Contains(resp, "content_preview") {
		t.Fatalf("a v3 record with a raw preview must be refused (%d): %s", code, resp)
	}
}

func TestExtensionsWithoutContentPreviewAreUntouched(t *testing.T) {
	h := newSrv(t)
	rec, _ := postRecord(t, h, `{"idempotency_key":"e","project_id":"p1","session_id":"s1","action":"a","extensions":{"framework":{"name":"x"}}}`)
	if ext, _ := rec["extensions"].(map[string]any); ext["framework"] == nil {
		t.Fatalf("unrelated extensions were dropped: %v", rec["extensions"])
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
