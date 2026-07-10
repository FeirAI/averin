package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

const truncMarker = "…[averin: preview truncated]"

// TestTruncatePreviewBoundsAndValidUTF8 (averin#17): content_preview bodies are append-only and permanently
// un-erasable, so truncatePreview is the ONLY bound on their stored size. It must cap the payload at maxPreview
// bytes, keep the result valid UTF-8 (never split a multi-byte rune at the seam), and carry a visible marker.
func TestTruncatePreviewBoundsAndValidUTF8(t *testing.T) {
	// Under the cap: passed through verbatim (no marker).
	if got := truncatePreview("hello world"); got != "hello world" {
		t.Fatalf("a small preview must pass through unchanged, got %q", got)
	}

	// Over the cap (single-byte runes): payload trimmed to <= maxPreview, marker appended.
	big := strings.Repeat("a", maxPreview+5000)
	got := truncatePreview(big)
	if !strings.HasSuffix(got, truncMarker) {
		t.Fatalf("a truncated preview must carry the marker")
	}
	if payload := strings.TrimSuffix(got, truncMarker); len(payload) > maxPreview {
		t.Fatalf("truncated payload %d bytes exceeds maxPreview %d", len(payload), maxPreview)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncated preview must remain valid UTF-8")
	}

	// Over the cap with 3-byte runes so the byte cut lands MID-rune: the boundary back-up must keep it valid.
	multi := strings.Repeat("界", maxPreview) // 3 bytes each
	gotM := truncatePreview(multi)
	if !utf8.ValidString(gotM) {
		t.Fatal("truncation split a multi-byte rune (invalid UTF-8)")
	}
	if payload := strings.TrimSuffix(gotM, truncMarker); len(payload) > maxPreview {
		t.Fatalf("multibyte truncated payload %d exceeds maxPreview %d", len(payload), maxPreview)
	}
}

// TestProxyTruncatesHugePreview (averin#17): a large prompt/completion must be hard-truncated in the sealed
// record — proof the truncation is wired into BOTH content_preview sides, not just the helper.
func TestProxyTruncatesHugePreview(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"` + strings.Repeat("z", maxPreview+4000) + `"}}]}`))
	}))
	defer upstream.Close()

	rec := newStub()
	p := New(upstream.URL, "p1", rec)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("q", maxPreview+4000) + `"}]}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	rec.wait(t, 1)
	preview := rec.records[0]["extensions"].(map[string]any)["content_preview"].(map[string]any)
	in := preview["input"].(string)
	out := preview["output"].(string)
	if len(in) > maxPreview+len(truncMarker) || !strings.HasSuffix(in, truncMarker) {
		t.Fatalf("input preview not truncated: %d bytes, suffix-ok=%v", len(in), strings.HasSuffix(in, truncMarker))
	}
	if len(out) > maxPreview+len(truncMarker) || !strings.HasSuffix(out, truncMarker) {
		t.Fatalf("output preview not truncated: %d bytes, suffix-ok=%v", len(out), strings.HasSuffix(out, truncMarker))
	}
}
