package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/store"
)

func metricsBody(t *testing.T, s *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("/metrics: %d", rec.Code)
	}
	return rec.Body.String()
}

func TestMemoryGaugesReportContentStoreAndRuntime(t *testing.T) {
	s := New(testCore(t), store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithMemoryGauges()
	if c, b := precheckDo(s.Routes(), "POST", "/v2/records", `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","record_id":"r1","rationale":"because"}`); c != 201 {
		t.Fatalf("record: %d %s", c, b)
	}
	st := s.content.(content.Statser).Stats()
	if st.Entries == 0 || st.Bytes == 0 {
		t.Fatalf("the record's raw rationale should be in the in-memory store: %+v", st)
	}
	body := metricsBody(t, s)
	for _, want := range []string{
		"# TYPE averin_content_store_entries gauge", "# TYPE averin_content_store_bytes gauge",
		"averin_content_store_durable 0", "# TYPE averin_go_heap_inuse_bytes gauge",
		"# TYPE averin_go_heap_alloc_bytes gauge", "# TYPE averin_go_heap_objects gauge", "# TYPE averin_go_goroutines gauge",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "averin_content_store_entries 0\n") || strings.Contains(body, "averin_go_heap_inuse_bytes 0\n") || strings.Contains(body, "averin_go_goroutines 0\n") {
		t.Fatalf("gauges must carry live values:\n%s", body)
	}
}

func TestMemoryGaugesMarkADurableContentStore(t *testing.T) {
	fs, err := content.NewEncryptedFSStore(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := New(testCore(t), store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithContent(fs).WithMemoryGauges()
	if body := metricsBody(t, s); !strings.Contains(body, "averin_content_store_durable 1") {
		t.Fatalf("a filesystem store is durable:\n%s", body)
	}
}
