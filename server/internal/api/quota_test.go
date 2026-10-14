package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

func quotaRec(project, idem string) string {
	return fmt.Sprintf(`{"idempotency_key":%q,"project_id":%q,"session_id":"s1","action":"a"}`, idem, project)
}

func usageRecords(t *testing.T, h http.Handler, project string) int {
	t.Helper()
	code, resp := do(t, h, "GET", "/v2/usage?project="+project, "")
	if code != 200 {
		t.Fatalf("usage: %d %s", code, resp)
	}
	var u struct {
		Records int `json:"records"`
	}
	json.Unmarshal([]byte(resp), &u)
	return u.Records
}

// TestQuota_RefusesWritesPastTheCap (AVE-07): the cap is per project, exact, item by item for a batch (the items that fit before the cap stay stored),
// does not refuse an idempotent replay, and reads keep working.
func TestQuota_RefusesWritesPastTheCap(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(c, store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithProjectQuota(3)
	h := srv.Routes()
	for i := 1; i <= 3; i++ {
		if code, r := do(t, h, "POST", "/v2/records?project=p1", quotaRec("p1", fmt.Sprintf("i%d", i))); code != http.StatusCreated {
			t.Fatalf("record %d within the cap: %d %s", i, code, r)
		}
	}
	// The fourth distinct record is refused with 507 and the stored count stays at the cap.
	code, r := do(t, h, "POST", "/v2/records?project=p1", quotaRec("p1", "i4"))
	if code != http.StatusInsufficientStorage || !strings.Contains(r, "quota") {
		t.Fatalf("record past the cap: want 507 quota, got %d %s", code, r)
	}
	if n := usageRecords(t, h, "p1"); n != 3 {
		t.Fatalf("a refused write must store nothing: records=%d", n)
	}
	// An idempotent replay of a stored record creates nothing, so it is still answered.
	if code, r := do(t, h, "POST", "/v2/records?project=p1", quotaRec("p1", "i2")); code != http.StatusCreated {
		t.Fatalf("replay at the cap must still succeed: %d %s", code, r)
	}
	// Another project has its own allowance.
	if code, r := do(t, h, "POST", "/v2/records?project=p2", quotaRec("p2", "x1")); code != http.StatusCreated {
		t.Fatalf("a different project is not limited by p1: %d %s", code, r)
	}
	// Reads and metrics keep working at the cap.
	if code, _ := do(t, h, "GET", "/v2/records?project=p1", ""); code != 200 {
		t.Fatalf("reads at the cap: %d", code)
	}
	if _, m := do(t, h, "GET", "/metrics", ""); !strings.Contains(m, "averin_quota_rejections_total 1") {
		t.Fatalf("the refusal must be counted:\n%s", m)
	}
}

// TestQuota_BatchStopsAtTheCap: a batch is processed item by item, so the items that fit stay stored and
// the first item past the cap gets the 507 (the rest of the batch is not stored either).
func TestQuota_BatchStopsAtTheCap(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(c, store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithProjectQuota(3).Routes()
	do(t, h, "POST", "/v2/records?project=p1", quotaRec("p1", "a"))
	do(t, h, "POST", "/v2/records?project=p1", quotaRec("p1", "b"))
	batch := "[" + quotaRec("p1", "c") + "," + quotaRec("p1", "d") + "," + quotaRec("p1", "e") + "]"
	if code, r := do(t, h, "POST", "/v2/records?project=p1", batch); code != http.StatusInsufficientStorage {
		t.Fatalf("batch past the cap: want 507, got %d %s", code, r)
	}
	if n := usageRecords(t, h, "p1"); n != 3 {
		t.Fatalf("the project must stop exactly at the cap: records=%d", n)
	}
}

// TestQuota_OffByDefault: with no quota a project grows without a refusal.
func TestQuota_OffByDefault(t *testing.T) {
	h := newSrv(t)
	for i := 0; i < 20; i++ {
		if code, r := do(t, h, "POST", "/v2/records?project=p1", quotaRec("p1", fmt.Sprintf("i%d", i))); code != http.StatusCreated {
			t.Fatalf("record %d: %d %s", i, code, r)
		}
	}
}
