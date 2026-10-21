package api

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// loadCountingStore counts the whole-history loads (AllRecords) and checkpoint loads taken through a read
// snapshot, to prove the size precheck refuses before anything is materialized.
type loadCountingStore struct {
	store.Store
	loads *atomic.Int64
}

func (c *loadCountingStore) bind(st store.Store) *loadCountingStore {
	return &loadCountingStore{Store: st, loads: c.loads}
}
func (c *loadCountingStore) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return c.Store.WithProjectRead(ctx, p, func(st store.Store) error { return fn(c.bind(st)) })
}
func (c *loadCountingStore) AllRecords(p string) ([]store.Record, error) {
	c.loads.Add(1)
	return c.Store.AllRecords(p)
}
func (c *loadCountingStore) Checkpoints(p string) ([]store.Checkpoint, error) {
	c.loads.Add(1)
	return c.Store.Checkpoints(p)
}

func precheckServer(t *testing.T) (*Server, *loadCountingStore, http.Handler) {
	t.Helper()
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	cs := &loadCountingStore{Store: store.NewMem().WithClock(clock), loads: &atomic.Int64{}}
	s := New(testCore(t), cs, "k0").WithAuth(auth.NewOpenStore()).WithClock(clock)
	return s, cs, s.Routes()
}

func precheckDo(h http.Handler, method, path, body string) (int, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec.Code, rec.Body.String()
}

func seedHistory(t *testing.T, h http.Handler, project string, records int, rng *rand.Rand, checkpointEvery int) {
	t.Helper()
	for i := 0; i < records; i++ {
		pad := strings.Repeat("x", rng.Intn(400))
		body := fmt.Sprintf(`{"idempotency_key":"k%d","project_id":%q,"session_id":"s%d","record_id":"r%d","rationale":%q}`, i, project, rng.Intn(3), i, pad)
		if c, b := precheckDo(h, "POST", "/v2/records", body); c != http.StatusCreated {
			t.Fatalf("record %d: %d %s", i, c, b)
		}
		if checkpointEvery > 0 && (i+1)%checkpointEvery == 0 {
			if c, b := precheckDo(h, "POST", "/v2/checkpoints?project="+project, ""); c != http.StatusCreated {
				t.Fatalf("checkpoint: %d %s", c, b)
			}
		}
	}
}

func estimateFor(t *testing.T, s *Server, project string) int64 {
	t.Helper()
	parts, err := s.st.BundleSizeParts(project)
	if err != nil {
		t.Fatal(err)
	}
	return wholeBundleSizeLowerBound(project, parts)
}

// A history whose estimate already exceeds the cap is answered 413 (export and verify, same body as the exact
// check) WITHOUT loading records or checkpoints; one whose estimate fits is loaded and judged exactly as before.
func TestExportPrecheckRefusesOverCapWithoutLoading(t *testing.T) {
	s, cs, h := precheckServer(t)
	seedHistory(t, h, "p1", 6, rand.New(rand.NewSource(1)), 3)
	est := estimateFor(t, s, "p1")
	whole, _, err := s.buildBundleView(context.Background(), "p1", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if est > int64(len(whole)) {
		t.Fatalf("estimate %d is larger than the real bundle %d", est, len(whole))
	}

	old := maxSingleBundleBytes
	defer func() { maxSingleBundleBytes = old }()

	// estimate over the cap: refused, nothing loaded
	maxSingleBundleBytes = int(est) - 1
	cs.loads.Store(0)
	for _, path := range []string{"/v2/export?project=p1", "/v2/verify?project=p1"} {
		code, body := precheckDo(h, "GET", path, "")
		if code != http.StatusRequestEntityTooLarge || !strings.Contains(body, errBundleTooBig.Error()) {
			t.Fatalf("%s: %d %s", path, code, body)
		}
	}
	if n := cs.loads.Load(); n != 0 {
		t.Fatalf("an over-cap estimate must refuse before loading anything; %d load(s) happened", n)
	}
	if _, _, err := s.buildBundleView(context.Background(), "p1", false, ""); !errors.Is(err, errBundleTooBig) || cs.loads.Load() != 0 {
		t.Fatalf("build: err=%v loads=%d", err, cs.loads.Load())
	}

	// estimate exactly at the cap but the real bundle larger: loaded, then refused by the exact check
	maxSingleBundleBytes = int(est)
	cs.loads.Store(0)
	if _, _, err := s.buildBundleView(context.Background(), "p1", false, ""); !errors.Is(err, errBundleTooBig) {
		t.Fatalf("real bundle over the cap must still be refused: %v", err)
	}
	if cs.loads.Load() == 0 {
		t.Fatal("an estimate that fits the cap must fall through to the exact load-and-check")
	}

	// cap exactly the real size: served; one under: refused (boundary unchanged)
	maxSingleBundleBytes = len(whole)
	if _, _, err := s.buildBundleView(context.Background(), "p1", false, ""); err != nil {
		t.Fatalf("bundle exactly at the cap is served: %v", err)
	}
	maxSingleBundleBytes = len(whole) - 1
	if _, _, err := s.buildBundleView(context.Background(), "p1", false, ""); !errors.Is(err, errBundleTooBig) {
		t.Fatalf("one byte over: %v", err)
	}

	// a month segment is not prechecked (it is judged on its own records)
	maxSingleBundleBytes = old
	if c, b := precheckDo(h, "GET", "/v2/export?project=p1&month=2026-06", ""); c != http.StatusOK {
		t.Fatalf("month export: %d %s", c, b)
	}
}

// The estimate is never larger than the real serialized bundle, over random histories (record sizes,
// session spread, checkpoint cadence, anchors), so refusing on it cannot refuse a bundle the exact check would serve.
func TestExportPrecheckEstimateIsALowerBound(t *testing.T) {
	for seed := int64(0); seed < 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		s, _, h := precheckServer(t)
		project := fmt.Sprintf("proj-%d", seed)
		n := rng.Intn(12)
		seedHistory(t, h, project, n, rng, rng.Intn(4))
		if n > 0 && rng.Intn(2) == 0 {
			if cps, _ := s.st.Checkpoints(project); len(cps) > 0 {
				if err := s.st.PutAnchor(project, cps[0].Seq, "dG9rZW4"); err != nil {
					t.Fatal(err)
				}
			}
		}
		whole, _, err := s.buildBundleView(context.Background(), project, false, "")
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if est := estimateFor(t, s, project); est > int64(len(whole)) || est <= 0 {
			t.Fatalf("seed %d: estimate %d vs real %d (records=%d)", seed, est, len(whole), n)
		}
	}
}

func TestWholeBundleSizeLowerBoundCountsEveryPart(t *testing.T) {
	base := wholeBundleSizeLowerBound("p", store.BundleSizeParts{})
	got := wholeBundleSizeLowerBound("p", store.BundleSizeParts{RecordBytes: 100, Records: 3, CheckpointBytes: 40, Checkpoints: 2})
	if want := base + 100 + 2 + 40 + 1; got != want {
		t.Fatalf("got %d want %d", got, want)
	}
}
