package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// interleavingStore runs `hook` exactly once, right AFTER the first AllRecords/Checkpoints read it serves — i.e.
// between the export's two snapshot reads, whichever order they happen in — to reproduce a record + checkpoint
// landing concurrently with an export.
type interleavingStore struct {
	store.Store
	armed bool
	hook  func()
	parent *interleavingStore
}

func (s *interleavingStore) fire() {
	if s.parent != nil {
		s.parent.fire()
		return
	}
	if s.armed {
		s.armed = false
		s.hook()
	}
}

func (s *interleavingStore) WithProjectRead(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return s.Store.WithProjectRead(ctx, projectID, func(st store.Store) error {
		return fn(&interleavingStore{Store: st, parent: s})
	})
}

func (s *interleavingStore) AllRecords(p string) ([]store.Record, error) {
	recs, err := s.Store.AllRecords(p)
	s.fire()
	return recs, err
}

func (s *interleavingStore) Checkpoints(p string) ([]store.Checkpoint, error) {
	cps, err := s.Store.Checkpoints(p)
	s.fire()
	return cps, err
}

// TestExportSnapshotNotTorn: buildBundle used to read records THEN checkpoints with no lock, so a record +
// checkpoint created between the two reads produced a bundle whose latest checkpoint frontier referenced a
// record missing from the bundle (a false verification failure). Every exported checkpoint's frontier must be
// contained in the exported records.
func TestExportSnapshotNotTorn(t *testing.T) {
	is := &interleavingStore{Store: store.NewMem()}
	h := api.New(mustCore(t), is, "k0").Routes()
	postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1"}`)
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, r)
	}
	is.hook = func() {
		postRecord(t, h, `{"idempotency_key":"k2","project_id":"p1","session_id":"s1"}`)
		if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Errorf("concurrent checkpoint (%d): %s", code, r)
		}
	}
	is.armed = true
	code, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("export (%d): %s", code, exp)
	}
	if is.armed {
		t.Fatal("the interleaving hook never fired")
	}
	var b struct {
		Records []struct {
			ContentHash string `json:"content_hash"`
		} `json:"records"`
		Checkpoints []struct {
			Frontier []string `json:"frontier"`
		} `json:"checkpoints"`
	}
	if err := json.Unmarshal([]byte(exp), &b); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	have := map[string]bool{}
	for _, r := range b.Records {
		have[r.ContentHash] = true
	}
	for i, cp := range b.Checkpoints {
		for _, f := range cp.Frontier {
			if !have[f] {
				t.Fatalf("torn export: checkpoint %d frontier references %s, which is not in the exported records", i, f)
			}
		}
	}
}
