package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// interleavingStore runs `hook` exactly once, right AFTER the first AllRecords/Checkpoints read it serves — i.e.
// between the export's two snapshot reads, whichever order they happen in — to reproduce a record + checkpoint
// landing concurrently with an export.
type interleavingStore struct {
	store.Store
	armed  bool
	hook   func()
	parent *interleavingStore
}

func TestExportSnapshotNotTornPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	is := &interleavingStore{Store: pg}
	h := api.New(mustCore(t), is, "k0").WithRevocation(revocationKey()).Routes()
	postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1"}`)
	if code, response := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("first checkpoint (%d): %s", code, response)
	}
	is.hook = func() {
		postRecord(t, h, `{"idempotency_key":"k2","project_id":"p1","session_id":"s1"}`)
		if code, response := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("concurrent checkpoint (%d): %s", code, response)
		}
		if code, response := do(t, h, "POST", "/v2/revoke?project=p1", `{"project_id":"p1","grant_id":"late-grant"}`); code != http.StatusCreated {
			t.Fatalf("concurrent revoke (%d): %s", code, response)
		}
	}
	is.armed = true
	code, before := do(t, h, "GET", "/v2/export?project=p1", "")
	if code != http.StatusOK || is.armed {
		t.Fatalf("snapshot interleaving not exercised (%d): %s", code, before)
	}
	var first struct {
		Records     []json.RawMessage `json:"records"`
		Checkpoints []json.RawMessage `json:"checkpoints"`
	}
	if err := json.Unmarshal([]byte(before), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 1 || len(first.Checkpoints) != 1 || strings.Contains(before, "late-grant") {
		t.Fatalf("snapshot included state from after cutoff: %s", before)
	}
	code, after := do(t, h, "GET", "/v2/export?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("later export (%d): %s", code, after)
	}
	var second struct {
		Records     []json.RawMessage `json:"records"`
		Checkpoints []json.RawMessage `json:"checkpoints"`
	}
	if err := json.Unmarshal([]byte(after), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Records) != 2 || len(second.Checkpoints) != 2 || !strings.Contains(after, "late-grant") {
		t.Fatalf("later export missed committed state: %s", after)
	}
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
