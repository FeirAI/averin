package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// exerciseTemporalRevocation is the plan 009 store contract shared by Mem and Postgres.
func exerciseTemporalRevocation(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	write := func(fn func(Store) error) error { return s.WithProjectWrite(ctx, "p1", fn) }
	var first RevocationEvent
	if err := write(func(st Store) error {
		o, err := st.AllocateAuthorizationOrder("p1")
		if err != nil || o != 1 {
			t.Fatalf("first ordinal %d %v", o, err)
		}
		if err := st.PutAuthorizationReceipt("p1", AuthorizationReceipt{Ordinal: 1, RecordID: "use-1", GrantID: "g1", Kind: "use"}); err != nil {
			t.Fatal(err)
		}
		var created bool
		var err2 error
		first, created, err2 = st.PutRevocationEvent(RevocationEvent{ProjectID: "p1", GrantID: "g1", Mode: RevocationProspective, Issuer: "i", Reason: "cancel"})
		if err2 != nil || !created || first.CutoffOrder != 2 {
			t.Fatalf("prospective event %+v created=%v err=%v", first, created, err2)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// One receipt per ordinal and one ordinal per receipt. A conflict aborts its transaction.
	for _, dup := range []AuthorizationReceipt{
		{Ordinal: 1, RecordID: "use-2", GrantID: "g1", Kind: "use"},
		{Ordinal: 2, RecordID: "use-1", GrantID: "g1", Kind: "use"},
	} {
		err := write(func(st Store) error { return st.PutAuthorizationReceipt("p1", dup) })
		if !errors.Is(err, ErrAuthorizationOrderConflict) {
			t.Fatalf("duplicate receipt %+v accepted: %v", dup, err)
		}
	}
	// A rolled-back transaction's allocations and events never persist.
	rollback := errors.New("rollback")
	if err := write(func(st Store) error {
		if _, err := st.AllocateAuthorizationOrder("p1"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.PutRevocationEvent(RevocationEvent{ProjectID: "p1", GrantID: "g-rolled", Mode: RevocationTotal, Issuer: "i"}); err != nil {
			t.Fatal(err)
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback: %v", err)
	}
	if err := write(func(st Store) error {
		again, created, err := st.PutRevocationEvent(RevocationEvent{ProjectID: "p1", GrantID: "g1", Mode: RevocationProspective, Issuer: "i", Reason: "retry"})
		if err != nil || created || again.CutoffOrder != first.CutoffOrder || again.Reason != "cancel" {
			t.Fatalf("retry moved or replaced the event: %+v created=%v err=%v", again, created, err)
		}
		if _, created, err := st.PutRevocationEvent(RevocationEvent{ProjectID: "p1", GrantID: "g1", Mode: RevocationTotal, Issuer: "i", Reason: "compromise"}); err != nil || !created {
			t.Fatalf("total upgrade: created=%v err=%v", created, err)
		}
		if o, err := st.AllocateAuthorizationOrder("p1"); err != nil || o != 3 {
			t.Fatalf("order after rollback %d %v, want 3", o, err)
		}
		if err := st.PutAuthorizationReceipt("p1", AuthorizationReceipt{Ordinal: 9, RecordID: "use-9", GrantID: "g2", Kind: "use"}); err == nil {
			t.Fatal("receipt with an unallocated ordinal accepted")
		}
		if _, _, err := st.PutRevocationEvent(RevocationEvent{ProjectID: "p1", GrantID: "g3", Mode: RevocationProspective, CutoffOrder: 9, Issuer: "i"}); err == nil {
			t.Fatal("cutoff beyond the allocated order accepted")
		}
		for _, bad := range []RevocationEvent{
			{ProjectID: "p1", GrantID: "g4", Mode: RevocationTotal, CutoffOrder: 1, Issuer: "i"},
			{ProjectID: "p1", GrantID: "g4", Mode: "sometimes", Issuer: "i"},
			{ProjectID: "p1", GrantID: "g4", Mode: RevocationTotal},
		} {
			if _, _, err := st.PutRevocationEvent(bad); err == nil {
				t.Fatalf("malformed event accepted: %+v", bad)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Second)
	if err := s.WithProjectRead(ctx, "p1", func(st Store) error {
		at, watermark, err := st.SnapshotBoundary("p1")
		if err != nil || watermark != 3 || at.Before(before) || at.After(time.Now().Add(time.Second)) {
			t.Fatalf("snapshot boundary %v watermark %d err %v", at, watermark, err)
		}
		events, err := st.RevocationEvents("p1")
		if err != nil || len(events) != 2 || events[0].Mode != RevocationProspective || events[1].Mode != RevocationTotal {
			t.Fatalf("events %+v %v", events, err)
		}
		ids, err := st.RevokedGrantIDs("p1")
		if err != nil || len(ids) != 1 || ids[0] != "g1" {
			t.Fatalf("revoked ids %v %v", ids, err)
		}
		if revoked, err := st.IsRevoked("p1", "g1"); err != nil || !revoked {
			t.Fatalf("g1 not revoked: %v %v", revoked, err)
		}
		if revoked, err := st.IsRevoked("p1", "g-rolled"); err != nil || revoked {
			t.Fatalf("rolled-back event visible: %v %v", revoked, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithProjectRead(ctx, "p2", func(st Store) error {
		_, watermark, err := st.SnapshotBoundary("p2")
		if err != nil || watermark != 0 {
			t.Fatalf("unrelated project watermark %d %v", watermark, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMemTemporalRevocationContract(t *testing.T) {
	exerciseTemporalRevocation(t, NewMem())
}

func TestPostgresTemporalRevocationContract(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseTemporalRevocation(t, p)
	if _, _, err := p.SnapshotBoundary("p1"); err == nil {
		t.Fatal("snapshot boundary read outside a repeatable-read project transaction")
	}
}
