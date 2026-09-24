package store

import (
	"context"
	"errors"
	"testing"
)

func exerciseRecoveryFence(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	seq, _, err := st.AllocateBrokerSeq("p", "g")
	if err != nil || seq != 1 {
		t.Fatalf("reserve: %d %v", seq, err)
	}
	f := RecoveryFence{ProjectID: "p", Seq: seq, GrantID: "g", Generation: 1, OperationID: "op-1", ActorID: "actor-1", SessionID: "recovery", Reason: "abandoned", RequestDigest: "digest"}
	rollback := errors.New("rollback")
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		if _, created, e := bound.PutRecoveryFence(f); e != nil || !created {
			t.Fatalf("fence in aborted tx: %v %v", created, e)
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("abort: %v", err)
	}
	if _, found, err := st.RecoveryFenceAt("p", seq); err != nil || found {
		t.Fatalf("aborted fence persisted: %v %v", found, err)
	}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		got, created, e := bound.PutRecoveryFence(f)
		if e != nil || !created || got.FencedAt.IsZero() {
			t.Fatalf("fence: %+v %v %v", got, created, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		_, created, e := bound.PutRecoveryFence(f)
		if e != nil || created {
			t.Fatalf("identical retry: %v %v", created, e)
		}
		other := f
		other.ActorID = "actor-2"
		if _, _, e := bound.PutRecoveryFence(other); !errors.Is(e, ErrRecoveryConflict) {
			t.Fatalf("other actor claimed fence: %v", e)
		}
		if _, _, e := bound.AllocateBrokerSeq("p", "g"); !errors.Is(e, ErrRecoveryFenced) {
			t.Fatalf("fenced grant allocated: %v", e)
		}
		return bound.ReleaseBrokerSeq("p", "g")
	}); err != nil {
		t.Fatal(err)
	}
	if held, found, err := st.BrokerSeqAt("p", seq); err != nil || !found || held.GrantID != "g" {
		t.Fatalf("fenced reservation released: %+v %v %v", held, found, err)
	}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		if _, _, e := bound.PutRecord("p", "grant-idem", Record{JSON: `{"record_id":"g","extensions":{"broker":{"kind":"grant"}}}`, ContentHash: "grant-hash", SessionID: "s"}); !errors.Is(e, ErrRecoveryFenced) {
			t.Fatalf("fenced grant inserted: %v", e)
		}
		if _, created, e := bound.PutRecord("p", "grant-void:1", Record{JSON: `{"record_id":"g","extensions":{"broker":{"kind":"grant_void"}}}`, ContentHash: "void-hash", SessionID: "s"}); e != nil || !created {
			t.Fatalf("tombstone: %v %v", created, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r := RecoveryResult{ProjectID: "p", Seq: 1, Generation: 1, Outcome: "voided", WinningRecordHash: "void-hash"}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		_, created, e := bound.PutRecoveryResult(r)
		if e != nil || !created {
			t.Fatalf("terminal result: %v %v", created, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		got, created, e := bound.PutRecoveryResult(r)
		if e != nil || created || got.CompletedAt.IsZero() {
			t.Fatalf("terminal replay: %+v %v %v", got, created, e)
		}
		other := r
		other.Outcome = "recorded"
		if _, _, e := bound.PutRecoveryResult(other); !errors.Is(e, ErrRecoveryConflict) {
			t.Fatalf("terminal overwritten: %v", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMemRecoveryFenceContract(t *testing.T) { exerciseRecoveryFence(t, NewMem()) }
func TestPostgresRecoveryFenceContract(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseRecoveryFence(t, p)
}
