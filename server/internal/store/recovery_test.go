package store

import (
	"context"
	"errors"
	"testing"
)

func exerciseRecoveryFence(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	zero := RecoveryFence{ProjectID: "p", Seq: 0, GrantID: "missing", Generation: 1, OperationID: "zero", ActorID: "actor", SessionID: "s", Reason: "r", RequestDigest: "d"}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		_, _, e := bound.PutRecoveryFence(zero)
		if !errors.Is(e, ErrRecoveryConflict) {
			t.Fatalf("zero reservation fence: %v", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
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
		if _, created, e := bound.PutRecord("p", "grant-void:1", Record{JSON: `{"project_id":"p","record_id":"g","session_id":"recovery","event_type":"credential_grant_void","authority":{"source":"gateway_enforced","enforcement_point":"credential_broker","grant_id":"g"},"extensions":{"broker":{"kind":"grant_void","void_evidence":{"domain":"averin.broker.grant_void.v1","project_id":"p","grant_id":"g","broker_seq":1,"actor_id":"actor-1","operation_id":"op-1","reason":"abandoned"}}}}`, ContentHash: "void-hash", SessionID: "recovery", Parents: []string{"parent"}}); e != nil || !created {
			t.Fatalf("tombstone: %v %v", created, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read, found, err := st.RecordByRecordID("p", "g")
	if err != nil || !found {
		t.Fatalf("read winner: %v %v", found, err)
	}
	read.Parents[0] = "mutated"
	read, _, _ = st.RecordByRecordID("p", "g")
	if read.Parents[0] != "parent" {
		t.Fatal("record read aliased committed parents")
	}
	if _, _, err := st.PutRecord("q", "foreign", Record{JSON: `{"record_id":"other"}`, ContentHash: "foreign-hash", SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.PutRecord("p", "wrong-grant", Record{JSON: `{"record_id":"other","project_id":"p"}`, ContentHash: "wrong-grant-hash", SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	r := RecoveryResult{ProjectID: "p", Seq: 1, Generation: 1, Outcome: "voided", WinningRecordHash: "void-hash"}
	if err := st.WithProjectWrite(ctx, "p", func(bound Store) error {
		for _, bad := range []RecoveryResult{
			{ProjectID: "p", Seq: 1, Generation: 1, Outcome: "voided", WinningRecordHash: "missing"},
			{ProjectID: "p", Seq: 1, Generation: 1, Outcome: "recorded", WinningRecordHash: "void-hash"},
			{ProjectID: "p", Seq: 1, Generation: 1, Outcome: "voided", WinningRecordHash: "foreign-hash"},
			{ProjectID: "p", Seq: 1, Generation: 1, Outcome: "voided", WinningRecordHash: "wrong-grant-hash"},
		} {
			if _, _, e := bound.PutRecoveryResult(bad); !errors.Is(e, ErrRecoveryConflict) {
				t.Fatalf("invalid result %+v: %v", bad, e)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
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
