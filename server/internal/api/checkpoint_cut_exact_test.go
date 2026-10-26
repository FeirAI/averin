package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

func bogusBase(project string) func(store.Checkpoint) store.Checkpoint {
	return func(cp store.Checkpoint) store.Checkpoint {
		var m map[string]any
		_ = json.Unmarshal([]byte(cp.JSON), &m)
		if m["project_id"] != project {
			return cp
		}
		m["frontier"] = append(m["frontier"].([]any), "sha256:bogus-head")
		b, _ := json.Marshal(m)
		cp.JSON = string(b)
		return cp
	}
}

// TestCheckpointCutShadowIsPerProject: two projects cut in a fixed rotation on one server. The sample is chosen
// from the checkpoint being cut, so project A (whose base is corrupted) is shadow-checked at its own seq 100
// however the cuts of B interleave; a global counter always landed the sample on B.
func TestCheckpointCutShadowIsPerProject(t *testing.T) {
	st := store.NewMem()
	spy := newRowSpy(st)
	s := api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowMinInterval(0)
	ha := newCutHistory(t, st, "A", 1)
	hb := newCutHistory(t, st, "B", 2)
	ha.plain()
	hb.plain()
	for _, p := range []string{"A", "B"} {
		if _, err := cutOnce(t, s, spy, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"A", "B"} { // honest seq 1: the first cut after start passes its shadow check
		if p == "A" {
			ha.plain()
		} else {
			hb.plain()
		}
		if _, err := cutOnce(t, s, spy, p); err != nil {
			t.Fatal(err)
		}
	}
	spy.tamper = bogusBase("A")
	var refusedAt int
	for i := 1; i <= 150 && refusedAt == 0; i++ {
		ha.plain()
		cp, err := cutOnce(t, s, spy, "A")
		if err != nil {
			refusedAt = i
			if cp.Seq != 0 {
				t.Fatalf("a refused cut returned a checkpoint: %+v", cp)
			}
			break
		}
		hb.plain()
		if _, err := cutOnce(t, s, spy, "B"); err != nil {
			t.Fatalf("B cut %d: %v", i, err)
		}
	}
	// A's cuts so far were seq 1 (first after start, passed) .. the refused one is the cut of seq 100.
	if refusedAt != 99 {
		t.Fatalf("A's corrupted base was refused at its cut %d (checkpoint seq %d), want the cut of seq 100", refusedAt, refusedAt+1)
	}
	// Both projects were each shadow-checked at least once (the first cut after start) plus A's seq-100 cut.
	if _, _, checks, mism := s.CutStatsForTest(); checks < 3 || mism != 1 {
		t.Fatalf("shadow checks %d mismatches %d, want >=3 and 1", checks, mism)
	}
}

// TestCheckpointCutRefusalSurvivesRestart: a refused seq is retried as the same seq, so a new process over the
// same store shadows and refuses it again (no state outside the store), and the first incremental cut of a
// project after a start is shadow-checked, so a base altered while the process was down is refused at once.
func TestCheckpointCutRefusalSurvivesRestart(t *testing.T) {
	st := store.NewMem()
	spy := newRowSpy(st)
	s := api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowMinInterval(0)
	h := newCutHistory(t, st, "A", 5)
	h.plain()
	if _, err := cutOnce(t, s, spy, "A"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 98; i++ { // cuts of seq 1..98 are signed
		h.plain()
		if _, err := cutOnce(t, s, spy, "A"); err != nil {
			t.Fatal(err)
		}
	}
	h.plain()
	if _, err := cutOnce(t, s, spy, "A"); err != nil { // seq 99, honest
		t.Fatal(err)
	}
	spy.tamper = bogusBase("A")
	h.plain()
	if _, err := cutOnce(t, s, spy, "A"); err == nil { // seq 100: shadowed
		t.Fatal("seq 100 must be shadow-checked and refused")
	}
	for r := 0; r < 3; r++ { // restarts: the same seq, shadowed again every time
		s = api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore())
		if cp, err := cutOnce(t, s, spy, "A"); err == nil {
			t.Fatalf("restart %d signed the refused divergent cut: %s", r, cp.JSON)
		}
	}
	// A base altered while the process was down, at a seq that is not a sampled one: the first cut after start is shadowed.
	spy.tamper = nil
	if _, err := cutOnce(t, s, spy, "A"); err != nil { // honest seq 100 signs
		t.Fatal(err)
	}
	h.plain()
	spy.tamper = bogusBase("A")
	s = api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore())
	if _, err := cutOnce(t, s, spy, "A"); err == nil {
		t.Fatal("the first cut after a restart must be shadow-checked: a tampered base at seq 101 was signed")
	}
}

// grantProbeHandlers runs the generic ingest and checkpoint endpoints over st.
func exactCaseWedge(t *testing.T, st store.Store) {
	h := api.New(mustCore(t), st, "k0").WithAuth(auth.NewOpenStore()).Routes()
	post := func(id, ext string) int {
		code, resp := do(t, h, "POST", "/v2/records", fmt.Sprintf(`{"idempotency_key":%q,"project_id":"p1","session_id":"s1","action":"x"%s}`, id, ext))
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("ingest %s: %d %s", id, code, resp)
		}
		return code
	}
	cut := func(when string) {
		code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
		if code != http.StatusCreated {
			t.Fatalf("%s: checkpoint %d %s", when, code, resp)
		}
	}
	post("a0", "")
	cut("first")
	for i, ext := range []string{
		`,"extensions":{"Broker":1}`,
		`,"extensions":{"Broker":"x"}`,
		`,"authority":{"enforcement_point":"credential_broker"},"extensions":{"BROKER":{"kind":"grant_void","void_evidence":{"broker_seq":1}}}`,
	} {
		post(fmt.Sprintf("w%d", i), ext)
		cut("after " + ext) // a generic record must never wedge the cut
	}
	code, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	if code != http.StatusOK {
		t.Fatalf("export %d", code)
	}
	if rep := mustCore(t).VerifyBundle(exp); !strings.Contains(rep, `"ok":true`) {
		t.Fatalf("verifier rejects the chain: %s", rep)
	}
}

// exactCasePoison: while a broker_seq is reserved with no recorded grant, a generic record that only looks like a
// grant under a case-variant key must not close the gap: the cut refuses, as before the incremental cut, and
// signs (verifiably) once the reservation is voided.
func exactCasePoison(t *testing.T, st store.Store) {
	h := api.New(mustCore(t), st, "k0").WithAuth(auth.NewOpenStore()).Routes()
	do(t, h, "POST", "/v2/records", `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"x"}`)
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("first cut %d %s", code, resp)
	}
	seq, _, err := st.AllocateBrokerSeq("p1", "in-flight")
	if err != nil || seq != 1 {
		t.Fatalf("reserve: %d %v", seq, err)
	}
	for _, ext := range []string{
		`{"Broker":{"kind":"grant","grant_evidence":{"broker_seq":1}}}`,
	} {
		if code, resp := do(t, h, "POST", "/v2/records", `{"idempotency_key":"f`+fmt.Sprint(len(ext))+`","project_id":"p1","session_id":"s1","action":"x","authority":{"enforcement_point":"credential_broker"},"extensions":`+ext+`}`); code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("forged ingest %d %s", code, resp)
		}
	}
	for i := 0; i < 2; i++ {
		if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code == http.StatusCreated || !strings.Contains(resp, "broker_seq") {
			t.Fatalf("a record with a case-variant grant marker closed the reservation gap: %d %s", code, resp)
		}
	}
	// The reservation is voided (tombstone recorded): the cut signs and the verifier accepts the chain.
	if err := st.VoidBrokerSeq("p1", "in-flight", 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.PutRecord("p1", "void-1", store.Record{ContentHash: "sha256:void-1", SessionID: "s1",
		JSON: `{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":"grant_void","void_evidence":{"broker_seq":1}}}}`}); err != nil {
		t.Fatal(err)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("after the void: %d %s", code, resp)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	if rep := mustCore(t).VerifyBundle(exp); strings.Contains(rep, "broker_grant_head") {
		t.Fatalf("verifier objects to the head: %s", rep)
	}
}

func TestCheckpointCutExactCaseWedgeMem(t *testing.T)  { exactCaseWedge(t, store.NewMem()) }
func TestCheckpointCutExactCasePoisonMem(t *testing.T) { exactCasePoison(t, store.NewMem()) }
func TestCheckpointCutExactCaseWedgePostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	exactCaseWedge(t, pg)
}
func TestCheckpointCutExactCasePoisonPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	exactCasePoison(t, pg)
}

// TestCheckpointCutRefusesAMissingRecordInAPage: a record missing from a page (deleted by a role that can) makes the
// page shorter than its ordinal span; the cut refuses instead of reading the next page one row early.
func TestCheckpointCutRefusesAMissingRecordInAPage(t *testing.T) {
	st := store.NewMem()
	spy := newRowSpy(st)
	s := api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30)
	h := newCutHistory(t, st, "p", 8)
	for i := 0; i < 10; i++ {
		h.plain()
	}
	if _, err := cutOnce(t, s, spy, "p"); err != nil { // checkpoint at 10
		t.Fatal(err)
	}
	for i := 0; i < 1100; i++ { // ords 11..1110: the first page of the next cut is full, so a gap there is not the last page
		h.plain()
	}
	spy.dropOrd = 500
	cp, err := cutOnce(t, s, spy, "p")
	if err == nil || !strings.Contains(err.Error(), "ordinals are not contiguous") {
		t.Fatalf("a missing record in a non-last page must refuse, got cp %+v err %v", cp, err)
	}
	spy.dropOrd = 0
	if cp, err := cutOnce(t, s, spy, "p"); err != nil || !strings.Contains(cp.JSON, `"record_count":1110`) {
		t.Fatalf("the intact history must cut: %v %s", err, cp.JSON)
	}
}
