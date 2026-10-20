package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func useIntentJSON(id, session string) string {
	return fmt.Sprintf(`{"record_id":%q,"session_id":%q,"extensions":{"broker":{"kind":"use_intent"}}}`, id, session)
}

func useOutcomeJSON(id, session, intentRef string) string {
	return fmt.Sprintf(`{"record_id":%q,"session_id":%q,"extensions":{"broker":{"kind":"use_outcome","use_outcome":{"intent_ref":%q,"status":"ok"}}}}`, id, session, intentRef)
}

func putUse(t *testing.T, st Store, proj, sess, hash, js string) {
	t.Helper()
	if _, created, err := st.PutRecord(proj, "k-"+hash, Record{JSON: js, ContentHash: hash, SessionID: sess, Parents: []string{}}); err != nil || !created {
		t.Fatalf("put %s: created=%v err=%v", hash, created, err)
	}
}

// useStores runs fn on the in-memory store and on Postgres (when configured).
func useStores(t *testing.T, fn func(t *testing.T, st Store)) {
	t.Run("mem", func(t *testing.T) { fn(t, NewMem()) })
	t.Run("postgres", func(t *testing.T) {
		p, done := newTestStore(t)
		defer done()
		fn(t, p)
	})
}

// TestUseOutcomeLookupSemantics pins the contract on both stores: the FIRST outcome in insertion order wins,
// a session boundary and the broker-kind requirement are honoured, and a spoofed generic record is nothing.
func TestUseOutcomeLookupSemantics(t *testing.T) {
	useStores(t, func(t *testing.T, st Store) {
		putUse(t, st, "p", "s1", "sha256:1", useIntentJSON("use-1", "s1"))
		putUse(t, st, "p", "s1", "sha256:2", useOutcomeJSON("out-a", "s1", "use-1"))
		putUse(t, st, "p", "s1", "sha256:3", useOutcomeJSON("out-b", "s1", "use-1")) // a second outcome for the same intent
		putUse(t, st, "p", "s2", "sha256:4", useOutcomeJSON("out-c", "s2", "use-1")) // other session, same intent_ref
		// generic record: no extensions.broker.kind, but a use_outcome-shaped block and a record_id
		putUse(t, st, "p", "s1", "sha256:5", `{"record_id":"gen-1","extensions":{"broker":{"use_outcome":{"intent_ref":"use-9"}}}}`)
		putUse(t, st, "p", "s1", "sha256:6", `{"record_id":"gen-2","extensions":{}}`)
		// another project with the same ids
		putUse(t, st, "q", "s1", "sha256:7", useOutcomeJSON("out-q", "s1", "use-1"))

		if id, ok, err := st.UseOutcomeFor("p", "s1", "use-1"); err != nil || !ok || id != "out-a" {
			t.Fatalf("UseOutcomeFor(p,s1,use-1) = %q,%v,%v; want out-a (first by insertion order)", id, ok, err)
		}
		if id, ok, _ := st.UseOutcomeFor("p", "s2", "use-1"); !ok || id != "out-c" {
			t.Fatalf("UseOutcomeFor(p,s2,use-1) = %q,%v; want out-c", id, ok)
		}
		if id, ok, _ := st.UseOutcomeFor("q", "s1", "use-1"); !ok || id != "out-q" {
			t.Fatalf("UseOutcomeFor(q,s1,use-1) = %q,%v; want out-q", id, ok)
		}
		if _, ok, _ := st.UseOutcomeFor("p", "s3", "use-1"); ok {
			t.Fatal("outcome found in a session that has none")
		}
		if _, ok, _ := st.UseOutcomeFor("p", "s1", "use-9"); ok {
			t.Fatal("a record without extensions.broker.kind was taken for an outcome")
		}
		if _, ok, _ := st.UseOutcomeFor("p", "s1", "use-nope"); ok {
			t.Fatal("absent intent_ref found")
		}

		if rec, ok, err := st.IntentRecord("p", "s1", "use-1"); err != nil || !ok || rec.JSON != useIntentJSON("use-1", "s1") || rec.SessionID != "s1" {
			t.Fatalf("IntentRecord(p,s1,use-1) = %+v,%v,%v", rec, ok, err)
		}
		if _, ok, _ := st.IntentRecord("p", "s2", "use-1"); ok {
			t.Fatal("intent found in the wrong session")
		}
		if _, ok, _ := st.IntentRecord("p", "s1", "gen-2"); ok {
			t.Fatal("a generic record (no extensions.broker.kind) was taken for an intent")
		}
		if _, ok, _ := st.IntentRecord("q", "s1", "use-1"); ok {
			t.Fatal("intent found in another project (q has only the outcome, whose record_id is out-q)")
		}
	})
}

// bulkUseHistory loads n/2 (intent, outcome) pairs into one session as the write path would order them (ord is
// assigned by the insert trigger), then ANALYZEs so the planner has statistics.
func bulkUseHistory(t *testing.T, p *Postgres, n int) {
	t.Helper()
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `
		INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json)
		SELECT 'proj', 'bulk'||g, 'sha256:b'||lpad(g::text, 7, '0'), 'vultrino', '{}'::text[],
		       CASE WHEN g % 2 = 1
		            THEN format('{"record_id":"use-%s","session_id":"vultrino","extensions":{"broker":{"kind":"use_intent"}}}', (g+1)/2)
		            ELSE format('{"record_id":"out-%s","session_id":"vultrino","extensions":{"broker":{"kind":"use_outcome","use_outcome":{"intent_ref":"use-%s","status":"ok"}}}}', g/2, g/2)
		       END
		FROM generate_series(1, $1) g ORDER BY g`, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `ANALYZE records`); err != nil {
		t.Fatal(err)
	}
}

func explain(t *testing.T, p *Postgres, analyze bool, sql string, args ...any) string {
	t.Helper()
	pre := "EXPLAIN "
	if analyze {
		pre = "EXPLAIN (ANALYZE, BUFFERS) "
	}
	rows, err := p.pool.Query(context.Background(), pre+sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// TestUseOutcomeLookupsUseTheirIndexes is the regression guard for the plans: the intent lookup must go
// through records_project_record_id_uniq and the outcome lookup through records_use_outcome_intent_idx (not a
// scan of the session or an ordinal walk).
func TestUseOutcomeLookupsUseTheirIndexes(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	bulkUseHistory(t, p, 6000)
	intentPlan := explain(t, p, false, intentRecordSQL(), "proj", "vultrino", "use-2500")
	if !strings.Contains(intentPlan, "records_project_record_id_uniq") {
		t.Fatalf("intent lookup does not use records_project_record_id_uniq:\n%s", intentPlan)
	}
	outcomePlan := explain(t, p, false, useOutcomeForSQL(), "proj", "vultrino", "use-2500")
	if !strings.Contains(outcomePlan, "records_use_outcome_intent_idx") {
		t.Fatalf("outcome lookup does not use records_use_outcome_intent_idx:\n%s", outcomePlan)
	}
	t.Logf("intent plan:\n%s\noutcome plan:\n%s", intentPlan, outcomePlan)
}

// TestUseOutcomeLookupFlat measures one (IntentRecord + UseOutcomeFor) pair, the work of one /v2/use-outcome,
// in a single session of N = 1k and 20k records, for the first 100 and the last 100 intents, and the old
// scan for contrast. The lookup must not grow with N beyond noise. AVERIN_INTENT_LATENCY=1 to run.
func TestUseOutcomeLookupFlat(t *testing.T) {
	if testing.Short() || os.Getenv("AVERIN_INTENT_LATENCY") == "" {
		t.Skip("set AVERIN_INTENT_LATENCY=1 to run the lookup latency scaling test")
	}
	stat := func(d []time.Duration) string {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		var sum time.Duration
		for _, x := range d {
			sum += x
		}
		return fmt.Sprintf("mean %v p50 %v p95 %v", (sum / time.Duration(len(d))).Round(time.Microsecond), d[len(d)/2].Round(time.Microsecond), d[len(d)*95/100].Round(time.Microsecond))
	}
	for _, n := range []int{1000, 20000} {
		n := n
		t.Run(fmt.Sprintf("N%d", n), func(t *testing.T) {
			p, done := newTestStore(t)
			defer done()
			bulkUseHistory(t, p, n)
			pairs := n / 2
			measure := func(from, to int) []time.Duration {
				var ds []time.Duration
				for k := from; k <= to; k++ {
					ref := fmt.Sprintf("use-%d", k)
					t0 := time.Now()
					_, ok, err := p.IntentRecord("proj", "vultrino", ref)
					if err != nil || !ok {
						t.Fatalf("IntentRecord %s: ok=%v err=%v", ref, ok, err)
					}
					id, ok, err := p.UseOutcomeFor("proj", "vultrino", ref)
					if err != nil || !ok || id != fmt.Sprintf("out-%d", k) {
						t.Fatalf("UseOutcomeFor %s = %q,%v,%v", ref, id, ok, err)
					}
					ds = append(ds, time.Since(t0))
				}
				return ds
			}
			measure(1, 20) // warm the cache
			first := measure(1, 100)
			last := measure(pairs-99, pairs)
			var miss []time.Duration
			for i := 0; i < 100; i++ {
				t0 := time.Now()
				if _, ok, err := p.UseOutcomeFor("proj", "vultrino", fmt.Sprintf("use-absent-%d", i)); err != nil || ok {
					t.Fatalf("absent: ok=%v err=%v", ok, err)
				}
				miss = append(miss, time.Since(t0))
			}
			var scan []time.Duration
			for i := 0; i < 5; i++ {
				t0 := time.Now()
				recs, err := p.SessionRecords("proj", "vultrino")
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range recs {
					var probe struct {
						RecordID string `json:"record_id"`
					}
					_ = json.Unmarshal([]byte(r.JSON), &probe)
				}
				scan = append(scan, time.Since(t0))
			}
			t.Logf("N=%d lookup pair (intent+outcome), first 100 intents: %s", n, stat(first))
			t.Logf("N=%d lookup pair (intent+outcome), last 100 intents:  %s", n, stat(last))
			t.Logf("N=%d outcome lookup, absent intent_ref (miss):        %s", n, stat(miss))
			t.Logf("N=%d old scan (SessionRecords + decode), for contrast: %s", n, stat(scan))
			t.Logf("N=%d intent plan:\n%s", n, explain(t, p, true, intentRecordSQL(), "proj", "vultrino", fmt.Sprintf("use-%d", pairs-5)))
			t.Logf("N=%d outcome plan (hit):\n%s", n, explain(t, p, true, useOutcomeForSQL(), "proj", "vultrino", fmt.Sprintf("use-%d", pairs-5)))
			t.Logf("N=%d outcome plan (miss):\n%s", n, explain(t, p, true, useOutcomeForSQL(), "proj", "vultrino", "use-absent-1"))
		})
	}
}

// TestUseOutcomeLookupAfterIndexBackfill: rows written WITHOUT the index (as under schema 9), then migration 0010
// applied to them, answer through the store's lookups exactly as the rows say.
func TestUseOutcomeLookupAfterIndexBackfill(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx := context.Background()
	if _, err := p.pool.Exec(ctx, `DROP INDEX records_use_outcome_intent_idx`); err != nil {
		t.Fatal(err)
	}
	putUse(t, p, "p", "s1", "sha256:1", useIntentJSON("use-1", "s1"))
	putUse(t, p, "p", "s1", "sha256:2", useOutcomeJSON("out-a", "s1", "use-1"))
	putUse(t, p, "p", "s1", "sha256:3", useOutcomeJSON("out-b", "s1", "use-1"))
	putUse(t, p, "p", "s1", "sha256:4", useIntentJSON("use-2", "s1"))
	mig, err := os.ReadFile("../../migrations/0010_use_outcome_intent_index.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, string(mig)); err != nil {
		t.Fatalf("apply 0010 over existing rows: %v", err)
	}
	if id, ok, err := p.UseOutcomeFor("p", "s1", "use-1"); err != nil || !ok || id != "out-a" {
		t.Fatalf("after backfill UseOutcomeFor(use-1) = %q,%v,%v; want out-a", id, ok, err)
	}
	if _, ok, _ := p.UseOutcomeFor("p", "s1", "use-2"); ok {
		t.Fatal("an intent with no outcome reported one")
	}
	if _, ok, err := p.IntentRecord("p", "s1", "use-2"); err != nil || !ok {
		t.Fatalf("IntentRecord(use-2) = %v,%v", ok, err)
	}
	// rows written after the backfill are indexed too (first-by-insertion still holds)
	putUse(t, p, "p", "s1", "sha256:5", useOutcomeJSON("out-c", "s1", "use-2"))
	if id, ok, _ := p.UseOutcomeFor("p", "s1", "use-2"); !ok || id != "out-c" {
		t.Fatalf("post-backfill outcome = %q,%v", id, ok)
	}
}
