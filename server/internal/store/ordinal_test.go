package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// exerciseRecordOrdinal is the history-scaling PR1 contract shared by Mem and Postgres: the per-project
// insertion ordinal is the 1-based position in insertion order, and RecordsAfter, RecordCount, RecordsPage and
// ProjectHeadsSince agree with the full-history reads at every position.
func exerciseRecordOrdinal(t *testing.T, s Store) {
	t.Helper()
	const p = "ord"
	// A forked DAG: a root, two children of it, a merge naming both, a record forced onto an old parent, and a
	// second session. Insertion order is the order below.
	puts := []Record{
		rec("sha256:r0", "s1"),
		rec("sha256:r1", "s1", "sha256:r0"),
		rec("sha256:r2", "s1", "sha256:r0"),
		rec("sha256:r3", "s1", "sha256:r1", "sha256:r2"),
		rec("sha256:r4", "s2"),
		rec("sha256:r5", "s1", "sha256:r0"), // names an old, already-referenced record
		rec("sha256:r6", "s2", "sha256:r4"),
	}
	for i, r := range puts {
		if _, created, err := s.PutRecord(p, fmt.Sprintf("k%d", i), r); err != nil || !created {
			t.Fatalf("put %s: created=%v err=%v", r.ContentHash, created, err)
		}
		// A byte-identical retry collapses and must not consume an ordinal.
		if _, created, err := s.PutRecord(p, fmt.Sprintf("retry%d", i), r); err != nil || created {
			t.Fatalf("retry %s: created=%v err=%v", r.ContentHash, created, err)
		}
	}
	n := len(puts)
	if c, err := s.RecordCount(p); err != nil || c != n {
		t.Fatalf("RecordCount = %d, %v; want %d (collapsed retries leave no gap)", c, err, n)
	}
	if c, err := s.RecordCount("empty"); err != nil || c != 0 {
		t.Fatalf("RecordCount of an empty project = %d, %v; want 0", c, err)
	}
	all, err := s.AllRecords(p)
	if err != nil || len(all) != n {
		t.Fatalf("AllRecords: %d, %v", len(all), err)
	}
	for i, r := range all {
		if r.ContentHash != puts[i].ContentHash {
			t.Fatalf("AllRecords[%d] = %s, want insertion order %s", i, r.ContentHash, puts[i].ContentHash)
		}
	}
	hashes := func(rs []Record) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ContentHash)
		}
		return strings.Join(out, ",")
	}
	// RecordsAfter(after, limit) is exactly the AllRecords slice (after, after+limit].
	for after := -1; after <= n+1; after++ {
		for limit := 0; limit <= n+1; limit++ {
			got, err := s.RecordsAfter(p, int64(after), limit)
			if err != nil || got == nil {
				t.Fatalf("RecordsAfter(%d,%d) = %v, %v; want non-nil", after, limit, got, err)
			}
			lo := max(after, 0)
			hi := min(lo+limit, n)
			want := []Record{}
			if lo < n && limit > 0 {
				want = all[lo:hi]
			}
			if hashes(got) != hashes(want) {
				t.Fatalf("RecordsAfter(%d,%d) = %s, want %s", after, limit, hashes(got), hashes(want))
			}
		}
	}
	// The newest record is a limit-1 page.
	if pg, err := s.RecordsPage(p, 1, 0); err != nil || len(pg) != 1 || pg[0].ContentHash != "sha256:r6" {
		t.Fatalf("newest record = %v, %v; want r6", pg, err)
	}
	if pg, err := s.RecordsPage(p, 2, 1); err != nil || hashes(pg) != "sha256:r5,sha256:r4" {
		t.Fatalf("RecordsPage(2,1) = %s, %v", hashes(pg), err)
	}
	// The incremental frontier equals the full one from every prefix.
	full, err := s.ProjectHeads(p)
	if err != nil {
		t.Fatal(err)
	}
	for k := 0; k <= n; k++ {
		base := headsOf(all[:k])
		if base == nil {
			base = []string{}
		}
		got, err := ProjectHeadsSince(s, p, base, int64(k))
		if err != nil || strings.Join(got, ",") != strings.Join(full, ",") {
			t.Fatalf("ProjectHeadsSince(prefix %d) = %v, %v; want %v", k, got, err, full)
		}
	}
	if want := []string{"sha256:r3", "sha256:r5", "sha256:r6"}; strings.Join(full, ",") != strings.Join(want, ",") {
		t.Fatalf("ProjectHeads = %v, want %v", full, want)
	}

	// Checkpoints and anchors by seq range.
	if _, ok, err := s.LatestCheckpoint(p); err != nil || ok {
		t.Fatalf("LatestCheckpoint with none = ok=%v err=%v", ok, err)
	}
	for i := int64(0); i < 4; i++ {
		if err := s.PutCheckpoint(p, Checkpoint{JSON: fmt.Sprintf(`{"checkpoint_seq":%d}`, i), CheckpointHash: fmt.Sprintf("sha256:c%d", i), Seq: i}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := s.PutAnchor(p, i, fmt.Sprintf("tok%d", i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if cp, ok, err := s.LatestCheckpoint(p); err != nil || !ok || cp.Seq != 3 || cp.CheckpointHash != "sha256:c3" || cp.JSON != `{"checkpoint_seq":3}` {
		t.Fatalf("LatestCheckpoint = %+v ok=%v err=%v", cp, ok, err)
	}
	if next, err := s.NextCheckpointSeq(p); err != nil || next != 4 {
		t.Fatalf("NextCheckpointSeq = %d, %v; want 4", next, err)
	}
	if next, err := s.NextCheckpointSeq("empty"); err != nil || next != 0 {
		t.Fatalf("NextCheckpointSeq of none = %d, %v; want 0", next, err)
	}
	cps, err := s.CheckpointsRange(p, 1, 2)
	if err != nil || len(cps) != 2 || cps[0].Seq != 1 || cps[1].Seq != 2 {
		t.Fatalf("CheckpointsRange(1,2) = %+v, %v", cps, err)
	}
	if cps, err := s.CheckpointsRange(p, 4, 9); err != nil || cps == nil || len(cps) != 0 {
		t.Fatalf("CheckpointsRange past the end = %+v, %v; want empty non-nil", cps, err)
	}
	an, err := s.AnchorsRange(p, 1, 3)
	if err != nil || len(an) != 1 || an[2] != "tok2" {
		t.Fatalf("AnchorsRange(1,3) = %v, %v; want only seq 2", an, err)
	}
	if an, err := s.AnchorsRange(p, 5, 9); err != nil || an == nil || len(an) != 0 {
		t.Fatalf("AnchorsRange past the end = %v, %v", an, err)
	}
}

func TestMemRecordOrdinal(t *testing.T) { exerciseRecordOrdinal(t, NewMem()) }

func TestPostgresRecordOrdinal(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseRecordOrdinal(t, p)
	// The ordinals themselves are 1..n in insertion order.
	rows, err := p.pool.Query(context.Background(), `SELECT ord FROM records WHERE project_id='ord' ORDER BY ord`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := int64(1)
	for rows.Next() {
		var o int64
		if err := rows.Scan(&o); err != nil || o != want {
			t.Fatalf("ord = %d (%v), want %d", o, err, want)
		}
		want++
	}
	if want != 8 {
		t.Fatalf("stored %d ordinals, want 7", want-1)
	}
}

// TestPostgresOrdinalConcurrentWriters: writers of different projects and of one project (serialized by the
// project guard) end with gapless, unique ordinals per project.
func TestPostgresOrdinalConcurrentWriters(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	var wg sync.WaitGroup
	for _, proj := range []string{"c1", "c2", "c3"} {
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					h := fmt.Sprintf("sha256:%s-%d-%d", proj, w, i)
					if _, _, err := p.PutRecord(proj, h, rec(h, "s")); err != nil {
						t.Errorf("put %s: %v", h, err)
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	for _, proj := range []string{"c1", "c2", "c3"} {
		var n, mx, distinct int64
		if err := p.pool.QueryRow(context.Background(), `SELECT count(*), max(ord), count(DISTINCT ord) FROM records WHERE project_id=$1`, proj).Scan(&n, &mx, &distinct); err != nil {
			t.Fatal(err)
		}
		if n != 40 || mx != 40 || distinct != 40 {
			t.Fatalf("%s: rows=%d max=%d distinct=%d, want 40 gapless", proj, n, mx, distinct)
		}
		if c, err := p.RecordCount(proj); err != nil || c != 40 {
			t.Fatalf("%s RecordCount = %d, %v", proj, c, err)
		}
	}
}

// sqlTrace records the statements a pool sends while enabled.
type sqlTrace struct {
	mu   sync.Mutex
	on   bool
	sqls []tracedSQL
}

type tracedSQL struct {
	sql  string
	args []any
}

func (s *sqlTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.on {
		s.sqls = append(s.sqls, tracedSQL{sql: d.SQL, args: d.Args})
	}
	return ctx
}

func (s *sqlTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (s *sqlTrace) record(fn func()) []tracedSQL {
	s.mu.Lock()
	s.on, s.sqls = true, nil
	s.mu.Unlock()
	fn()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.on = false
	return s.sqls
}

// planRows is the number of table rows the executor examined for one statement: the rows every scan node
// returned plus the rows its filter removed, times its loops. It is the operation count of the statement, and
// unlike wall time it does not depend on the machine.
func planRows(t *testing.T, p *Postgres, q tracedSQL) int64 {
	t.Helper()
	var raw []byte
	if err := p.pool.QueryRow(context.Background(), "EXPLAIN (ANALYZE, FORMAT JSON) "+q.sql, q.args...).Scan(&raw); err != nil {
		t.Fatalf("explain %q: %v", q.sql, err)
	}
	var plans []struct{ Plan map[string]any }
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	var walk func(n map[string]any) int64
	walk = func(n map[string]any) int64 {
		var total int64
		if nt, _ := n["Node Type"].(string); strings.Contains(nt, "Scan") && nt != "Bitmap Index Scan" { // the bitmap heap node above it reports the table rows
			loops, _ := n["Actual Loops"].(float64)
			rows, _ := n["Actual Rows"].(float64)
			removed, _ := n["Rows Removed by Filter"].(float64)
			total += int64((rows + removed) * loops)
		}
		if kids, ok := n["Plans"].([]any); ok {
			for _, k := range kids {
				total += walk(k.(map[string]any))
			}
		}
		return total
	}
	var total int64
	for _, pl := range plans {
		total += walk(pl.Plan)
	}
	return total
}

// TestPostgresPerPassWorkIsConstantInHistory is the history-scaling PR1 scale test. A project holds 1, 3 and
// 12 months of history (the same 50 new records each time, history backdated month by month at a fixed rate).
// One pass of what the checkpoint loop does per cycle (the record count, the newest record, the records
// after the last checkpoint, the frontier from the checkpoint's) must examine the same number of rows at every
// history size: assert on rows examined, not wall time. On the previous store (count(DISTINCT) over the project,
// a sort on the unindexed inserted_at) the count and the newest-record read examined every row.
func TestPostgresPerPassWorkIsConstantInHistory(t *testing.T) {
	const newRecords = 50
	const perMonth = 600 // test-sized stand-in for the soak's rate; only the ratio between sizes matters
	months := []int{1, 3, 12}
	type pass struct{ count, newest, after, heads int64 }
	got := map[int]pass{}
	for _, m := range months {
		p, tr, done := newTracedTestStore(t)
		ctx := context.Background()
		hist := m * perMonth
		total := hist + newRecords
		// Backdated history as one chain, then 50 recent records, with the ordinals the write path assigns.
		if _, err := p.pool.Exec(ctx, `
			INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json, inserted_at, ord)
			SELECT 'scale', 'k'||g, 'sha256:'||g, 's'||(g % 7), CASE WHEN g=1 THEN '{}'::text[] ELSE ARRAY['sha256:'||(g-1)] END, '{}',
			       now() - make_interval(mins => ($2 - g) * 40), g
			FROM generate_series(1, $1) g`, total, total); err != nil {
			t.Fatal(err)
		}
		if _, err := p.pool.Exec(ctx, `ANALYZE records`); err != nil {
			t.Fatal(err)
		}
		baseFrontier := []string{fmt.Sprintf("sha256:%d", hist)}

		var c int
		var newest []Record
		var after []Record
		var heads []string
		var res pass
		for _, step := range []struct {
			name string
			dst  *int64
			fn   func()
		}{
			{"count", &res.count, func() {
				var err error
				if c, err = p.RecordCount("scale"); err != nil || c != total {
					t.Fatalf("RecordCount = %d, %v; want %d", c, err, total)
				}
			}},
			{"newest", &res.newest, func() {
				var err error
				if newest, err = p.RecordsPage("scale", 1, 0); err != nil || len(newest) != 1 || newest[0].ContentHash != fmt.Sprintf("sha256:%d", total) {
					t.Fatalf("newest = %v, %v", newest, err)
				}
			}},
			{"after", &res.after, func() {
				var err error
				if after, err = p.RecordsAfter("scale", int64(hist), 1000); err != nil || len(after) != newRecords {
					t.Fatalf("RecordsAfter = %d, %v; want %d", len(after), err, newRecords)
				}
			}},
			{"heads", &res.heads, func() {
				var err error
				if heads, err = ProjectHeadsSince(p, "scale", baseFrontier, int64(hist)); err != nil || len(heads) != 1 || heads[0] != fmt.Sprintf("sha256:%d", total) {
					t.Fatalf("frontier = %v, %v", heads, err)
				}
			}},
		} {
			sqls := tr.record(step.fn)
			for _, q := range sqls {
				*step.dst += planRows(t, p, q)
			}
			if *step.dst == 0 {
				t.Fatalf("%s: no statement was traced", step.name)
			}
		}
		got[m] = res
		done()
	}
	t.Logf("rows examined per pass (count/newest/after/heads): 1mo=%+v 3mo=%+v 12mo=%+v", got[1], got[3], got[12])
	for _, m := range months[1:] {
		if got[m] != got[1] {
			t.Fatalf("work grew with history: 1 month %+v, %d months %+v", got[1], m, got[m])
		}
	}
	// Absolute bound: a count and a newest read each touch one index entry; the range read touches its 50.
	if g := got[1]; g.count > 2 || g.newest > 2 || g.after > newRecords+2 || g.heads > newRecords+2 {
		t.Fatalf("a pass examined more rows than the index reads need: %+v", g)
	}
}

// TestPostgresOrdinalIndexServesReads: the three ordinal reads use the (project_id, ord) index, not a
// sequential scan, even with other projects' rows present and a table large enough to tempt one.
func TestPostgresOrdinalIndexServesReads(t *testing.T) {
	p, tr, done := newTracedTestStore(t)
	defer done()
	ctx := context.Background()
	if _, err := p.pool.Exec(ctx, `
		INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json, ord)
		SELECT 'p'||(g % 3), 'k'||g, 'sha256:'||g, 's', '{}', '{}', (g / 3) + 1 FROM generate_series(0, 29999) g`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `ANALYZE records`); err != nil {
		t.Fatal(err)
	}
	sqls := tr.record(func() {
		if _, err := p.RecordCount("p1"); err != nil {
			t.Fatal(err)
		}
		if _, err := p.RecordsPage("p1", 1, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := p.RecordsAfter("p1", 9990, 100); err != nil {
			t.Fatal(err)
		}
	})
	if len(sqls) != 3 {
		t.Fatalf("traced %d statements, want 3", len(sqls))
	}
	for _, q := range sqls {
		var plan strings.Builder
		rows, err := p.pool.Query(ctx, "EXPLAIN "+q.sql, q.args...)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		rows.Close()
		if !strings.Contains(plan.String(), "records_project_ord_uniq") || strings.Contains(plan.String(), "Seq Scan") {
			t.Fatalf("statement %q does not use the ordinal index:\n%s", q.sql, plan.String())
		}
	}
}
