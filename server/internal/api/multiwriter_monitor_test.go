package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/feirai/averin/server/internal/store"
)

// mwEvent is one HTTP operation as the parent observed it: logical invoke and response times from
// one shared counter, so two operations are ordered only when one returned before the other began.
type mwEvent struct {
	Proc       string // "A" or "B"
	Op         string // use, revoke, finalize, prepare, checkpoint, void
	Grant      string // grant id, for use and revoke
	Nonce      string // use nonce
	Idem       string // idempotency key, for use and finalize
	Mode       string // revoke mode
	Inv, Res   int64
	Code       int
	Idempotent bool // use: the reply was an exact retry of a stored receipt
	Created    bool // finalize, revoke: the reply reports a fresh row
	Body       string
	Err        error
}

type mwTrace struct {
	clock  atomic.Int64
	mu     sync.Mutex
	events []mwEvent
}

// call runs one request against a process and records it. It never calls t, so it is safe to use
// from goroutines. The caller fills Proc/Op/Grant/Nonce/Idem/Mode.
func (tr *mwTrace) call(p *projectTxProcess, ev mwEvent, path, body string) mwEvent {
	ev.Inv = tr.clock.Add(1)
	client := http.Client{Timeout: 45 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "http://"+p.addr+path, strings.NewReader(body))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if strings.HasPrefix(path, "/v2/broker-seq/void") {
			req.Header.Set("Authorization", "Bearer test-recovery-token")
		}
		var resp *http.Response
		resp, err = client.Do(req)
		if err == nil {
			var raw []byte
			raw, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			ev.Code, ev.Body = resp.StatusCode, string(raw)
		}
	}
	ev.Res = tr.clock.Add(1)
	ev.Err = err
	var reply struct {
		Idempotent bool `json:"idempotent"`
		Created    bool `json:"created"`
	}
	if err == nil && json.Unmarshal([]byte(ev.Body), &reply) == nil {
		ev.Idempotent, ev.Created = reply.Idempotent, reply.Created
	}
	tr.mu.Lock()
	tr.events = append(tr.events, ev)
	tr.mu.Unlock()
	return ev
}

func (tr *mwTrace) snapshot() []mwEvent {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]mwEvent(nil), tr.events...)
}

// mwCheckTrace holds the invariants that need only the recorded run. They are the operational
// reading of formal/tla/ProjectTx.tla NoRevokedUse (ProjectTx_operational_safe.cfg): a use is
// admitted only against the authoritative revocation state, so none is admitted after a revoke
// was acknowledged, and a capability's nonce is consumed by at most one admitted use.
func mwCheckTrace(events []mwEvent) []string {
	var out []string
	type nk struct{ grant, nonce string }
	consumed := map[nk]int{}
	for _, u := range events {
		if u.Op != "use" || u.Err != nil || u.Code != http.StatusCreated || u.Idempotent {
			continue
		}
		consumed[nk{u.Grant, u.Nonce}]++
		for _, r := range events {
			if r.Op == "revoke" && r.Err == nil && r.Code == http.StatusCreated && r.Grant == u.Grant && r.Res < u.Inv {
				out = append(out, fmt.Sprintf("NoRevokedUse: use %q (proc %s) admitted after a %s revoke of %s had been acknowledged by proc %s", u.Idem, u.Proc, r.Mode, u.Grant, r.Proc))
			}
		}
	}
	for k, n := range consumed {
		if n > 1 {
			out = append(out, fmt.Sprintf("NonceConsumedOnce: nonce %q of grant %s was consumed by %d admitted uses", k.nonce, k.grant, n))
		}
	}
	sort.Strings(out)
	return out
}

// mwCheckState holds the invariants read from the committed database state after the run. They
// are the operational reading of ProjectTx_safe.cfg (NoFrontierFork, NoCheckpointFork,
// NoStaleCheckpoint) plus the temporal cutoff and the gapless broker_seq log. finalCheckpoint
// says the last stored checkpoint was taken after every write had returned, so it must describe
// the whole frontier exactly.
func mwCheckState(ctx context.Context, pg *store.Postgres, admin *pgxpool.Pool, trace []mwEvent, finalCheckpoint bool) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	sessions, err := pg.Sessions("p1")
	if err != nil {
		return []string{"state read failed: sessions: " + err.Error()}
	}
	for _, s := range sessions {
		heads, err := pg.Heads("p1", s)
		if err != nil {
			add("state read failed: heads: %v", err)
			continue
		}
		if len(heads) != 1 {
			add("NoFrontierFork: session %q has %d heads %v", s, len(heads), heads)
		}
	}

	cps, err := pg.Checkpoints("p1")
	if err != nil {
		return append(out, "state read failed: checkpoints: "+err.Error())
	}
	prevHash, prevCount := "", -1
	for i, cp := range cps {
		var body struct {
			Seq     int64    `json:"checkpoint_seq"`
			Prev    *string  `json:"prev_checkpoint_hash"`
			Hash    string   `json:"checkpoint_hash"`
			Front   []string `json:"frontier"`
			Records int      `json:"record_count"`
		}
		if err := json.Unmarshal([]byte(cp.JSON), &body); err != nil {
			add("state read failed: checkpoint %d json: %v", cp.Seq, err)
			continue
		}
		if cp.Seq != int64(i) || body.Seq != cp.Seq {
			add("NoCheckpointFork: checkpoint %d stored at position %d (body seq %d)", cp.Seq, i, body.Seq)
		}
		wantPrev := prevHash
		gotPrev := ""
		if body.Prev != nil {
			gotPrev = *body.Prev
		}
		if gotPrev != wantPrev {
			add("NoCheckpointFork: checkpoint %d links to %q, want %q", cp.Seq, gotPrev, wantPrev)
		}
		prevHash = cp.CheckpointHash
		if body.Records < prevCount {
			add("NoStaleCheckpoint: checkpoint %d covers %d records, fewer than the %d of its predecessor", cp.Seq, body.Records, prevCount)
		}
		prevCount = body.Records
		for _, h := range body.Front {
			var n int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM records WHERE project_id='p1' AND content_hash=$1`, h).Scan(&n); err != nil || n != 1 {
				add("NoStaleCheckpoint: checkpoint %d frontier names %s, which is not a stored record (n=%d err=%v)", cp.Seq, h, n, err)
			}
		}
		if finalCheckpoint && i == len(cps)-1 {
			heads, err := pg.ProjectHeads("p1")
			count, err2 := pg.RecordCount("p1")
			if err != nil || err2 != nil {
				add("state read failed: final frontier: %v %v", err, err2)
			} else if strings.Join(heads, ",") != strings.Join(body.Front, ",") || count != body.Records {
				add("NoStaleCheckpoint: the last checkpoint (frontier %v, %d records) does not describe the committed state (frontier %v, %d records)", body.Front, body.Records, heads, count)
			}
		}
	}

	var bad int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authorization_receipts r JOIN revocation_events e
		ON e.project_id=r.project_id AND e.grant_id=r.grant_id AND e.mode='prospective' WHERE r.ordinal >= e.cutoff_order`).Scan(&bad); err != nil {
		add("state read failed: cutoff: %v", err)
	} else if bad != 0 {
		add("NoRevokedUse: %d committed receipts carry an ordinal at or after their grant's prospective cutoff", bad)
	}

	rows, err := admin.Query(ctx, `SELECT seq FROM broker_seq WHERE project_id='p1' ORDER BY seq`)
	if err != nil {
		return append(out, "state read failed: broker_seq: "+err.Error())
	}
	want := int64(1)
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			add("state read failed: broker_seq scan: %v", err)
			break
		}
		if seq != want {
			add("BrokerSeqGapless: sequence %d where %d was expected", seq, want)
			want = seq
		}
		want++
	}
	rows.Close()

	for _, e := range trace {
		if e.Err != nil || e.Code != http.StatusCreated || e.Idem == "" || (e.Op != "use" && e.Op != "finalize") {
			continue
		}
		if _, found, err := pg.RecordByIdem("p1", e.Idem); err != nil || !found {
			add("AcknowledgedOperationDurable: %s %q was acknowledged with 201 but no record is stored under its identity (err=%v)", e.Op, e.Idem, err)
		}
	}
	sort.Strings(out)
	return out
}

// mwRequireClean fails the test with every violation the monitor found.
func mwRequireClean(t *testing.T, pg *store.Postgres, admin *pgxpool.Pool, tr *mwTrace, finalCheckpoint bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := tr.snapshot()
	violations := append(mwCheckTrace(events), mwCheckState(ctx, pg, admin, events, finalCheckpoint)...)
	if len(violations) != 0 {
		t.Fatalf("trace monitor: %d violations over %d recorded operations:\n  %s", len(violations), len(events), strings.Join(violations, "\n  "))
	}
}

// The monitor is only evidence if it can fail. Each case builds a run that breaks exactly one
// invariant and requires the monitor to name it; the clean run must pass.
func TestMultiWriterMonitorNegativeControls(t *testing.T) {
	grantUse := func(proc, idem, nonce string, inv, res int64) mwEvent {
		return mwEvent{Proc: proc, Op: "use", Grant: "g1", Nonce: nonce, Idem: idem, Inv: inv, Res: res, Code: http.StatusCreated}
	}
	revoke := func(mode string, inv, res int64) mwEvent {
		return mwEvent{Proc: "A", Op: "revoke", Grant: "g1", Mode: mode, Inv: inv, Res: res, Code: http.StatusCreated}
	}
	t.Run("trace", func(t *testing.T) {
		if v := mwCheckTrace([]mwEvent{grantUse("B", "u1", "n1", 1, 4), revoke("total", 2, 5), grantUse("A", "u2", "n2", 6, 7)}); len(v) != 1 || !strings.Contains(v[0], "NoRevokedUse") {
			t.Fatalf("use after an acknowledged revoke not reported: %v", v)
		}
		if v := mwCheckTrace([]mwEvent{grantUse("A", "u1", "n1", 1, 3), grantUse("B", "u2", "n1", 2, 4)}); len(v) != 1 || !strings.Contains(v[0], "NonceConsumedOnce") {
			t.Fatalf("double consumption not reported: %v", v)
		}
		overlap := []mwEvent{grantUse("B", "u1", "n1", 1, 6), revoke("prospective", 2, 5)}
		if v := mwCheckTrace(overlap); len(v) != 0 {
			t.Fatalf("a use overlapping a revoke is not a violation by itself: %v", v)
		}
		retry := grantUse("A", "u1", "n1", 8, 9)
		retry.Idempotent = true
		if v := mwCheckTrace([]mwEvent{revoke("total", 1, 2), retry}); len(v) != 0 {
			t.Fatalf("an idempotent replay of a stored receipt is not an admission: %v", v)
		}
		if v := mwCheckTrace(nil); len(v) != 0 {
			t.Fatalf("empty trace: %v", v)
		}
	})
	t.Run("state", func(t *testing.T) {
		pg, admin := newVoidTestPostgres(t)
		ctx := context.Background()
		if v := mwCheckState(ctx, pg, admin, nil, false); len(v) != 0 {
			t.Fatalf("empty state reported violations: %v", v)
		}
		exec := func(sql string, args ...any) {
			t.Helper()
			if _, err := admin.Exec(ctx, sql, args...); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
		// A forked frontier: two records of one session with no parent link between them.
		exec(`INSERT INTO records(project_id, idempotency_key, content_hash, session_id, parents, json) VALUES
			('p1','fork-1','sha256:f1','fork','{}','{"record_id":"fork-1"}'),
			('p1','fork-2','sha256:f2','fork','{}','{"record_id":"fork-2"}')`)
		// A checkpoint chain (numbered from 0) with a hole, a wrong link and a frontier naming no record.
		exec(`INSERT INTO checkpoints(project_id, seq, checkpoint_hash, json) VALUES
			('p1',0,'sha256:c1','{"checkpoint_seq":0,"checkpoint_hash":"sha256:c1","prev_checkpoint_hash":null,"frontier":["sha256:f1"],"record_count":2}'),
			('p1',2,'sha256:c3','{"checkpoint_seq":2,"checkpoint_hash":"sha256:c3","prev_checkpoint_hash":"sha256:other","frontier":["sha256:missing"],"record_count":1}')`)
		// A receipt at the ordinal of its grant's cutoff, and a hole in broker_seq.
		exec(`INSERT INTO revocation_events(project_id, grant_id, format, mode, cutoff_order, issuer, reason) VALUES ('p1','g1','averin.revocation.event.v1','prospective',3,'t','t')`)
		exec(`INSERT INTO project_write_guard(project_id, authorization_order) VALUES ('p1', 5) ON CONFLICT (project_id) DO UPDATE SET authorization_order = 5`)
		exec(`INSERT INTO authorization_receipts(project_id, ordinal, record_id, grant_id, kind) VALUES ('p1',4,'fork-1','g1','use')`)
		exec(`INSERT INTO broker_seq(project_id, grant_id, seq) VALUES ('p1','ga',1),('p1','gb',3)`)
		violations := strings.Join(mwCheckState(ctx, pg, admin, []mwEvent{{Op: "use", Idem: "never-stored", Code: http.StatusCreated}}, true), "\n")
		for _, want := range []string{"NoFrontierFork", "NoCheckpointFork: checkpoint 2 stored at position 1", "NoCheckpointFork: checkpoint 2 links", "NoStaleCheckpoint: checkpoint 2 frontier names sha256:missing",
			"NoStaleCheckpoint: checkpoint 2 covers 1 records", "NoStaleCheckpoint: the last checkpoint", "NoRevokedUse: 1 committed receipts", "BrokerSeqGapless: sequence 3 where 2", "AcknowledgedOperationDurable"} {
			if !strings.Contains(violations, want) {
				t.Fatalf("monitor missed %q in:\n%s", want, violations)
			}
		}
	})
}
