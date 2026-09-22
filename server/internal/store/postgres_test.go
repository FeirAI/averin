package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests require a real Postgres. They are hermetic: each run creates a private, randomly
// named schema, applies the REAL migrations/0001_init.sql into it, runs against it, and drops it.
// Set AVERIN_TEST_DATABASE_URL (e.g. postgres://postgres:postgres@localhost:5432/postgres) to enable.
//
// We apply the actual migration file (not a copy) so the tests exercise the production schema and
// cannot drift from it. Caveat: the migration's append-only REVOKE is a no-op for a superuser or the
// table owner, and in this single-role harness the connecting role OWNS the temp schema's tables, so
// these tests do NOT prove mutation is rejected at the DB level — that requires a dedicated
// non-owner least-privilege role (a deployment concern, see the migration header). They DO prove the
// schema applies cleanly and every query/semantic matches Mem.

// newTestStore connects, creates an isolated schema, applies the migration into it, and returns a
// store whose pool defaults to that schema. The returned cleanup drops the schema and closes.
func newTestStore(t *testing.T) (*Postgres, func()) {
	t.Helper()
	dsn := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run Postgres store tests")
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0001_init.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	schema := fmt.Sprintf("averin_test_%d", time.Now().UnixNano())

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	// Pin every connection in the pool to the private schema so the migration's unqualified table
	// names resolve there and the test is fully isolated.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		pool.Close()
		t.Fatalf("create schema: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		pool.Close()
		t.Fatalf("apply migration: %v", err)
	}
	// Apply every later versioned step too (0002: the record_id uniqueness index), so the tests exercise the
	// full production schema.
	migration2, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0002_record_id_unique.sql"))
	if err != nil {
		pool.Close()
		t.Fatalf("read migration 0002: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migration2)); err != nil {
		pool.Close()
		t.Fatalf("apply migration 0002: %v", err)
	}

	p := &Postgres{pool: pool}
	cleanup := func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		_, _ = pool.Exec(dctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		pool.Close()
	}
	return p, cleanup
}

func rec(hash, session string, parents ...string) Record {
	return Record{
		JSON:        `{"content_hash":"` + hash + `"}`,
		ContentHash: hash,
		SessionID:   session,
		Parents:     parents,
	}
}

func TestPostgresPutRecordIdempotency(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	r := rec("sha256:aaa", "s1")

	stored, created, err := p.PutRecord("proj", "idem-1", r)
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	if !created {
		t.Fatalf("first put: created=false, want true")
	}
	if stored.ContentHash != r.ContentHash {
		t.Fatalf("first put: got hash %q want %q", stored.ContentHash, r.ContentHash)
	}

	// Same idempotency key with the same record -> existing row, created=false.
	stored2, created2, err := p.PutRecord("proj", "idem-1", r)
	if err != nil {
		t.Fatalf("retry put: %v", err)
	}
	if created2 {
		t.Fatalf("retry put: created=true, want false")
	}
	if stored2.ContentHash != r.ContentHash || stored2.JSON != stored.JSON {
		t.Fatalf("retry put: row mismatch: %+v vs %+v", stored2, stored)
	}

	if n, err := p.RecordCount("proj"); err != nil || n != 1 {
		t.Fatalf("record count = %d, %v; want 1", n, err)
	}
}

// TestPostgresGrantRecords (averin#5b) proves the SQL grant-tuple filter returns exactly the grant-kind
// records (a superset of api.grantLog's set) and excludes non-grant records — so checkpoint creation folds
// the grant head from the grant rows alone without a full-history scan, and NEVER omits a real grant.
func TestPostgresGrantRecords(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	grant := func(hash string, seq int64) Record {
		return Record{
			JSON:        fmt.Sprintf(`{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":"grant","grant_evidence":{"broker_seq":%d}}}}`, seq),
			ContentHash: hash, SessionID: "s1",
		}
	}
	generic := func(hash string) Record {
		return Record{JSON: `{"authority":{"source":"caller_declared"},"action":"db.read"}`, ContentHash: hash, SessionID: "s1"}
	}

	if _, _, err := p.PutRecord("proj", "g1", grant("sha256:g1", 1)); err != nil {
		t.Fatalf("put g1: %v", err)
	}
	if _, _, err := p.PutRecord("proj", "r1", generic("sha256:r1")); err != nil {
		t.Fatalf("put r1: %v", err)
	}
	if _, _, err := p.PutRecord("proj", "g2", grant("sha256:g2", 2)); err != nil {
		t.Fatalf("put g2: %v", err)
	}

	got, err := p.GrantRecords("proj")
	if err != nil {
		t.Fatalf("grant records: %v", err)
	}
	hashes := map[string]bool{}
	for _, r := range got {
		hashes[r.ContentHash] = true
	}
	if !hashes["sha256:g1"] || !hashes["sha256:g2"] {
		t.Fatalf("GrantRecords must include every grant, got %v", hashes)
	}
	if hashes["sha256:r1"] {
		t.Fatalf("GrantRecords must exclude non-grant records, got %v", hashes)
	}
}

// TestPostgresRecordsPage (averin#5a) proves the SQL LIMIT/OFFSET page returns records newest-first and pages
// correctly, so the app list endpoint no longer loads the whole history into RAM.
func TestPostgresRecordsPage(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	for i, h := range []string{"sha256:a", "sha256:b", "sha256:c"} { // inserted oldest->newest (a, b, c)
		if _, _, err := p.PutRecord("proj", fmt.Sprintf("idem-%d", i), rec(h, "s1")); err != nil {
			t.Fatalf("put %s: %v", h, err)
		}
	}
	page, err := p.RecordsPage("proj", 2, 0)
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page) != 2 || page[0].ContentHash != "sha256:c" || page[1].ContentHash != "sha256:b" {
		t.Fatalf("newest-first page of 2 want [c b], got %+v", page)
	}
	next, err := p.RecordsPage("proj", 2, 2)
	if err != nil {
		t.Fatalf("page offset 2: %v", err)
	}
	if len(next) != 1 || next[0].ContentHash != "sha256:a" {
		t.Fatalf("offset=2 want [a], got %+v", next)
	}
}

// TestPostgresAppendOnlyRejectsMutation proves the headline security property: the database itself
// rejects UPDATE/DELETE/TRUNCATE on the history tables. The hermetic harness connects as the schema
// owner (so REVOKE on the owner is a no-op), but `SET ROLE` to a freshly-created least-privilege
// non-owner role — granted only INSERT/SELECT — drops to exactly the production app-role privileges,
// where the migration's REVOKE is enforced. This is the deployment topology the append-only claim
// depends on, exercised end to end.
func TestPostgresAppendOnlyRejectsMutation(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx := context.Background()

	// Seed one record (carrying a disclosure) + checkpoint as the owner so each history table has a
	// row to attempt to mutate.
	seed := rec("sha256:ao", "s")
	seed.Disclosures = []DisclosureSecret{{RecordID: "ao", Field: "input", ValueDigest: "sha256:dv", NonceHex: "aa"}}
	if _, _, err := p.PutRecord("p", "k", seed); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	if err := p.PutCheckpoint("p", Checkpoint{JSON: "{}", CheckpointHash: "sha256:c", Seq: 0}); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	if err := p.PutAnchor("p", 0, "tok"); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}

	var schema string
	if err := p.pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatalf("current_schema: %v", err)
	}
	role := fmt.Sprintf("averin_ro_%d", time.Now().UnixNano())
	mustExec := func(sql string) {
		if _, err := p.pool.Exec(ctx, sql); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	mustExec("CREATE ROLE " + role + " NOLOGIN")
	defer func() {
		bg := context.Background()
		_, _ = p.pool.Exec(bg, "DROP OWNED BY "+role)
		_, _ = p.pool.Exec(bg, "DROP ROLE IF EXISTS "+role)
	}()
	mustExec(fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", schema, role))
	mustExec("GRANT INSERT, SELECT ON records, checkpoints, disclosures, anchors TO " + role)

	// A dedicated connection we SET ROLE on, then RESET before returning it to the pool.
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SET ROLE "+role); err != nil {
		t.Fatalf("set role: %v", err)
	}
	defer conn.Exec(ctx, "RESET ROLE") //nolint:errcheck

	// INSERT is permitted for the app role...
	if _, err := conn.Exec(ctx, `INSERT INTO records (project_id,idempotency_key,content_hash,session_id,parents,json)
		VALUES ('p','k2','sha256:ao2','s','{}','{}')`); err != nil {
		t.Fatalf("app-role INSERT should be allowed, got: %v", err)
	}
	// ...but every mutation of history is denied by the database (SQLSTATE 42501).
	denied := func(label, sql string) {
		_, err := conn.Exec(ctx, sql)
		if err == nil {
			t.Fatalf("%s: expected permission denied, but it succeeded (append-only NOT enforced)", label)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("%s: expected 42501 permission denied, got: %v", label, err)
		}
	}
	denied("UPDATE records", "UPDATE records SET json='tampered' WHERE content_hash='sha256:ao'")
	denied("DELETE records", "DELETE FROM records WHERE content_hash='sha256:ao'")
	denied("DELETE checkpoints", "DELETE FROM checkpoints")
	denied("TRUNCATE records", "TRUNCATE records")
	denied("UPDATE disclosures", "UPDATE disclosures SET nonce_hex='x'")
	denied("DELETE disclosures", "DELETE FROM disclosures")
	denied("UPDATE anchors", "UPDATE anchors SET token_b64='x'")
	denied("DELETE anchors", "DELETE FROM anchors")
}

func TestPostgresDisclosures(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseDisclosures(t, p)
}

func TestPostgresAnchors(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseAnchors(t, p)
}

func TestPostgresBrokerSeq(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseBrokerSeq(t, p)
}

func TestPostgresIdemBinding(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseIdemBinding(t, p)
}

func TestPostgresReleaseKeepsNonMaxSeq(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseReleaseKeepsNonMaxSeq(t, p)
}

func TestPostgresRecordIDUnique(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	exerciseRecordIDUnique(t, p)
}

func TestPostgresDuplicateContentHashCollapse(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	r := rec("sha256:bbb", "s1")

	// First insert under one idem key.
	if _, created, err := p.PutRecord("proj", "idem-A", r); err != nil || !created {
		t.Fatalf("first put: created=%v err=%v", created, err)
	}

	// Same bytes (same content_hash) under a DIFFERENT idem key must collapse to the existing row,
	// created=false (threat #8).
	stored, created, err := p.PutRecord("proj", "idem-B", r)
	if err != nil {
		t.Fatalf("dup put: %v", err)
	}
	if created {
		t.Fatalf("dup put: created=true, want false (content_hash collapse)")
	}
	if stored.ContentHash != r.ContentHash {
		t.Fatalf("dup put: hash %q want %q", stored.ContentHash, r.ContentHash)
	}

	// The new idem key should now resolve to the same existing row on retry.
	stored2, created2, err := p.PutRecord("proj", "idem-B", r)
	if err != nil || created2 {
		t.Fatalf("idem-B retry: created=%v err=%v", created2, err)
	}
	if stored2.ContentHash != stored.ContentHash {
		t.Fatalf("idem-B retry: hash mismatch")
	}

	if n, err := p.RecordCount("proj"); err != nil || n != 1 {
		t.Fatalf("record count = %d, %v; want 1 (collapsed)", n, err)
	}
}

func TestPostgresHeadsAndProjectHeads(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	// Small DAG in session s1: root <- child. child references root as a parent, so root is no longer
	// a head; the head is the child.
	root := rec("sha256:root", "s1")
	child := rec("sha256:child", "s1", "sha256:root")

	if _, _, err := p.PutRecord("proj", "k-root", root); err != nil {
		t.Fatalf("put root: %v", err)
	}
	if _, _, err := p.PutRecord("proj", "k-child", child); err != nil {
		t.Fatalf("put child: %v", err)
	}

	heads, err := p.Heads("proj", "s1")
	if err != nil {
		t.Fatalf("heads: %v", err)
	}
	if len(heads) != 1 || heads[0] != "sha256:child" {
		t.Fatalf("heads = %v, want [sha256:child]", heads)
	}

	// A second independent session contributes its own head; ProjectHeads spans both.
	other := rec("sha256:other", "s2")
	if _, _, err := p.PutRecord("proj", "k-other", other); err != nil {
		t.Fatalf("put other: %v", err)
	}

	ph, err := p.ProjectHeads("proj")
	if err != nil {
		t.Fatalf("project heads: %v", err)
	}
	// Byte-sorted ascending: "sha256:child" < "sha256:other".
	if len(ph) != 2 || ph[0] != "sha256:child" || ph[1] != "sha256:other" {
		t.Fatalf("project heads = %v, want [sha256:child sha256:other]", ph)
	}

	// Heads scoped to s1 must not include s2's head.
	if h1, _ := p.Heads("proj", "s1"); len(h1) != 1 || h1[0] != "sha256:child" {
		t.Fatalf("s1 heads = %v, want [sha256:child]", h1)
	}

	// Empty session/project return non-nil empty slices.
	if h, err := p.Heads("proj", "nope"); err != nil || h == nil || len(h) != 0 {
		t.Fatalf("empty heads = %v (nil=%v), err=%v; want non-nil empty", h, h == nil, err)
	}
}

func TestPostgresNextDisplaySeqMonotonic(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	for want := int64(0); want < 5; want++ {
		got, err := p.NextDisplaySeq("proj", "s1")
		if err != nil {
			t.Fatalf("next display seq: %v", err)
		}
		if got != want {
			t.Fatalf("display seq = %d, want %d", got, want)
		}
	}

	// A different session has its own independent counter starting at 0.
	if got, err := p.NextDisplaySeq("proj", "s2"); err != nil || got != 0 {
		t.Fatalf("s2 display seq = %d, %v; want 0", got, err)
	}
}

func TestPostgresCheckpointSeqAndLatest(t *testing.T) {
	p, done := newTestStore(t)
	defer done()

	// No checkpoints yet.
	if seq, err := p.NextCheckpointSeq("proj"); err != nil || seq != 0 {
		t.Fatalf("initial next seq = %d, %v; want 0", seq, err)
	}
	if _, ok, err := p.LatestCheckpointHash("proj"); err != nil || ok {
		t.Fatalf("initial latest: ok=%v err=%v; want ok=false", ok, err)
	}

	for i := int64(0); i < 3; i++ {
		seq, err := p.NextCheckpointSeq("proj")
		if err != nil {
			t.Fatalf("next seq: %v", err)
		}
		if seq != i {
			t.Fatalf("next seq = %d, want %d", seq, i)
		}
		cp := Checkpoint{
			JSON:           fmt.Sprintf(`{"seq":%d}`, seq),
			CheckpointHash: fmt.Sprintf("sha256:cp%d", seq),
			Seq:            seq,
		}
		if err := p.PutCheckpoint("proj", cp); err != nil {
			t.Fatalf("put checkpoint %d: %v", seq, err)
		}
	}

	cps, err := p.Checkpoints("proj")
	if err != nil {
		t.Fatalf("checkpoints: %v", err)
	}
	if len(cps) != 3 {
		t.Fatalf("got %d checkpoints, want 3", len(cps))
	}
	for i, cp := range cps {
		if cp.Seq != int64(i) {
			t.Fatalf("checkpoint[%d].Seq = %d, want %d (ordered ascending)", i, cp.Seq, i)
		}
	}

	hash, ok, err := p.LatestCheckpointHash("proj")
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v; want ok=true", ok, err)
	}
	if hash != "sha256:cp2" {
		t.Fatalf("latest hash = %q, want sha256:cp2", hash)
	}
}
