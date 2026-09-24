package pgschema

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedV6 builds a stamped v6 database carrying every kind of pre-v7 revocation: a boolean
// revocation, a plan 008 void marker and a signed grant_void tombstone committed without a marker.
func seedV6(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for v := 1; v <= 6; v++ {
		if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
			t.Fatalf("apply v%d: %v", v, err)
		}
	}
	for _, sql := range []string{
		`CREATE TABLE schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`,
		`INSERT INTO schema_migrations(version) VALUES (1),(2),(3),(4),(5),(6)`,
		`INSERT INTO project_write_guard(project_id) VALUES ('p1')`,
		`INSERT INTO revocations(project_id, grant_id) VALUES ('p1','boolean-grant')`,
		`INSERT INTO broker_seq(project_id, seq, grant_id) VALUES ('p1', 1, 'voided-grant')`,
		`INSERT INTO broker_seq_void(project_id, grant_id, seq) VALUES ('p1','voided-grant',1)`,
		`INSERT INTO records(project_id, idempotency_key, content_hash, session_id, json) VALUES
			('p1','grant-void:2','sha256:tomb','s','{"record_id":"tombstone-grant","extensions":{"broker":{"kind":"grant_void"}}}')`,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("seed v6: %s: %v", sql, err)
		}
	}
}

func retiredRoles(t *testing.T, admin *pgxpool.Pool) (old, next string, drop func()) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next = "averin_v6_"+suffix, "averin_v7_"+suffix
	for _, sql := range []string{"CREATE ROLE " + old + " NOLOGIN", "CREATE ROLE " + next + " LOGIN"} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	return old, next, func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+old)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
	}
}

// TestTemporalRevocationCutoverFromV6 requires a fresh validated maintenance barrier for v7 even
// though v6 was already cut over, migrates every pre-v7 revocation as total, retires the boolean
// table without a compatibility bridge, keeps 0006's legacy-exclusion time, and makes the new
// state immutable and the authorization order monotonic.
func TestTemporalRevocationCutoverFromV6(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	seedV6(t, admin)
	var holdBefore time.Time
	if err := admin.QueryRow(ctx, `SELECT legacy_exclusion_until FROM nonce_ledger_cutover WHERE singleton`).Scan(&holdBefore); err != nil {
		t.Fatal(err)
	}
	oldConn, err := pgx.Connect(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	defer oldConn.Close(context.Background())
	if _, err := oldConn.Prepare(ctx, "old-revoke", `INSERT INTO revocations(project_id, grant_id) VALUES ('p1','late-boolean')`); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(ctx, scoped); err == nil || !strings.Contains(err.Error(), "maintenance cutover to v7") {
		t.Fatalf("ordinary startup advanced a v6 schema without a barrier: %v", err)
	}
	if maxVersion(t, admin) != 6 {
		t.Fatal("refused startup changed the schema version")
	}
	// The barrier is re-validated for v7: a LOGIN old runtime is refused.
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	live, next := "averin_v6_live_"+suffix, "averin_v7_next_"+suffix
	for _, sql := range []string{"CREATE ROLE " + live + " LOGIN PASSWORD 'temporary-test-only'", "CREATE ROLE " + next + " LOGIN"} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+live)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
	}()
	if err := Cutover(ctx, scoped, []string{live}, next); err == nil || !strings.Contains(err.Error(), "NOLOGIN") {
		t.Fatalf("v7 cutover accepted a LOGIN old runtime: %v", err)
	}
	cfg, err := pgx.ParseConfig(scoped)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = live, "temporary-test-only"
	liveConn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+live+" NOLOGIN PASSWORD 'rotated-unusable'"); err != nil {
		t.Fatal(err)
	}
	if err := Cutover(ctx, scoped, []string{live}, next); err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("an established v6 session did not block the v7 cutover: %v", err)
	}
	if maxVersion(t, admin) != 6 || regExists(t, admin, "revocation_events") {
		t.Fatal("refused v7 cutover changed the schema")
	}
	if err := liveConn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := Cutover(ctx, scoped, []string{live}, next); err != nil {
		t.Fatalf("authorized v7 cutover: %v", err)
	}
	if maxVersion(t, admin) != 7 || regExists(t, admin, "revocations") {
		t.Fatal("v7 cutover did not advance or left the boolean relation writable by name")
	}

	rows, err := admin.Query(ctx, `SELECT grant_id, mode, cutoff_order IS NULL, reason FROM revocation_events WHERE project_id='p1' ORDER BY grant_id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var gid, mode, reason string
		var noCutoff bool
		if err := rows.Scan(&gid, &mode, &noCutoff, &reason); err != nil {
			t.Fatal(err)
		}
		if mode != "total" || !noCutoff {
			t.Fatalf("pre-v7 revocation %s migrated as %s (no cutoff=%v)", gid, mode, noCutoff)
		}
		got = append(got, gid+":"+reason)
	}
	rows.Close()
	want := "boolean-grant:legacy_boolean_revocation,tombstone-grant:grant_void_tombstone,voided-grant:broker_seq_void"
	if strings.Join(got, ",") != want {
		t.Fatalf("migrated events = %v, want %s", got, want)
	}

	var holdAfter time.Time
	if err := admin.QueryRow(ctx, `SELECT legacy_exclusion_until FROM nonce_ledger_cutover WHERE singleton`).Scan(&holdAfter); err != nil || !holdAfter.Equal(holdBefore) {
		t.Fatalf("v7 reset 0006's legacy-exclusion time: before=%v after=%v err=%v", holdBefore, holdAfter, err)
	}
	var order int64
	if err := admin.QueryRow(ctx, `SELECT authorization_order FROM project_write_guard WHERE project_id='p1'`).Scan(&order); err != nil || order != 0 {
		t.Fatalf("existing guard row order=%d err=%v", order, err)
	}
	for _, sql := range []string{
		// No compatibility bridge: an old boolean writer fails instead of silently landing.
		`INSERT INTO revocations(project_id, grant_id) VALUES ('p1','late-boolean')`,
		`INSERT INTO legacy_boolean_revocations(project_id, grant_id) VALUES ('p1','late-boolean')`,
		`DELETE FROM legacy_boolean_revocations`,
		`UPDATE revocation_events SET mode='prospective', cutoff_order=1 WHERE grant_id='boolean-grant'`,
		`DELETE FROM revocation_events`,
		`TRUNCATE revocation_events`,
		`INSERT INTO revocation_events(project_id, grant_id, format, mode, issuer, reason) VALUES ('p1','boolean-grant','averin.revocation.event.v1','total','x','dup')`,
		`INSERT INTO revocation_events(project_id, grant_id, format, mode, issuer, reason) VALUES ('p1','g','averin.revocation.event.v1','prospective','x','no cutoff')`,
		`INSERT INTO revocation_events(project_id, grant_id, format, mode, cutoff_order, issuer, reason) VALUES ('p1','g','averin.revocation.event.v1','total',3,'x','cutoff on total')`,
		`UPDATE project_write_guard SET authorization_order = authorization_order - 1 WHERE project_id='p1'`,
		`DELETE FROM project_write_guard WHERE project_id='p1'`,
		`TRUNCATE project_write_guard`,
	} {
		if _, err := admin.Exec(ctx, sql); err == nil {
			t.Fatalf("v7 accepted: %s", sql)
		}
	}
	if _, err := oldConn.Exec(ctx, `EXECUTE "old-revoke"`); err == nil {
		t.Fatal("an old prepared boolean revocation still lands after v7")
	}
	var ordinal int64
	if err := admin.QueryRow(ctx, `UPDATE project_write_guard SET authorization_order = authorization_order + 1 WHERE project_id='p1' RETURNING authorization_order`).Scan(&ordinal); err != nil || ordinal != 1 {
		t.Fatalf("authorization order does not advance: %d %v", ordinal, err)
	}
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatalf("steady-state startup after v7: %v", err)
	}
}

// TestTemporalRevocationCutoverInterruptedRollsBackAndRetries forces the real v7 cutover to fail
// mid-step and proves schema, version and data roll back, then an authorized retry applies once.
func TestTemporalRevocationCutoverInterruptedRollsBackAndRetries(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	seedV6(t, admin)
	// A test-owned function conflicts with v7's second CREATE FUNCTION, after the step has already
	// added the guard column and its first trigger.
	if _, err := admin.Exec(ctx, `CREATE FUNCTION temporal_revocation_reject_mutation() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$`); err != nil {
		t.Fatal(err)
	}
	old, next, drop := retiredRoles(t, admin)
	defer drop()
	if err := Cutover(ctx, scoped, []string{old}, next); err == nil || !strings.Contains(err.Error(), "apply step v7") {
		t.Fatalf("conflicting function did not abort the real v7 cutover: %v", err)
	}
	var column int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='project_write_guard' AND column_name='authorization_order'`).Scan(&column); err != nil {
		t.Fatal(err)
	}
	if maxVersion(t, admin) != 6 || column != 0 || !regExists(t, admin, "revocations") ||
		regExists(t, admin, "revocation_events") || regExists(t, admin, "authorization_receipts") {
		t.Fatal("interrupted v7 cutover leaked schema, version or a renamed relation")
	}
	var boolean int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM revocations WHERE grant_id='boolean-grant'`).Scan(&boolean); err != nil || boolean != 1 {
		t.Fatalf("interrupted cutover lost the boolean revocation: %d %v", boolean, err)
	}
	if _, err := admin.Exec(ctx, `DROP FUNCTION temporal_revocation_reject_mutation()`); err != nil {
		t.Fatal(err)
	}
	if err := Cutover(ctx, scoped, []string{old}, next); err != nil {
		t.Fatalf("retry cutover: %v", err)
	}
	var stamped, events int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=7`).Scan(&stamped); err != nil || stamped != 1 {
		t.Fatalf("retry stamped v7 %d times: %v", stamped, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM revocation_events`).Scan(&events); err != nil || events != 3 {
		t.Fatalf("retry migrated %d events: %v", events, err)
	}
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM revocation_events`).Scan(&events); err != nil || events != 3 {
		t.Fatalf("steady-state startup re-migrated events: %d %v", events, err)
	}
}
