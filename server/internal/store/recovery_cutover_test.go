package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestBrokerSeqRecoveryOldRuntimeCredentialCutoff proves the migration barrier
// against a real previously-established connection. NOLOGIN alone cannot stop
// that session; revocation plus backend termination and credential rotation do.
func TestBrokerSeqRecoveryOldRuntimeCredentialCutoff(t *testing.T) {
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL for real Postgres cutover")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	schema, oldRole, newRole := "averin_cutover_"+suffix, "averin_old_"+suffix, "averin_new_"+suffix
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	oldPassword := hex.EncodeToString(secret)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	newPassword := hex.EncodeToString(secret)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	scopedDSN := base + "&search_path=" + schema
	if err := pgschema.Migrate(ctx, scopedDSN); err != nil {
		t.Fatalf("migrate actual Averin schema: %v", err)
	}
	create := []string{
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", oldRole, oldPassword),
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", newRole, newPassword),
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s,%s", schema, oldRole, newRole),
		fmt.Sprintf("GRANT SELECT,INSERT ON %s.project_write_guard,%s.broker_seq,%s.broker_seq_void,%s.records,%s.broker_seq_recovery_fence,%s.broker_seq_recovery_result TO %s,%s", schema, schema, schema, schema, schema, schema, oldRole, newRole),
		fmt.Sprintf("GRANT UPDATE ON %s.project_write_guard TO %s,%s", schema, oldRole, newRole),
	}
	for _, sql := range create {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		clean, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		_, _ = admin.Exec(clean, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		_, _ = admin.Exec(clean, "DROP OWNED BY "+oldRole+","+newRole)
		_, _ = admin.Exec(clean, "DROP ROLE IF EXISTS "+oldRole)
		_, _ = admin.Exec(clean, "DROP ROLE IF EXISTS "+newRole)
	}()
	connect := func(role, password string) (*pgx.Conn, error) {
		cfg, e := pgx.ParseConfig(base)
		if e != nil {
			return nil, e
		}
		cfg.User, cfg.Password = role, password
		cfg.RuntimeParams["search_path"] = schema
		return pgx.ConnectConfig(ctx, cfg)
	}
	old, err := connect(oldRole, oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close(context.Background())
	if _, err := old.Exec(ctx, "INSERT INTO broker_seq(project_id,grant_id,seq) VALUES ('old-project','old-before',1)"); err != nil {
		t.Fatalf("old runtime initially unable to write: %v", err)
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+oldRole+" NOLOGIN PASSWORD 'rotated-unusable'"); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, "INSERT INTO broker_seq(project_id,grant_id,seq) VALUES ('old-project','old-after-nologin',2)"); err != nil {
		t.Fatalf("NOLOGIN unexpectedly killed established session: %v", err)
	}
	var prepared int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_prepared_xacts WHERE owner=$1`, oldRole).Scan(&prepared); err != nil {
		t.Fatal(err)
	}
	if prepared != 0 {
		t.Fatalf("old runtime has %d unresolved prepared transactions; cutover must resolve them", prepared)
	}
	for _, sql := range []string{
		fmt.Sprintf("REVOKE ALL ON ALL TABLES IN SCHEMA %s FROM %s", schema, oldRole),
		fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM %s", schema, oldRole),
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()`, oldRole); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, "INSERT INTO broker_seq(project_id,grant_id,seq) VALUES ('old-project','old-after-cutoff',3)"); err == nil {
		t.Fatal("terminated old session could still write")
	}
	if stale, err := connect(oldRole, oldPassword); err == nil {
		stale.Close(context.Background())
		t.Fatal("old runtime credential could reconnect")
	}
	newConn, err := connect(newRole, newPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer newConn.Close(context.Background())
	roleCfg, err := pgxpool.ParseConfig(scopedDSN)
	if err != nil {
		t.Fatal(err)
	}
	roleCfg.ConnConfig.User, roleCfg.ConnConfig.Password = newRole, newPassword
	rolePool, err := pgxpool.NewWithConfig(ctx, roleCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rolePool.Close()
	actualNew := &Postgres{pool: rolePool}
	if err := actualNew.WithProjectWrite(ctx, "p", func(st Store) error {
		seq, _, e := st.AllocateBrokerSeq("p", "g1")
		if e != nil || seq != 1 {
			return fmt.Errorf("new guarded allocation seq=%d: %w", seq, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := actualNew.WithProjectWrite(ctx, "p", func(st Store) error {
		_, _, e := st.PutRecoveryFence(RecoveryFence{ProjectID: "p", Seq: 1, GrantID: "g1", Generation: 1, OperationID: "cutover", ActorID: "operator", SessionID: "recovery", Reason: "abandoned", RequestDigest: "digest"})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := actualNew.WithProjectWrite(ctx, "p", func(st Store) error {
		if _, _, e := st.AllocateBrokerSeq("p", "g1"); !errors.Is(e, ErrRecoveryFenced) {
			return fmt.Errorf("fenced allocation: %v", e)
		}
		seq, _, e := st.AllocateBrokerSeq("p", "g2")
		if e != nil || seq != 2 {
			return fmt.Errorf("new allocation seq=%d: %w", seq, e)
		}
		_, _, e = st.PutRecord("p", "new-grant", Record{JSON: `{"project_id":"p","record_id":"g2"}`, ContentHash: "new-record", SessionID: "s"})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"broker_seq_recovery_fence", "broker_seq_recovery_result"} {
		if _, err := newConn.Exec(ctx, "UPDATE "+table+" SET generation=2 WHERE project_id='p'"); err == nil {
			t.Fatalf("runtime role updated immutable %s", table)
		}
		if _, err := newConn.Exec(ctx, "DELETE FROM "+table+" WHERE project_id='p'"); err == nil {
			t.Fatalf("runtime role deleted immutable %s", table)
		}
	}
	var oldWrites int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+schema+".broker_seq WHERE project_id='old-project'").Scan(&oldWrites); err != nil {
		t.Fatal(err)
	}
	if oldWrites != 2 {
		t.Fatalf("old writes after cutoff = %d, want only pre-cutoff writes", oldWrites)
	}
}
