package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
	create := []string{
		"CREATE SCHEMA " + schema,
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", oldRole, oldPassword),
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", newRole, newPassword),
		"CREATE TABLE " + schema + ".cutover_probe (n integer)",
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s,%s", schema, oldRole, newRole),
		fmt.Sprintf("GRANT INSERT ON %s.cutover_probe TO %s,%s", schema, oldRole, newRole),
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
	if _, err := old.Exec(ctx, "INSERT INTO cutover_probe VALUES (1)"); err != nil {
		t.Fatalf("old runtime initially unable to write: %v", err)
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+oldRole+" NOLOGIN PASSWORD 'rotated-unusable'"); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, "INSERT INTO cutover_probe VALUES (2)"); err != nil {
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
		fmt.Sprintf("REVOKE ALL ON %s.cutover_probe FROM %s", schema, oldRole),
		fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM %s", schema, oldRole),
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()`, oldRole); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, "INSERT INTO cutover_probe VALUES (3)"); err == nil {
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
	if _, err := newConn.Exec(ctx, "INSERT INTO cutover_probe VALUES (4)"); err != nil {
		t.Fatalf("new runtime could not write after cutoff: %v", err)
	}
	var values string
	if err := admin.QueryRow(ctx, "SELECT string_agg(n::text, ',' ORDER BY n) FROM "+schema+".cutover_probe").Scan(&values); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(values) != "1,2,4" {
		t.Fatalf("cutover writes = %q", values)
	}
}
