package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func runCLI(env map[string]string, args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, envOf(env), &out, &errb)
	return code, out.String(), errb.String()
}

// Usage and configuration errors need no database and exit 2.
func TestRunUsageErrorsExitTwo(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"modes are exclusive":         {map[string]string{"AVERIN_MIGRATION_DATABASE_URL": "x"}, []string{"--hook", "--init"}, "mutually exclusive"},
		"hook and check-runtime":      {nil, []string{"--hook", "--check-runtime"}, "mutually exclusive"},
		"hook needs both roles":       {map[string]string{"AVERIN_MIGRATION_DATABASE_URL": "x"}, []string{"--hook", "--old-runtime", "a"}, "together or not at all"},
		"init refuses cutover flags":  {map[string]string{"AVERIN_MIGRATION_DATABASE_URL": "x"}, []string{"--init", "--new-runtime", "b"}, "cannot combine"},
		"check-runtime refuses roles": {map[string]string{"AVERIN_DATABASE_URL": "x"}, []string{"--check-runtime", "--old-runtime", "a"}, "cannot combine"},
		"purge needs roles":           {map[string]string{"AVERIN_MIGRATION_DATABASE_URL": "x"}, []string{"--purge-legacy"}, "requires --old-runtime"},
		"migration dsn missing":       {nil, []string{"--hook"}, "AVERIN_MIGRATION_DATABASE_URL is required"},
		"check-runtime dsn missing":   {nil, []string{"--check-runtime"}, "AVERIN_DATABASE_URL"},
		"positional argument":         {nil, []string{"--hook", "extra"}, "positional"},
		"non-positive timeout":        {nil, []string{"--hook", "--timeout", "0s"}, "timeout must be positive"},
		"bad AVERIN_MIGRATE_TIMEOUT":  {map[string]string{"AVERIN_MIGRATE_TIMEOUT": "soon", "AVERIN_MIGRATION_DATABASE_URL": "x"}, []string{"--hook"}, "AVERIN_MIGRATE_TIMEOUT"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCLI(c.env, c.args...)
			if code != exitUsage || !strings.Contains(stderr, c.want) {
				t.Fatalf("code %d, stderr %q; want %d containing %q", code, stderr, exitUsage, c.want)
			}
		})
	}
	if code, _, _ := runCLI(nil, "--no-such-flag"); code != exitUsage {
		t.Fatalf("unknown flag: code %d, want %d", code, exitUsage)
	}
}

// scopedDatabase creates a private database holding a private schema and returns a DSN scoped to it,
// like the pgschema tests (set AVERIN_TEST_DATABASE_URL to run).
func scopedDatabase(t *testing.T) (dsn string, admin *pgxpool.Pool) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run the Postgres-backed averin-migrate tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	dbName, schema := fmt.Sprintf("averin_migrate_cmd_%d", suffix), fmt.Sprintf("averin_migrate_cmd_%d", suffix)
	if _, err := root.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		root.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + dbName
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	admin, err = pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Close()
		_, _ = root.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		root.Close()
	})
	return u.String(), admin
}

type hookLine struct {
	Plane   string `json:"plane"`
	Action  string `json:"action"`
	Before  int    `json:"schema_before"`
	After   int    `json:"schema_after"`
	Current int    `json:"schema_current"`
}

// --hook on an empty database initializes it and prints one JSON line; a rerun prints noop and exits 0.
func TestRunHookInitializesThenNoops(t *testing.T) {
	dsn, _ := scopedDatabase(t)
	env := map[string]string{"AVERIN_MIGRATION_DATABASE_URL": dsn}
	code, stdout, stderr := runCLI(env, "--hook")
	if code != exitOK {
		t.Fatalf("first run: code %d, stderr %q", code, stderr)
	}
	var l hookLine
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &l); err != nil {
		t.Fatalf("stdout is not one JSON line: %q (%v)", stdout, err)
	}
	if l.Plane != "averin" || l.Action != "initialized" || l.Before != 0 || l.After != l.Current || l.Current == 0 {
		t.Fatalf("first run = %+v", l)
	}
	code, stdout, stderr = runCLI(env, "--hook")
	if code != exitOK {
		t.Fatalf("rerun: code %d, stderr %q", code, stderr)
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(stdout)), &l)
	if l.Action != "noop" {
		t.Fatalf("rerun action = %q, want noop", l.Action)
	}
}

// --hook on a database that holds an unstamped legacy schema must not bootstrap over it: it prints
// cutover_required and exits 3 (a distinct status a Job can surface), changing nothing.
func TestRunHookExitsThreeWhenACutoverIsNeeded(t *testing.T) {
	dsn, admin := scopedDatabase(t)
	if _, err := admin.Exec(context.Background(), `CREATE TABLE records (id int)`); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(map[string]string{"AVERIN_MIGRATION_DATABASE_URL": dsn}, "--hook")
	if code != exitCutoverNeeded {
		t.Fatalf("code %d, stderr %q; want %d", code, stderr, exitCutoverNeeded)
	}
	var l hookLine
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &l); err != nil || l.Action != "cutover_required" {
		t.Fatalf("stdout %q (%v); want a cutover_required line", stdout, err)
	}
	if !strings.Contains(stderr, "maintenance cutover") {
		t.Fatalf("stderr = %q, want the cutover instruction", stderr)
	}
}

// --check-runtime refuses the migration (owner) credential: it owns every table, which the server
// would also refuse. It prints a JSON line with ok=false and exits 1.
func TestRunCheckRuntimeRefusesAnOwningCredential(t *testing.T) {
	dsn, _ := scopedDatabase(t)
	if code, _, stderr := runCLI(map[string]string{"AVERIN_MIGRATION_DATABASE_URL": dsn}, "--hook"); code != exitOK {
		t.Fatalf("setup: code %d, %q", code, stderr)
	}
	code, stdout, stderr := runCLI(map[string]string{"AVERIN_DATABASE_URL": dsn}, "--check-runtime")
	if code != exitFailed {
		t.Fatalf("code %d, stderr %q; want %d", code, stderr, exitFailed)
	}
	var l struct {
		Action string `json:"action"`
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &l); err != nil || l.Action != runtimeCheckAction || l.OK || l.Error == "" {
		t.Fatalf("stdout %q (%v)", stdout, err)
	}
}
