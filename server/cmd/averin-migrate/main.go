// Command averin-migrate performs the selected, offline schema cutover. The
// operator drains old workers, retires their DB identities, and provisions a
// distinct new runtime identity before invoking this command.
//
// Modes (exactly one):
//
//	--init           bootstrap only a truly empty database (idempotent: a no-op at the current version)
//	--hook           the pre-upgrade Job: initialize an empty database, change nothing at the current
//	                 version, advance an older one only when --old-runtime and --new-runtime are given,
//	                 and print one JSON status line (see pgschema.Hook); exit 3 when a cutover is needed
//	--check-runtime  verify AVERIN_DATABASE_URL (the RUNTIME role) is a least-privilege identity the
//	                 server would accept (pgschema.CheckRuntime) and print one JSON status line
//	--purge-legacy   remove aged legacy exclusions after the database-time hold
//	(none)           the explicit maintenance cutover (--old-runtime and --new-runtime)
//
// Every state change runs under pgschema's advisory-lock transaction, so a rerun, a retried Job and a
// concurrent run are safe: one applies, the others see the finished version.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/pgschema"
)

// defaultTimeout bounds one migration run. Cutover steps rewrite every historical row they migrate in one
// transaction (e.g. v7 backfills revocation events from records), so large histories may need more.
const defaultTimeout = 90 * time.Second

// Exit statuses. 0 success, 1 failure (the database or a check refused), 2 usage or configuration, 3 the
// database needs the explicit maintenance cutover and --hook was not given the roles (nothing changed).
const (
	exitOK             = 0
	exitFailed         = 1
	exitUsage          = 2
	exitCutoverNeeded  = 3
	runtimeCheckAction = "runtime_checked"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("averin-migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	old := fs.String("old-runtime", "", "comma-separated retired old runtime database roles")
	next := fs.String("new-runtime", "", "distinct new runtime database role")
	purge := fs.Bool("purge-legacy", false, "remove aged legacy exclusions after the database-time hold")
	init := fs.Bool("init", false, "bootstrap only a truly empty database with the migration credential")
	hook := fs.Bool("hook", false, "pre-upgrade Job mode: idempotent initialize/no-op, cutover only with --old-runtime and --new-runtime, one JSON status line, exit 3 when a cutover is needed")
	checkRuntime := fs.Bool("check-runtime", false, "verify AVERIN_DATABASE_URL (the runtime role) is a least-privilege identity the server would accept")
	timeout := fs.Duration("timeout", defaultTimeout, "overall deadline for the selected operation; raise it for large histories (env AVERIN_MIGRATE_TIMEOUT)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	timeoutSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "timeout" {
			timeoutSet = true
		}
	})
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "averin-migrate: "+format+"\n", a...)
		return code
	}
	if !timeoutSet {
		if raw := strings.TrimSpace(getenv("AVERIN_MIGRATE_TIMEOUT")); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fail(exitUsage, "AVERIN_MIGRATE_TIMEOUT: %v", err)
			}
			*timeout = d
		}
	}
	if *timeout <= 0 {
		return fail(exitUsage, "timeout must be positive")
	}
	if fs.NArg() != 0 {
		return fail(exitUsage, "unexpected positional arguments")
	}
	modes := 0
	for _, m := range []bool{*init, *hook, *checkRuntime, *purge} {
		if m {
			modes++
		}
	}
	if modes > 1 {
		return fail(exitUsage, "--init, --hook, --check-runtime and --purge-legacy are mutually exclusive")
	}
	var oldRoles []string
	for _, role := range strings.Split(*old, ",") {
		if role == "" {
			continue
		}
		oldRoles = append(oldRoles, strings.TrimSpace(role))
	}
	newRole := strings.TrimSpace(*next)
	if (*init || *checkRuntime) && (*old != "" || *next != "") {
		return fail(exitUsage, "--init and --check-runtime cannot combine with cutover flags")
	}
	if *hook && ((*old == "") != (*next == "")) {
		return fail(exitUsage, "--hook takes --old-runtime and --new-runtime together or not at all")
	}
	if *purge && (len(oldRoles) == 0 || newRole == "") {
		return fail(exitUsage, "--purge-legacy requires --old-runtime and --new-runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *checkRuntime {
		dsn := getenv("AVERIN_DATABASE_URL")
		if dsn == "" {
			return fail(exitUsage, "AVERIN_DATABASE_URL (the runtime role's DSN) is required for --check-runtime")
		}
		if err := pgschema.CheckRuntime(ctx, dsn); err != nil {
			printJSON(stdout, map[string]any{"plane": "averin", "action": runtimeCheckAction, "ok": false, "error": err.Error()})
			return fail(exitFailed, "runtime credential check refused: %v", err)
		}
		printJSON(stdout, map[string]any{"plane": "averin", "action": runtimeCheckAction, "ok": true, "schema_current": pgschema.CurrentSchemaVersion})
		return exitOK
	}

	dsn := getenv("AVERIN_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return fail(exitUsage, "AVERIN_MIGRATION_DATABASE_URL is required")
	}
	switch {
	case *hook:
		res, err := pgschema.Hook(ctx, dsn, oldRoles, newRole)
		if res.Action != "" {
			printJSON(stdout, res)
		}
		switch {
		case err == nil:
			return exitOK
		case errors.Is(err, pgschema.ErrCutoverRequired):
			return fail(exitCutoverNeeded, "%v", err)
		default:
			return fail(exitFailed, "hook refused: %v", err)
		}
	case *init:
		initialized, err := pgschema.Initialize(ctx, dsn)
		if err != nil {
			return fail(exitFailed, "fresh initialization refused: %v", err)
		}
		if !initialized {
			fmt.Fprintf(stderr, "averin-migrate: already initialized at version %d; no-op\n", pgschema.CurrentSchemaVersion)
			return exitOK
		}
		fmt.Fprintf(stderr, "averin-migrate: fresh database initialized at version %d; grant new least-privilege runtime access before starting the server\n", pgschema.CurrentSchemaVersion)
		return exitOK
	case *purge:
		n, err := pgschema.PurgeLegacy(ctx, dsn, oldRoles, newRole)
		if err != nil {
			return fail(exitFailed, "purge refused: %v", err)
		}
		fmt.Fprintf(stderr, "averin-migrate: removed %d expired legacy exclusions\n", n)
		return exitOK
	}
	if err := pgschema.Cutover(ctx, dsn, oldRoles, newRole); err != nil {
		return fail(exitFailed, "cutover refused: %v", err)
	}
	fmt.Fprintf(stderr, "averin-migrate: schema at version %d; verify new-runtime readiness before reopening traffic\n", pgschema.CurrentSchemaVersion)
	return exitOK
}

func printJSON(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintln(w, string(b))
}
