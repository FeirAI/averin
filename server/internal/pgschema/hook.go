package pgschema

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Hook actions reported by Hook (and printed by `averin-migrate --hook`).
const (
	// HookInitialized: the database was empty and this run bootstrapped it at CurrentSchemaVersion.
	HookInitialized = "initialized"
	// HookNoop: the database was already at CurrentSchemaVersion; nothing was changed. A rerun, a
	// retried Job and a concurrent run that lost the lock all report this.
	HookNoop = "noop"
	// HookCutover: an existing database was advanced to CurrentSchemaVersion through the validated
	// maintenance cutover (retired old writers, distinct new runtime role).
	HookCutover = "cutover"
	// HookCutoverRequired: the database is behind this binary (or an unstamped legacy schema) and the
	// run was not given the cutover roles. Nothing was changed. This is the one state a hook must NOT
	// resolve on its own: an advancing step needs every old writer retired first.
	HookCutoverRequired = "cutover_required"
)

// ErrCutoverRequired is returned by Hook with HookCutoverRequired so a caller can map it to a
// distinct exit status.
var ErrCutoverRequired = errors.New("pgschema: the database is behind this binary and needs the explicit maintenance cutover (--old-runtime and --new-runtime); stop and retire every old writer first")

// State is the read-only view of a database a hook branches on.
type State struct {
	// Stored is the highest stamped schema version (0 for an empty or unstamped database).
	Stored int
	// HasLedger is whether the schema_migrations table exists.
	HasLedger bool
	// HasTables is whether the current schema holds any table at all.
	HasTables bool
}

// Fresh reports a truly empty database: no ledger and no tables, the only state ordinary
// initialization may bootstrap.
func (s State) Fresh() bool { return !s.HasLedger && !s.HasTables }

// Inspect reads a database's schema state with SELECTs only: no DDL, no advisory lock. A hook uses
// it to choose a path; the path itself (Initialize or CutoverReport) re-reads the state under the
// advisory lock, so a race between Inspect and the action is resolved there, never here.
func Inspect(ctx context.Context, dsn string) (State, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return State{}, fmt.Errorf("pgschema: connect: %w", err)
	}
	defer pool.Close()
	var st State
	if err := pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&st.HasLedger); err != nil {
		return State{}, fmt.Errorf("pgschema: probe schema_migrations: %w", err)
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=current_schema() AND c.relkind IN ('r','p'))`).Scan(&st.HasTables); err != nil {
		return State{}, fmt.Errorf("pgschema: probe existing tables: %w", err)
	}
	if st.HasLedger {
		if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&st.Stored); err != nil {
			return State{}, fmt.Errorf("pgschema: read version: %w", err)
		}
	}
	return st, nil
}

// HookResult is what one hook run did, printed as one JSON line by `averin-migrate --hook`.
type HookResult struct {
	Plane   string `json:"plane"`
	Action  string `json:"action"`
	Before  int    `json:"schema_before"`
	After   int    `json:"schema_after"`
	Current int    `json:"schema_current"`
}

// Hook is the body of `averin-migrate --hook`, the pre-upgrade Job. It is idempotent and safe to
// run concurrently with itself and with booting servers, because every state change goes through
// the advisory-lock transaction in migrate:
//
//   - empty database: bootstrap it (HookInitialized, or HookNoop when a concurrent run got there
//     first, reported by Initialize);
//   - at CurrentSchemaVersion: change nothing (HookNoop);
//   - behind (or an unstamped legacy schema): advance it ONLY when both cutover roles are given,
//     through Cutover's validated barrier (HookCutover); without them change nothing and return
//     ErrCutoverRequired with HookCutoverRequired;
//   - ahead of this binary: refuse (the downgrade guard in migrate), nothing changed.
//
// The returned HookResult is meaningful even alongside an error (Action says what was decided).
func Hook(ctx context.Context, dsn string, oldRoles []string, newRole string) (HookResult, error) {
	res := HookResult{Plane: "averin", Current: CurrentSchemaVersion}
	st, err := Inspect(ctx, dsn)
	if err != nil {
		return res, err
	}
	res.Before, res.After = st.Stored, st.Stored
	switch {
	case st.Stored > CurrentSchemaVersion:
		// migrate re-reads under the lock and refuses with the downgrade message.
		_, err := Initialize(ctx, dsn)
		return res, err
	case st.Fresh():
		initialized, err := Initialize(ctx, dsn)
		if err != nil {
			return res, err
		}
		res.After = CurrentSchemaVersion
		res.Action = HookNoop
		if initialized {
			res.Action = HookInitialized
		}
		return res, nil
	case st.Stored == CurrentSchemaVersion:
		res.Action = HookNoop
		return res, nil
	}
	// Behind, or unstamped legacy tables.
	if len(oldRoles) == 0 || newRole == "" {
		res.Action = HookCutoverRequired
		return res, ErrCutoverRequired
	}
	applied, err := CutoverReport(ctx, dsn, oldRoles, newRole)
	if err != nil {
		return res, err
	}
	res.After = CurrentSchemaVersion
	res.Action = HookNoop
	if applied {
		res.Action = HookCutover
	}
	return res, nil
}

// CutoverReport is Cutover reporting whether it advanced the schema (false: a concurrent run had
// already brought the database to the current version, so this one was a no-op).
func CutoverReport(ctx context.Context, dsn string, oldRoles []string, newRole string) (applied bool, err error) {
	if len(oldRoles) == 0 || newRole == "" {
		return false, fmt.Errorf("pgschema: cutover requires old runtime roles and a new runtime role")
	}
	err = migrate(ctx, dsn, &cutoverRoles{old: oldRoles, next: newRole}, false, &applied)
	return applied, err
}
