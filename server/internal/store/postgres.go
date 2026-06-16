package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is a production, append-only Store backed by Postgres (via pgxpool). It satisfies the
// same Store interface as Mem and matches its semantics exactly: idempotency and content-hash
// collapse on PutRecord (threat #8), heads/frontier derived from the DAG (never trusted from the
// client), and a per-(project, session) monotonic display counter.
//
// The schema (migrations/0001_init.sql) REVOKEs UPDATE/DELETE on the history tables from the
// application role, so integrity does not rely on application correctness — the database itself
// rejects mutation. See that file for the append-only rationale.
type Postgres struct {
	pool *pgxpool.Pool
}

// compile-time assertion that *Postgres implements Store.
var _ Store = (*Postgres)(nil)

// NewPostgres connects to dsn and returns a ready Postgres store. The caller owns the lifecycle and
// must call Close. dsn is a standard libpq/pgx connection string (e.g. "postgres://user:pw@host/db").
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	// The Store interface carries no per-call context, so bound every statement at the database: a
	// blocked/hung query (lock contention, a stalled peer) then aborts after the timeout instead of
	// pinning a request goroutine and a pool connection forever. Operator-set value in the DSN wins.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if _, set := cfg.ConnConfig.RuntimeParams["statement_timeout"]; !set {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000" // 30s, in ms
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	// Fail fast if the DSN is bad rather than surfacing it on first query.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases the underlying connection pool. Safe to call once.
func (p *Postgres) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// Migrate applies the schema SQL (migrations.Schema). The schema is idempotent (CREATE ... IF NOT
// EXISTS), so this is safe to call on every startup. NOTE: the migration's append-only REVOKE only
// constrains a non-owner, non-superuser role; when the server connects as the role that owns the
// tables (e.g. auto-migrate in single-credential self-host), the REVOKE is a no-op and the migration
// RAISE NOTICEs — see the migration header. For DB-enforced append-only, run migrations as a
// privileged role and the server as a separate least-privilege role.
func (p *Postgres) Migrate(ctx context.Context, schemaSQL string) error {
	if _, err := p.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// background returns a context for the internal queries. The Store interface predates context
// plumbing; we use context.Background so the implementation stays drop-in compatible with Mem. Query
// runtime is bounded by the connection-level statement_timeout set in NewPostgres.
func background() context.Context { return context.Background() }

// PutRecord stores rec under idemKey, idempotently and safely under concurrent callers.
//
// Semantics matched to Mem:
//   - If idemKey was already used for this project, return the stored row, created=false.
//   - Otherwise, if the content_hash already exists (identical sealed bytes), collapse to that row,
//     return it with created=false (and bind idemKey to it for future retries).
//   - Otherwise insert and return rec, created=true.
//
// Concurrency: we never read-then-write. A single INSERT ... ON CONFLICT DO NOTHING claims the row
// atomically; "created" is decided by whether THAT insert produced a row (RETURNING) — so two racing
// callers with the same key see exactly one created=true, the other created=false.
func (p *Postgres) PutRecord(projectID, idemKey string, rec Record) (Record, bool, error) {
	ctx := background()

	// parents is `NOT NULL DEFAULT '{}'`. A nil slice binds as SQL NULL (not an omitted column, so
	// the DEFAULT does not apply) and violates the constraint — root records (no causal parents)
	// would fail to insert. Normalize to an empty array.
	parents := rec.Parents
	if parents == nil {
		parents = []string{}
	}

	// One transaction so the post-conflict lookup sees a consistent view with the insert attempt.
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Record{}, false, fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after a successful commit is a no-op.

	// Fast path: a prior insert already used this idempotency key -> return that row verbatim.
	if idemKey != "" {
		existing, ok, err := selectByIdem(ctx, tx, projectID, idemKey)
		if err != nil {
			return Record{}, false, err
		}
		if ok {
			if err := tx.Commit(ctx); err != nil {
				return Record{}, false, fmt.Errorf("store: commit: %w", err)
			}
			return existing, false, nil
		}
	}

	// Attempt the insert. ON CONFLICT DO NOTHING (no target) covers BOTH unique indexes
	// (idempotency_key and content_hash) and suppresses the unique_violation, so a conflict yields
	// pgx.ErrNoRows rather than an error; a RETURNING row means this statement actually inserted —
	// our authoritative "created" signal under concurrency.
	var inserted bool
	err = tx.QueryRow(ctx, `
		INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT DO NOTHING
		RETURNING true
	`, projectID, idemKey, rec.ContentHash, rec.SessionID, parents, rec.JSON).Scan(&inserted)
	switch {
	case err == nil:
		// Inserted a fresh row. Persist its disclosure secrets in the SAME transaction so a committed
		// field can never end up durably sealed with no way to disclose it (atomic with the record).
		if err := insertDisclosures(ctx, tx, projectID, rec.Disclosures); err != nil {
			return Record{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			// The ONLY commit-AMBIGUOUS path: a fresh record was inserted and this commit's outcome is unknown,
			// so the record may or may not be durable. Flag it so a caller that consumed an irreversible
			// resource does NOT roll back here. Every other error above (begin/select/insert/disclosure) and
			// the read-only/collapse commits below write NO new row, so they stay plain — safe to roll back.
			return Record{}, false, fmt.Errorf("%w: %v", ErrCommitAmbiguous, err)
		}
		return rec, true, nil
	case errors.Is(err, pgx.ErrNoRows):
		// No row returned => a conflict on idempotency_key or content_hash. Fall through to collapse.
	default:
		return Record{}, false, fmt.Errorf("store: insert record: %w", err)
	}

	// Collapse: the conflict was either on idempotency_key (a concurrent caller raced us with the
	// same key) or on content_hash (identical sealed bytes already stored — threat #8). Resolve to
	// the canonical existing row. We deliberately do NOT bind idemKey onto the existing row: `records`
	// is append-only (the schema REVOKEs UPDATE), and a later retry with the same key simply collapses
	// on content_hash to the same row again, so the binding would buy nothing but a forbidden mutation.
	if idemKey != "" {
		if existing, ok, err := selectByIdem(ctx, tx, projectID, idemKey); err != nil {
			return Record{}, false, err
		} else if ok {
			if err := tx.Commit(ctx); err != nil {
				return Record{}, false, fmt.Errorf("store: commit: %w", err)
			}
			return existing, false, nil
		}
	}
	existing, ok, err := selectByContentHash(ctx, tx, projectID, rec.ContentHash)
	if err != nil {
		return Record{}, false, err
	}
	if !ok {
		// Should not happen: ON CONFLICT waits for the racing tx to finish, so the conflicting row is
		// committed and visible by now. Surface it rather than silently returning a zero Record.
		return Record{}, false, fmt.Errorf("store: put record: conflict with no resolvable row")
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, false, fmt.Errorf("store: commit: %w", err)
	}
	return existing, false, nil
}

// ReleaseBrokerSeq deletes the (project, grant) row so a failed-after-allocation grant's seq is freed;
// the next AllocateBrokerSeq's MAX(seq)+1 reuses it. Append-only is not violated: a broker_seq row that
// never had a committed grant is rolled back, not a recorded one mutated. Called under the api ingest
// lock, so no concurrent allocation observes the gap.
func (p *Postgres) ReleaseBrokerSeq(projectID, grantID string) error {
	ctx := background()
	if _, err := p.pool.Exec(ctx, `DELETE FROM broker_seq WHERE project_id = $1 AND grant_id = $2`, projectID, grantID); err != nil {
		return fmt.Errorf("store: release broker seq: %w", err)
	}
	return nil
}

func (p *Postgres) RecordByIdem(projectID, idemKey string) (Record, bool, error) {
	ctx := background()
	row := p.pool.QueryRow(ctx, `
		SELECT json, content_hash, session_id, parents
		FROM records WHERE project_id = $1 AND idempotency_key = $2
	`, projectID, idemKey)
	var rec Record
	if err := row.Scan(&rec.JSON, &rec.ContentHash, &rec.SessionID, &rec.Parents); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("store: record by idem: %w", err)
	}
	return rec, true, nil
}

func selectByIdem(ctx context.Context, tx pgx.Tx, projectID, idemKey string) (Record, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT json, content_hash, session_id, parents
		FROM records
		WHERE project_id = $1 AND idempotency_key = $2
	`, projectID, idemKey)
	var rec Record
	if err := row.Scan(&rec.JSON, &rec.ContentHash, &rec.SessionID, &rec.Parents); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("store: select by idem: %w", err)
	}
	return rec, true, nil
}

func selectByContentHash(ctx context.Context, tx pgx.Tx, projectID, hash string) (Record, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT json, content_hash, session_id, parents
		FROM records
		WHERE project_id = $1 AND content_hash = $2
	`, projectID, hash)
	var rec Record
	if err := row.Scan(&rec.JSON, &rec.ContentHash, &rec.SessionID, &rec.Parents); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("store: select by content hash: %w", err)
	}
	return rec, true, nil
}

// Heads returns the head content_hashes for a session: records whose content_hash is not referenced
// as a causal parent by any record in the SAME session. De-duplicated and byte-sorted ascending,
// never nil. Heads are derived here (not trusted from the client) — this is the frontier authority.
func (p *Postgres) Heads(projectID, sessionID string) ([]string, error) {
	ctx := background()
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT r.content_hash
		FROM records r
		WHERE r.project_id = $1 AND r.session_id = $2
		  AND NOT EXISTS (
			SELECT 1 FROM records c
			WHERE c.project_id = $1 AND c.session_id = $2
			  AND r.content_hash = ANY (c.parents)
		  )
		ORDER BY r.content_hash ASC
	`, projectID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: heads: %w", err)
	}
	return collectHashes(rows)
}

// ProjectHeads returns the heads across all sessions in the project (the checkpoint frontier):
// records whose content_hash is not referenced as a causal parent by any record in the project.
// De-duplicated and byte-sorted ascending, never nil.
func (p *Postgres) ProjectHeads(projectID string) ([]string, error) {
	ctx := background()
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT r.content_hash
		FROM records r
		WHERE r.project_id = $1
		  AND NOT EXISTS (
			SELECT 1 FROM records c
			WHERE c.project_id = $1
			  AND r.content_hash = ANY (c.parents)
		  )
		ORDER BY r.content_hash ASC
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: project heads: %w", err)
	}
	return collectHashes(rows)
}

// collectHashes drains a single-text-column result into a non-nil slice (matching Mem, which never
// returns nil for head/frontier queries the HTTP layer marshals directly).
func collectHashes(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("store: scan hash: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate hashes: %w", err)
	}
	return out, nil
}

// NextDisplaySeq returns the current per-(project, session) display counter and atomically
// increments it. It starts at 0 (the first call returns 0, the next returns 1, ...). The UPSERT is
// atomic, so concurrent callers each get a distinct, monotonically increasing value.
func (p *Postgres) NextDisplaySeq(projectID, sessionID string) (int64, error) {
	ctx := background()
	var current int64
	// On first call the row is inserted with next=0 and we return 0 (next becomes 1). On subsequent
	// calls the conflict path bumps and RETURNS the pre-increment value via the arithmetic below.
	err := p.pool.QueryRow(ctx, `
		INSERT INTO display_seq (project_id, session_id, next)
		VALUES ($1, $2, 1)
		ON CONFLICT (project_id, session_id)
		DO UPDATE SET next = display_seq.next + 1
		RETURNING next - 1
	`, projectID, sessionID).Scan(&current)
	if err != nil {
		return 0, fmt.Errorf("store: next display seq: %w", err)
	}
	return current, nil
}

// Sessions returns the distinct session ids that have at least one record, in first-seen
// (insertion) order to match Mem. Never nil.
func (p *Postgres) Sessions(projectID string) ([]string, error) {
	ctx := background()
	// DISTINCT ON keeps each session once; ordering by the earliest row reproduces Mem's first-seen
	// iteration order. ctid breaks ties deterministically for rows inserted in the same instant.
	rows, err := p.pool.Query(ctx, `
		SELECT session_id FROM (
			SELECT DISTINCT ON (session_id) session_id, inserted_at, ctid
			FROM records
			WHERE project_id = $1
			ORDER BY session_id, inserted_at, ctid
		) s
		ORDER BY s.inserted_at, s.ctid
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: sessions: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("store: scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate sessions: %w", err)
	}
	return out, nil
}

// SessionRecords returns all records in a session, in insertion order. Never nil.
func (p *Postgres) SessionRecords(projectID, sessionID string) ([]Record, error) {
	ctx := background()
	rows, err := p.pool.Query(ctx, `
		SELECT json, content_hash, session_id, parents
		FROM records
		WHERE project_id = $1 AND session_id = $2
		ORDER BY inserted_at, ctid
	`, projectID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: session records: %w", err)
	}
	return collectRecords(rows)
}

// AllRecords returns every record in the project, in insertion order. Never nil.
func (p *Postgres) AllRecords(projectID string) ([]Record, error) {
	ctx := background()
	rows, err := p.pool.Query(ctx, `
		SELECT json, content_hash, session_id, parents
		FROM records
		WHERE project_id = $1
		ORDER BY inserted_at, ctid
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: all records: %w", err)
	}
	return collectRecords(rows)
}

func collectRecords(rows pgx.Rows) ([]Record, error) {
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var rec Record
		if err := rows.Scan(&rec.JSON, &rec.ContentHash, &rec.SessionID, &rec.Parents); err != nil {
			return nil, fmt.Errorf("store: scan record: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate records: %w", err)
	}
	return out, nil
}

// RecordCount returns the number of DISTINCT content_hashes stored for the project (matching Mem,
// which counts unique content, not insert attempts). Because (project_id, content_hash) is unique,
// this equals the row count, but DISTINCT keeps the semantics explicit.
func (p *Postgres) RecordCount(projectID string) (int, error) {
	ctx := background()
	var n int
	err := p.pool.QueryRow(ctx, `
		SELECT count(DISTINCT content_hash) FROM records WHERE project_id = $1
	`, projectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: record count: %w", err)
	}
	return n, nil
}

// PutCheckpoint inserts a checkpoint. Insert-only: the schema forbids UPDATE/DELETE on checkpoints,
// and (project_id, seq) is the primary key, so a re-used seq is rejected rather than overwriting.
func (p *Postgres) PutCheckpoint(projectID string, cp Checkpoint) error {
	ctx := background()
	_, err := p.pool.Exec(ctx, `
		INSERT INTO checkpoints (project_id, seq, checkpoint_hash, json)
		VALUES ($1, $2, $3, $4)
	`, projectID, cp.Seq, cp.CheckpointHash, cp.JSON)
	if err != nil {
		return fmt.Errorf("store: put checkpoint: %w", err)
	}
	return nil
}

// Checkpoints returns all checkpoints for the project ordered by seq ascending. Never nil.
func (p *Postgres) Checkpoints(projectID string) ([]Checkpoint, error) {
	ctx := background()
	rows, err := p.pool.Query(ctx, `
		SELECT json, checkpoint_hash, seq
		FROM checkpoints
		WHERE project_id = $1
		ORDER BY seq ASC
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: checkpoints: %w", err)
	}
	defer rows.Close()
	out := []Checkpoint{}
	for rows.Next() {
		var cp Checkpoint
		if err := rows.Scan(&cp.JSON, &cp.CheckpointHash, &cp.Seq); err != nil {
			return nil, fmt.Errorf("store: scan checkpoint: %w", err)
		}
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate checkpoints: %w", err)
	}
	return out, nil
}

// NextCheckpointSeq returns the next checkpoint sequence number: the count of existing checkpoints
// for the project (0-based, matching Mem). This is the value the caller passes as Checkpoint.Seq.
func (p *Postgres) NextCheckpointSeq(projectID string) (int64, error) {
	ctx := background()
	var n int64
	err := p.pool.QueryRow(ctx, `
		SELECT count(*) FROM checkpoints WHERE project_id = $1
	`, projectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: next checkpoint seq: %w", err)
	}
	return n, nil
}

// AllocateBrokerSeq allocates (or returns the existing) gapless, idempotent broker_seq for a grant
// (ADR 0004 D6 / MF2). It runs under a per-project transaction-scoped advisory lock so two concurrent
// issuances cannot read the same MAX(seq) and mint two grants at the same number; the lock auto-releases
// at COMMIT/ROLLBACK. The INSERT ... ON CONFLICT (project_id, grant_id) DO NOTHING makes a retry of the
// same deterministic grant_id a no-op, and the trailing SELECT returns the existing-or-just-inserted seq.
func (p *Postgres) AllocateBrokerSeq(projectID, grantID string) (int64, error) {
	ctx := background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: begin broker seq: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op.

	// Serialize allocation per project (hashtext is stable within a PG major version; the lock value is
	// purely an internal serialization token, never persisted, so its exact hash does not matter).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, projectID); err != nil {
		return 0, fmt.Errorf("store: broker seq lock: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO broker_seq (project_id, grant_id, seq)
		SELECT $1, $2, COALESCE(MAX(seq), 0) + 1 FROM broker_seq WHERE project_id = $1
		ON CONFLICT (project_id, grant_id) DO NOTHING
	`, projectID, grantID); err != nil {
		return 0, fmt.Errorf("store: broker seq insert: %w", err)
	}
	var seq int64
	if err := tx.QueryRow(ctx, `
		SELECT seq FROM broker_seq WHERE project_id = $1 AND grant_id = $2
	`, projectID, grantID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("store: broker seq select: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: broker seq commit: %w", err)
	}
	return seq, nil
}

// insertDisclosures writes a record's disclosure secrets inside the caller's transaction. Insert-only
// and idempotent on (project_id, record_id, field): ON CONFLICT DO NOTHING, since the commitment for
// a field is immutable once sealed.
func insertDisclosures(ctx context.Context, tx pgx.Tx, projectID string, ds []DisclosureSecret) error {
	for _, d := range ds {
		if _, err := tx.Exec(ctx, `
			INSERT INTO disclosures (project_id, record_id, field, value_digest, nonce_hex)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (project_id, record_id, field) DO NOTHING
		`, projectID, d.RecordID, d.Field, d.ValueDigest, d.NonceHex); err != nil {
			return fmt.Errorf("store: insert disclosure: %w", err)
		}
	}
	return nil
}

// PutAnchor records a checkpoint's RFC 3161 token (base64url) by seq. Insert-only and idempotent on
// (project_id, seq): ON CONFLICT DO NOTHING (the anchor for a seq is immutable once set).
func (p *Postgres) PutAnchor(projectID string, seq int64, tokenB64 string) error {
	ctx := background()
	_, err := p.pool.Exec(ctx, `
		INSERT INTO anchors (project_id, seq, token_b64)
		VALUES ($1, $2, $3)
		ON CONFLICT (project_id, seq) DO NOTHING
	`, projectID, seq, tokenB64)
	if err != nil {
		return fmt.Errorf("store: put anchor: %w", err)
	}
	return nil
}

// Anchors returns seq -> token_b64 for the project. Never nil.
func (p *Postgres) Anchors(projectID string) (map[int64]string, error) {
	ctx := background()
	rows, err := p.pool.Query(ctx, `SELECT seq, token_b64 FROM anchors WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: anchors: %w", err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var seq int64
		var tok string
		if err := rows.Scan(&seq, &tok); err != nil {
			return nil, fmt.Errorf("store: scan anchor: %w", err)
		}
		out[seq] = tok
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate anchors: %w", err)
	}
	return out, nil
}

// Disclosures returns every disclosure secret for the project, ordered by insertion. Never nil.
func (p *Postgres) Disclosures(projectID string) ([]DisclosureSecret, error) {
	ctx := background()
	// Order canonically by the (record_id, field) key — unique within a project, so the result is
	// fully deterministic and identical to Mem regardless of insertion timing (a same-timestamp tie
	// must not reorder the export vs. the in-memory store).
	rows, err := p.pool.Query(ctx, `
		SELECT record_id, field, value_digest, nonce_hex
		FROM disclosures
		WHERE project_id = $1
		ORDER BY record_id, field
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: disclosures: %w", err)
	}
	defer rows.Close()
	out := []DisclosureSecret{}
	for rows.Next() {
		var d DisclosureSecret
		if err := rows.Scan(&d.RecordID, &d.Field, &d.ValueDigest, &d.NonceHex); err != nil {
			return nil, fmt.Errorf("store: scan disclosure: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate disclosures: %w", err)
	}
	return out, nil
}

// LatestCheckpointHash returns the highest-seq checkpoint hash for the project, ok=false if there
// are no checkpoints yet. (Mem returns its last-appended checkpoint; with monotonic seq that is the
// max-seq row.)
func (p *Postgres) LatestCheckpointHash(projectID string) (string, bool, error) {
	ctx := background()
	var hash string
	err := p.pool.QueryRow(ctx, `
		SELECT checkpoint_hash
		FROM checkpoints
		WHERE project_id = $1
		ORDER BY seq DESC
		LIMIT 1
	`, projectID).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("store: latest checkpoint hash: %w", err)
	}
	return hash, true, nil
}
