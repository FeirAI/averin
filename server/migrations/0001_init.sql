-- 0001_init.sql — append-only metadata store for sealed records and checkpoints.
--
-- Integrity comes from the DAG + anchor; this schema is defense in depth. The store is
-- INSERT-ONLY: after creating the tables we REVOKE UPDATE and DELETE from the application
-- role so that even a compromised app credential cannot mutate or remove history. The only
-- writes permitted are INSERTs (records, checkpoints) and the per-session display counter,
-- which is the single intentionally-mutable cell (a monotonic counter, never decremented).
--
-- This migration is idempotent (CREATE ... IF NOT EXISTS) so it can be applied repeatedly,
-- including against a fresh temp schema in tests.

-- records: one row per sealed Decision Record.
--   (project_id, idempotency_key) is unique  -> retry duplication collapses (threat #8).
--   (project_id, content_hash)    is unique  -> identical bytes collapse to one row (threat #8).
--   parents holds causal_prev_hashes so heads can be derived in SQL (never trusted from client).
CREATE TABLE IF NOT EXISTS records (
    project_id      text   NOT NULL,
    idempotency_key text   NOT NULL,
    content_hash    text   NOT NULL,
    session_id      text   NOT NULL,
    parents         text[] NOT NULL DEFAULT '{}',
    json            text   NOT NULL,
    inserted_at     timestamptz NOT NULL DEFAULT now()
);

-- Unique on content_hash: the canonical dedupe key (identical sealed bytes => identical hash).
CREATE UNIQUE INDEX IF NOT EXISTS records_project_content_hash_uniq
    ON records (project_id, content_hash);

-- Partial unique on idempotency_key: empty key means "no idempotency requested" and must not
-- collapse unrelated rows, so only non-empty keys participate in the constraint.
CREATE UNIQUE INDEX IF NOT EXISTS records_project_idem_key_uniq
    ON records (project_id, idempotency_key)
    WHERE idempotency_key <> '';

-- Lookups by session (Heads, SessionRecords, Sessions).
CREATE INDEX IF NOT EXISTS records_project_session_idx
    ON records (project_id, session_id);

-- GIN index over parents to make the "content_hash NOT in any parents" head query fast.
CREATE INDEX IF NOT EXISTS records_parents_gin
    ON records USING gin (parents);

-- checkpoints: one row per sealed (and possibly anchored) checkpoint. Insert-only; seq is the
-- 0-based ordinal assigned by the application (count of prior checkpoints for the project).
CREATE TABLE IF NOT EXISTS checkpoints (
    project_id      text   NOT NULL,
    seq             bigint NOT NULL,
    checkpoint_hash text   NOT NULL,
    json            text   NOT NULL,
    inserted_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, seq)
);

-- anchors: the third-party RFC 3161 timestamp token for one checkpoint (by seq), stored SEPARATELY
-- from the checkpoint row so anchoring is decoupled from checkpoint creation — the TSA network call
-- happens out of the checkpoint critical section, and a checkpoint that failed to anchor (TSA down)
-- can be back-anchored later by inserting here (the checkpoints table is append-only, never UPDATEd).
-- The export joins this token into the checkpoint's `anchor` block. Insert-only/idempotent per seq.
CREATE TABLE IF NOT EXISTS anchors (
    project_id text   NOT NULL,
    seq        bigint NOT NULL,
    token_b64  text   NOT NULL,
    inserted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, seq)
);

-- disclosures: the secret needed to reveal one committed low-entropy field on a selective_disclosure
-- export — the content-store digest of the raw value + the nonce that opens its hiding commitment.
-- Bound to (project_id, record_id, field); the signed record body carries only the commitment.
-- Insert-only (the commitment for a field is immutable once sealed).
CREATE TABLE IF NOT EXISTS disclosures (
    project_id   text NOT NULL,
    record_id    text NOT NULL,
    field        text NOT NULL,
    value_digest text NOT NULL,
    nonce_hex    text NOT NULL,
    inserted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, record_id, field)
);

-- display_seq: per-(project, session) counter starting at 0. This is the one mutable cell in the
-- store; the application only ever increments it (UPSERT ... next = next + 1). UPDATE is retained
-- here (the counter must increment) and DELETE is revoked below. NOTE: display_seq is NOT
-- integrity-bearing — it only affects display ordering, never the signed DAG/anchor. Because UPDATE
-- is retained, a compromised app credential could rewind this counter; that is an accepted, bounded
-- weakness (it cannot forge or rewrite sealed history, which the content-hash chain + anchor cover).
CREATE TABLE IF NOT EXISTS display_seq (
    project_id text   NOT NULL,
    session_id text   NOT NULL,
    next       bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, session_id)
);

-- broker_seq: the grant-transparency ALLOCATION LEDGER (ADR 0004 D6 / MF2). Per (project, grant_id) row,
-- the gapless broker_seq bound into the SIGNED grant_evidence. This table is NOT integrity-bearing — the
-- integrity is the signed grant_evidence + the anchored broker_grant_head; this is only an allocation
-- helper (like display_seq, a mutable cell). Rows are INSERTed on allocation and DELETEd on rollback when
-- a grant fails AFTER allocation but before its record commits (so the durable max only advances for
-- recorded grants, keeping the log gapless); they are never UPDATEd. The PK makes allocation idempotent on
-- grant_id; UNIQUE (project_id, seq) keeps the per-project sequence non-colliding; allocation runs under a
-- per-project advisory lock so concurrent issuance cannot mint two grants at the same seq.
CREATE TABLE IF NOT EXISTS broker_seq (
    project_id text   NOT NULL,
    grant_id   text   NOT NULL,
    seq        bigint NOT NULL,
    PRIMARY KEY (project_id, grant_id),
    UNIQUE (project_id, seq)
);

-- Append-only enforcement (defense in depth — the PRIMARY integrity guarantee is the signed,
-- hash-linked DAG + external anchor, not the database). Revoke mutation on the history tables.
--
-- DEPLOYMENT REQUIREMENT: REVOKE only constrains a role that is NEITHER a superuser NOR the table
-- owner — both bypass it. For real enforcement, run the application under a dedicated least-privilege
-- role that owns nothing and is granted only INSERT/SELECT on records & checkpoints (+ UPDATE on
-- display_seq). Migrations may run as a more privileged role; revoking from PUBLIC and from the
-- migrating role (CURRENT_USER) covers inherited/default grants, but does NOT constrain a
-- superuser/owner app role. We RAISE NOTICE (not EXCEPTION, so superuser dev/test still works) when
-- the migrating role is a superuser, so operators are not lulled into a false sense of enforcement.
DO $$
BEGIN
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON records     FROM PUBLIC';
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON checkpoints FROM PUBLIC';
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON disclosures FROM PUBLIC';
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON anchors     FROM PUBLIC';
    EXECUTE 'REVOKE UPDATE,         TRUNCATE ON broker_seq  FROM PUBLIC';
    EXECUTE 'REVOKE         DELETE, TRUNCATE ON display_seq FROM PUBLIC';
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON records     FROM %I', CURRENT_USER);
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON checkpoints FROM %I', CURRENT_USER);
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON disclosures FROM %I', CURRENT_USER);
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON anchors     FROM %I', CURRENT_USER);
    EXECUTE format('REVOKE UPDATE,         TRUNCATE ON broker_seq  FROM %I', CURRENT_USER);
    EXECUTE format('REVOKE         DELETE, TRUNCATE ON display_seq FROM %I', CURRENT_USER);
    IF (SELECT rolsuper FROM pg_roles WHERE rolname = CURRENT_USER) THEN
        RAISE NOTICE 'feir: migrating role % is a SUPERUSER, so REVOKE is a no-op and append-only is NOT database-enforced. Run the application under a dedicated least-privilege, non-owner role.', CURRENT_USER;
    END IF;
END
$$;
