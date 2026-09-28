-- Plan 009: authorization order and immutable revocation events (schema version 7).
-- Maintenance cutover only. Like 0006, it runs behind the validated writer barrier:
-- every old runtime identity is NOLOGIN, has no sessions or prepared transactions and
-- no effective write privilege. A v6 writer would otherwise append unordered receipts
-- or boolean revocations that this schema no longer reads. 0006's nonce cutover row is
-- not touched, so its original legacy-exclusion time is preserved.

-- One monotonic authorization ordinal per project, allocated on plan 007's exact guard
-- row while the project write transaction holds it. Successful use, use-intent and
-- native introspection receipts, and prospective revocation cutoffs, all draw from it.
ALTER TABLE project_write_guard
    ADD COLUMN authorization_order bigint NOT NULL DEFAULT 0
    CHECK (authorization_order >= 0);

CREATE FUNCTION project_guard_order_monotonic() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'project guard rows are permanent once authorization order exists';
    END IF;
    IF NEW.project_id <> OLD.project_id OR NEW.authorization_order < OLD.authorization_order THEN
        RAISE EXCEPTION 'project authorization order can only advance';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER project_guard_order_advances
    BEFORE UPDATE OR DELETE ON project_write_guard
    FOR EACH ROW EXECUTE FUNCTION project_guard_order_monotonic();
CREATE TRIGGER project_guard_rows_not_truncated
    BEFORE TRUNCATE ON project_write_guard
    FOR EACH STATEMENT EXECUTE FUNCTION project_guard_order_monotonic();
REVOKE DELETE, TRUNCATE ON project_write_guard FROM PUBLIC;

CREATE FUNCTION temporal_revocation_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'temporal revocation rows are immutable';
END;
$$;

-- Backstop: one receipt per ordinal and one ordinal per receipt. The signed receipt
-- carries the ordinal; this table is operational, not a proof surface.
CREATE TABLE authorization_receipts (
    project_id text NOT NULL CHECK (project_id <> ''),
    ordinal bigint NOT NULL CHECK (ordinal > 0),
    record_id text NOT NULL CHECK (record_id <> ''),
    grant_id text NOT NULL CHECK (grant_id <> ''),
    kind text NOT NULL CHECK (kind IN ('use', 'use_intent', 'introspection_transcript')),
    PRIMARY KEY (project_id, ordinal),
    UNIQUE (project_id, record_id)
);
CREATE TRIGGER authorization_receipts_immutable
    BEFORE UPDATE OR DELETE ON authorization_receipts
    FOR EACH ROW EXECUTE FUNCTION temporal_revocation_reject_mutation();
CREATE TRIGGER authorization_receipts_not_truncated
    BEFORE TRUNCATE ON authorization_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION temporal_revocation_reject_mutation();

-- Versioned revocation events. At most one total and one prospective event per grant:
-- a retry can never move a cutoff later, and a later total (compromise) event is always
-- recordable. Readers combine conservatively: any total wins, else the earliest cutoff.
CREATE TABLE revocation_events (
    project_id text NOT NULL CHECK (project_id <> ''),
    grant_id text NOT NULL CHECK (grant_id <> ''),
    format text NOT NULL CHECK (format = 'averin.revocation.event.v1'),
    mode text NOT NULL CHECK (mode IN ('total', 'prospective')),
    cutoff_order bigint CHECK (cutoff_order > 0),
    issuer text NOT NULL CHECK (issuer <> ''),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((mode = 'prospective') = (cutoff_order IS NOT NULL)),
    PRIMARY KEY (project_id, grant_id, mode)
);
CREATE TRIGGER revocation_events_immutable
    BEFORE UPDATE OR DELETE ON revocation_events
    FOR EACH ROW EXECUTE FUNCTION temporal_revocation_reject_mutation();
CREATE TRIGGER revocation_events_not_truncated
    BEFORE TRUNCATE ON revocation_events
    FOR EACH STATEMENT EXECUTE FUNCTION temporal_revocation_reject_mutation();

-- Every pre-v7 revocation is total: boolean revocations, plan 008 void markers and
-- signed grant_void tombstones (a tombstone may have committed without its marker).
INSERT INTO revocation_events (project_id, grant_id, format, mode, issuer, reason, created_at)
SELECT project_id, grant_id, 'averin.revocation.event.v1', 'total', 'averin-migration-0007',
       'legacy_boolean_revocation', revoked_at
FROM revocations
ON CONFLICT DO NOTHING;
INSERT INTO revocation_events (project_id, grant_id, format, mode, issuer, reason, created_at)
SELECT project_id, grant_id, 'averin.revocation.event.v1', 'total', 'averin-migration-0007',
       'broker_seq_void', voided_at
FROM broker_seq_void
ON CONFLICT DO NOTHING;
INSERT INTO revocation_events (project_id, grant_id, format, mode, issuer, reason)
SELECT DISTINCT project_id, json::jsonb ->> 'record_id', 'averin.revocation.event.v1', 'total',
       'averin-migration-0007', 'grant_void_tombstone'
FROM records
WHERE json::jsonb #>> '{extensions,broker,kind}' = 'grant_void'
  AND COALESCE(json::jsonb ->> 'record_id', '') <> ''
ON CONFLICT DO NOTHING;

-- The boolean table is retired, not bridged: no trigger maps a later boolean insert
-- into an event, so no compatibility path can swallow a later total upgrade. Renaming
-- also invalidates old prepared statements that name it.
ALTER TABLE revocations RENAME TO legacy_boolean_revocations;
CREATE TRIGGER legacy_boolean_revocations_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON legacy_boolean_revocations
    FOR EACH ROW EXECUTE FUNCTION temporal_revocation_reject_mutation();
CREATE TRIGGER legacy_boolean_revocations_not_truncated
    BEFORE TRUNCATE ON legacy_boolean_revocations
    FOR EACH STATEMENT EXECUTE FUNCTION temporal_revocation_reject_mutation();

DO $$
BEGIN
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON authorization_receipts, revocation_events FROM PUBLIC';
    EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON legacy_boolean_revocations FROM PUBLIC';
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON authorization_receipts, revocation_events FROM %I', CURRENT_USER);
END
$$;
