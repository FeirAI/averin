-- Maintenance cutover only. The caller has drained old workers and database sessions,
-- retired their credentials, and resolved prepared transactions before this step.
-- Historical rows have no authenticated project/resource owner. Keep them as global
-- exclusions, never infer ownership or backfill them into a tenant namespace.
ALTER TABLE consume_ledger RENAME TO legacy_consume_exclusions;

CREATE FUNCTION legacy_consume_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'legacy consume exclusions are immutable after nonce cutover';
END;
$$;
CREATE TRIGGER legacy_consume_rows_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON legacy_consume_exclusions
    FOR EACH ROW EXECUTE FUNCTION legacy_consume_reject_mutation();
CREATE TRIGGER legacy_consume_truncate_immutable
    BEFORE TRUNCATE ON legacy_consume_exclusions
    FOR EACH STATEMENT EXECUTE FUNCTION legacy_consume_reject_mutation();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON legacy_consume_exclusions FROM PUBLIC;

-- This timestamp comes from the database. The 24-hour hold is the existing safe
-- retention floor and exceeds MaxTTL (1h) plus accepted issuance skew (30s).
-- The application checks those constants against this floor at startup.
CREATE TABLE nonce_ledger_cutover (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    cutover_at timestamptz NOT NULL,
    legacy_exclusion_until timestamptz NOT NULL,
    CHECK (legacy_exclusion_until > cutover_at)
);
WITH cutoff AS (SELECT clock_timestamp() AS at)
INSERT INTO nonce_ledger_cutover(singleton, cutover_at, legacy_exclusion_until)
SELECT true, at, at + interval '24 hours' FROM cutoff;
CREATE TRIGGER nonce_cutover_rows_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON nonce_ledger_cutover
    FOR EACH ROW EXECUTE FUNCTION legacy_consume_reject_mutation();
CREATE TRIGGER nonce_cutover_truncate_immutable
    BEFORE TRUNCATE ON nonce_ledger_cutover
    FOR EACH STATEMENT EXECUTE FUNCTION legacy_consume_reject_mutation();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON nonce_ledger_cutover FROM PUBLIC;

CREATE TABLE consumed_nonces (
    project_id text NOT NULL CHECK (project_id <> ''),
    resource_id text NOT NULL CHECK (resource_id <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    owner_id text NOT NULL CHECK (length(owner_id) = 32),
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (project_id, resource_id, nonce)
);
CREATE INDEX consumed_nonces_consumed_at_idx ON consumed_nonces(consumed_at);

CREATE TABLE consumed_jtis (
    consume_key text PRIMARY KEY CHECK (consume_key <> ''),
    owner_id text NOT NULL CHECK (length(owner_id) = 32),
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX consumed_jtis_consumed_at_idx ON consumed_jtis(consumed_at);
