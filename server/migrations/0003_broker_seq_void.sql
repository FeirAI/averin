-- 0003_broker_seq_void.sql — operator remediation for a wedged grant-transparency log (ADR 0004 D6).
--
-- A broker_seq reserved by a grant whose commit was ambiguous (or whose release failed) and that is never retried
-- leaves a hole in the recorded [1..N] prefix; checkpoint creation then refuses to sign forever. POST
-- /v2/broker-seq/void fills such a hole with a signed grant_void tombstone record. Two pieces of state support it:
--
--   * broker_seq.allocated_at — when the seq was reserved, so the endpoint can refuse to void a reservation younger
--     than the configured safety age (AVERIN_BROKER_SEQ_VOID_MIN_AGE). Existing rows take the migration time, so a
--     reservation that predates this migration becomes voidable one safety age after the upgrade (conservative).
--   * broker_seq_void — an INSERT-ONLY marker per voided reservation. The broker_seq row itself is KEPT (MAX(seq)+1
--     must never re-issue the voided number), ReleaseBrokerSeq never deletes a voided row, and AllocateBrokerSeq
--     refuses a voided grant_id. UNIQUE (project_id, seq) mirrors broker_seq.
--
-- Idempotent (IF NOT EXISTS). The append-only REVOKE mirrors 0001 (see its header for the role requirements).
ALTER TABLE broker_seq ADD COLUMN IF NOT EXISTS allocated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS broker_seq_void (
    project_id text        NOT NULL,
    grant_id   text        NOT NULL,
    seq        bigint      NOT NULL,
    voided_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, grant_id),
    UNIQUE (project_id, seq)
);

DO $$
BEGIN
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON broker_seq_void FROM PUBLIC';
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON broker_seq_void FROM %I', CURRENT_USER);
END
$$;
