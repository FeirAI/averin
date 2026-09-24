-- An immutable recovery fence retires one reserved sequence from future grant
-- attempts. The terminal row is separate so a crash after fencing is resumable.
CREATE TABLE IF NOT EXISTS broker_seq_recovery_fence (
    project_id text NOT NULL,
    seq bigint NOT NULL CHECK (seq > 0),
    grant_id text NOT NULL,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation = 1),
    operation_id text NOT NULL,
    actor_id text NOT NULL,
    session_id text NOT NULL,
    reason text NOT NULL,
    request_digest text NOT NULL,
    fenced_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (project_id, seq),
    UNIQUE (project_id, grant_id),
    UNIQUE (project_id, operation_id),
    UNIQUE (project_id, seq, generation),
    FOREIGN KEY (project_id, seq) REFERENCES broker_seq(project_id, seq)
);

CREATE TABLE IF NOT EXISTS broker_seq_recovery_result (
    project_id text NOT NULL,
    seq bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation = 1),
    outcome text NOT NULL CHECK (outcome IN ('recorded', 'voided')),
    winning_record_hash text NOT NULL CHECK (winning_record_hash <> ''),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (project_id, seq),
    FOREIGN KEY (project_id, seq, generation)
        REFERENCES broker_seq_recovery_fence(project_id, seq, generation)
);

DO $$
BEGIN
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON broker_seq_recovery_fence, broker_seq_recovery_result FROM PUBLIC';
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON broker_seq_recovery_fence, broker_seq_recovery_result FROM %I', CURRENT_USER);
END
$$;
