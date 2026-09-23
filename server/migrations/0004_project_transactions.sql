-- Project serialization is an operational row lock, not a hash advisory lock.
-- A distinct project owns a distinct row, so lock collisions cannot stall it.
-- The runtime role needs INSERT and SELECT/UPDATE on this table only; evidence
-- remains insert-only and is never rewritten to acquire the lock.
CREATE TABLE IF NOT EXISTS project_write_guard (
    project_id text PRIMARY KEY
);
