-- 0009_session_heads.sql: the per-session frontier, kept incrementally (schema version 9,
-- availability fix; LIMITATIONS "A seal reads the session frontier from an index, not a scan").
--
-- session_heads(project_id, session_id, content_hash) holds exactly the set Heads() returns: every
-- record of the session whose content_hash is not named in `parents` by any record of the SAME project
-- and session. Before this step every seal derived that set with an anti-join over the whole session,
-- so a session that only grows (the metered-call session of a busy tenant) made each seal slower than
-- the last: the join probes the parents GIN index once per record in the session, so the cost of a
-- seal grew linearly with the session's history (measured: 1.4 s per seal at 7,164 records).
--
-- Maintenance. The store keeps the table in the SAME transaction as the record insert, and only when
-- the insert created a new row (an idempotent replay or a content_hash collapse touches nothing): it
-- deletes the new record's parents from the session's heads, then adds the new record. Parents that live in another session are simply absent
-- from this session's heads, so deleting them is a no-op, which matches the definition (heads are per
-- session). The write path already serializes a project's writers on the project write guard (0004),
-- so two inserts of one project never race on this table.
--
-- Not evidence. Nothing here is signed, hashed or part of any record: the table is derived,
-- operational state that can always be rebuilt from `records` with the backfill statement below, so it
-- takes plain DML (no append-only REVOKE, no immutability trigger). The runtime role needs SELECT,
-- INSERT and DELETE on it (pgschema.CheckRuntime verifies this; deploy/postgres/runtime-grants.sql
-- already grants DML on every table). It needs no UPDATE: rows are only added and removed.
--
-- Backfill (existing data). One statement computes the set from `records` (see the comment on it). It
-- runs in the migration transaction, needs no UPDATE on records, and is linear in records plus parent
-- edges (about 0.2 s for the 7,164-record soak session). The cutover already requires the
-- retired-writer barrier, so no record is written meanwhile.

CREATE TABLE session_heads (
    project_id   text NOT NULL,
    session_id   text NOT NULL,
    content_hash text NOT NULL,
    PRIMARY KEY (project_id, session_id, content_hash)
);

-- Set-based, not a correlated anti-join. The obvious backfill is "no record of the session names this
-- hash in parents @> ARRAY[hash]", but the planner turns that into a hash anti-join on (project,
-- session) with the containment test as a join filter: 25.7 million comparisons and 34 s for the 7,165
-- records of one session, quadratic in the session whatever the statistics say. EXCEPT over the unnested
-- parents hashes the two sets once and is linear in the number of records and parent edges, whatever
-- plan the statistics suggest. Same set: a hash is a head of (project, session) iff no record of that
-- project and session lists it in parents; a parent that is absent from the session, or from the store,
-- never appears on the left and so changes nothing.
INSERT INTO session_heads (project_id, session_id, content_hash)
SELECT project_id, session_id, content_hash FROM records
EXCEPT
SELECT c.project_id, c.session_id, p.hash
  FROM records c CROSS JOIN LATERAL unnest(c.parents) AS p(hash);
