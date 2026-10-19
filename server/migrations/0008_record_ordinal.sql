-- 0008_record_ordinal.sql: a per-project insertion ordinal on records (schema version 8,
-- history-scaling PR1; LIMITATIONS "A month's record range is read by position").
--
-- records.ord is 1, 2, 3, ... per project, in insertion order, with no gaps. It is the position a
-- checkpoint's record_count refers to, so "the records after checkpoint N" is an index range read,
-- the record count is the largest ordinal, and the newest record is the highest ordinal. None of
-- these reads touches the rest of the history. Before this step the order was (inserted_at, ctid),
-- which has no index, so each of them scanned and sorted the whole project.
--
-- Assignment. A BEFORE INSERT trigger gives a row without an ordinal max(ord)+1 for its project.
-- The write path already holds the project's write-guard row lock (0004) for the whole project
-- transaction, so two inserts of one project never race; a racing direct insert that bypassed the
-- guard fails on the unique index (project_id, ord) instead of reusing an ordinal. Records are
-- insert-only, so max(ord) never moves backwards. The trigger runs before ON CONFLICT DO NOTHING
-- decides, but it consumes no counter, so a collapsed retry leaves no gap.
--
-- Backfill (existing data). Existing rows are numbered per project in the order the store has read
-- them until now: (inserted_at, ctid). That is the order every existing checkpoint's record_count
-- was cut against, so existing checkpoints keep meaning exactly what they meant. The step needs
-- UPDATE on records, which the append-only REVOKE of 0001 removed from the migrating role: it is
-- granted back for this statement and revoked again before the step ends, inside one transaction
-- (a failure rolls both back). It writes a new column only; no signed bytes change. Cost: one
-- rewrite of the records table (every row gets a new tuple version), so size the maintenance window
-- to the table and expect it to roughly double until vacuum. The cutover already requires the
-- retired-writer barrier, so nothing writes meanwhile.
--
-- A database whose records span a clock step back or two replicas committing out of order keeps the
-- order it has today for old rows (the documented position hazard); only rows inserted from now on
-- are immune.

ALTER TABLE records ADD COLUMN ord bigint;

DO $$
BEGIN
    EXECUTE format('GRANT UPDATE ON records TO %I', CURRENT_USER);
END
$$;

UPDATE records r
   SET ord = s.rn
  FROM (SELECT ctid AS c,
               row_number() OVER (PARTITION BY project_id ORDER BY inserted_at, ctid) AS rn
          FROM records) s
 WHERE r.ctid = s.c;

DO $$
BEGIN
    EXECUTE format('REVOKE UPDATE ON records FROM %I', CURRENT_USER);
END
$$;

ALTER TABLE records ALTER COLUMN ord SET NOT NULL;
ALTER TABLE records ADD CONSTRAINT records_ord_positive CHECK (ord > 0);
CREATE UNIQUE INDEX records_project_ord_uniq ON records (project_id, ord);

CREATE FUNCTION records_assign_ord() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ord IS NULL THEN
        SELECT COALESCE(max(ord), 0) + 1 INTO NEW.ord FROM records WHERE project_id = NEW.project_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER records_assign_ord
    BEFORE INSERT ON records
    FOR EACH ROW EXECUTE FUNCTION records_assign_ord();

-- The heads anti-join tested content_hash = ANY(parents), which the GIN index on parents cannot
-- serve (GIN serves @>). The queries now use @>, which it can.
