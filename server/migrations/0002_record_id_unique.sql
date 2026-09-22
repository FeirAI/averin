-- 0002_record_id_unique.sql — record_id is unique per project.
--
-- The offline verifier rejects a bundle with a "duplicate record_id", and disclosure secrets are keyed
-- (project_id, record_id, field) with ON CONFLICT DO NOTHING — so a second record under an existing record_id
-- would permanently poison verification AND silently lose its opening secret. The store enforces uniqueness
-- in PutRecord (under the api ingest lock); this index is the database backstop, over the record_id carried in
-- the sealed JSON (an expression index — no new column, no backfill, no UPDATE of append-only rows).
--
-- If a pre-existing DB ALREADY holds a duplicate (written before this enforcement existed), a UNIQUE index
-- cannot be built; failing the migration would refuse to boot over historical evidence that cannot be
-- rewritten. In that case we build the SAME expression as a plain index (so the store's per-insert uniqueness
-- probe stays an index lookup) and RAISE WARNING so the operator knows the DB backstop is absent — the
-- application-level check still rejects every NEW duplicate. Idempotent (IF NOT EXISTS).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM records
        GROUP BY project_id, (json::jsonb ->> 'record_id')
        HAVING count(*) > 1 AND (json::jsonb ->> 'record_id') IS NOT NULL
    ) THEN
        RAISE WARNING 'averin: records already contain a duplicate (project_id, record_id); building a NON-unique record_id index. New duplicates are still rejected by the application, but the database backstop is absent until the historical duplicate is resolved.';
        CREATE INDEX IF NOT EXISTS records_project_record_id_idx
            ON records (project_id, (json::jsonb ->> 'record_id'));
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS records_project_record_id_uniq
            ON records (project_id, (json::jsonb ->> 'record_id'));
    END IF;
END
$$;
