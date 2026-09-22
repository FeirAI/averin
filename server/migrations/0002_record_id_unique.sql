-- 0002_record_id_unique.sql — record_id is unique per project.
--
-- The offline verifier rejects a bundle with a "duplicate record_id", and disclosure secrets are keyed
-- (project_id, record_id, field) with ON CONFLICT DO NOTHING — so a second record under an existing record_id
-- would permanently poison verification AND silently lose its opening secret. The store enforces uniqueness
-- in PutRecord (under the api ingest lock); this index is the database backstop, over the record_id carried in
-- the sealed JSON (an expression index — no new column, no backfill, no UPDATE of append-only rows).
--
-- The index is over md5(record_id), NOT the raw record_id: a btree entry is capped at ~2704 bytes, and a
-- historical record (written before the api capped record_id at 256 bytes) may carry a longer, incompressible
-- id — indexing the raw value would abort this migration and every replica would refuse to boot. The md5 key is
-- a fixed 32 chars. The store's probes compare md5 (index lookup) AND the full record_id (exactness). A false
-- conflict needs two DISTINCT caller-chosen ids with equal md5 in the SAME project (only that project's own
-- writer can produce it); squatting another record's id would need an md5 second preimage.
--
-- If a pre-existing DB ALREADY holds a duplicate (written before this enforcement existed), a UNIQUE index
-- cannot be built; failing the migration would refuse to boot over historical evidence that cannot be
-- rewritten. In that case we build the SAME expression as a plain index (so the store's per-insert uniqueness
-- probe stays an index lookup) and RAISE WARNING so the operator knows the DB backstop is absent — the
-- application-level check still rejects every NEW duplicate. The UNIQUE build is also guarded by an exception
-- handler, so no historical row can make this step fail. Idempotent (IF NOT EXISTS).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM records
        WHERE (json::jsonb ->> 'record_id') IS NOT NULL
        GROUP BY project_id, md5(json::jsonb ->> 'record_id')
        HAVING count(*) > 1
    ) THEN
        RAISE WARNING 'averin: records already contain a duplicate (project_id, record_id); building a NON-unique record_id index. New duplicates are still rejected by the application, but the database backstop is absent until the historical duplicate is resolved.';
        CREATE INDEX IF NOT EXISTS records_project_record_id_idx
            ON records (project_id, md5(json::jsonb ->> 'record_id'));
    ELSE
        BEGIN
            CREATE UNIQUE INDEX IF NOT EXISTS records_project_record_id_uniq
                ON records (project_id, md5(json::jsonb ->> 'record_id'));
        EXCEPTION WHEN unique_violation OR program_limit_exceeded THEN
            RAISE WARNING 'averin: could not build the UNIQUE record_id index (%); building a NON-unique one. New duplicates are still rejected by the application.', SQLERRM;
            CREATE INDEX IF NOT EXISTS records_project_record_id_idx
                ON records (project_id, md5(json::jsonb ->> 'record_id'));
        END;
    END IF;
END
$$;
