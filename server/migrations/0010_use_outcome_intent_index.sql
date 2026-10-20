-- 0010_use_outcome_intent_index.sql: index the "is there already an outcome for this intent" lookup
-- (schema version 10, availability fix, same class as 0009; LIMITATIONS "A use-outcome finds its intent
-- and prior outcome by index, not by scanning the session").
--
-- /v2/use-outcome (vultrino seals a use intent and its outcome per metered call, one session per tenant,
-- a session that only grows) used to read the whole session and decode every record to find the intent
-- record and any outcome already completing it. Measured on the live confirm soak: that read was the
-- dominant query (up to 213 ms at about 11k records) and metered-call p50 drifted from 140 ms to 480 ms
-- over 2 h. The intent is found through records_project_record_id_uniq (0002) and needs no new index.
-- The outcome needs this one.
--
-- records_use_outcome_intent_idx covers exactly the rows the old scan accepted as an outcome: a use_outcome
-- broker record (extensions.broker.kind = 'use_outcome') whose record_id and
-- extensions.broker.use_outcome.intent_ref are JSON strings (or absent/null, which the scan's Go decoder read as
-- the empty string; a field of any other JSON type made the decoder fail and the scan skip the record, so the
-- predicate excludes it too). It is keyed (project_id, session_id,
-- md5(intent_ref), ord): the lookup fixes the first three and takes the lowest ord, which is the first row in
-- insertion order (ord is the gapless per-project insertion ordinal of 0008), so the answer is one index
-- descent whatever the history. md5(...) as in 0002, so an unusually long intent_ref can never exceed the
-- btree row limit and fail a record insert; the query rechecks the full value, so a collision cannot match.
--
-- json is a text column and json::jsonb is immutable, as 0002's expression index already relies on. The
-- predicate is repeated verbatim by Postgres.UseOutcomeFor so the planner can use the partial index.
--
-- Not evidence: an index is derived state. It adds no table, so the runtime role needs no new privilege
-- (INSERT on records maintains it). Build cost is one pass over records under the retired-writer barrier of
-- the cutover.

CREATE INDEX records_use_outcome_intent_idx ON records (
    project_id,
    session_id,
    md5(coalesce(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome' ->> 'intent_ref', '')),
    ord
)
WHERE json::jsonb -> 'extensions' -> 'broker' ->> 'kind' = 'use_outcome'
  AND coalesce(jsonb_typeof(json::jsonb -> 'record_id'), 'null') IN ('string', 'null')
  AND coalesce(jsonb_typeof(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome'), 'null') IN ('object', 'null')
  AND coalesce(jsonb_typeof(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome' -> 'intent_ref'), 'null') IN ('string', 'null');
