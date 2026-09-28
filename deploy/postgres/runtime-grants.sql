-- Runtime privileges for averin_app, applied by the compose `grants` service as averin_owner after
-- every `averin-migrate --init` (idempotent: GRANT/REVOKE of an already granted/revoked privilege is
-- a no-op). Only the table owner can change these, and the runtime role is not the owner.
--
-- Shape: DML on every averin table, then the mutation privileges the append-only contract forbids
-- are revoked again. The REVOKE lists mirror pgschema.CheckRuntime (server/internal/pgschema), which
-- refuses to serve while the runtime holds any of them; broker_seq keeps DELETE (an unrecorded max
-- allocation is released), display_seq and project_write_guard keep UPDATE (counter and
-- authorization order). Operational tables (nonce/JTI claims, pending grants, ...) keep full DML.
-- A later schema version needs the explicit averin-migrate cutover with a NEW runtime role
-- (docs/operator-verification.md#required-deployment-cutoff); re-running this file is not an upgrade.
\set ON_ERROR_STOP on
BEGIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO averin_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO averin_app;
REVOKE UPDATE, DELETE, TRUNCATE ON
  records, checkpoints, anchors, disclosures, broker_seq_void, broker_seq_recovery_fence,
  broker_seq_recovery_result, authorization_receipts, revocation_events
  FROM averin_app;
REVOKE UPDATE, TRUNCATE ON broker_seq FROM averin_app;
REVOKE DELETE, TRUNCATE ON display_seq, project_write_guard FROM averin_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON
  legacy_boolean_revocations, legacy_consume_exclusions, nonce_ledger_cutover, schema_migrations
  FROM averin_app;
COMMIT;
