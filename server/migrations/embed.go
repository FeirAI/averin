// Package migrations embeds the SQL schema so the server (and tests) apply the exact same file that
// ships in the repo — a single source of truth, with no copy to drift and no runtime path lookup.
package migrations

import _ "embed"

// Schema is the full contents of 0001_init.sql (the append-only records/checkpoints/display_seq
// schema). It is idempotent (CREATE ... IF NOT EXISTS) so applying it on every startup is safe.
//
//go:embed 0001_init.sql
var Schema string

// RecordIDUnique is the full contents of 0002_record_id_unique.sql: the per-project record_id uniqueness
// backstop (schema version 2). Idempotent (IF NOT EXISTS).
//
//go:embed 0002_record_id_unique.sql
var RecordIDUnique string

// BrokerSeqVoid is the full contents of 0003_broker_seq_void.sql: broker_seq.allocated_at + the insert-only
// broker_seq_void marker table behind the operator's grant_void remediation (schema version 3). Idempotent.
//
//go:embed 0003_broker_seq_void.sql
var BrokerSeqVoid string

// ProjectTransactions creates the operational per-project serialization row.
//
//go:embed 0004_project_transactions.sql
var ProjectTransactions string

// BrokerSeqRecovery adds immutable fence and terminal rows (schema version 5).
//go:embed 0005_broker_seq_recovery.sql
var BrokerSeqRecovery string

// TenantNonceLedger keeps unknown-owner historical claims as immutable exclusions
// and creates project/resource nonce and global JTI ledgers (schema version 6).
//go:embed 0006_tenant_nonce_ledger.sql
var TenantNonceLedger string
