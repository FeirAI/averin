// Package migrations embeds the SQL schema so the server (and tests) apply the exact same file that
// ships in the repo — a single source of truth, with no copy to drift and no runtime path lookup.
package migrations

import _ "embed"

// Schema is the full contents of 0001_init.sql (the append-only records/checkpoints/display_seq
// schema). It is idempotent (CREATE ... IF NOT EXISTS) so applying it on every startup is safe.
//
//go:embed 0001_init.sql
var Schema string
