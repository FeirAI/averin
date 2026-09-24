// Command averin-migrate performs the selected, offline schema cutover. The
// operator drains old workers, retires their DB identities, and provisions a
// distinct new runtime identity before invoking this command.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/pgschema"
)

func main() {
	old := flag.String("old-runtime", "", "comma-separated retired old runtime database roles")
	next := flag.String("new-runtime", "", "distinct new runtime database role")
	purge := flag.Bool("purge-legacy", false, "remove aged legacy exclusions after the database-time hold")
	init := flag.Bool("init", false, "bootstrap only a truly empty database with the migration credential")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("averin-migrate: unexpected positional arguments")
	}
	dsn := os.Getenv("AVERIN_MIGRATION_DATABASE_URL")
	if dsn == "" {
		log.Fatal("averin-migrate: AVERIN_MIGRATION_DATABASE_URL is required")
	}
	var oldRoles []string
	for _, role := range strings.Split(*old, ",") {
		if role == "" {
			continue
		}
		oldRoles = append(oldRoles, strings.TrimSpace(role))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if *init {
		if *purge || *old != "" || *next != "" {
			log.Fatal("averin-migrate: --init cannot combine with cutover or purge flags")
		}
		if err := pgschema.Migrate(ctx, dsn); err != nil {
			log.Fatalf("averin-migrate: fresh initialization refused: %v", err)
		}
		log.Printf("averin-migrate: fresh database initialized at version %d; grant new least-privilege runtime access before starting the server", pgschema.CurrentSchemaVersion)
		return
	}
	if *purge {
		n, err := pgschema.PurgeLegacy(ctx, dsn, oldRoles, strings.TrimSpace(*next))
		if err != nil {
			log.Fatalf("averin-migrate: purge refused: %v", err)
		}
		log.Printf("averin-migrate: removed %d expired legacy exclusions", n)
		return
	}
	if err := pgschema.Cutover(ctx, dsn, oldRoles, strings.TrimSpace(*next)); err != nil {
		log.Fatalf("averin-migrate: cutover refused: %v", err)
	}
	log.Printf("averin-migrate: schema at version %d; verify new-runtime readiness before reopening traffic", pgschema.CurrentSchemaVersion)
}
