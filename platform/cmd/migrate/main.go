// Command migrate reports applied schema migrations and can roll numbered
// migrations back. Apply-up is automatic on platform startup.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Autumn-27/protocol-agent/db"
)

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL DSN (default: config/env)")
	statusOnly := flag.Bool("status", false, "print applied migrations only")
	downTo := flag.Int64("down-to", -1, "roll back migrations above this version; -1 = no rollback")
	flag.Parse()
	if *dsn == "" {
		resolved, _, err := db.DSN()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		*dsn = resolved
	}
	pg, err := db.Open(*dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer pg.Close()
	ctx := context.Background()
	if !*statusOnly && *downTo >= 0 {
		if err := pg.MigrateDown(ctx, *downTo); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	rows, err := pg.SchemaMigrationStatus(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(map[string]any{"migrations": rows}, "", "  ")
	fmt.Println(string(out))
}
