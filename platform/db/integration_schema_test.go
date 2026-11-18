//go:build integration

package db

import "testing"

// Ensures schema.sql + migrations leave the objects the application relies on
// (and records the latest embedded migration) on a real PostgreSQL instance.
func TestIntegrationSchemaMatchesMigrations(t *testing.T) {
	pg := integrationDB(t)
	if err := pg.verifySchema(); err != nil {
		t.Fatalf("verifySchema: %v", err)
	}
	items, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("no embedded migrations")
	}
	var applied int64
	if err := pg.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	latest := items[len(items)-1].Version
	if applied != latest {
		t.Fatalf("schema_migrations max=%d, latest embedded=%d", applied, latest)
	}
}
