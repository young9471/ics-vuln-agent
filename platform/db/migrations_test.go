package db

import "testing"

func TestLoadMigrationsSorted(t *testing.T) {
	items, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) < 2 {
		t.Fatalf("expected at least 2 migrations, got %d", len(items))
	}
	for i, item := range items {
		if i > 0 && item.Version <= items[i-1].Version {
			t.Fatalf("migrations not sorted at %d", i)
		}
		if item.Up == "" || item.Down == "" {
			t.Fatalf("migration %d needs both up and down", item.Version)
		}
	}
}
