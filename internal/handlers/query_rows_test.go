package handlers

import (
	"context"
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestDumpTableAndRowsByKeyShareRowConversion(t *testing.T) {
	// Given
	database, err := sql.Open("sqlite", t.TempDir()+"/rows.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	oldDB := db.DB
	db.DB = database
	t.Cleanup(func() { db.DB = oldDB })
	if _, err := database.Exec("CREATE TABLE sample_rows (id INTEGER PRIMARY KEY, payload BLOB); INSERT INTO sample_rows VALUES (1, x'616263')"); err != nil {
		t.Fatal(err)
	}

	// When
	allRows, err := dumpTable(context.Background(), database, "sample_rows")
	if err != nil {
		t.Fatal(err)
	}
	keyRows, err := dumpRowsByKey(context.Background(), "sample_rows", "id", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if len(allRows) != 1 || len(keyRows) != 1 || allRows[0]["payload"] != "abc" || keyRows[0]["payload"] != "abc" {
		t.Fatalf("all=%#v keyed=%#v", allRows, keyRows)
	}
}
