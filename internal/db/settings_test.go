package db

import (
	"database/sql"
	"strings"
	"testing"
)

func TestSetDefaultCAProvider(t *testing.T) {
	tests := []struct {
		name      string
		seedRow   bool
		wantID    int
		wantError string
	}{
		{name: "updates singleton row", seedRow: true, wantID: 7},
		{name: "rejects missing singleton row", wantID: 7, wantError: "global_config row not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, err := sql.Open("sqlite", t.TempDir()+"/settings.db")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			oldDB := DB
			DB = database
			defer func() { DB = oldDB }()
			if _, err := database.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, default_ca_provider_id INTEGER, updated_at DATETIME)"); err != nil {
				t.Fatalf("create global config: %v", err)
			}
			if tt.seedRow {
				if _, err := database.Exec("INSERT INTO global_config (id) VALUES (1)"); err != nil {
					t.Fatalf("seed global config: %v", err)
				}
			}

			err = SetDefaultCAProvider(tt.wantID)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error=%v, want containing %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("set default CA provider: %v", err)
			}
			got, err := GetDefaultCAProvider()
			if err != nil {
				t.Fatalf("get default CA provider: %v", err)
			}
			if got != tt.wantID {
				t.Fatalf("default CA provider=%d, want %d", got, tt.wantID)
			}
		})
	}
}
