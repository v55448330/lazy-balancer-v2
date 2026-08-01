package db

import (
	"context"
	"database/sql"
	"testing"
)

func TestLoadPathRulesDecodesUpstreamsAndSortsRows(t *testing.T) {
	// Given
	database, err := sql.Open("sqlite", t.TempDir()+"/paths.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TABLE path_rules (id INTEGER PRIMARY KEY, rule_id TEXT, sort_order INTEGER, match_type TEXT, path TEXT, upstreams_json TEXT);
		INSERT INTO path_rules VALUES (2,'lb_path',20,'exact','/second',NULL);
		INSERT INTO path_rules VALUES (1,'lb_path',10,'prefix','/first','[{"host":"127.0.0.1","port":8080}]');`); err != nil {
		t.Fatal(err)
	}

	// When
	rules, err := LoadPathRules(context.Background(), database, "lb_path")

	// Then
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Path != "/first" || len(rules[0].Upstreams) != 1 || rules[0].Upstreams[0].Port != 8080 || rules[1].Path != "/second" {
		t.Fatalf("path rules=%#v", rules)
	}
}
