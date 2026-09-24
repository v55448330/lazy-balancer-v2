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
	if _, err := database.Exec(`CREATE TABLE path_rules (id INTEGER PRIMARY KEY, rule_id TEXT, sort_order INTEGER, match_type TEXT, path TEXT, upstream_path TEXT NOT NULL DEFAULT '', upstreams_json TEXT);
		INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstream_path,upstreams_json) VALUES (2,'lb_path',20,'exact','/second','/v2',NULL);
		INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstream_path,upstreams_json) VALUES (1,'lb_path',10,'prefix','/first','/v1','[{"address":"127.0.0.1","port":8080}]');`); err != nil {
		t.Fatal(err)
	}

	// When
	rules, err := LoadPathRules(context.Background(), database, "lb_path")

	// Then
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Path != "/first" || len(rules[0].Upstreams) != 1 || rules[0].Upstreams[0].Address != "127.0.0.1" || rules[0].Upstreams[0].Port != 8080 || rules[1].Path != "/second" {
		t.Fatalf("path rules=%#v", rules)
	}
	if rules[0].UpstreamPath != "/v1" || rules[1].UpstreamPath != "/v2" {
		t.Fatalf("upstream_path=(%q,%q), want (/v1,/v2)", rules[0].UpstreamPath, rules[1].UpstreamPath)
	}
}
