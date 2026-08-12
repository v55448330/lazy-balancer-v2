package services

import (
	"context"
	"encoding/json"
	"testing"
)

func TestClusterSync_rateLimitResponseRoundTrips(t *testing.T) {
	// Given a master with a rate-limited policy using the block-page response
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,rate_limit_enabled,rate_limit_rps,rate_limit_burst,rate_limit_response,enabled) VALUES (5,'rl-policy','off',1,100,50,'block_page',1)`); err != nil {
		t.Fatal(err)
	}

	// When the snapshot is taken
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then the snapshot carries rate_limit_response
	var policies []map[string]interface{}
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatalf("parse security policies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("policies=%d, want 1", len(policies))
	}
	if got := snapshotScalarString(policies[0]["rate_limit_response"]); got != "block_page" {
		t.Fatalf("snapshot rate_limit_response=%q, want block_page", got)
	}

	// When the slave wipes its table and applies the snapshot
	if _, err := database.Exec("DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then the column round-trips with its value intact
	var response string
	var rps, burst int
	if err := database.QueryRow("SELECT rate_limit_response, rate_limit_rps, rate_limit_burst FROM security_policies WHERE id=5").Scan(&response, &rps, &burst); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if response != "block_page" || rps != 100 || burst != 50 {
		t.Fatalf("round trip = (%q,%d,%d), want (block_page,100,50)", response, rps, burst)
	}
}
