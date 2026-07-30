package middleware

import "testing"

func TestClusterVersionTriggers_bumpWhenCertificateStatusTransitionsBetweenNullAndIssued(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('null_status_rule','example.com',NULL)`); err != nil {
		t.Fatalf("seed certificate with null status: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='null_status_rule'"); err != nil {
		t.Fatalf("transition null status to issued: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after null to issued=%d, want 1", got)
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status=NULL WHERE rule_id='null_status_rule'"); err != nil {
		t.Fatalf("transition issued status to null: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("version after issued to null=%d, want 2", got)
	}
}
