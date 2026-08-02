package middleware

import "testing"

func TestCertJobs_rejectsNullStatus(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)

	// When
	_, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('null_status_rule','example.com',NULL)`)

	// Then
	if err == nil {
		t.Fatal("cert_jobs accepted a null status")
	}
}

func TestClusterVersionTriggers_bumpWhenCertificateStatusTransitionsToIssued(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	certPEM, keyPEM := clusterVersionCertificatePair(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('pending_rule','example.com','pending',?,?,datetime('now','+30 days'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed pending certificate: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='pending_rule'"); err != nil {
		t.Fatalf("transition pending status to issued: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after pending to issued=%d, want 1", got)
	}
}
