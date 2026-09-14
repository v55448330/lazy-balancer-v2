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

// CL25-1(第 25 轮审计):cert_jobs UPDATE 触发器簿记抖动守卫——
// 签发/续期阶段写(message/attempts/updated_at 等簿记列)不 bump 集群版本;
// 语义列(rule_id/domain/status/cert_pem/key_pem/expires_at/ca_provider_id)
// 值真实变化才 bump。
func TestClusterVersionTriggers_certJobsBookkeepingDoesNotBump(t *testing.T) {
	// Given: 有效证书任务(成员条件满足)
	database := newClusterVersionTestDB(t)
	certPEM, keyPEM := clusterVersionCertificatePair(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('book_rule','example.com','issued',?,?,datetime('now','+30 days'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed issued certificate: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}

	// When: 簿记列写(message/renewal_attempts/deployment_attempts/updated_at)
	if _, err := database.Exec(`UPDATE cert_jobs SET message='阶段簿记', renewal_attempts=3, deployment_attempts=2, updated_at=datetime('now') WHERE rule_id='book_rule'`); err != nil {
		t.Fatalf("bookkeeping write: %v", err)
	}

	// Then: 版本不 bump
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after bookkeeping write=%d, want 0 (bookkeeping must not bump)", got)
	}

	// When: 语义列写(status 变化)
	if _, err := database.Exec("UPDATE cert_jobs SET status='downloaded' WHERE rule_id='book_rule'"); err != nil {
		t.Fatalf("semantic write: %v", err)
	}

	// Then: 版本 bump
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after semantic write=%d, want 1", got)
	}
}
