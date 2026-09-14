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

	// Then: CL26-1(第 26 轮审计)——status 移出语义列,纯状态迁移不再 bump;
	// 材料 bump 由 INSERT 触发器(种子 INSERT 已含 cert_pem/key_pem)负责
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after pending to issued=%d, want 0 (status-only, CL26-1)", got)
	}
}

// CL25-1+CL26-1(第 25/26 轮审计):cert_jobs UPDATE 触发器簿记抖动守卫——
// 签发/续期阶段写(message/attempts/updated_at 等簿记列)不 bump 集群版本;
// 语义列(rule_id/domain/cert_pem/key_pem/expires_at/ca_provider_id——CL26-1
// 起 status 移出,仅 disabled 例外)值真实变化才 bump。
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

	// When: 语义列写(expires_at 推进=续期材料变化,CL26-1 后 status 不再是语义列)
	if _, err := database.Exec("UPDATE cert_jobs SET expires_at=datetime('now','+90 days') WHERE rule_id='book_rule'"); err != nil {
		t.Fatalf("semantic write: %v", err)
	}

	// Then: 版本 bump
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after semantic write=%d, want 1", got)
	}
}

// CL26-1(第 26 轮审计):status 移出语义列——续期/签发中间态迁移不 bump
// (成员条件恒真时阶段写是纯簿记);材料变化(cert_pem/expires_at)才 bump。
func TestClusterVersionTriggers_certJobsStatusTransitionDoesNotBump(t *testing.T) {
	database := newClusterVersionTestDB(t)
	certPEM, keyPEM := clusterVersionCertificatePair(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('renew_rule','example.com','issued',?,?,datetime('now','+30 days'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed issued certificate: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}

	// When: 中间态迁移(续期排队——成员条件恒真,纯簿记)
	if _, err := database.Exec("UPDATE cert_jobs SET status='queued' WHERE rule_id='renew_rule'"); err != nil {
		t.Fatalf("intermediate status: %v", err)
	}
	// Then: 不 bump
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after intermediate status=%d, want 0 (CL26-1)", got)
	}

	// When: 材料变化(续期完成——expires_at 推进;cert_pem 用固定测试证书
	// 两次生成相同,改用 expires_at 语义列模拟材料变化)
	if _, err := database.Exec(`UPDATE cert_jobs SET expires_at=datetime('now','+90 days'), status='issued' WHERE rule_id='renew_rule'`); err != nil {
		t.Fatalf("material change: %v", err)
	}
	// Then: bump(材料变化)
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after material change=%d, want 1", got)
	}
}

// CL27-P2-1(第 27 轮审计):disabled 例外单向——恢复方向(disabled→成员态)
// 不 bump 会导致从端定格「规则启用+证书缺席」。必须双向。
func TestClusterVersionTriggers_certJobsReenableFromDisabledBumps(t *testing.T) {
	database := newClusterVersionTestDB(t)
	certPEM, keyPEM := clusterVersionCertificatePair(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('reenable_rule','example.com','disabled',?,?,datetime('now','+30 days'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed disabled certificate: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}

	// When: disabled→issued(恢复——材料不变,纯 status 迁移)
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='reenable_rule'"); err != nil {
		t.Fatalf("reenable: %v", err)
	}

	// Then: 必须 bump(从端需要感知恢复)
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after reenable from disabled=%d, want 1 (bidirectional disabled exception, CL27-P2-1)", got)
	}
}
