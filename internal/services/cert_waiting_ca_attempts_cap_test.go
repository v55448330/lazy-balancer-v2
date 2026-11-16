package services

// CA 冷却补扫的重试上限门（与续期扫描 checkFailedFirstIssuance 同口径）：
// failed + 窗口到期但 renewal_attempts 已达 cert_renewal_attempts 上限的行
// 不得被 30s 补扫重排——配置下调（如 5→2）后，存量 attempts=3/4 且窗口非空
// 的行会绕过上限每 30s 白烧一次 CA 尝试。上限行仅手动重试可达。

import (
	"testing"
)

func TestRequeueWaitingCAJobs_attemptsCapGate(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)

	// Given：上限下调为 2；三行 failed + 窗口到期——attempts=1（未达上限，
	// 应重排）、attempts=2（恰达上限，不重排）、attempts=4（超上限，不重排）。
	if _, err := database.Exec(`UPDATE global_config SET cert_renewal_attempts=2 WHERE id=1`); err != nil {
		t.Fatalf("lower attempts cap: %v", err)
	}
	seedRuleWithCAProvider(t, "lb_cap_below", "cap-below.example.test", 1)
	seedRuleWithCAProvider(t, "lb_cap_at", "cap-at.example.test", 1)
	seedRuleWithCAProvider(t, "lb_cap_over", "cap-over.example.test", 1)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,renewal_attempts,ca_available_after,last_error_code,ca_provider_id) VALUES
		('lb_cap_below','cap-below.example.test','failed',1,datetime('now','-1 minute'),'429',1),
		('lb_cap_at','cap-at.example.test','failed',2,datetime('now','-1 minute'),'429',1),
		('lb_cap_over','cap-over.example.test','failed',4,datetime('now','-1 minute'),'429',1)`); err != nil {
		t.Fatalf("seed capped jobs: %v", err)
	}

	// When
	requeued, disabled, err := NewCertificateService().requeueWaitingCAJobs()
	if err != nil {
		t.Fatalf("补扫失败: %v", err)
	}

	// Then：仅未达上限行被重排；上限/超限行原样停留 failed（窗口保留，
	// 仅手动重试可达——与续期扫描上限分支同语义）。
	if requeued != 1 || disabled != 0 {
		t.Fatalf("requeued=%d disabled=%d, want 1/0（上限门只放行未达上限行）", requeued, disabled)
	}
	for _, tc := range []struct {
		ruleID     string
		wantStatus string
	}{
		{"lb_cap_at", "failed"},
		{"lb_cap_over", "failed"},
	} {
		var status string
		var windowOK bool
		if err := database.QueryRow(`SELECT status, ca_available_after IS NOT NULL FROM cert_jobs WHERE rule_id=?`, tc.ruleID).Scan(&status, &windowOK); err != nil {
			t.Fatalf("read %s: %v", tc.ruleID, err)
		}
		if status != tc.wantStatus || !windowOK {
			t.Fatalf("%s status=%q window=%v, want failed+窗口保留（上限行不得被补扫复活）", tc.ruleID, status, windowOK)
		}
	}
	// 未达上限行离开原到期窗口（queued+清空，或真实队列重消费后再失败——
	// 与 TestFailureSemantics_requeueWaitingCAJobs_failedWindowDue 同口径）。
	var belowStatus string
	var belowWindowOK bool
	var belowCode string
	if err := database.QueryRow(`SELECT status, ca_available_after IS NOT NULL, COALESCE(last_error_code,'') FROM cert_jobs WHERE rule_id='lb_cap_below'`).Scan(&belowStatus, &belowWindowOK, &belowCode); err != nil {
		t.Fatal(err)
	}
	switch {
	case belowStatus == "queued" && !belowWindowOK && belowCode == "":
	case belowStatus == "failed" && belowWindowOK && belowCode == "issuance_failed":
	default:
		t.Fatalf("未达上限行 status=%q window=%v code=%q, want 离开原到期窗口", belowStatus, belowWindowOK, belowCode)
	}
}
