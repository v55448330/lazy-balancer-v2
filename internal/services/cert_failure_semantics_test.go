package services

// B2：ACME 失败语义统一（waiting_ca 停车状态退役）。
//
// 目标语义（用户裁定，不可再改设计）：
//   - 429 与其它失败统一：任何签发失败都落 failed，不再产生 waiting_ca；
//   - 失败即：renewal_attempts+1、写 ca_available_after（429 用 Retry-After，
//     其余走 computeBackoff 1h/2h/3h 阶梯，同封顶 3h）、写 last_error_code、
//     写 message、写任务日志；达 cert_renewal_attempts 上限则窗口 NULL；
//   - 续签失败（旧行带旧材料）不得被 30s 部署补扫折回 issued；
//   - 30s 补扫改扫 failed+窗口到期并重新入队；
//   - certJobsActive 把 failed+窗口非空计入活跃；失败写窗后唤醒 cert-waiting-ca。

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// parseFailureWindow 解析库内 UTC 文本时刻（"2006-01-02 15:04:05"）。
func parseFailureWindow(t *testing.T, raw string) time.Time {
	t.Helper()
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", raw, time.UTC)
	if err != nil {
		t.Fatalf("parse ca_available_after %q: %v", raw, err)
	}
	return parsed
}

// assertFailureWindow 断言窗口与期望时点的偏差在 ±10 分钟内（写入时刻与断言
// 时刻的秒级差远小于容差；容差只用于吸收测试进程调度抖动）。
func assertFailureWindow(t *testing.T, got time.Time, want time.Duration) {
	t.Helper()
	deadline := time.Now().Add(want)
	diff := got.Sub(deadline)
	if diff < -10*time.Minute || diff > 10*time.Minute {
		t.Fatalf("ca_available_after=%s, want ~now+%s（偏差 %s 超容差）", got.Format(time.RFC3339), want, diff)
	}
}

// TestFailureSemantics_renewalAuthorizationFailure_landsFailedWithWindow（RED 1a）：
// 续签行（旧材料在库）在签发生命周期内授权失败 → failed + attempts=1 +
// 窗口≈now+1h（自有阶梯第一档）+ 旧材料原样保留 + 不产生 deployment_deferred
// 日志行。
func TestFailureSemantics_renewalAuthorizationFailure_landsFailedWithWindow(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	// certjob-*.log 断言写入临时日志根（不落真实日志目录）。
	useTemporaryCertJobLogDir(t)
	const ruleID = "lb_renew_fail"
	seedRuleWithCAProvider(t, ruleID, "renew-fail.example.test", 1)
	certPEM, keyPEM := certificatePairForDomains(t, time.Now().Add(-24*time.Hour), time.Now().Add(60*24*time.Hour), "renew-fail.example.test")
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id)
		VALUES (?,?,?,?,?,datetime('now','+60 days'),1)`, ruleID, "renew-fail.example.test", "validating", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("seed renewal job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	// When：非限流的授权失败走真实队列错误分派链。
	handleQueueExecutionError(int(jobID), errors.New("wait authorization: JWS verification failure"))

	// Then：failed + 次数 +1 + 阶梯窗口 + 材料保留。
	var status string
	var attempts int
	var windowRaw string
	var windowOK bool
	var storedCert, storedKey string
	var message string
	if err := database.QueryRow(`SELECT status, COALESCE(renewal_attempts,0), COALESCE(ca_available_after,''), ca_available_after IS NOT NULL, COALESCE(cert_pem,''), COALESCE(key_pem,''), COALESCE(message,'')
		FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &attempts, &windowRaw, &windowOK, &storedCert, &storedKey, &message); err != nil {
		t.Fatalf("read failed job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（waiting_ca 已退役，任何失败都落 failed）", status)
	}
	if attempts != 1 {
		t.Fatalf("renewal_attempts=%d, want 1", attempts)
	}
	if !windowOK {
		t.Fatal("ca_available_after 必须写入（非上限失败走 1h/2h/3h 阶梯）")
	}
	assertFailureWindow(t, parseFailureWindow(t, windowRaw), time.Hour)
	if storedCert != certPEM || storedKey != keyPEM {
		t.Fatal("失败不得触碰旧证书材料")
	}
	if !strings.Contains(message, "CA 签发失败") {
		t.Fatalf("message=%q, want 签发失败文案（不得折入部署延迟文案）", message)
	}
	logData, err := os.ReadFile(CertJobLogPath(ruleID))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	if strings.Contains(string(logData), "deployment_deferred") {
		t.Fatalf("失败路径不得产生 deployment_deferred 日志行:\n%s", logData)
	}
	if !strings.Contains(string(logData), "] failed - ") {
		t.Fatalf("失败必须落任务日志 failed 行:\n%s", logData)
	}
}

// TestFailureSemantics_cleanupLifecycleRenewalFailure_notDeploymentDeferred（RED 1b）：
// F1/F2 组合场景——签发中途的清理阶段把行带到 cleanup_dns（Downloaded 生命周期）
// 且旧行有旧材料时，续签失败必须落 failed，不得被「材料在身的部署生命周期」
// 判据降级为部署延迟、更不得被 30s 部署补扫折回 issued。
func TestFailureSemantics_cleanupLifecycleRenewalFailure_notDeploymentDeferred(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	const ruleID = "lb_renew_cleanup"
	seedRuleWithCAProvider(t, ruleID, "renew-cleanup.example.test", 1)
	certPEM, keyPEM := certificatePairForDomains(t, time.Now().Add(-24*time.Hour), time.Now().Add(60*24*time.Hour), "renew-cleanup.example.test")
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id)
		VALUES (?,?,?,?,?,datetime('now','+60 days'),1)`, ruleID, "renew-cleanup.example.test", "cleanup_dns", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("seed renewal job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	// When
	handleQueueExecutionError(int(jobID), errors.New("finalize order: 500 internal error"))

	// Then：failed 终态，30s 部署补扫不折回。
	var status string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（续签失败不是部署失败）", status)
	}
	if _, err := NewCertificateService().rescanDroppedDeploymentRetries(); err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatalf("reread job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("30s 部署补扫把失败行折回 %q——续签失败不得被当成部署失败", status)
	}
}

// TestFailureSemantics_rateLimitRetryAfter_cappedAt3h（RED 2）：429 → failed +
// 次数 +1 + 窗口取 Retry-After（超 3h 封顶）+ last_error_code='429'。
func TestFailureSemantics_rateLimitRetryAfter_cappedAt3h(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_rl_capped", "rl-capped.example.test", 1)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_rl_capped','rl-capped.example.test','finalizing',1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	handleQueueExecutionError(int(jobID), &CAProviderRateLimitError{RetryAfter: 24 * time.Hour, Reason: "too many certificates"})

	var status string
	var attempts int
	var windowRaw string
	var windowOK bool
	var errorCode string
	if err := database.QueryRow(`SELECT status, COALESCE(renewal_attempts,0), COALESCE(ca_available_after,''), ca_available_after IS NOT NULL, COALESCE(last_error_code,'')
		FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &attempts, &windowRaw, &windowOK, &errorCode); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || attempts != 1 {
		t.Fatalf("status=%q attempts=%d, want failed/1", status, attempts)
	}
	if !windowOK {
		t.Fatal("429 必须按 Retry-After 写退避窗口")
	}
	assertFailureWindow(t, parseFailureWindow(t, windowRaw), 3*time.Hour)
	if errorCode != "429" {
		t.Fatalf("last_error_code=%q, want 429", errorCode)
	}
}

// TestFailureSemantics_rateLimitRetryAfter_underCap（RED 2 补充）：未超封顶时
// 窗口原样取 Retry-After。
func TestFailureSemantics_rateLimitRetryAfter_underCap(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_rl_sub", "rl-sub.example.test", 1)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_rl_sub','rl-sub.example.test','finalizing',1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	handleQueueExecutionError(int(jobID), &CAProviderRateLimitError{RetryAfter: 30 * time.Minute, Reason: "limited"})

	var status string
	var windowRaw string
	var windowOK bool
	if err := database.QueryRow(`SELECT status, COALESCE(ca_available_after,''), ca_available_after IS NOT NULL FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &windowRaw, &windowOK); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（429 与其它失败同语义，不再停车 waiting_ca）", status)
	}
	if !windowOK {
		t.Fatal("窗口必须写入")
	}
	assertFailureWindow(t, parseFailureWindow(t, windowRaw), 30*time.Minute)
}

// TestFailureSemantics_maxAttempts_capsWindowToNull（RED 3）：达上限 → failed、
// ca_available_after NULL、message 含上限说明。
func TestFailureSemantics_maxAttempts_capsWindowToNull(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_cap", "cap.example.test", 1)
	if _, err := database.Exec(`UPDATE global_config SET cert_renewal_attempts=3 WHERE id=1`); err != nil {
		t.Fatalf("set attempts cap: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.Exec(`UPDATE global_config SET cert_renewal_attempts=? WHERE id=1`, db.DefaultCertRenewalAttempts)
	})
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,renewal_attempts,ca_provider_id)
		VALUES ('lb_cap','cap.example.test','validating',2,1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	handleQueueExecutionError(int(jobID), errors.New("wait authorization: timeout"))

	var status string
	var attempts int
	var windowOK bool
	var message string
	if err := database.QueryRow(`SELECT status, COALESCE(renewal_attempts,0), ca_available_after IS NOT NULL, COALESCE(message,'')
		FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &attempts, &windowOK, &message); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || attempts != 3 {
		t.Fatalf("status=%q attempts=%d, want failed/3", status, attempts)
	}
	if windowOK {
		t.Fatal("达上限后 ca_available_after 必须为 NULL（停止自动重试）")
	}
	if !strings.Contains(message, "已达到最大重试次数") {
		t.Fatalf("message=%q, want 含上限说明", message)
	}
}

// TestFailureSemantics_certJobsActive_countsFailedWithWindow（RED 4）。
func TestFailureSemantics_certJobsActive_countsFailedWithWindow(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after) VALUES
		('lb_active_cooling','cooling.example','failed',datetime('now','+1 hour')),
		('lb_active_capped','capped.example','failed',NULL),
		('lb_active_ok','ok.example','issued',NULL)`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}
	if !certJobsActive() {
		t.Fatal("failed + 窗口非空必须计入活跃（30s 补扫的在途信号）")
	}
	if _, err := database.Exec(`DELETE FROM cert_jobs WHERE rule_id='lb_active_cooling'`); err != nil {
		t.Fatal(err)
	}
	if certJobsActive() {
		t.Fatal("failed + 窗口 NULL（终态）不得计入活跃")
	}
}

// TestFailureSemantics_requeueWaitingCAJobs_failedWindowDue（RED 5）：补扫取出
// 「failed + 窗口到期」并重新入队（queued、窗口/错误码清空）；未到期不取。
func TestFailureSemantics_requeueWaitingCAJobs_failedWindowDue(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)

	seedRuleWithCAProvider(t, "lb_due", "due.example.test", 1)
	seedRuleWithCAProvider(t, "lb_future", "future.example.test", 1)
	dueRes, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,renewal_attempts,ca_available_after,last_error_code,ca_provider_id)
		VALUES ('lb_due','due.example.test','failed',1,datetime('now','-1 minute'),'429',1)`)
	if err != nil {
		t.Fatalf("seed due job: %v", err)
	}
	dueID, _ := dueRes.LastInsertId()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,renewal_attempts,ca_available_after,last_error_code,ca_provider_id)
		VALUES ('lb_future','future.example.test','failed',1,datetime('now','+1 hour'),'429',1)`); err != nil {
		t.Fatalf("seed future job: %v", err)
	}

	requeued, disabled, err := NewCertificateService().requeueWaitingCAJobs()
	if err != nil {
		t.Fatalf("补扫失败: %v", err)
	}
	if requeued != 1 || disabled != 0 {
		t.Fatalf("requeued=%d disabled=%d, want 1/0", requeued, disabled)
	}
	var status string
	var windowOK bool
	var errorCode string
	if err := database.QueryRow(`SELECT status, ca_available_after IS NOT NULL, COALESCE(last_error_code,'') FROM cert_jobs WHERE id=?`, dueID).Scan(&status, &windowOK, &errorCode); err != nil {
		t.Fatalf("read due job: %v", err)
	}
	// 重排后存在两个确定终态：①queued+双清空（尚未被队列重新消费）；
	// ②真实队列已消费并在预检失败后按统一失败语义再次落 failed（新窗口、
	// issuance_failed 错误码）——两者都以「离开原到期窗口」为前提，均可接受；
	// 其它形态（原窗口残留/无归因失败）才是缺陷。
	switch {
	case status == "queued" && !windowOK && errorCode == "":
	case status == "failed" && windowOK && errorCode == "issuance_failed":
	default:
		t.Fatalf("到期行 status=%q window=%v code=%q, want queued/清空 或 重消费后再失败（新窗口+issuance_failed）", status, windowOK, errorCode)
	}
	var futureStatus string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE rule_id='lb_future'`).Scan(&futureStatus); err != nil {
		t.Fatal(err)
	}
	if futureStatus != "failed" {
		t.Fatalf("未到期行 status=%q, want failed 原样保留", futureStatus)
	}
}

// TestFailureSemantics_CheckExpiration_failedWindowGate（RED 6）：候选不含
// 「failed + 窗口未来」，含窗口已到期的 failed 行。
func TestFailureSemantics_CheckExpiration_failedWindowGate(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_exp_future", "exp-future.example.test", 1)
	seedRuleWithCAProvider(t, "lb_exp_due", "exp-due.example.test", 1)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_available_after,ca_provider_id) VALUES
		('lb_exp_future','exp-future.example.test','failed',datetime('now','+5 days'),datetime('now','+2 hours'),1),
		('lb_exp_due','exp-due.example.test','failed',datetime('now','+5 days'),datetime('now','-1 minute'),1)`); err != nil {
		t.Fatalf("seed expiring jobs: %v", err)
	}

	jobs, _, err := NewCertificateService().CheckExpiration(context.Background())
	if err != nil {
		t.Fatalf("CheckExpiration: %v", err)
	}
	seen := map[int]bool{}
	for _, j := range jobs {
		seen[j.ID] = true
	}
	for _, j := range jobs {
		if j.RuleID == "lb_exp_future" {
			t.Fatalf("failed + 窗口未来的行不得进入续期候选（id=%d）", j.ID)
		}
	}
	if !seenByRule(t, "lb_exp_due", seen) {
		t.Fatalf("窗口已到期的 failed 行必须进入候选: %v", seen)
	}
}

// seenByRule 复查规则的任务行是否出现在续期候选里（按 rule_id 回查行 id）。
func seenByRule(t *testing.T, ruleID string, seen map[int]bool) bool {
	t.Helper()
	var jobID int
	if err := db.DB.QueryRow(`SELECT id FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&jobID); err != nil {
		t.Fatalf("read job id for %s: %v", ruleID, err)
	}
	return seen[jobID]
}

// TestFailureSemantics_firstIssuanceRetryUnchanged（RED 7）：首次签发失败
// （无材料）行为不变——failed + 次数 +1 + 30 分钟首发重试冷却（窗口列照写，
// 但首发重试通道仍按 updated_at+30min 判定）。
func TestFailureSemantics_firstIssuanceRetryUnchanged(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_first", "first.example.test", 1)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_first','first.example.test','creating_order',1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	handleQueueExecutionError(int(jobID), errors.New("no enabled DNS provider selected for rule"))

	var status string
	var attempts int
	var windowOK bool
	var expiresOK bool
	if err := database.QueryRow(`SELECT status, COALESCE(renewal_attempts,0), ca_available_after IS NOT NULL, expires_at IS NOT NULL
		FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &attempts, &windowOK, &expiresOK); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || attempts != 1 {
		t.Fatalf("status=%q attempts=%d, want failed/1", status, attempts)
	}
	if expiresOK {
		t.Fatal("首发失败行 expires_at 必须保持 NULL")
	}

	maxAttempts := getCertRenewalAttempts()
	// 刚失败：30 分钟首发冷却未到，不得进入自动重试。
	if jobs, _, err := NewCertificateService().checkFailedFirstIssuance(context.Background(), maxAttempts); err != nil {
		t.Fatalf("checkFailedFirstIssuance: %v", err)
	} else {
		for _, j := range jobs {
			if j.ID == int(jobID) {
				t.Fatal("首发失败后 30 分钟内不得进入自动重试候选")
			}
		}
	}
	// 冷却期满（回拨 updated_at）：照常进入首发重试（行为不变）。
	if _, err := database.Exec(`UPDATE cert_jobs SET updated_at=datetime('now','-31 minutes') WHERE id=?`, jobID); err != nil {
		t.Fatal(err)
	}
	jobs, _, err := NewCertificateService().checkFailedFirstIssuance(context.Background(), maxAttempts)
	if err != nil {
		t.Fatalf("checkFailedFirstIssuance after cooldown: %v", err)
	}
	found := false
	for _, j := range jobs {
		if j.ID == int(jobID) {
			found = true
		}
	}
	if !found {
		t.Fatal("首发冷却期满后必须进入自动重试候选（行为不变）")
	}
}

// rearmCertWaitingCAForTest 换入补扫唤醒记录器并返回还原函数（测试缝）。
func rearmCertWaitingCAForTest(f func(bool)) (restore func()) {
	prev := rearmCertWaitingCAAfterFailure
	rearmCertWaitingCAAfterFailure = f
	return func() { rearmCertWaitingCAAfterFailure = prev }
}

// TestFailureSemantics_failureWakesCertWaitingCA（RED 8）：失败写窗后唤醒
// cert-waiting-ca 补扫（测试缝断言）；达上限（窗口 NULL）不唤醒。
func TestFailureSemantics_failureWakesCertWaitingCA(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_wake", "wake.example.test", 1)

	var wakes []bool
	restore := rearmCertWaitingCAForTest(func(hasWork bool) {
		wakes = append(wakes, hasWork)
	})
	t.Cleanup(restore)

	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_wake','wake.example.test','validating',1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	handleQueueExecutionError(int(jobID), &CAProviderRateLimitError{RetryAfter: time.Hour, Reason: "limited"})

	if len(wakes) != 1 || wakes[0] != true {
		t.Fatalf("失败写窗后必须以 hasWork=true 唤醒 cert-waiting-ca: %v", wakes)
	}
}
