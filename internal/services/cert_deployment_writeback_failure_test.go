package services

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 部署失败的状态回写本身失败（瞬时 DB 故障/CAS 冲突）时，任务行与内存调度
// 必须仍可收敛：窗口列由独立簿记 UPDATE 推进（30s 补扫只收非 NULL 窗口），
// 重试 timer 与 DB 状态解耦登记。否则行停在「downloaded + 窗口 NULL」，
// 补扫/对账/恢复都不收，HTTPS 规则静默不可用直到重启或升主。

const deploymentWritebackRuleID = "lb_deploy_writeback"

func seedDeploymentWritebackJob(t *testing.T) (database *sql.DB, jobID int) {
	t.Helper()
	_, database = newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'deploy-writeback', 'writeback.example.com', 'http', 8443, 1, 1, 'acme_dns')`, deploymentWritebackRuleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,expires_at,deployment_available_after,updated_at)
		VALUES (?, 'writeback.example.com', 'downloaded', 0, 'cert', 'key', datetime('now','+60 days'), NULL, datetime('now'))`, deploymentWritebackRuleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return database, int(id)
}

func deploymentTestMaterial() issuedCertificate {
	return issuedCertificate{
		ruleID:     deploymentWritebackRuleID,
		certPEM:    "cert",
		keyPEM:     "key",
		notAfter:   time.Now().Add(60 * 24 * time.Hour),
		providerID: 0,
	}
}

// waitDeploymentRetry 等待异步重试登记（deploymentFailed 起独立 goroutine）。
func waitDeploymentRetry(t *testing.T, scheduled <-chan int) int {
	t.Helper()
	select {
	case id := <-scheduled:
		return id
	case <-time.After(2 * time.Second):
		t.Fatal("deployment failure did not register a retry")
		return 0
	}
}

func TestCertIssuer_deploymentFailed_registersRetryWhenWritebackFails(t *testing.T) {
	// Given：部署失败回写本身失败（瞬时 DB 故障/CAS 冲突）
	database, jobID := seedDeploymentWritebackJob(t)
	original := deploymentFailureWriteback
	deploymentFailureWriteback = func(jobTransitionExecutor, int, []string, string, map[string]any) error {
		return errors.New("database is locked")
	}
	t.Cleanup(func() { deploymentFailureWriteback = original })

	scheduled := make(chan int, 1)
	issuer := &CertIssuer{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}}

	// When
	err := issuer.deploymentFailed(jobID, deploymentTestMaterial(), "写文件失败", errors.New("disk full"))

	// Then：仍返回部署类错误
	var deployErr *certificateDeploymentError
	if !errors.As(err, &deployErr) {
		t.Fatalf("error=%v, want certificateDeploymentError", err)
	}

	// 重试 timer 与回写解耦：必须照常登记（回调会重读行状态，胜者已推进时自然 no-op）
	if got := waitDeploymentRetry(t, scheduled); got != jobID {
		t.Fatalf("scheduled job=%d, want %d", got, jobID)
	}

	// 窗口列由独立簿记 UPDATE 推进——补扫的 downloaded 分支只收非 NULL 窗口
	var status, message string
	var availableAfter sql.NullString
	if err := database.QueryRow("SELECT status, COALESCE(message,''), deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if !availableAfter.Valid || availableAfter.String == "" {
		t.Fatalf("deployment_available_after=%v, want advanced by best-effort writeback", availableAfter)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded", status)
	}
	if len(message) == 0 {
		t.Fatal("message empty, want deployment failure reason persisted")
	}
}

func TestCertIssuer_deploymentFailedFrom_acceptsIssuedForFastPath(t *testing.T) {
	// 快速重部署链的进度写（issued→downloaded）可能未落库，失败回写必须能
	// 从 issued 收敛；常规部署链保持原 from 集合（并发胜者已提交 issued 时
	// 不得把成功结果拉回部署生命周期）。
	database, jobID := seedDeploymentWritebackJob(t)
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued', deployment_available_after=NULL WHERE id=?", jobID); err != nil {
		t.Fatalf("mark issued: %v", err)
	}

	scheduled := make(chan int, 2)
	issuer := &CertIssuer{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}}

	// When：常规链（不含 issued）——CAS 冲突，行不得被改动
	_ = issuer.deploymentFailed(jobID, deploymentTestMaterial(), "重载失败", errors.New("caddy 503"))

	var status string
	var availableAfter sql.NullString
	if err := database.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "issued" || availableAfter.Valid {
		t.Fatalf("status=%q window=%v, want issued with NULL window（并发胜者状态不得被拉回）", status, availableAfter)
	}

	// When：快速重部署链（含 issued）——必须回落到可重试的部署生命周期
	_ = issuer.deploymentFailedFrom(jobID, deploymentTestMaterial(), "重载失败", errors.New("caddy 503"), deploymentFailureFromStatuses(true))

	if err := database.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded after fast-path failure writeback", status)
	}
	if !availableAfter.Valid || availableAfter.String == "" {
		t.Fatalf("deployment_available_after=%v, want retry window", availableAfter)
	}
}

// 部署前置确认拒绝（行不在部署生命周期）必须仍能落材料+登记重试：ACME 材料
// 已签发完成，但 downloaded 进度写因瞬时 DB 故障未落库时行停在 active 签发态。
// 收窄的回写源态集会让首查 0 行提前返回——材料只存在内存、任务滞留 active 且
// 补扫/恢复/续期全都收不到，只能重启或手动重试（白烧一次 CA 订单）。
func TestCertIssuer_deploymentFailed_recoversActiveIssuanceStatus(t *testing.T) {
	// Given：行停在 active 签发态、材料仅在内存
	database, jobID := seedDeploymentWritebackJob(t)
	if _, err := database.Exec("UPDATE cert_jobs SET status='downloading', cert_pem='', key_pem='', expires_at=NULL, deployment_available_after=NULL WHERE id=?", jobID); err != nil {
		t.Fatalf("mark downloading: %v", err)
	}
	useTemporaryCertJobLogDir(t)
	scheduled := make(chan int, 2)
	issuer := &CertIssuer{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}}

	// When
	err := issuer.deploymentFailed(jobID, deploymentTestMaterial(), "部署确认失败", errors.New("confirm failed"))

	// Then：部署类错误（不当签发失败处理）+ 重试登记 + 材料落库 + 状态转可部署
	var deployErr *certificateDeploymentError
	if !errors.As(err, &deployErr) {
		t.Fatalf("error=%v, want certificateDeploymentError", err)
	}
	if got := waitDeploymentRetry(t, scheduled); got != jobID {
		t.Fatalf("scheduled job=%d, want %d", got, jobID)
	}
	var status, certPEM, keyPEM, expiresAt, availableAfter string
	if err := database.QueryRow(`SELECT status, COALESCE(cert_pem,''), COALESCE(key_pem,''), COALESCE(expires_at,''), COALESCE(deployment_available_after,'')
		FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &certPEM, &keyPEM, &expiresAt, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" || certPEM != "cert" || keyPEM != "key" || expiresAt == "" || availableAfter == "" {
		t.Fatalf("job=(%q,%q,%q,expires=%q,window=%q), want downloaded + 材料落库 + 窗口推进", status, certPEM, keyPEM, expiresAt, availableAfter)
	}
	// 失败必须落 certjob 日志（该路径此前静默）
	data, readErr := os.ReadFile(CertJobLogPath(deploymentWritebackRuleID))
	if readErr != nil {
		t.Fatalf("read cert job log: %v", readErr)
	}
	if !strings.Contains(string(data), "deployment_failed") {
		t.Fatalf("cert job log 缺部署失败行: %s", string(data))
	}
}

// 「行不在可回写集合」必须显式留痕：行已不存在或停在终态/由队列维护时材料
// 不落库是正确的（无归属），但静默返回会让排障无法从 certjob 日志还原时间线。
func TestCertIssuer_deploymentFailed_logsWhenNoWritableRow(t *testing.T) {
	database, jobID := seedDeploymentWritebackJob(t)
	if _, err := database.Exec("UPDATE cert_jobs SET status='queued' WHERE id=?", jobID); err != nil {
		t.Fatalf("mark queued: %v", err)
	}
	useTemporaryCertJobLogDir(t)
	issuer := &CertIssuer{deploymentRetry: func(int, issuedCertificate, time.Duration) error { return nil }}

	err := issuer.deploymentFailed(jobID, deploymentTestMaterial(), "部署失败", errors.New("disk full"))

	var deployErr *certificateDeploymentError
	if !errors.As(err, &deployErr) {
		t.Fatalf("error=%v, want certificateDeploymentError", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（队列维护的状态不得被部署回写改写）", status)
	}
	data, readErr := os.ReadFile(CertJobLogPath(deploymentWritebackRuleID))
	if readErr != nil {
		t.Fatalf("read cert job log: %v", readErr)
	}
	if !strings.Contains(string(data), "deployment_failed_no_row") {
		t.Fatalf("cert job log 缺「无处回写」行: %s", string(data))
	}
}

// 部署前置落库的 CAS 冲突必须按「重读状态」归因：并发胜者已提交终态时保持 raw
// （材料陈旧），行仍非终态时是自身进度写丢失——必须落材料+登记重试，不得让
// 队列把它当签发失败打成终态并丢材料。
func TestCertIssuer_deployIssuedCertificate_classifiesPersistConflict(t *testing.T) {
	useTemporaryCertJobLogDir(t)
	original := deploymentPersistenceWriteback
	t.Cleanup(func() { deploymentPersistenceWriteback = original })

	t.Run("并发胜者已提交终态保持 raw", func(t *testing.T) {
		jobID, ruleID := seedCertificateJob(t, "downloaded")
		useTemporaryCertDir(t)
		deploymentPersistenceWriteback = func(executor jobTransitionExecutor, id int, _ []string, _ string, _ map[string]any) error {
			if _, err := executor.Exec("UPDATE cert_jobs SET status='issued' WHERE id=?", id); err != nil {
				t.Fatalf("simulate concurrent winner: %v", err)
			}
			return ErrJobTransitionConflict
		}
		scheduled := make(chan int, 1)
		issuer := NewCertIssuer(nil)
		issuer.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
			scheduled <- id
			return nil
		}
		material := issuedCertificate{ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key", notAfter: time.Now().Add(90 * 24 * time.Hour)}

		err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

		if err == nil {
			t.Fatal("deployment returned nil on persist conflict")
		}
		var deployErr *certificateDeploymentError
		if errors.As(err, &deployErr) {
			t.Fatalf("error=%v, want raw（并发胜者路径不得进入部署重试链）", err)
		}
		// 同步可观测：上方 errors.As 断言已证返回是 raw 错误——部署失败重试登记
		// 的唯一入口 deploymentFailed 未被进入（其返回必为
		// certificateDeploymentError），登记经独立 goroutine 也无从发生；此处
		// 非阻塞核查缓冲通道即可，固定观测窗在负载下会假绿。
		select {
		case id := <-scheduled:
			t.Fatalf("job %d 被登记部署重试，want 无（胜者已提交）", id)
		default:
		}
		var status, certPEM string
		if err := db.DB.QueryRow("SELECT status, COALESCE(cert_pem,'') FROM cert_jobs WHERE id=?", jobID).Scan(&status, &certPEM); err != nil {
			t.Fatalf("read job: %v", err)
		}
		if status != "issued" || certPEM != "" {
			t.Fatalf("job=(%q,%q), want 胜者状态 issued 且材料未被陈旧回调覆写", status, certPEM)
		}
	})

	t.Run("自身进度写丢失落材料并重试", func(t *testing.T) {
		jobID, ruleID := seedCertificateJob(t, "downloaded")
		useTemporaryCertDir(t)
		deploymentPersistenceWriteback = func(jobTransitionExecutor, int, []string, string, map[string]any) error {
			return ErrJobTransitionConflict
		}
		scheduled := make(chan int, 1)
		issuer := NewCertIssuer(nil)
		issuer.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
			scheduled <- id
			return nil
		}
		material := issuedCertificate{ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key", notAfter: time.Now().Add(90 * 24 * time.Hour)}

		err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

		var deployErr *certificateDeploymentError
		if !errors.As(err, &deployErr) {
			t.Fatalf("error=%v, want certificateDeploymentError（非终态冲突须走材料保留链）", err)
		}
		if got := waitDeploymentRetry(t, scheduled); got != jobID {
			t.Fatalf("scheduled job=%d, want %d", got, jobID)
		}
		var status, certPEM string
		var availableAfter sql.NullString
		if err := db.DB.QueryRow("SELECT status, COALESCE(cert_pem,''), deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &certPEM, &availableAfter); err != nil {
			t.Fatalf("read job: %v", err)
		}
		if status != "downloaded" || certPEM != "new-cert" || !availableAfter.Valid {
			t.Fatalf("job=(%q,%q,window=%v), want downloaded + 材料落库 + 窗口推进", status, certPEM, availableAfter)
		}
	})
}

// useTemporaryCertJobLogDir 把证书任务日志重定向到临时目录（失败路径的
// certjob-*.log 断言不得写真实日志根）。
func useTemporaryCertJobLogDir(t *testing.T) string {
	t.Helper()
	oldDir := taskengine.LogDir()
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldDir) })
	return filepath.Join(dir, "certjobs")
}

func TestCertificateService_rescanPicksUpNullDeploymentWindowAfterSettle(t *testing.T) {
	// Given：部署失败回写未落库（窗口 NULL）且已过沉降阈值
	database, jobID := seedDeploymentWritebackJob(t)
	if _, err := database.Exec("UPDATE cert_jobs SET updated_at=datetime('now','-1 hour') WHERE id=?", jobID); err != nil {
		t.Fatalf("age job: %v", err)
	}
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	scheduled := make(chan int, 4)
	service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}

	// When
	rescheduled, err := service.rescanDroppedDeploymentRetries()

	// Then：必须被补扫接管
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if rescheduled != 1 {
		t.Fatalf("rescheduled=%d, want 1", rescheduled)
	}
	if got := waitDeploymentRetry(t, scheduled); got != jobID {
		t.Fatalf("scheduled job=%d, want %d", got, jobID)
	}

	// Given：同一行退回「窗口 NULL 且刚更新」——部署正在主路径执行的正常形态
	if _, err := database.Exec("UPDATE cert_jobs SET deployment_available_after=NULL, updated_at=datetime('now') WHERE id=?", jobID); err != nil {
		t.Fatalf("reset window: %v", err)
	}

	// When：沉降阈值内补扫
	rescheduled, err = service.rescanDroppedDeploymentRetries()

	// Then：不得与主部署路径抢同一任务
	if err != nil {
		t.Fatalf("rescan fresh: %v", err)
	}
	if rescheduled != 0 {
		t.Fatalf("rescheduled=%d, want 0（沉降阈值内的 NULL 窗口属主路径执行中）", rescheduled)
	}
	// 同步可观测：返回计数=0 之外直查在册 timer 集（防「计数谎报 + 短延迟
	// timer 异步触发」形态），非阻塞核查回调通道；固定观测窗判「没发生」
	// 在负载下会假绿。
	service.timerMu.Lock()
	_, hasTimer := service.deploymentTimers[jobID]
	service.timerMu.Unlock()
	if hasTimer {
		t.Fatalf("fresh NULL-window job %d got a deployment timer registered", jobID)
	}
	select {
	case id := <-scheduled:
		t.Fatalf("fresh NULL-window job %d scheduled too early", id)
	default:
	}
}
