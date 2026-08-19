package services

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type CertificateService struct {
	mu                  sync.Mutex
	ctx                 context.Context
	cancel              context.CancelFunc
	done                chan struct{}
	recoverJobs         func(context.Context)
	deploymentRetry     func(int, issuedCertificate, time.Duration)
	timerMu             sync.Mutex
	deploymentTimers    map[int]*deploymentTimer
	deploymentCallbacks map[int]map[*deploymentTimer]struct{}
	timersPaused        bool
	stopping            bool
	retryDeployment     func(context.Context, int) error
	// cancelWaitTimeout 上限取消部署重试时的在途等待；0 走默认 30s。测试可覆盖。
	cancelWaitTimeout time.Duration
}

type deploymentTimer struct {
	timer    *time.Timer
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	ruleID   string
	canceled bool
}

var (
	certificateServiceMu sync.Mutex
	certificateService   *CertificateService
)

type certJobSnapshot struct {
	id                       int
	ruleID                   string
	domain                   string
	status                   string
	message                  sql.NullString
	expiresAt                sql.NullTime
	certPEM                  sql.NullString
	keyPEM                   sql.NullString
	caProviderID             int
	renewalAttempts          int
	caAvailableAfter         sql.NullTime
	lastErrorCode            sql.NullString
	deploymentAttempts       int
	deploymentAvailableAfter sql.NullTime
	createdAt                sql.NullTime
	updatedAt                sql.NullTime
}

// CertJobsSnapshot is an opaque cert_jobs restore point used to compensate a
// failed UpdateRule ACME enqueue after an UPSERT may have replaced old state.
type CertJobsSnapshot struct {
	ruleID string
	jobs   []certJobSnapshot
}

// SnapshotCertJobsForRule captures all cert_jobs rows for UpdateRule ACME
// enqueue compensation.
func SnapshotCertJobsForRule(ruleID string) (CertJobsSnapshot, error) {
	snapshot := CertJobsSnapshot{ruleID: ruleID}
	rows, err := db.DB.Query(`SELECT id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,
		renewal_attempts,ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at
		FROM cert_jobs WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return CertJobsSnapshot{}, fmt.Errorf("query certificate job snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var job certJobSnapshot
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.message, &job.expiresAt,
			&job.certPEM, &job.keyPEM, &job.caProviderID, &job.renewalAttempts, &job.caAvailableAfter,
			&job.lastErrorCode, &job.deploymentAttempts, &job.deploymentAvailableAfter, &job.createdAt, &job.updatedAt); err != nil {
			return CertJobsSnapshot{}, fmt.Errorf("scan certificate job snapshot: %w", err)
		}
		snapshot.jobs = append(snapshot.jobs, job)
	}
	if err := rows.Err(); err != nil {
		return CertJobsSnapshot{}, fmt.Errorf("iterate certificate job snapshot: %w", err)
	}
	return snapshot, nil
}

// RestoreCertJobsForRule restores UPSERT-overwritten rows and removes jobs
// created after SnapshotCertJobsForRule captured the rule state.
func RestoreCertJobsForRule(snapshot CertJobsSnapshot) error {
	return restoreCertJobsForRule(context.Background(), snapshot)
}

func restoreCertJobsForRule(ctx context.Context, snapshot CertJobsSnapshot) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin certificate job restore: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE rule_id=?", snapshot.ruleID); err != nil {
		return fmt.Errorf("clear certificate jobs for restore: %w", err)
	}
	for _, job := range snapshot.jobs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cert_jobs (id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,
			renewal_attempts,ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, job.id, job.ruleID, job.domain, job.status, job.message,
			job.expiresAt, job.certPEM, job.keyPEM, job.caProviderID, job.renewalAttempts, job.caAvailableAfter,
			job.lastErrorCode, job.deploymentAttempts, job.deploymentAvailableAfter, job.createdAt, job.updatedAt); err != nil {
			return fmt.Errorf("restore certificate job %d: %w", job.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit certificate job restore: %w", err)
	}
	return nil
}

func requeueCertJobsSnapshot(ctx context.Context, snapshot CertJobsSnapshot, manager *CAQueueManager) error {
	var ruleDomain string
	var enabled, enableTLS bool
	var tlsSource string
	if err := db.DB.QueryRowContext(ctx, `SELECT domain,IIF(enabled IN ('1',1),1,0),enable_tls,COALESCE(tls_source,'manual') FROM lb_rules WHERE caddy_id=?`, snapshot.ruleID).
		Scan(&ruleDomain, &enabled, &enableTLS, &tlsSource); err != nil {
		return fmt.Errorf("load rule for certificate job requeue: %w", err)
	}
	if !enabled || !enableTLS || tlsSource != "acme_dns" {
		return nil
	}
	canonicalRule, err := CanonicalACMEDomains(ruleDomain)
	if err != nil {
		return fmt.Errorf("canonicalize rule certificate domains: %w", err)
	}
	for _, job := range snapshot.jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if JobIsTerminal(job.status) {
			continue
		}
		canonicalJob, err := CanonicalACMEDomains(job.domain)
		if err != nil || canonicalJob != canonicalRule {
			continue
		}
		if err := manager.enqueueCompensation(job.caProviderID, job.id, job.ruleID, job.domain); err != nil {
			return fmt.Errorf("requeue restored certificate job %d: %w", job.id, err)
		}
	}
	return nil
}

func NewCertificateService() *CertificateService {
	ctx, cancel := context.WithCancel(context.Background())
	service := &CertificateService{
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		deploymentRetry:     scheduleCertificateDeploymentRetry,
		deploymentTimers:    make(map[int]*deploymentTimer),
		deploymentCallbacks: make(map[int]map[*deploymentTimer]struct{}),
	}
	service.retryDeployment = func(ctx context.Context, jobID int) error {
		manager := GetCAQueueManager()
		if manager == nil {
			return fmt.Errorf("Caddy reloader is not initialized")
		}
		manager.mu.Lock()
		reloader := manager.reloader
		manager.mu.Unlock()
		return retryCertificateDeployment(ctx, jobID, reloader)
	}
	service.recoverJobs = service.recoverCertJobs
	certificateServiceMu.Lock()
	certificateService = service
	certificateServiceMu.Unlock()
	return service
}

func (s *CertificateService) scheduleDeploymentRetry(jobID int, ruleID string, delay time.Duration) {
	for {
		s.timerMu.Lock()
		if s.stopping || s.timersPaused {
			s.timerMu.Unlock()
			return
		}
		if previous := s.deploymentTimers[jobID]; previous != nil {
			previous.canceled = true
			previous.cancel()
			stopped := previous.timer.Stop()
			delete(s.deploymentTimers, jobID)
			s.timerMu.Unlock()
			if stopped {
				close(previous.done)
			} else {
				<-previous.done
			}
			continue
		}
		entry := &deploymentTimer{done: make(chan struct{}), ruleID: ruleID}
		entry.ctx, entry.cancel = context.WithCancel(s.ctx)
		entry.timer = time.AfterFunc(delay, func() {
			s.timerMu.Lock()
			if s.deploymentTimers[jobID] == entry {
				delete(s.deploymentTimers, jobID)
			}
			callbacks := s.deploymentCallbacks[jobID]
			if callbacks == nil {
				callbacks = make(map[*deploymentTimer]struct{})
				s.deploymentCallbacks[jobID] = callbacks
			}
			callbacks[entry] = struct{}{}
			stopping := entry.canceled || s.stopping || s.timersPaused
			s.timerMu.Unlock()
			defer func() {
				s.timerMu.Lock()
				delete(s.deploymentCallbacks[jobID], entry)
				if len(s.deploymentCallbacks[jobID]) == 0 {
					delete(s.deploymentCallbacks, jobID)
				}
				s.timerMu.Unlock()
				close(entry.done)
			}()
			if stopping {
				return
			}
			if err := s.retryDeployment(entry.ctx, jobID); err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.Canceled) {
				log.Printf("certificate deployment retry failed for job %d: %v", jobID, err)
			}
		})
		s.deploymentTimers[jobID] = entry
		s.timerMu.Unlock()
		return
	}
}

func (s *CertificateService) cancelDeploymentRetry(jobID int) {
	s.timerMu.Lock()
	entry := s.deploymentTimers[jobID]
	var pendingDone <-chan struct{}
	if entry != nil {
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			delete(s.deploymentTimers, jobID)
			close(entry.done)
		} else {
			pendingDone = entry.done
		}
	}
	runningDone := make([]<-chan struct{}, 0, len(s.deploymentCallbacks[jobID]))
	for callback := range s.deploymentCallbacks[jobID] {
		callback.canceled = true
		callback.cancel()
		runningDone = append(runningDone, callback.done)
	}
	s.timerMu.Unlock()
	// 在途部署回调退出等待必须有界：回调链条最终调到 caddyReloader（非
	// context-aware），Caddy admin 请求异常挂起时 HTTP 调用方会被永久挂起；
	// 与 CAQueueManager.CancelJob 的 30s 上限同模式（R36 C-1 / R42 发现3）。
	waitTimeout := s.cancelWaitTimeout
	if waitTimeout <= 0 {
		waitTimeout = 30 * time.Second
	}
	if pendingDone != nil {
		select {
		case <-pendingDone:
		case <-time.After(waitTimeout):
			Logf("warn", "取消证书任务 %d：等待待定部署定时器退出超时（%s），继续后续流程", jobID, waitTimeout)
		}
	}
	for _, done := range runningDone {
		select {
		case <-done:
		case <-time.After(waitTimeout):
			Logf("warn", "取消证书任务 %d：等待在途部署回调退出超时（%s），继续后续流程", jobID, waitTimeout)
		}
	}
}

func (s *CertificateService) signalCancelDeploymentRetriesForRule(ruleID string) []<-chan struct{} {
	s.timerMu.Lock()
	waitFor := make(map[*deploymentTimer]struct{})
	for jobID, entry := range s.deploymentTimers {
		if entry.ruleID != ruleID {
			continue
		}
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			delete(s.deploymentTimers, jobID)
			close(entry.done)
		} else {
			waitFor[entry] = struct{}{}
		}
	}
	for _, callbacks := range s.deploymentCallbacks {
		for callback := range callbacks {
			if callback.ruleID == ruleID {
				callback.canceled = true
				callback.cancel()
				waitFor[callback] = struct{}{}
			}
		}
	}
	s.timerMu.Unlock()
	done := make([]<-chan struct{}, 0, len(waitFor))
	for entry := range waitFor {
		done = append(done, entry.done)
	}
	return done
}

func (s *CertificateService) pauseDeploymentRetries() {
	s.timerMu.Lock()
	s.timersPaused = true
	var waitFor []<-chan struct{}
	for jobID, entry := range s.deploymentTimers {
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			close(entry.done)
		} else {
			waitFor = append(waitFor, entry.done)
		}
		delete(s.deploymentTimers, jobID)
	}
	for _, callbacks := range s.deploymentCallbacks {
		for callback := range callbacks {
			callback.canceled = true
			callback.cancel()
			waitFor = append(waitFor, callback.done)
		}
	}
	s.timerMu.Unlock()
	for _, done := range waitFor {
		<-done
	}
}

func (s *CertificateService) resumeDeploymentRetries() {
	s.timerMu.Lock()
	if s.stopping {
		s.timerMu.Unlock()
		return
	}
	s.timersPaused = false
	s.timerMu.Unlock()
	s.rescanDroppedDeploymentRetries()
}

// rescanDroppedDeploymentRetries 重新调度暂停期间被丢弃的部署重试：暂停时
// scheduleDeploymentRetry 直接返回，'downloaded' 且窗口已过的任务只能靠启动
// 恢复重排；恢复暂停后补一次扫描，避免部署重试静默丢失直到进程重启。
func (s *CertificateService) rescanDroppedDeploymentRetries() {
	if db.DB == nil {
		return
	}
	rows, err := db.DB.Query(`
		SELECT j.id, COALESCE(j.rule_id,''), COALESCE(j.domain,''), COALESCE(j.ca_provider_id,0), COALESCE(j.deployment_attempts,0),
		       COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END,
		       CASE WHEN COALESCE(j.cert_pem,'') <> '' AND COALESCE(j.key_pem,'') <> '' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status='downloaded'
		  AND j.deployment_available_after IS NOT NULL
		  AND datetime(j.deployment_available_after) <= datetime('now')
	`)
	if err != nil {
		log.Printf("resume deployment retries: scan failed: %v", err)
		return
	}
	type droppedRetry struct {
		id, providerID, deploymentAttempts int
		ruleID, jobDomain, ruleDomain      string
		applicable, hasCertMaterial        bool
	}
	var jobs []droppedRetry
	for rows.Next() {
		var job droppedRetry
		if err := rows.Scan(&job.id, &job.ruleID, &job.jobDomain, &job.providerID, &job.deploymentAttempts, &job.ruleDomain, &job.applicable, &job.hasCertMaterial); err != nil {
			continue
		}
		jobs = append(jobs, job)
	}
	// 先关闭读迭代器再写库：SQLite 连接池上行迭代未结束时写入会触发 SQLITE_BUSY。
	if err := rows.Close(); err != nil {
		log.Printf("resume deployment retries: close rows failed: %v", err)
		return
	}
	for _, job := range jobs {
		if !job.hasCertMaterial || !certJobRuleApplicable(job.applicable, job.ruleDomain, job.jobDomain) {
			continue
		}
		s.deploymentRetry(job.id, issuedCertificate{ruleID: job.ruleID, providerID: job.providerID, deploymentAttempt: job.deploymentAttempts}, 0)
	}
}

func (s *CertificateService) Start() {
	defer close(s.done)
	// Recover any jobs left in non-terminal states from a previous run.
	s.recoverJobs(s.ctx)

	// Run renewal check shortly after startup, then every 6 hours.
	initialRenewal := time.NewTimer(30 * time.Second)
	renewalTicker := time.NewTicker(6 * time.Hour)
	manualTicker := time.NewTicker(10 * time.Minute)
	waitingCATicker := time.NewTicker(30 * time.Second)
	reconcileTicker := time.NewTicker(6 * time.Hour)
	defer initialRenewal.Stop()
	defer renewalTicker.Stop()
	defer manualTicker.Stop()
	defer waitingCATicker.Stop()
	defer reconcileTicker.Stop()
	for {
		select {
		case <-initialRenewal.C:
			s.renewExpiringCertificates()
		case <-renewalTicker.C:
			s.renewExpiringCertificates()
		case <-manualTicker.C:
			s.checkManualCertExpiration()
		case <-waitingCATicker.C:
			s.requeueWaitingCAJobs()
		case <-reconcileTicker.C:
			reconcileMissingCertFiles(db.DB)
			sweepOrphanedCertJobs(s.ctx)
		case <-s.ctx.Done():
			return
		}
	}
}

// requeueWaitingCAJobs re-enqueues cert jobs parked in 'waiting_ca' once
// their CA cooling period has elapsed. This covers first-time issuance jobs
// (expires_at IS NULL) that renewExpiringCertificates cannot see.
func (s *CertificateService) requeueWaitingCAJobs() {
	qm := GetCAQueueManager()
	if qm == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 与孤儿 sweep 同口径：规则删除/迁移/停用后的 waiting_ca 任务不得重排签发。
	rows, err := db.DB.Query(`
		SELECT j.id, j.rule_id, COALESCE(j.domain,''), j.ca_provider_id,
		       COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status = 'waiting_ca'
		  AND j.ca_available_after IS NOT NULL
		  AND datetime(j.ca_available_after) <= datetime('now')
	`)
	if err != nil {
		log.Printf("waiting_ca scan: query failed: %v", err)
		return
	}
	type waitingJob struct {
		id           int
		ruleID       string
		domain       string
		caProviderID int
		ruleDomain   string
		ruleBound    bool
	}
	var jobs []waitingJob
	for rows.Next() {
		var job waitingJob
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.caProviderID, &job.ruleDomain, &job.ruleBound); err != nil {
			continue
		}
		jobs = append(jobs, job)
	}
	// 先关闭读迭代器再写库：SQLite 连接池上行迭代未结束时 UPDATE 会触发 SQLITE_BUSY。
	if err := rows.Close(); err != nil {
		log.Printf("waiting_ca scan: close rows failed: %v", err)
		return
	}

	for _, job := range jobs {
		if !certJobRuleApplicable(job.ruleBound, job.ruleDomain, job.domain) {
			if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "disabled", map[string]any{"message": "关联规则已不再使用当前 ACME 证书任务"}); err != nil {
				if !errors.Is(err, ErrJobTransitionConflict) {
					log.Printf("waiting_ca scan: disable orphaned job %d failed: %v", job.id, err)
				}
				continue
			}
			RecordAuditLog("system", "禁用", "证书签发任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("ca_cooldown")), "")
			continue
		}
		_, changed, err := qm.EnqueueIfActive(job.caProviderID, job.id, job.ruleID, job.domain, func() (int, bool, error) {
			err := transitionJob(db.DB, job.id, []string{"waiting_ca"}, "queued", map[string]any{"message": "冷却结束，重新排队签发"})
			if errors.Is(err, ErrJobTransitionConflict) {
				return job.id, false, nil
			}
			return job.id, err == nil, err
		})
		if err != nil {
			log.Printf("waiting_ca scan: failed to requeue job %d: %v", job.id, err)
			continue
		}
		if !changed {
			continue
		}
		RecordAuditLog("system", "重新排队", "证书签发任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("ca_cooldown")), "")
	}
}

// recoverCertJobs re-enqueues cert jobs that were not in a terminal state when
// the process last exited. Jobs whose rule or CA provider no longer exist are
// marked as failed.
func (s *CertificateService) recoverCertJobs(ctx context.Context) {
	if err := requeueNonTerminalCertJobs(ctx, s.deploymentRetry); err != nil {
		log.Printf("Failed to recover non-terminal cert jobs: %v", err)
	}
}

// reconcileMissingCertFiles 巡检已签发（issued/downloaded）的 ACME 证书任务，若其磁盘
// 证书/私钥文件缺失，则从数据库 cert_pem/key_pem 重建，避免容器重建或磁盘清理后 Caddy
// 因缺证书文件而拒绝加载。仅覆盖 ACME 任务：手动证书内联在 lb_rules.tls_cert，由启动时
// MaterializeAllCertsFromDB 物化；本函数随证书服务（仅主节点）每 6 小时对账一次。
func reconcileMissingCertFiles(dbh *sql.DB) {
	rows, err := dbh.Query(`SELECT j.rule_id, j.domain, COALESCE(j.cert_pem,''), COALESCE(j.key_pem,'')
		FROM cert_jobs j
		WHERE j.status IN ('issued','downloaded')
		  AND COALESCE(j.cert_pem,'') <> '' AND COALESCE(j.key_pem,'') <> ''`)
	if err != nil {
		log.Printf("cert reconcile: query issued certificates failed: %v", err)
		return
	}
	defer rows.Close()
	rebuilt := 0
	for rows.Next() {
		var ruleID, domain, certPEM, keyPEM string
		if err := rows.Scan(&ruleID, &domain, &certPEM, &keyPEM); err != nil {
			log.Printf("cert reconcile: scan certificate row failed: %v", err)
			continue
		}
		certPath, keyPath := CertFilePaths(ruleID)
		if certPath == "" {
			continue
		}
		if fileExists(certPath) && fileExists(keyPath) {
			continue
		}
		if err := materializeCertPair(ruleID, certPEM, keyPEM); err != nil {
			log.Printf("cert reconcile: rebuild certificate files for %s failed: %v", ruleID, err)
			continue
		}
		rebuilt++
		log.Printf("证书文件缺失，已从数据库重建: %s", domain)
	}
	if err := rows.Err(); err != nil {
		log.Printf("cert reconcile: iterate issued certificates failed: %v", err)
	}
	if rebuilt > 0 {
		RecordAuditLog("system", "重建", "证书文件", FormatAuditDetail(AuditSourcePart("runtime_reconcile"), fmt.Sprintf("重建 %d 个证书文件", rebuilt)), "")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func RequeueNonTerminalCertJobs() error {
	return requeueNonTerminalCertJobs(context.Background(), scheduleCertificateDeploymentRetry)
}

func requeueNonTerminalCertJobs(ctx context.Context, deploymentRetry func(int, issuedCertificate, time.Duration)) error {
	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.domain, j.status, j.ca_provider_id, COALESCE(j.deployment_attempts,0), j.deployment_available_after,
		       COALESCE(r.domain,''), CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END,
		       CASE WHEN COALESCE(j.cert_pem,'') <> '' AND COALESCE(j.key_pem,'') <> '' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status != 'disabled'
		  AND (j.status != 'waiting_ca' OR j.ca_available_after IS NULL OR datetime(j.ca_available_after) <= datetime('now'))
	`)
	if err != nil {
		return fmt.Errorf("query non-terminal certificate jobs: %w", err)
	}
	type recoveryJob struct {
		id, providerID, deploymentAttempts int
		ruleID, domain, status, ruleDomain string
		deploymentAvailableAfter           sql.NullTime
		applicable, hasCertMaterial        bool
	}
	var jobs []recoveryJob
	for rows.Next() {
		var job recoveryJob
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.providerID, &job.deploymentAttempts, &job.deploymentAvailableAfter, &job.ruleDomain, &job.applicable, &job.hasCertMaterial); err != nil {
			rows.Close()
			return fmt.Errorf("scan non-terminal certificate job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate non-terminal certificate jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close non-terminal certificate jobs: %w", err)
	}
	renewalDays := 30
	_ = db.DB.QueryRowContext(ctx, "SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&renewalDays)
	if renewalDays <= 0 {
		renewalDays = 30
	}
	now := time.Now()
	selectedByRule := make(map[string]CertificateSelection)
	selectionLoaded := make(map[string]bool)

	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if JobIsTerminal(job.status) {
			// 失败任务不得在启动恢复时复活：即使它仍持有之前签发的有效证书，也不能
			// 被"检测到已有有效证书"分支拉回 issued。证书维持之前部署的版本，下一次
			// 尝试只能由续签巡检（CheckExpiration）或手动重签（RetryCertJob）驱动。
			continue
		}
		if job.applicable {
			job.applicable = certJobRuleApplicable(job.applicable, job.ruleDomain, job.domain)
		}
		if !job.applicable {
			if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "disabled", map[string]any{"message": "关联规则已不再使用当前 ACME 证书任务"}); err != nil {
				return fmt.Errorf("disable ineligible recovered certificate job %d: %w", job.id, err)
			}
			continue
		}
		if JobLifecycle(job.status) != JobLifecycleDownloaded {
			selection, loaded := selectedByRule[job.ruleID]
			if !selectionLoaded[job.ruleID] {
				selection, loaded, err = selectStoredRuleCertificate(ctx, job.ruleID, job.ruleDomain, now)
				if err != nil {
					return fmt.Errorf("select existing certificate for recovered job %d: %w", job.id, err)
				}
				selectionLoaded[job.ruleID] = true
				if loaded {
					selectedByRule[job.ruleID] = selection
				}
			}
			if loaded {
				canonicalSelected, selectedErr := CanonicalACMEDomains(selection.Candidate.Domain)
				canonicalRule, ruleErr := CanonicalACMEDomains(job.ruleDomain)
				if selectedErr == nil && ruleErr == nil && canonicalSelected == canonicalRule && selection.Certificate.NotAfter.After(now.Add(time.Duration(renewalDays)*24*time.Hour)) {
					if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "issued", map[string]any{"message": "检测到已有有效证书，跳过恢复签发"}); err != nil {
						return fmt.Errorf("complete recovered certificate job %d with existing certificate: %w", job.id, err)
					}
					continue
				}
			}
		}
		if JobLifecycle(job.status) == JobLifecycleDownloaded && job.hasCertMaterial {
			delay := time.Duration(0)
			if job.deploymentAvailableAfter.Valid {
				delay = time.Until(job.deploymentAvailableAfter.Time)
				if delay < 0 {
					delay = 0
				}
			}
			deploymentRetry(job.id, issuedCertificate{ruleID: job.ruleID, providerID: job.providerID, deploymentAttempt: job.deploymentAttempts}, delay)
			continue
		}

		if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "queued", map[string]any{"message": "等待排队签发"}); err != nil {
			return fmt.Errorf("queue recovered certificate job %d: %w", job.id, err)
		}
		RecordAuditLog("system", "恢复排队", "证书签发任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("startup_recovery")), "")
		qm := GetCAQueueManager()
		if qm == nil {
			return fmt.Errorf("CA queue manager not initialized")
		}
		if err := qm.Enqueue(job.providerID, job.id, job.ruleID, job.domain); err != nil {
			return fmt.Errorf("enqueue recovered certificate job %d: %w", job.id, err)
		}
	}
	return nil
}

// certJobRuleApplicable 判断证书任务是否仍被规则引用：规则存在、启用、开启 TLS 且
// 证书来源为 acme_dns（SQL CASE 结果，即 ruleBound），且任务域名与规则域名规范化后一致。
func certJobRuleApplicable(ruleBound bool, ruleDomain, jobDomain string) bool {
	if !ruleBound {
		return false
	}
	canonicalRule, ruleErr := CanonicalACMEDomains(ruleDomain)
	canonicalJob, jobErr := CanonicalACMEDomains(jobDomain)
	return ruleErr == nil && jobErr == nil && canonicalRule == canonicalJob
}

// sweepOrphanedCertJobs 禁用规则已不再引用的非终态证书任务（域名迁移/规则停用/删除后
// 遗留，启动恢复 requeueNonTerminalCertJobs 只在重启时处理一次），随 6 小时对账巡检执行，
// 避免孤儿任务滞留到重启或被 waiting_ca 重排队白白签发。
func sweepOrphanedCertJobs(ctx context.Context) {
	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.status, COALESCE(j.domain,''), COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status != 'disabled'
	`)
	if err != nil {
		log.Printf("cert sweep: query certificate jobs failed: %v", err)
		return
	}
	type orphanCandidate struct {
		id         int
		ruleID     string
		status     string
		jobDomain  string
		ruleDomain string
		ruleBound  bool
	}
	var orphans []orphanCandidate
	for rows.Next() {
		var job orphanCandidate
		if err := rows.Scan(&job.id, &job.ruleID, &job.status, &job.jobDomain, &job.ruleDomain, &job.ruleBound); err != nil {
			rows.Close()
			log.Printf("cert sweep: scan certificate job failed: %v", err)
			return
		}
		if JobIsTerminal(job.status) {
			continue
		}
		if !certJobRuleApplicable(job.ruleBound, job.ruleDomain, job.jobDomain) {
			orphans = append(orphans, job)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		log.Printf("cert sweep: iterate certificate jobs failed: %v", err)
		return
	}
	rows.Close()
	for _, job := range orphans {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "disabled", map[string]any{"message": "关联规则已不再使用当前 ACME 证书任务"}); err != nil {
			if errors.Is(err, ErrJobTransitionConflict) {
				continue
			}
			log.Printf("cert sweep: disable orphaned certificate job %d failed: %v", job.id, err)
			continue
		}
		RecordAuditLog("system", "禁用", "证书签发任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("runtime_sweep")), "")
	}
}

func (s *CertificateService) Stop() {
	s.timerMu.Lock()
	s.stopping = true
	s.timerMu.Unlock()
	s.pauseDeploymentRetries()
	s.cancel()
	<-s.done
}

// CreateOrRequeueCertJob creates a queued cert job for the rule and enqueues it.
// Uses an atomic INSERT ... ON CONFLICT to avoid races between concurrent callers.
func CreateOrRequeueCertJob(ruleID, domains string, caProviderID int, qm *CAQueueManager) (int, error) {
	jobID, changed, err := CreateOrRequeueCertJobWithChange(ruleID, domains, caProviderID, qm)
	if err != nil || changed {
		return jobID, err
	}
	if jobID > 0 && qm.IsJobActive(jobID) {
		return jobID, nil
	}
	return jobID, fmt.Errorf("certificate job %d was not queued", jobID)
}

func CreateOrRequeueCertJobWithChange(ruleID, domains string, caProviderID int, qm *CAQueueManager) (int, bool, error) {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return 0, false, fmt.Errorf("invalid ACME domains: %s", domains)
	}
	joined := strings.Join(list, ",")
	reversed := joined
	if len(list) == 2 {
		reversed = list[1] + "," + list[0]
	}

	// Defensive: if no explicit CA provider was supplied, use the rule's own
	// setting rather than falling back to the global default.
	if caProviderID == 0 {
		var ruleCA int
		if err := db.DB.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&ruleCA); err == nil && ruleCA != 0 {
			caProviderID = ruleCA
		}
	}
	log.Printf("CreateOrRequeueCertJob rule=%s domain=%s ca_provider_id=%d", ruleID, joined, caProviderID)

	if qm == nil {
		return 0, false, fmt.Errorf("CA queue manager not initialized")
	}
	jobID, changed, err := qm.EnqueueIfActive(caProviderID, 0, ruleID, joined, func() (int, bool, error) {
		var id int
		err := db.DB.QueryRow(`
			INSERT INTO cert_jobs (rule_id, domain, status, message, ca_provider_id)
			VALUES (?, ?, 'queued', '等待排队签发', ?)
			ON CONFLICT(rule_id, domain) DO UPDATE SET
				status = 'queued',
				message = '重新排队签发',
				renewal_attempts = 0,
				ca_available_after = NULL,
				last_error_code = NULL,
				ca_provider_id = excluded.ca_provider_id,
				updated_at = datetime('now')
			WHERE cert_jobs.status IN ('waiting_ca','issued','failed','downloaded')
			   OR (cert_jobs.status='disabled' AND EXISTS (
				SELECT 1 FROM lb_rules r
				WHERE r.caddy_id=cert_jobs.rule_id AND r.enabled=1 AND r.enable_tls=1
				  AND r.tls_source='acme_dns' AND lower(replace(r.domain,' ','')) IN (?,?)
			   ))
			RETURNING id
		`, ruleID, joined, caProviderID, joined, reversed).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id=? AND domain=?", ruleID, joined).Scan(&id); err != nil {
				return 0, false, err
			}
			return id, false, nil
		}
		return id, err == nil, err
	})
	if err != nil {
		return jobID, false, fmt.Errorf("create or enqueue cert job: %w", err)
	}
	if !changed {
		if jobID != 0 {
			return jobID, false, nil
		}
		return 0, false, fmt.Errorf("CA queue is paused")
	}
	return jobID, true, nil
}

// HasCertJob reports whether any certificate job row exists for the given
// rule and domain, regardless of status. It is used to avoid re-creating
// jobs when one already exists (in any state); the existing ON CONFLICT
// and queue/renewal logic handle the rest.
func HasCertJob(ruleID, domains string) bool {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return false
	}
	joined := strings.Join(list, ",")

	var exists bool
	err := db.DB.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM cert_jobs
			WHERE rule_id = ? AND domain = ?
		)
	`, ruleID, joined).Scan(&exists)
	if err != nil {
		log.Printf("HasCertJob query failed for rule %s: %v", ruleID, err)
		return false
	}
	return exists
}

func (s *CertificateService) renewExpiringCertificates() {
	qm := GetCAQueueManager()

	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}

	// CheckExpiration locks s.mu internally; the loop below only touches the
	// DB and the queue, so holding s.mu here would deadlock the renewal.
	maxAttempts := GetCertRenewalAttempts()
	jobs := s.CheckExpiration()
	jobs = append(jobs, s.checkFailedFirstIssuance(maxAttempts)...)
	if len(jobs) == 0 {
		return
	}

	for _, j := range jobs {
		if j.RenewalAttempts >= maxAttempts {
			if j.Status == "waiting_ca" {
				if err := transitionJob(db.DB, j.ID, []string{"waiting_ca"}, "failed", map[string]any{"message": "已达到最大重试次数，请检查 CA 配置后手动重签"}); err != nil {
					log.Printf("Renewal: failed to convert waiting_ca job %d to failed: %v", j.ID, err)
				} else {
					RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(j.ID), AuditRulePart(j.RuleID), AuditResultPart("max_attempts")), "")
				}
			}
			continue
		}

		if qm == nil {
			log.Printf("Renewal: CA queue manager not initialized")
			return
		}
		message := "等待排队续期"
		action := "续签排队"
		source := "renewal"
		if !j.ExpiresAt.Valid {
			message = "首次签发失败，冷却结束自动重试"
			action = "重试排队"
			source = "first_issuance_retry"
		}
		_, changed, err := qm.EnqueueIfActive(j.CAProviderID, j.ID, j.RuleID, j.Domain, func() (int, bool, error) {
			err := transitionJob(db.DB, j.ID, []string{"issued", "failed", "waiting_ca"}, "queued", map[string]any{"message": message})
			if errors.Is(err, ErrJobTransitionConflict) {
				return j.ID, false, nil
			}
			return j.ID, err == nil, err
		})
		if err != nil {
			log.Printf("Renewal: failed to update job %d status: %v", j.ID, err)
			continue
		}
		if !changed {
			continue
		}
		RecordAuditLog("system", action, "证书签发任务", FormatAuditDetail(AuditJobPart(j.ID), AuditRulePart(j.RuleID), AuditSourcePart(source)), "")
	}
}

func (s *CertificateService) checkManualCertExpiration() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-read all manual certificates into memory, then close cursor before parsing
	rows, err := db.DB.Query(`
		SELECT caddy_id, name, domain, tls_cert 
		FROM lb_rules 
		WHERE enable_tls = 1 AND COALESCE(tls_source,'manual') = 'manual' AND tls_cert != ''
	`)
	if err != nil {
		log.Printf("Failed to query TLS certificates for expiration check: %v", err)
		return
	}
	type certInfo struct {
		caddyID string
		name    string
		domain  string
		certPEM string
	}
	var certs []certInfo
	for rows.Next() {
		var c certInfo
		if err := rows.Scan(&c.caddyID, &c.name, &c.domain, &c.certPEM); err != nil {
			// Round 35 B4: 静默 continue 会让证书过期检查遗漏，必须记录告警。
			log.Printf("Warning: scan failed during expiration check, skipping row: %v", err)
			continue
		}
		certs = append(certs, c)
	}
	// Round 35 B4: 显式检查 rows.Err 和 rows.Close 错误，避免迭代期间错误被吞没。
	if err := rows.Err(); err != nil {
		log.Printf("Warning: iteration error during expiration check: %v", err)
	}
	if err := rows.Close(); err != nil {
		log.Printf("Warning: close rows failed during expiration check: %v", err)
	}

	now := time.Now()
	var expiredCount, expiringSoonCount int

	// Round 35 I-20: 不再忽略 warnDays 错误，避免查询失败时所有证书都被误报即将过期。
	warnDays := 30
	if err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&warnDays); err != nil {
		log.Printf("Warning: read cert_expiry_days failed, using default 30: %v", err)
		warnDays = 30
	}
	for _, c := range certs {
		block, _ := pem.Decode([]byte(c.certPEM))
		if block == nil {
			log.Printf("Warning: Invalid certificate PEM for rule %s (%s)", c.caddyID, c.name)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Warning: Failed to parse certificate for rule %s (%s): %v", c.caddyID, c.name, err)
			continue
		}

		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

		if now.After(cert.NotAfter) {
			log.Printf("⚠️ CRITICAL: TLS certificate expired for rule '%s' (domain: %s, caddy_id: %s). Expired on %s",
				c.name, c.domain, c.caddyID, cert.NotAfter.Format("2006-01-02"))
			expiredCount++
		} else if daysUntilExpiry <= warnDays {
			log.Printf("⚠️ WARNING: TLS certificate expiring soon for rule '%s' (domain: %s, caddy_id: %s). Expires in %d days (%s)",
				c.name, c.domain, c.caddyID, daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
			expiringSoonCount++
		}
	}

	if expiredCount > 0 || expiringSoonCount > 0 {
		log.Printf("TLS Certificate Check: %d expired, %d expiring within %d days", expiredCount, expiringSoonCount, warnDays)
	}
}

func (s *CertificateService) CheckExpiration() []models.CertJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&days)
	if err != nil {
		days = 30
	}
	if days <= 0 {
		days = 30
	}

	rows, err := db.DB.Query(`
		SELECT j.id, j.rule_id, j.domain, j.status, j.expires_at, j.ca_provider_id, COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''),r.domain
		FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.expires_at IS NOT NULL
		  AND datetime(j.expires_at) <= datetime('now', '+' || ? || ' days')
		  AND j.status IN ('issued', 'failed', 'waiting_ca')
		  AND (j.status != 'waiting_ca' OR j.ca_available_after IS NULL OR datetime(j.ca_available_after) <= datetime('now'))
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		ORDER BY j.expires_at ASC
	`, days)
	if err != nil {
		log.Printf("Failed to query expiring certificates: %v", err)
		return nil
	}
	defer rows.Close()

	var jobs []models.CertJob
	now := time.Now()
	selectedByRule := make(map[string]CertificateSelection)
	selectionLoaded := make(map[string]bool)
	for rows.Next() {
		var j models.CertJob
		var ruleDomain string
		if err := rows.Scan(
			&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt, &j.CAProviderID, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode, &ruleDomain,
		); err != nil {
			continue
		}
		canonicalRule, ruleErr := CanonicalACMEDomains(ruleDomain)
		canonicalJob, jobErr := CanonicalACMEDomains(j.Domain)
		if ruleErr != nil || jobErr != nil || canonicalRule != canonicalJob {
			continue
		}
		selection, selected := selectedByRule[j.RuleID]
		if !selectionLoaded[j.RuleID] {
			selection, selected, err = selectStoredRuleCertificate(context.Background(), j.RuleID, ruleDomain, now)
			selectionLoaded[j.RuleID] = true
			if err != nil {
				log.Printf("Failed to select current certificate for rule %s: %v", j.RuleID, err)
				continue
			}
			if selected {
				selectedByRule[j.RuleID] = selection
			}
		}
		if selected {
			canonicalSelected, selectedErr := CanonicalACMEDomains(selection.Candidate.Domain)
			if selectedErr == nil && canonicalSelected == canonicalRule && selection.Certificate.NotAfter.After(now.Add(time.Duration(days)*24*time.Hour)) {
				continue
			}
		}
		jobs = append(jobs, j)
	}
	return jobs
}

const firstIssuanceRetryCooldownMinutes = 30

// checkFailedFirstIssuance 返回首次签发失败（expires_at IS NULL，从未签发成功）、
// 已过冷却期且未达最大重试次数的证书任务，供续期巡检自动重试。规则筛选与
// 已有证书判读逻辑与 CheckExpiration 保持一致。
func (s *CertificateService) checkFailedFirstIssuance(maxAttempts int) []models.CertJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&days)
	if err != nil || days <= 0 {
		days = 30
	}

	rows, err := db.DB.Query(`
		SELECT j.id, j.rule_id, j.domain, j.status, j.expires_at, j.ca_provider_id, COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''),r.domain
		FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status = 'failed'
		  AND j.expires_at IS NULL
		  AND COALESCE(j.renewal_attempts,0) < ?
		  AND datetime(COALESCE(j.updated_at,j.created_at)) <= datetime('now', '-' || ? || ' minutes')
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		ORDER BY j.updated_at ASC
	`, maxAttempts, firstIssuanceRetryCooldownMinutes)
	if err != nil {
		log.Printf("Failed to query failed first-issuance certificates: %v", err)
		return nil
	}
	defer rows.Close()

	var jobs []models.CertJob
	now := time.Now()
	selectedByRule := make(map[string]CertificateSelection)
	selectionLoaded := make(map[string]bool)
	for rows.Next() {
		var j models.CertJob
		var ruleDomain string
		if err := rows.Scan(
			&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt, &j.CAProviderID, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode, &ruleDomain,
		); err != nil {
			continue
		}
		canonicalRule, ruleErr := CanonicalACMEDomains(ruleDomain)
		canonicalJob, jobErr := CanonicalACMEDomains(j.Domain)
		if ruleErr != nil || jobErr != nil || canonicalRule != canonicalJob {
			continue
		}
		selection, selected := selectedByRule[j.RuleID]
		if !selectionLoaded[j.RuleID] {
			selection, selected, err = selectStoredRuleCertificate(context.Background(), j.RuleID, ruleDomain, now)
			selectionLoaded[j.RuleID] = true
			if err != nil {
				log.Printf("Failed to select current certificate for rule %s: %v", j.RuleID, err)
				continue
			}
			if selected {
				selectedByRule[j.RuleID] = selection
			}
		}
		if selected {
			canonicalSelected, selectedErr := CanonicalACMEDomains(selection.Candidate.Domain)
			if selectedErr == nil && canonicalSelected == canonicalRule && selection.Certificate.NotAfter.After(now.Add(time.Duration(days)*24*time.Hour)) {
				continue
			}
		}
		jobs = append(jobs, j)
	}
	return jobs
}

func selectStoredRuleCertificate(ctx context.Context, ruleID, ruleDomains string, now time.Time) (CertificateSelection, bool, error) {
	rows, err := db.DB.QueryContext(ctx, `SELECT id,domain,status,COALESCE(cert_pem,''),COALESCE(key_pem,''),
		COALESCE(julianday(COALESCE(updated_at,created_at)),0)
		FROM cert_jobs WHERE rule_id=? AND COALESCE(cert_pem,'')<>'' AND COALESCE(key_pem,'')<>''`, ruleID)
	if err != nil {
		return CertificateSelection{}, false, err
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Domain, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); err != nil {
			return CertificateSelection{}, false, err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return CertificateSelection{}, false, err
	}
	selection, selected := SelectCertificate(candidates, ruleDomains, now)
	return selection, selected, nil
}
