package services

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider"
	"lazy-balancer-v2/internal/models"

	xacme "golang.org/x/crypto/acme"
)

// CertIssuer coordinates ACME certificate issuance: creates/updates cert_jobs,
// runs the ACME flow, persists cert+key to DB, and triggers Caddy reload.
type CertIssuer struct {
	caddyReloader   func() error
	deploymentRetry func(int, issuedCertificate, time.Duration)
}

const maxCertificateDeploymentAttempts = 10

type issuedCertificate struct {
	ruleID            string
	certPEM           string
	keyPEM            string
	notAfter          time.Time
	providerID        int
	deploymentAttempt int
}

type certificateDeploymentError struct {
	err error
}

func (e *certificateDeploymentError) Error() string { return e.err.Error() }
func (e *certificateDeploymentError) Unwrap() error { return e.err }

// CAProviderRateLimitError indicates the CA rejected the request with 429.
type CAProviderRateLimitError struct {
	RetryAfter time.Duration
	Reason     string
}

func (e *CAProviderRateLimitError) Error() string {
	return fmt.Sprintf("CA rate limited (429), retry after %v: %s", e.RetryAfter, e.Reason)
}

// parseRetryAfter parses an HTTP Retry-After header value into a duration.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// defaultRetryAfter returns the default cooling duration when a CA does not provide Retry-After.
// computeBackoff returns the cooling duration based on attempt count and CA Retry-After.
func computeBackoff(attempts int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	switch attempts {
	case 1:
		return time.Hour
	case 2:
		return 2 * time.Hour
	default:
		return 3 * time.Hour
	}
}

// NewCertIssuer creates a new CertIssuer. The reloader is called after a
// certificate is successfully issued so Caddy picks up the new cert.
func NewCertIssuer(reloader func() error) *CertIssuer {
	return &CertIssuer{caddyReloader: reloader, deploymentRetry: scheduleCertificateDeploymentRetry}
}

func scheduleCertificateDeploymentRetry(jobID int, material issuedCertificate, delay time.Duration) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		log.Printf("certificate deployment retry skipped for job %d: certificate service is not initialized", jobID)
		return
	}
	service.scheduleDeploymentRetry(jobID, material.ruleID, delay)
}

func cancelCertificateDeploymentRetriesForRule(ruleID string) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.cancelDeploymentRetriesForRule(ruleID)
	}
}

func cancelCertificateDeploymentRetry(jobID int) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.cancelDeploymentRetry(jobID)
	}
}

func pauseCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.pauseDeploymentRetries()
	}
}

func resumeCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.resumeDeploymentRetries()
	}
}

func retryCertificateDeployment(ctx context.Context, jobID int, reloader func() error) error {
	var material issuedCertificate
	if err := db.DB.QueryRowContext(ctx, `SELECT rule_id, COALESCE(cert_pem,''), COALESCE(key_pem,''), expires_at,
		COALESCE(ca_provider_id,0), COALESCE(deployment_attempts,0)
		FROM cert_jobs WHERE id=? AND status='downloaded'`, jobID).Scan(
		&material.ruleID, &material.certPEM, &material.keyPEM, &material.notAfter,
		&material.providerID, &material.deploymentAttempt,
	); err != nil {
		return fmt.Errorf("load downloaded certificate for deployment: %w", err)
	}
	return NewCertIssuer(reloader).deployIssuedCertificate(ctx, jobID, material)
}

func (s *CertIssuer) deploymentFailed(jobID int, material issuedCertificate, message string, err error) error {
	var previousAttempt int
	if queryErr := db.DB.QueryRow("SELECT COALESCE(deployment_attempts,0) FROM cert_jobs WHERE id=? AND status!='disabled'", jobID).Scan(&previousAttempt); queryErr != nil {
		return &certificateDeploymentError{err: errors.Join(err, queryErr)}
	}
	if material.deploymentAttempt > previousAttempt {
		previousAttempt = material.deploymentAttempt
	}
	attempt := previousAttempt + 1
	status := "downloaded"
	if attempt >= maxCertificateDeploymentAttempts {
		status = "failed"
	}
	storedMessage := fmt.Sprintf("部署失败 [attempt=%d/%d]: %s", attempt, maxCertificateDeploymentAttempts, message)
	delay := certificateDeploymentBackoff(attempt)
	var availableAfter any
	if status == "downloaded" {
		availableAfter = time.Now().UTC().Add(delay).Format("2006-01-02 15:04:05")
	}
	result, updateErr := db.DB.Exec("UPDATE cert_jobs SET status=?, message=?, deployment_attempts=?, deployment_available_after=?, updated_at=datetime('now') WHERE id=? AND status!='disabled'", status, storedMessage, attempt, availableAfter, jobID)
	if updateErr == nil {
		var updated int64
		updated, updateErr = result.RowsAffected()
		if updateErr == nil && updated != 1 {
			updateErr = fmt.Errorf("certificate job is no longer deployable")
		}
	}
	if updateErr == nil && status == "downloaded" && s.deploymentRetry != nil {
		material.deploymentAttempt = attempt
		s.deploymentRetry(jobID, material, delay)
	}
	if updateErr == nil && status == "failed" {
		RecordAuditLog("system", "部署失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("max_attempts")), "")
	}
	return &certificateDeploymentError{err: errors.Join(err, updateErr)}
}

func certificateDeploymentBackoff(attempt int) time.Duration {
	delay := time.Second
	for i := 1; i < attempt && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}

// jobLogger writes issuance progress to cert job log files and updates cert_jobs.status.
type jobLogger struct {
	jobID  int
	ruleID string
	file   *CertJobFileLogger
}

func (l *jobLogger) Log(stage, message string) {
	l.file.Log(stage, message)
	if _, err := db.DB.Exec("UPDATE cert_jobs SET status=?, message=?, updated_at=datetime('now') WHERE id=? AND status!='disabled'",
		stage, message, l.jobID); err != nil {
		log.Printf("cert job %d status update failed: %v", l.jobID, err)
	}
}

// Issue obtains a certificate for the given rule and domains using the
// provided CA provider. The caller (queue manager) must pass a valid jobID.
func (s *CertIssuer) Issue(ctx context.Context, jobID int, ruleID, domains string, provider models.CAProvider) error {
	if jobID <= 0 {
		return fmt.Errorf("invalid job ID: %d", jobID)
	}

	domainList := normalizeAndValidateDomains(domains)
	if domainList == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}

	logger := &jobLogger{jobID: jobID, ruleID: ruleID, file: NewCertJobFileLogger(ruleID)}

	// Fast path: a previous attempt completed ACME issuance and persisted a
	// valid certificate, but file deployment failed. Redeploy instead of
	// re-issuing through the CA. Skipped when the job is disabled, the rule is
	// disabled, or the rule's CA provider changed since issuance (then the old
	// certificate is from the wrong CA and a fresh issuance is required).
	var jobStatus string
	var jobProviderID int
	var deploymentAttempt int
	var ruleEnabled bool
	var ruleProviderID int
	if err := db.DB.QueryRow(`SELECT j.status, COALESCE(j.ca_provider_id,0), COALESCE(j.deployment_attempts,0), COALESCE(r.enabled,0), COALESCE(r.ca_provider_id,0)
		FROM cert_jobs j LEFT JOIN lb_rules r ON r.caddy_id = j.rule_id WHERE j.id = ?`, jobID).
		Scan(&jobStatus, &jobProviderID, &deploymentAttempt, &ruleEnabled, &ruleProviderID); err == nil &&
		jobStatus != "disabled" && ruleEnabled && ruleProviderID == jobProviderID {
		var existingCert, existingKey string
		if err := db.DB.QueryRow("SELECT COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id=?", jobID).Scan(&existingCert, &existingKey); err == nil && existingCert != "" && existingKey != "" {
			renewalDays := 30
			_ = db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&renewalDays)
			if renewalDays <= 0 {
				renewalDays = 30
			}
			if notAfter, perr := parseCertNotAfter(existingCert); perr == nil && time.Until(notAfter) > time.Duration(renewalDays)*24*time.Hour {
				material := issuedCertificate{ruleID: ruleID, certPEM: existingCert, keyPEM: existingKey, notAfter: notAfter, providerID: jobProviderID, deploymentAttempt: deploymentAttempt}
				unlock := DeployLock(ruleID)
				defer unlock()
				if err := confirmCertificateDeployment(ctx, jobID, material, true); err != nil {
					return err
				}
				logger.Log("downloaded", "检测到已签发的有效证书，直接重新部署文件")
				snapshot, snapshotErr := SnapshotCertFiles([]string{ruleID})
				if snapshotErr != nil {
					return s.deploymentFailed(jobID, material, "读取现有证书文件失败: "+snapshotErr.Error(), fmt.Errorf("snapshot existing certificate files: %w", snapshotErr))
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := WriteCertFiles(ruleID, existingCert, existingKey); err != nil {
					return s.deploymentFailed(jobID, material, "已有证书重新部署失败: "+err.Error(), fmt.Errorf("redeploy existing certificate: %w", err))
				}
				if err := ctx.Err(); err != nil {
					return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
				}
				if s.caddyReloader != nil {
					if err := s.caddyReloader(); err != nil {
						return s.deploymentFailed(jobID, material, "重新部署后重载 Caddy 失败: "+err.Error(), fmt.Errorf("reload Caddy after certificate redeploy: %w", err))
					}
				}
				if err := ctx.Err(); err != nil {
					return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
				}
				result, err := db.DB.ExecContext(ctx, `UPDATE cert_jobs SET status='issued', message='证书文件重新部署成功', deployment_attempts=0, deployment_available_after=NULL, updated_at=datetime('now')
					WHERE id=? AND status='downloaded' AND EXISTS (SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1)
					AND EXISTS (SELECT 1 FROM global_config WHERE id=1 AND is_master=1)`, jobID, ruleID)
				if err == nil {
					var updated int64
					updated, err = result.RowsAffected()
					if err == nil && updated != 1 {
						err = fmt.Errorf("certificate job is no longer deployable")
					}
				}
				if err != nil {
					return errors.Join(fmt.Errorf("finalize certificate redeploy: %w", err), restoreCertificateDeployment(snapshot, s.caddyReloader))
				}
				RecordAuditLog("system", "签发成功", "证书签发任务", fmt.Sprintf("规则 %s 证书重新部署成功", ruleID), "")
				return nil
			}
		}
	}

	// Pre-flight check: verify the CA provider is reachable before starting the
	// real issuance flow. If the CA is down (e.g. ZeroSSL 504), fail fast and
	// let the retry scheduler handle the next attempt.
	logger.Log("creating_account", fmt.Sprintf("测试 CA 提供商 %s (%s) 连通性", provider.Name, provider.Provider))
	if err := NewCAProviderService().TestCAProvider(provider.ID); err != nil {
		logger.Log("failed", fmt.Sprintf("CA 提供商测试失败: %v", err))
		failJob(jobID, fmt.Sprintf("CA 提供商测试失败: %v", err))
		return fmt.Errorf("CA provider test failed: %w", err)
	}
	logger.Log("creating_account", "CA 提供商测试通过")

	// Reset the existing job row (queue manager already created/reused it).
	res, err := db.DB.Exec(
		"UPDATE cert_jobs SET status='creating_account', message='开始申请证书', updated_at=datetime('now') WHERE id=? AND status!='disabled'",
		jobID,
	)
	if err != nil {
		return fmt.Errorf("update cert job status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		failJob(jobID, "证书任务不存在")
		return fmt.Errorf("cert job %d not found", jobID)
	}

	// Resolve ACME config for the rule.
	var acmeConfigID int
	err = db.DB.QueryRow("SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&acmeConfigID)
	if err != nil {
		failJob(jobID, "读取规则 ACME 配置失败")
		return fmt.Errorf("read rule acme config: %w", err)
	}

	// Load ACME email from global config (single source of truth).
	var acmeEmail string
	if err := db.DB.QueryRow("SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail); err != nil {
		failJob(jobID, "读取 ACME 邮箱失败")
		return fmt.Errorf("read global acme email: %w", err)
	}

	// Load DNS credentials from the rule's selected provider.
	var dnsCredentialsJSON string
	if acmeConfigID > 0 {
		err = db.DB.QueryRow("SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=? AND enabled=1", acmeConfigID).Scan(&dnsCredentialsJSON)
		if err != nil && err != sql.ErrNoRows {
			failJob(jobID, "读取 DNS 凭证配置失败")
			return fmt.Errorf("read certificate config: %w", err)
		}
	}
	if dnsCredentialsJSON == "" {
		failJob(jobID, "未选择可用的 DNS 提供商，请先在规则中选择 DNS 凭证")
		return fmt.Errorf("no enabled DNS provider selected for rule")
	}

	dnsProvider, err := dnsprovider.NewProviderFromCredentials(dnsCredentialsJSON)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	// Create ACME client for the selected provider
	if strings.TrimSpace(acmeEmail) == "" {
		failJob(jobID, "ACME 邮箱未配置，请在「系统设置 / 免费证书」中填写邮箱")
		return fmt.Errorf("ACME 邮箱未配置")
	}
	client, err := acme.NewClientForProvider(provider, acmeEmail)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	issuer := &acme.Issuer{
		Client:   client,
		Provider: dnsProvider,
		Logger:   logger,
	}

	// Run the ACME issuance flow
	certPEM, keyPEM, _, err := issuer.Issue(ctx, domainList)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("certificate issuance canceled: %w", ctx.Err())
		}
		if raErr := detectRateLimit(err, provider.Provider); raErr != nil {
			return raErr
		}
		failJob(jobID, err.Error())
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("certificate issuance cancelled: %w", err)
	}

	// Parse certificate expiry
	notAfter, err := parseCertNotAfter(certPEM)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}
	var isMaster bool
	if err := db.DB.QueryRowContext(ctx, "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return fmt.Errorf("节点已切换为从节点，停止保存签发结果")
	}

	if err := s.deployIssuedCertificate(ctx, jobID, issuedCertificate{
		ruleID: ruleID, certPEM: certPEM, keyPEM: keyPEM,
		notAfter: notAfter, providerID: provider.ID,
	}); err != nil {
		return err
	}

	RecordAuditLog("system", "签发成功", "证书签发任务", fmt.Sprintf("规则 %s 证书签发成功，过期时间 %s", ruleID, notAfter.Format("2006-01-02")), "")
	return nil
}

func (s *CertIssuer) deployIssuedCertificate(ctx context.Context, jobID int, material issuedCertificate) error {
	unlock := DeployLock(material.ruleID)
	defer unlock()
	if err := confirmCertificateDeployment(ctx, jobID, material, false); err != nil {
		return err
	}

	result, err := db.DB.ExecContext(ctx, `UPDATE cert_jobs SET status='downloaded', cert_pem=?, key_pem=?, expires_at=?, ca_provider_id=?, deployment_attempts=0, deployment_available_after=NULL, updated_at=datetime('now')
		WHERE id=? AND status IN ('downloaded','cleanup_dns','cleanup_warning') AND EXISTS (SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1)
		AND EXISTS (SELECT 1 FROM global_config WHERE id=1 AND is_master=1)`,
		material.certPEM, material.keyPEM, material.notAfter, material.providerID, jobID, material.ruleID)
	if err != nil {
		return fmt.Errorf("persist downloaded certificate: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read downloaded certificate update result: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("certificate job %d is no longer deployable", jobID)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	snapshot, err := SnapshotCertFiles([]string{material.ruleID})
	if err != nil {
		return s.deploymentFailed(jobID, material, "读取现有证书文件失败: "+err.Error(), fmt.Errorf("snapshot existing certificate files: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := WriteCertFiles(material.ruleID, material.certPEM, material.keyPEM); err != nil {
		RecordAuditLog("system", "写入失败", "证书文件", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("io_error")), "")
		return s.deploymentFailed(jobID, material, "证书文件写入失败: "+err.Error(), fmt.Errorf("write certificate files: %w", err))
	}
	RecordAuditLog("system", "写入", "证书文件", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}

	if s.caddyReloader != nil {
		if err := s.caddyReloader(); err != nil {
			RecordAuditLog("system", "重载失败", "Caddy配置", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID)), "")
			return s.deploymentFailed(jobID, material, "Caddy 重载失败: "+err.Error(), fmt.Errorf("reload Caddy after certificate issuance: %w", err))
		}
		RecordAuditLog("system", "重载", "Caddy配置", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
	}

	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return errors.Join(fmt.Errorf("begin certificate transaction: %w", err), restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	defer func() { _ = tx.Rollback() }()
	result, err = tx.ExecContext(ctx, `UPDATE cert_jobs SET status='issued', message='签发成功', renewal_attempts=0,
		ca_available_after=NULL, last_error_code=NULL, deployment_attempts=0, deployment_available_after=NULL, updated_at=datetime('now')
		WHERE id=? AND status IN ('downloaded','cleanup_dns','cleanup_warning') AND EXISTS (SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1)
		AND EXISTS (SELECT 1 FROM global_config WHERE id=1 AND is_master=1)`, jobID, material.ruleID)
	if err == nil {
		updated, err = result.RowsAffected()
		if err == nil && updated != 1 {
			err = fmt.Errorf("certificate job is no longer deployable")
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		rollbackErr := tx.Rollback()
		cleanupErr := restoreCertificateDeployment(snapshot, s.caddyReloader)
		failJob(jobID, "证书部署确认失败: "+err.Error())
		return errors.Join(fmt.Errorf("finalize issued certificate: %w", err), rollbackErr, cleanupErr)
	}
	return nil
}

func confirmCertificateDeployment(ctx context.Context, jobID int, material issuedCertificate, allowIssued bool) error {
	var status string
	err := db.DB.QueryRowContext(ctx, `SELECT j.status FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		JOIN global_config g ON g.id=1
		WHERE j.id=? AND j.rule_id=?
		  AND r.enabled=1 AND r.domain=j.domain AND g.is_master=1
	`, jobID, material.ruleID).Scan(&status)
	if err != nil {
		return fmt.Errorf("confirm certificate deployment: %w", err)
	}
	deployable := status == "downloaded" || status == "cleanup_dns" || status == "cleanup_warning"
	if allowIssued {
		deployable = status == "issued" || status == "downloaded"
	}
	if !deployable {
		return fmt.Errorf("certificate job %d is no longer deployable", jobID)
	}
	return nil
}

func restoreCertificateDeployment(snapshot CertFilesSnapshot, reloader func() error) error {
	if err := RestoreCertFiles(snapshot); err != nil {
		return fmt.Errorf("restore previous certificate files: %w", err)
	}
	if reloader != nil {
		if err := reloader(); err != nil {
			return fmt.Errorf("reload Caddy after certificate rollback: %w", err)
		}
	}
	return nil
}

func detectRateLimit(err error, providerType string) *CAProviderRateLimitError {
	if err == nil {
		return nil
	}
	// Check for structured ACME 429 error first. golang.org/x/crypto/acme
	// returns *acme.Error with StatusCode and response headers for CA errors.
	var acmeErr *xacme.Error
	if errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusTooManyRequests {
		retryAfter := time.Duration(0)
		if ra := acmeErr.Header.Get("Retry-After"); ra != "" {
			retryAfter = parseRetryAfter(ra)
		}
		return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
	}

	// Fallback: string matching for providers/wrappers that don't surface the
	// structured *acme.Error.
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "429") && !strings.Contains(msg, "rate limit") && !strings.Contains(msg, "too many") {
		return nil
	}

	// Try to extract a Retry-After hint from the error text. The ACME library
	// sometimes includes it as "retry after 2026-01-02 03:04:05 +0000 UTC" or
	// "retry after 3600s".
	retryAfter := time.Duration(0)
	if d := extractRetryAfterFromError(err.Error()); d > 0 {
		retryAfter = d
	}
	return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
}

// extractRetryAfterFromError attempts to pull a Retry-After duration out of a
// CA error message. It is a best-effort fallback because golang.org/x/crypto/acme
// does not expose the HTTP response directly.
func extractRetryAfterFromError(errText string) time.Duration {
	lower := strings.ToLower(errText)
	if idx := strings.Index(lower, "retry after"); idx != -1 {
		suffix := errText[idx+len("retry after"):]
		suffix = strings.TrimSpace(suffix)
		// Strip a trailing period or comma.
		suffix = strings.TrimRight(suffix, ".")
		// Try parsing as seconds if it looks like "3600s".
		if strings.HasSuffix(suffix, "s") {
			if sec, err := strconv.Atoi(strings.TrimSuffix(suffix, "s")); err == nil && sec > 0 {
				return time.Duration(sec) * time.Second
			}
		}
		// Try parsing as an RFC3339 timestamp.
		if t, err := time.Parse(time.RFC3339, suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
		// Try parsing as HTTP date.
		if t, err := time.Parse(http.TimeFormat, suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	return 0
}

// ValidateACMEDomains returns an error if the domains string is not a valid
// ACME certificate request (single domain or root+www).
func ValidateACMEDomains(domains string) error {
	if normalizeAndValidateDomains(domains) == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}
	return nil
}

// normalizeAndValidateDomains returns a cleaned domain list if it is either
// a single domain or a root domain plus its www subdomain. Otherwise nil.
func normalizeAndValidateDomains(domains string) []string {
	parts := strings.Split(domains, ",")
	var list []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		d := strings.TrimSpace(strings.ToLower(p))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		list = append(list, d)
	}
	if len(list) == 0 || len(list) > 2 {
		return nil
	}
	for _, d := range list {
		if !isValidACMEIssuerDomain(d) {
			return nil
		}
	}
	if len(list) == 1 {
		return list
	}
	// Must be root + www.root (either ordering)
	a, b := list[0], list[1]
	if b == "www."+a || a == "www."+b {
		return list
	}
	return nil
}

// isValidACMEIssuerDomain rejects wildcards, IP addresses, empty labels and
// labels longer than 63 bytes.
func isValidACMEIssuerDomain(d string) bool {
	if d == "" {
		return false
	}
	if strings.Contains(d, "*") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	if len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
	}
	return true
}

// parseCertNotAfter extracts the NotAfter time from a PEM certificate chain.
func parseCertNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}
