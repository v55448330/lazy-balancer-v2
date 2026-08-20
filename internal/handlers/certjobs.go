package handlers

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var certJobOperationLocks [64]sync.Mutex

// retryCertJobPreEnqueueHook 是测试专用钩子：在 SELECT 状态之后、EnqueueIfActive
// 内 UPDATE 之前触发，用于模拟 worker 侧并发状态流转（R42 发现4 回归测试）。
var retryCertJobPreEnqueueHook func(jobID int)

var certJobIndexState struct {
	sync.Mutex
	databases map[*sql.DB]struct{}
}

var cancelCertJob = func(id int) {
	if qm := services.GetCAQueueManager(); qm != nil {
		qm.CancelJob(id)
	}
}

const maxCertJobPage int64 = 1_000_000

func certJobOperationLock(id int) *sync.Mutex {
	index := id % len(certJobOperationLocks)
	if index < 0 {
		index += len(certJobOperationLocks)
	}
	return &certJobOperationLocks[index]
}

func ensureCertJobListIndex() error {
	certJobIndexState.Lock()
	defer certJobIndexState.Unlock()
	if certJobIndexState.databases == nil {
		certJobIndexState.databases = make(map[*sql.DB]struct{})
	}
	if _, exists := certJobIndexState.databases[db.DB]; exists {
		return nil
	}
	if _, err := db.DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_created_at_desc ON cert_jobs(created_at DESC)"); err != nil {
		return err
	}
	certJobIndexState.databases[db.DB] = struct{}{}
	return nil
}

func (h *Handlers) ListCertJobs(c *gin.Context) {
	ruleID := c.Query("rule_id")
	page, err := strconv.ParseInt(c.DefaultQuery("page", "1"), 10, 64)
	if err != nil || page < 1 || page > maxCertJobPage {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("page 必须为 1-%d 之间的整数", maxCertJobPage)})
		return
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if err != nil || pageSize < 1 || pageSize > 200 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "page_size 必须在 1-200 之间"})
		return
	}
	if err := ensureCertJobListIndex(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "初始化证书任务分页索引失败"})
		return
	}
	if page-1 > math.MaxInt64/int64(pageSize) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "page 超出可查询范围"})
		return
	}
	offset := (page - 1) * int64(pageSize)
	whereClause := ""
	var filterArgs []interface{}
	if ruleID != "" {
		whereClause = " WHERE j.rule_id = ?"
		filterArgs = append(filterArgs, ruleID)
	}
	var total int64
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs j"+whereClause, filterArgs...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务失败"})
		return
	}
	var expiryDays int
	if err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&expiryDays); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书过期提醒配置失败"})
		return
	}
	query := `SELECT j.id, j.rule_id, j.domain, j.status, COALESCE(j.message,'') AS message, COALESCE(j.cert_pem,'') AS cert_pem, j.expires_at, j.created_at, j.updated_at, COALESCE(j.renewal_attempts,0) AS renewal_attempts, j.ca_available_after, COALESCE(j.last_error_code,'') AS last_error_code, COALESCE(j.ca_provider_id,0) AS ca_provider_id, COALESCE(p.name,'') AS ca_provider_name FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id`
	query += whereClause
	args := append([]interface{}{}, filterArgs...)
	query += " ORDER BY j.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query cert jobs"})
		return
	}
	defer rows.Close()

	type certJobListItem struct {
		ID                int                 `json:"id"`
		RuleID            string              `json:"rule_id"`
		Domain            string              `json:"domain"`
		CAProviderID      int                 `json:"ca_provider_id"`
		CAProviderName    string              `json:"ca_provider_name,omitempty"`
		Status            string              `json:"status"`
		Message           string              `json:"message"`
		Issuer            string              `json:"issuer"`
		DaysRemaining     int                 `json:"days_remaining"`
		CertificateStatus string              `json:"certificate_status"`
		RenewalAttempts   int                 `json:"renewal_attempts,omitempty"`
		CAAvailableAfter  models.JSONNullTime `json:"ca_available_after,omitempty"`
		LastErrorCode     string              `json:"last_error_code,omitempty"`
		ExpiresAt         models.JSONNullTime `json:"expires_at"`
		CreatedAt         time.Time           `json:"created_at"`
		UpdatedAt         models.JSONNullTime `json:"updated_at"`
	}
	jobs := make([]certJobListItem, 0, pageSize)
	now := time.Now()
	for rows.Next() {
		var j certJobListItem
		var certPEM string
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &certPEM,
			&j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode, &j.CAProviderID, &j.CAProviderName,
		); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
			return
		}
		j.Issuer = certificateIssuer(certPEM)
		j.CertificateStatus = "unknown"
		if j.ExpiresAt.Valid {
			remaining := j.ExpiresAt.Time.Sub(now)
			if !now.Before(j.ExpiresAt.Time) {
				j.DaysRemaining = int(math.Floor(remaining.Hours() / 24))
				j.CertificateStatus = "expired"
			} else {
				j.DaysRemaining = int(math.Ceil(remaining.Hours() / 24))
				if remaining <= time.Duration(expiryDays)*24*time.Hour {
					j.CertificateStatus = "expiring"
				} else {
					j.CertificateStatus = "valid"
				}
			}
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
		return
	}
	c.Header("X-Page", strconv.FormatInt(page, 10))
	c.Header("X-Page-Size", strconv.Itoa(pageSize))
	c.Header("X-Total", strconv.FormatInt(total, 10))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"list": jobs, "total": total, "page": page, "page_size": pageSize}})
}

// GetCurrentCertJobs returns the latest non-disabled job per requested rule so
// polling does not depend on offset pagination (which drifts under inserts).
func (h *Handlers) GetCurrentCertJobs(c *gin.Context) {
	var req struct {
		RuleIDs []string `json:"rule_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误: " + err.Error()})
		return
	}
	if len(req.RuleIDs) > 200 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "invalid_request：rule_ids 数量不能超过 200"})
		return
	}
	result := make(map[string]*models.CertJob, len(req.RuleIDs))
	for _, id := range req.RuleIDs {
		result[id] = nil
	}
	if len(req.RuleIDs) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
		return
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(req.RuleIDs)), ",")
	args := make([]interface{}, len(req.RuleIDs))
	for i, id := range req.RuleIDs {
		args[i] = id
	}
	rows, err := db.DB.QueryContext(c.Request.Context(), `SELECT j.id, j.rule_id, j.domain, COALESCE(j.ca_provider_id,0), COALESCE(p.name,''), j.status, COALESCE(j.message,''), COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''), j.expires_at, j.created_at, j.updated_at
		FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id
		WHERE j.rule_id IN (`+placeholders+`) AND j.status <> 'disabled'
		ORDER BY j.rule_id, j.created_at DESC, j.id DESC`, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询证书任务失败"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var job models.CertJob
		if err := rows.Scan(&job.ID, &job.RuleID, &job.Domain, &job.CAProviderID, &job.CAProviderName, &job.Status, &job.Message, &job.RenewalAttempts, &job.CAAvailableAfter, &job.LastErrorCode, &job.ExpiresAt, &job.CreatedAt, &job.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
			return
		}
		if result[job.RuleID] == nil {
			result[job.RuleID] = &job
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func certificateIssuer(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.CommonName
}

func (h *Handlers) RetryCertJob(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	operationLock := certJobOperationLock(id)
	operationLock.Lock()
	defer operationLock.Unlock()
	var ruleID, domain, status string
	var caProviderID int
	var updatedAt sql.NullTime
	err = db.DB.QueryRow("SELECT rule_id, domain, status, updated_at, ca_provider_id FROM cert_jobs WHERE id=?", id).Scan(&ruleID, &domain, &status, &updatedAt, &caProviderID)
	if dbQueryNotFound(c, err, "任务不存在", "RetryCertJob query job") {
		return
	}

	if blocked, message := certJobRetryBlocked(status, updatedAt, time.Now()); blocked {
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: message})
		return
	}

	qm := services.GetCAQueueManager()
	if qm == nil {
		log.Printf("Manual retry enqueue failed for job %d: CA queue manager not initialized", id)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA queue manager not initialized"})
		return
	}
	// cert_jobs.domain 按排序后的规范形式存储，而 lb_rules.domain 保留用户输入顺序，
	// 规则侧用 joined+reversed 双形式匹配（ACME 域名至多根域+www 两个）。
	reversedDomain := domain
	if parts := strings.Split(domain, ","); len(parts) == 2 {
		reversedDomain = parts[1] + "," + parts[0]
	}
	if retryCertJobPreEnqueueHook != nil {
		retryCertJobPreEnqueueHook(id)
	}
	_, changed, err := qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
		result, err := db.DB.Exec(`UPDATE cert_jobs
			SET status='queued', message='重新排队签发', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now')
			WHERE id=? AND status=? AND EXISTS (
				SELECT 1 FROM lb_rules
				WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
			)`, id, status, ruleID, domain, reversedDomain)
		if err != nil {
			return id, false, err
		}
		rowsAffected, err := result.RowsAffected()
		return id, rowsAffected != 0, err
	})
	if err != nil {
		log.Printf("Manual retry enqueue failed for job %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to enqueue retry"})
		return
	}
	if !changed {
		// SELECT(:254) 与 UPDATE 之间状态可能被 worker 流转（如 failed→creating_account），
		// 导致 0 行影响；此时归因是并发竞争而非规则禁用，重读当前状态区分文案（R42 发现4）。
		var currentStatus string
		scanErr := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&currentStatus)
		if scanErr != nil {
			// 重读失败属瞬时 DB 错误（SQLITE_BUSY 等），归因为规则禁用会误导用户，
			// 显式区分 500（R43 A-3）。
			log.Printf("RetryCertJob reread job %d status failed: %v", id, scanErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取任务状态失败"})
			return
		}
		if currentStatus != status {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务状态已变更，请刷新后重试"})
			return
		}
		// R46 A-F3：EnqueueIfActive 的在途命中（R45 发现2）同样走 !changed 且重读
		// 状态未变，需优先归因"任务正在队列中"，避免误导为规则禁用/配置变更。
		if qm.IsJobActive(id) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务正在签发队列中，请勿重复操作"})
			return
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务关联规则已禁用、证书配置已变更或队列已暂停"})
		return
	}
	recordAudit(c, "重试", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status), services.AuditResultPart("queued")))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Retry triggered"})
}

func certJobRetryBlocked(status string, updatedAt sql.NullTime, now time.Time) (bool, string) {
	if status == "disabled" {
		return true, "已退役的证书任务不能重试"
	}
	if !updatedAt.Valid {
		return false, ""
	}
	if status == "failed" && now.Sub(updatedAt.Time) < 5*time.Minute {
		return true, "失败后请等待 5 分钟再重试"
	}
	if status == "issued" || status == "failed" || status == "waiting_ca" {
		return false, ""
	}
	guard := 2 * time.Minute
	if status == "queued" {
		guard = 15 * time.Minute
	}
	return now.Sub(updatedAt.Time) < guard, "任务正在执行中，请稍后重试"
}

// reversedCertJobDomain 交换双域名任务的域名顺序：cert_jobs.domain 存排序
// 规范形式，lb_rules.domain 保留用户输入顺序，匹配需同时覆盖两种排列。
func reversedCertJobDomain(domain string) string {
	parts := strings.Split(domain, ",")
	if len(parts) == 2 {
		return parts[1] + "," + parts[0]
	}
	return domain
}

func (h *Handlers) DeleteCertJob(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	// R53 C-发现3 TOCTOU：N4 守卫读规则 enabled 状态后、删除前，EnableRule
	// （持 caddyOpMu）可完成启用并恢复任务，守卫放行被竞态绕过。caddyOpMu
	// 覆盖 查询→守卫→disabled 翻转→取消→删除 全程，与 EnableRule 互斥：
	// 删除先完成则 EnableRule 查不到任务行，走 EnableCertJobCreate 重建
	// （续签链不断）；EnableRule 先完成则守卫读到 enabled=1 返回 409。
	// worker 无法在翻转后复活任务：transitionJob 的 from 列表均不含
	// 'disabled'（唯一按现状重读的 caqueue.EnqueueIfActive 的调用方均持
	// caddyOpMu 或 certJobOperationLock 之一），'disabled' 对 worker 是终态。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	operationLock := certJobOperationLock(id)
	operationLock.Lock()
	defer operationLock.Unlock()
	var ruleID, domain, status string
	var caProviderID int
	if err := db.DB.QueryRow("SELECT rule_id, domain, status, COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id = ?", id).Scan(&ruleID, &domain, &status, &caProviderID); dbQueryNotFound(c, err, "Job not found", "DeleteCertJob query job") {
		return
	}
	// R52 N4：删除持有证书的 issued/downloaded 任务且规则仍在自动签发状态
	// 时，纯周期路径永不重建任务行（CreateOrRequeueCertJob 仅由规则写路径
	// 调用），自动续签永久断链且 UI 无信号——409 显式拒绝；运维可先禁用
	// 规则或切换证书来源后再删除，与既有 disabled-flow 语义一致。
	if status == "issued" || status == "downloaded" {
		var active int
		if err := db.DB.QueryRow(`SELECT COUNT(1) FROM lb_rules
			WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns'
			  AND lower(replace(domain,' ','')) IN (?,?)`,
			ruleID, domain, reversedCertJobDomain(domain)).Scan(&active); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule state"})
			return
		}
		if active > 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该任务持有有效证书且关联规则仍在自动签发状态，删除后自动续签将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"})
			return
		}
	}
	result, err := db.DB.Exec("UPDATE cert_jobs SET status='disabled', updated_at=datetime('now') WHERE id=? AND status=?", id, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to disable job"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to verify disabled job"})
		return
	}
	cancelCertJob(id)
	result, err = db.DB.Exec("DELETE FROM cert_jobs WHERE id = ?", id)
	if err != nil {
		deleteErr := err
		if status == "issued" || status == "failed" {
			if _, restoreErr := db.DB.Exec("UPDATE cert_jobs SET status=?, updated_at=datetime('now') WHERE id=?", status, id); restoreErr != nil {
				deleteErr = errors.Join(deleteErr, restoreErr)
			}
		} else {
			qm := services.GetCAQueueManager()
			var restoreErr error
			changed := false
			if qm == nil {
				restoreErr = errors.New("CA queue manager not initialized")
			} else {
				_, changed, restoreErr = qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
					updateResult, updateErr := db.DB.Exec(`UPDATE cert_jobs SET status='queued', message='删除失败，重新排队签发', updated_at=datetime('now')
						WHERE id=? AND status='disabled' AND EXISTS (
							SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
						)`, id, ruleID, domain, reversedCertJobDomain(domain))
					if updateErr != nil {
						return id, false, updateErr
					}
					rows, rowsErr := updateResult.RowsAffected()
					return id, rows == 1, rowsErr
				})
			}
			if restoreErr != nil || !changed {
				if restoreErr == nil {
					restoreErr = errors.New("job was not restored to active queue")
				}
				if _, failErr := db.DB.Exec("UPDATE cert_jobs SET status='failed', message='删除失败且恢复队列失败', updated_at=datetime('now') WHERE id=?", id); failErr != nil {
					restoreErr = errors.Join(restoreErr, failErr)
				}
				deleteErr = errors.Join(deleteErr, restoreErr)
			}
		}
		log.Printf("DeleteCertJob failed for job %d: %v", id, deleteErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete job"})
		return
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to verify deleted job"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
		return
	}
	recordAudit(c, "删除", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Job deleted"})
}

func (h *Handlers) GetCertJob(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	var j models.CertJob
	err = db.DB.QueryRow("SELECT id, rule_id, domain, status, COALESCE(message,'') AS message, expires_at, created_at, updated_at, ca_available_after FROM cert_jobs WHERE id=?", id).
		Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.CAAvailableAfter)
	if dbQueryNotFound(c, err, "Job not found", "GetCertJob query job") {
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: j})
}

func (h *Handlers) GetCertJobLogs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}

	var ruleID string
	if err := db.DB.QueryRow("SELECT rule_id FROM cert_jobs WHERE id=?", id).Scan(&ruleID); dbQueryNotFound(c, err, "Cert job not found", "GetCertJobLogs query job") {
		return
	}

	logPath := services.CertJobLogPath(ruleID)
	logPathBackup := logPath + ".1"

	content := readCertJobLogFile(logPath)
	if oldData := readCertJobLogFile(logPathBackup); oldData != "" {
		content = oldData + content
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

func readCertJobLogFile(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	const maxBytes = 128 * 1024
	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return ""
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return ""
	}

	if startOffset > 0 {
		if idx := bytes.IndexByte(data, '\n'); idx != -1 {
			data = data[idx+1:]
		}
	}

	const maxLines = 500
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}
