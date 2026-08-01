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

var certJobIndexState struct {
	sync.Mutex
	databases map[*sql.DB]struct{}
}

var cancelCertJob = func(id int) {
	if qm := services.GetCAQueueManager(); qm != nil {
		qm.CancelJob(id)
	}
}

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
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "page 必须为正整数"})
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
	query := `SELECT j.id, j.rule_id, j.domain, j.status, COALESCE(j.message,'') AS message, COALESCE(j.cert_pem,'') AS cert_pem, j.expires_at, j.created_at, j.updated_at, COALESCE(j.renewal_attempts,0) AS renewal_attempts, j.ca_available_after, COALESCE(j.last_error_code,'') AS last_error_code, COALESCE(j.ca_provider_id,0) AS ca_provider_id, COALESCE(p.name,'') AS ca_provider_name FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id`
	var args []interface{}
	if ruleID != "" {
		query += " WHERE j.rule_id = ?"
		args = append(args, ruleID)
	}
	query += " ORDER BY j.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, (page-1)*pageSize)

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
			j.DaysRemaining = int(j.ExpiresAt.Time.Sub(now).Hours() / 24)
			if !now.Before(j.ExpiresAt.Time) {
				j.CertificateStatus = "expired"
			} else if j.DaysRemaining <= 30 {
				j.CertificateStatus = "expiring"
			} else {
				j.CertificateStatus = "valid"
			}
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
		return
	}
	c.Header("X-Page", strconv.Itoa(page))
	c.Header("X-Page-Size", strconv.Itoa(pageSize))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: jobs})
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
	_, changed, err := qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
		result, err := db.DB.Exec(`UPDATE cert_jobs
			SET status='queued', message='重新排队签发', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now')
			WHERE id=? AND status=? AND EXISTS (
				SELECT 1 FROM lb_rules
				WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND domain=?
			)`, id, status, ruleID, domain)
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
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务关联规则已禁用、证书配置已变更或队列已暂停"})
		return
	}
	recordAudit(c, "重试", "证书签发任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status), services.AuditResultPart("queued")))

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

func (h *Handlers) DeleteCertJob(c *gin.Context) {

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
	if err := db.DB.QueryRow("SELECT rule_id, domain, status, COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id = ?", id).Scan(&ruleID, &domain, &status, &caProviderID); dbQueryNotFound(c, err, "Job not found", "DeleteCertJob query job") {
		return
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
							SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND domain=?
						)`, id, ruleID, domain)
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
	recordAudit(c, "删除", "证书签发任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status)))
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
