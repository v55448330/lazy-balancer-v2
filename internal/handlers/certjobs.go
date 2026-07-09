package handlers

import (
	"bytes"
	"database/sql"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListCertJobs(c *gin.Context) {
	ruleID := c.Query("rule_id")
	query := `SELECT id, rule_id, domain, status, COALESCE(message,'') AS message, COALESCE(cert_pem,'') AS cert_pem, expires_at, created_at, updated_at, COALESCE(renewal_attempts,0) AS renewal_attempts, ca_available_after, COALESCE(last_error_code,'') AS last_error_code FROM cert_jobs`
	var args []interface{}
	if ruleID != "" {
		query += " WHERE rule_id = ?"
		args = append(args, ruleID)
	}
	query += " ORDER BY created_at DESC"

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query cert jobs"})
		return
	}
	defer rows.Close()

	var jobs []models.CertJob
	for rows.Next() {
		var j models.CertJob
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &j.CertPEM,
			&j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode,
		); err != nil {
			log.Printf("ListCertJobs scan error: %v", err)
			continue
		}
		jobs = append(jobs, j)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: jobs})
}

func (h *Handlers) RetryCertJob(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot retry jobs on slave node"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	var ruleID, domain, status string
	var caProviderID int
	var updatedAt sql.NullTime
	err = db.DB.QueryRow("SELECT rule_id, domain, status, updated_at, ca_provider_id FROM cert_jobs WHERE id=?", id).Scan(&ruleID, &domain, &status, &updatedAt, &caProviderID)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
		return
	}

	if status != "issued" && status != "failed" && status != "waiting_ca" {
		// All ACME in-progress states get a short 2-minute guard so users can
		// force-retry a stuck job quickly. Only 'queued' gets the long guard.
		guard := 2 * time.Minute
		if status == "queued" {
			guard = 15 * time.Minute
		}
		if updatedAt.Valid && time.Since(updatedAt.Time) < guard {
			c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "任务正在执行中，请稍后重试"})
			return
		}
	}
	if status == "failed" {
		if updatedAt.Valid && time.Since(updatedAt.Time) < 5*time.Minute {
			c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "失败后请等待 5 分钟再重试"})
			return
		}
	}

	go func() {
		// Manual re-sign should use the current default CA provider selected by the user.
		if _, err := db.DB.Exec("UPDATE cert_jobs SET renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL WHERE id=?", id); err != nil {
			log.Printf("Failed to reset renewal attempts for job %d: %v", id, err)
		}
		qm := services.GetCAQueueManager()
		if qm == nil {
			log.Printf("Manual retry enqueue failed for job %d: CA queue manager not initialized", id)
			return
		}
		if err := services.CreateOrRequeueCertJob(ruleID, domain, 0, qm); err != nil {
			log.Printf("Manual retry enqueue failed for job %d: %v", id, err)
		}
	}()

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Retry triggered"})
}

func (h *Handlers) DeleteCertJob(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete jobs on slave node"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	db.DB.Exec("DELETE FROM cert_jobs WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Job deleted"})
}

func (h *Handlers) GetCertJob(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	var j models.CertJob
	err = db.DB.QueryRow("SELECT id, rule_id, domain, status, COALESCE(message,'') AS message, expires_at, created_at, updated_at FROM cert_jobs WHERE id=?", id).
		Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get job"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: j})
}

func (h *Handlers) GetCertJobLogs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}

	var ruleID string
	if err := db.DB.QueryRow("SELECT rule_id FROM cert_jobs WHERE id=?", id).Scan(&ruleID); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Cert job not found"})
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
