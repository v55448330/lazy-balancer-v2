package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListCertJobs(c *gin.Context) {
	ruleID := c.Query("rule_id")
	query := "SELECT id, rule_id, domain, status, message, expires_at, created_at, updated_at FROM cert_jobs"
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
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message,
			&j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt,
		); err != nil {
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

	id, _ := strconv.Atoi(c.Param("id"))
	var ruleID, domain string
	err := db.DB.QueryRow("SELECT rule_id, domain FROM cert_jobs WHERE id=?", id).Scan(&ruleID, &domain)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
		return
	}

	go func() {
		issuer := services.NewCertIssuer(func() error {
			h.applyCaddyConfig()
			return nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := issuer.Issue(ctx, ruleID, domain); err != nil {
			log.Printf("Cert issuance failed for %s: %v", domain, err)
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

	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM cert_jobs WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Job deleted"})
}

func (h *Handlers) GetCertJob(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var j models.CertJob
	err := db.DB.QueryRow("SELECT id, rule_id, domain, status, message, expires_at, created_at, updated_at FROM cert_jobs WHERE id=?", id).
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
	id, _ := strconv.Atoi(c.Param("id"))

	limit := 500
	if l, _ := strconv.Atoi(c.Query("limit")); l > 0 {
		if l > 5000 {
			l = 5000
		}
		limit = l
	}

	rows, err := db.DB.Query(
		"SELECT id, job_id, level, message, created_at FROM cert_job_logs WHERE job_id=? ORDER BY id DESC LIMIT ?",
		id, limit,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query logs: " + err.Error()})
		return
	}
	defer rows.Close()

	var logs []models.CertJobLog
	for rows.Next() {
		var l models.CertJobLog
		if err := rows.Scan(&l.ID, &l.JobID, &l.Level, &l.Message, &l.CreatedAt); err != nil {
			continue
		}
		logs = append(logs, l)
	}

	// Reverse to chronological order for display
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: logs})
}
